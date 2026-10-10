"""Connection manager: the heart of the daemon.

Owns the single active connection, its lifecycle thread, the network lock,
DNS/route changes, hooks, statistics and the log buffer.
"""

import collections
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import urllib.request

from . import __version__, backends, backup, blocks, dns, history, hotspot, leaktest, netlock, network, paths, proxysvc, schedule, share, split, stunnel, xray
from . import platform as plat
from .backends.base import CredentialsRequired
from .profiles import ProfileError, ProfileStore, public_view
from .settings import Settings


RESUME_GAP = 20          # seconds: the monitor loop wakes every 3 s, so a longer gap means the computer slept


class ConnectError(Exception):
    """A connection attempt failed (retryable)."""


class FatalError(ConnectError):
    """Configuration problem - retrying cannot help.  `kind` lets the UI react ("auth": ask for credentials)."""

    def __init__(self, msg, kind=None):
        super().__init__(msg)
        self.kind = kind


class LogBuffer:
    def __init__(self, size=5000):
        self._buf = collections.deque(maxlen=size)
        self._seq = 0
        self._lock = threading.Lock()
        self._fh = None

    def open_file(self, path):
        try:
            self._fh = open(path, "a", buffering=1)
            os.chmod(path, 0o640)
        except OSError:
            self._fh = None

    def add(self, level, msg):
        with self._lock:
            self._seq += 1
            e = {"seq": self._seq, "time": time.time(), "level": level, "msg": msg}
            self._buf.append(e)
            if self._fh:
                try:
                    self._fh.write("%s [%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg))
                except (OSError, ValueError):
                    pass
        return e

    def since(self, seq=0, limit=1000):
        with self._lock:
            items = [e for e in self._buf if e["seq"] > seq]
        return items[-limit:], (items[-1]["seq"] if items else seq)


def resolve_host(host, cache):
    """Resolve to a list of IP strings (v4 first); falls back to the cache."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos}, key=lambda a: (":" in a, a))
        if ips:
            cache[host] = ips
            return ips
    except OSError:
        pass
    return cache.get(host, [])


class Manager:
    def __init__(self, store=None, settings=None):
        self.store = store or ProfileStore()
        self.settings = settings or Settings()
        self.log = LogBuffer()
        self._mlock = threading.RLock()
        self._import_lock = threading.Lock()
        self._oplock = threading.RLock()    # serialises connect()/disconnect(): two clicks must not start two tunnels
        self._stop = threading.Event()
        self._thread = None
        self._proc = None
        self._fw = None
        self._dns = dns.DnsManager()
        self._ep_cache = {}
        self.lock_manual = False
        self.lock_engaged = False
        self._lock_endpoints = set()
        self._lock_ifaces = set()
        self._hotspot = hotspot.Scanner()
        self.hotspots = {}        # interfaces other devices connect to (a Wi-Fi hotspot...): {interface: [networks]}
        self._status = self._blank_status()
        self._state_cache = {}
        self._last_profile = None
        self._current = None      # (ctx, iface) of the live tunnel
        self._reserved_ifnames = set()
        self._split = split.SplitTunnel(lambda: split.names_from_settings(self.settings.get("split")), self.log.add)
        self._split_ctx = None    # (gateway, device, dns) of the live session, while the tunnel is up
        self._split_cur = None    # (gateway, device) the running bypass was built for
        self.scheduler = schedule.Scheduler(self)
        self.history = history.History()
        self._hist_cur = None     # the tunnel that is up right now: {profile, protocol, start, rx, tx}
        self._net = None          # last seen network (network.current())
        self._net_key = None
        self._reconnected_at = -1e9
        self._net_prev = None
        self._net_owned = False   # the current connection was started by the trusted-network rules
        self._net_stop = threading.Event()
        self._routes_added = []   # networks routed around the tunnel right now (mutated in place on network change)
        self._host_ips = {}       # domain -> IPv4 list, for "addresses that skip the VPN" given as names
        self._host_checked = 0.0
        self.proxy = proxysvc.ProxyService(self)
        self.blocks = blocks.BlockService(self)

    def _resolve(self, host):
        return resolve_host(host, self._ep_cache)

    # ------------------------------------------------------------------ status
    @staticmethod
    def _blank_status():
        return {"state": "disconnected", "profile_id": None, "profile": None, "protocol": None,
                "iface": None, "public_ip": None, "since": None, "message": "", "attempt": 0,
                "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0, "error_kind": None}

    def _set(self, **kw):
        with self._mlock:
            # A connection thread that has been replaced (switching servers) must not overwrite the status of the
            # connection that replaced it while it is still shutting down.
            mine = getattr(threading.current_thread(), "vpn_stop", None)
            if mine is not None and mine is not self._stop:
                return
            self._status.update(kw)

    def status(self):
        with self._mlock:
            s = dict(self._status)
        s["netlock"] = self.netlock_status()
        s["hotspots"] = sorted(self.hotspots)
        s["proxy_up"], s["proxy_name"] = self.proxy.up()
        if s["proxy_up"] and s["state"] != "connected":
            s["rx_rate"], s["tx_rate"] = self._open_rates()          # no tunnel to count: the way out itself
        s["last_profile"] = self._last_profile_id()
        s["version"] = __version__
        s["uptime"] = int(time.time() - s["since"]) if s.get("since") and s["state"] == "connected" else 0
        return s

    def _open_rates(self):
        """Bytes per second in and out on the interface that carries the traffic (no VPN: the default route)."""
        _gw, dev = plat.default_gateway()
        st = plat.iface_stats(dev) if dev else None
        now = time.time()
        last, self._open_last = getattr(self, "_open_last", None), None
        if st:
            self._open_last = (now, dev, st[0], st[1])
        if not st or not last or last[1] != dev or now - last[0] <= 0:
            return 0, 0
        dt = now - last[0]
        return max(st[0] - last[2], 0) / dt, max(st[1] - last[3], 0) / dt

    # --------------------------------------------------------------- persistent
    def _load_state(self):
        try:
            with open(paths.state_file()) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save_state(self, **kw):
        st = self._load_state()
        st.update(kw)
        try:
            os.makedirs(paths.config_dir(), mode=0o700, exist_ok=True)
            with open(paths.state_file(), "w") as fh:
                json.dump(st, fh)
        except OSError:
            pass

    # ------------------------------------------------------------- network lock
    def _firewall(self):
        want = self.settings.get("netlock.backend")
        if self._fw is None or (want != "auto" and self._fw.name != want):
            self._fw = netlock.pick_backend(want)
        return self._fw

    def _lock_apply(self):
        spec = netlock.Spec.from_settings(self.settings, set(self._lock_endpoints) | self.proxy.lock_ips(),
                                          self._lock_ifaces,
                                          split.MARK if self._split.active else 0, extra_out=self._route_nets())
        self._firewall().apply(spec)
        if not self.lock_engaged:
            self.log.add("info", "Network lock engaged (%s)" % self._fw.name)
        self.lock_engaged = True

    def hotspot_tick(self):
        """Look for hotspots (every few seconds).  Their devices follow the VPN (share.py) and the proxy: when one
        comes or goes while a proxy redirect is running, the redirect is rebuilt for it."""
        if plat.os_family() != "linux":
            return
        found = {}
        if self.settings.get("connection.share_tunnel"):
            skip = set(self._lock_ifaces) | {self._status.get("iface")}
            found = self._hotspot.scan(self.settings.get("connection.share_ifaces") or [], skip)
        if found == self.hotspots:
            return
        for dev in sorted(set(found) - set(self.hotspots)):
            self.log.add("info", "Hotspot %s (%s): its devices follow the VPN and the proxy" % (dev, ", ".join(found[dev])))
        for dev in sorted(set(self.hotspots) - set(found)):
            self.log.add("info", "Hotspot %s is gone" % dev)
        self.hotspots = found
        self.proxy.hotspots_changed()

    def _hotspot_flush(self):
        """The route of the devices behind a hotspot changed (the VPN came or went): what they have open took the old
        one and cannot continue (the NAT address is wrong), so start it again."""
        nets = [n for v in self.hotspots.values() for n in v]
        n = hotspot.flush(nets) if nets else 0
        if n:
            self.log.add("info", "The devices behind the hotspot reconnect through the new route (%d connections)" % n)

    def _share_sync(self, ifaces):
        """Other devices behind this computer (hotspot...) get the tunnel: segment size clamp + NAT while it is up."""
        try:
            if self.settings.get("connection.share_tunnel"):
                err = share.apply(ifaces)
                self._hotspot_flush()
            else:
                share.remove()
                err = ""
        except Exception as e:  # noqa: BLE001
            err = str(e)
        if err:
            self.log.add("warn", err)

    def _lock_remove(self):
        if self.lock_engaged or (self._fw and self._fw.active()):
            self._firewall().remove()
            self.log.add("info", "Network lock released")
        self.lock_engaged = False

    def netlock_status(self):
        return {"engaged": self.lock_engaged, "manual": self.lock_manual,
                "backend": self._fw.name if self._fw else None,
                "ifaces": sorted(self._lock_ifaces), "endpoints": sorted(self._lock_endpoints)}

    def netlock_enable(self):
        with self._mlock:
            self.lock_manual = True
            self._save_state(lock_manual=True)
            self._lock_apply()
            self._split_sync()
        return self.netlock_status()

    def netlock_disable(self):
        with self._mlock:
            self.lock_manual = False
            self._save_state(lock_manual=False)
            self._lock_remove()
            self._split_sync()
        return self.netlock_status()

    def _lock_wanted(self):
        return self.lock_manual or self.settings.get("netlock.enabled") or self.settings.get("netlock.persist")

    def _after_disconnect_lock(self):
        self._lock_ifaces.clear()
        keep = self.lock_manual or self.settings.get("netlock.persist")
        if keep:
            self._lock_endpoints.clear()
            self._lock_apply()
        else:
            self._lock_endpoints.clear()
            self._lock_remove()
        self._split_sync()

    # --------------------------------------------------------------- start / stop
    def startup(self):
        """Called once by the daemon: crash recovery and boot-time behaviour."""
        dns.restore_resolv_conf()
        if plat.os_family() == "linux":
            split.cleanup()
            share.cleanup()
            hotspot.restore()
            if xray.cleanup():
                self.log.add("warn", "Removed the proxy firewall rules left by a previous run")
        self.proxy.runner.kill_stale()
        if plat.os_family() == "linux":
            blocks.cleanup()
        self.blocks.expire()
        self.blocks.sync()
        self.scheduler.start()
        self._start_network_monitor()
        st = self._load_state()
        self.lock_manual = bool(st.get("lock_manual"))
        if self.lock_manual or self.settings.get("netlock.persist"):
            try:
                self._lock_apply()
            except Exception as e:  # noqa: BLE001
                self.log.add("error", "Could not restore network lock: %s" % e)
            self._split_sync()
        else:
            # a lock left by a daemon that crashed must not keep blocking the network once nobody owns it
            stale = netlock.cleanup_all()
            if stale:
                self.log.add("warn", "Removed a stale network lock left by a previous run (%s)" % ", ".join(stale))
        self.proxy.sync()
        auto = self.settings.get("connection.autoconnect")
        if auto and auto != "off":
            self._autoconnect(auto)

    def _autoconnect(self, auto):
        """Boot-time connect: wait for a network, then keep retrying until it works."""
        end = time.time() + self.settings.get("connection.autoconnect_wait")
        if not plat.default_gateway()[0]:
            self.log.add("info", "Auto-connect: waiting for a network connection")
        while not plat.default_gateway()[0] and time.time() < end:
            time.sleep(2)
        try:
            r = self.connect(None if auto == "last" else auto, fastest=(auto == "fastest"),
                             last=(auto == "last"), persistent=True)
            self.log.add("info", "Auto-connect to %s" % r["profile"])
        except Exception as e:  # noqa: BLE001
            self.log.add("error", "Auto-connect failed: %s" % e)

    def shutdown(self):
        self.scheduler.stop()
        self._net_stop.set()
        self.disconnect()
        self._split_stop()
        self.proxy.shutdown()
        self.blocks.shutdown()

    def _last_profile_id(self):
        """The profile that was connected (or being connected) most recently - what a front end should show selected."""
        if self._last_profile is None:
            self._last_profile = self._load_state().get("last_profile") or ""
        return self._last_profile

    def connect(self, ident=None, fastest=False, last=False, persistent=False):
        profiles = self.store.list()
        if not profiles:
            raise ProfileError("no profiles - import one first")
        if last or (not ident and not fastest):
            lid = self._last_profile_id()
            p = None
            for q in profiles:
                if q["id"] == lid:
                    p = q
            if not p:
                raise ProfileError("no previous connection; pick a profile")
        elif fastest:
            p = self._fastest(profiles)
        else:
            p = self.store.find(ident)
        with self._oplock:
            with self._mlock:
                # New generation first: the old connection thread's late status updates are ignored from here on,
                # and the UI shows "connecting" at once instead of the old server until the old tunnel is gone.
                old_stop = self._stop
                old_thread, old_iface = self._thread, self._status.get("iface")
                self._stop = stop = threading.Event()
                self._status = self._blank_status()
                self._set(state="connecting", profile_id=p["id"], profile=p["name"], protocol=p["protocol"],
                          message="Switching server" if self._thread and self._thread.is_alive() else "Starting")
            self._cancel(old_stop, wait=120)
            self._wait_torn_down(old_thread, old_iface)
            with self._mlock:
                self._thread = threading.Thread(target=self._run, args=(p, stop, persistent), daemon=True,
                                                name="vpn-conn")
                self._thread.start()
            self._last_profile = p["id"]
            self._save_state(last_profile=p["id"])
        return {"profile": p["name"], "id": p["id"]}

    def _fastest(self, profiles):
        cands = [p for p in profiles if not p.get("blacklisted")]
        if not cands:
            raise ProfileError("every profile is blacklisted")
        lat = self.latency([p["id"] for p in cands])
        scored = sorted(cands, key=lambda p: (lat.get(p["id"]) is None, lat.get(p["id"]) or 0))
        return scored[0]

    def _cancel(self, stop=None, wait=25):
        t = self._thread
        (stop or self._stop).set()
        proc = self._proc
        if proc and proc.poll() is None:
            _terminate(proc)
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=wait)
        self._thread = None

    def _wait_torn_down(self, thread, iface):
        """Switching servers: the old tunnel must be completely gone (its process stopped, `wg-quick down` finished,
        its interface removed) before the next one starts, so an OpenVPN and a WireGuard tunnel never overlap."""
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=60)
            if thread.is_alive():
                self.log.add("error", "The previous connection is still shutting down - not starting another on top of it")
                with self._mlock:
                    self._status = dict(self._blank_status(), state="error",
                                        message="the previous connection is still shutting down; try again in a moment")
                raise ProfileError("the previous connection is still shutting down; try again in a moment")
        if iface:
            for _ in range(60):
                if not plat.iface_exists(iface):
                    return
                time.sleep(0.25)
            self.log.add("warn", "Interface %s is still present after the old connection stopped" % iface)

    def disconnect(self, release_lock=True):
        with self._oplock:
            with self._mlock:
                was = self._status["state"]
                old_stop = self._stop
                if was != "disconnected":
                    # Tearing a tunnel down can take seconds: say so, and start a new generation so the old
                    # connection thread's last status updates cannot overwrite it ("connected" flickering back).
                    self._stop = threading.Event()
                    self._status = dict(self._blank_status(), state="disconnecting", message="Disconnecting",
                                        profile_id=self._status.get("profile_id"),
                                        profile=self._status.get("profile"), protocol=self._status.get("protocol"))
            self._cancel(old_stop)
            with self._mlock:
                self._status = self._blank_status()
            if release_lock:
                try:
                    self._after_disconnect_lock()
                except Exception as e:  # noqa: BLE001
                    self.log.add("error", "Network lock update failed: %s" % e)
            if was != "disconnected":
                self.log.add("info", "Disconnected")
        return True

    # -------------------------------------------------------------- run loop
    def _run(self, profile, stop, persistent=False):
        """persistent: never give up (used for boot-time auto-connect on slow/late networks)."""
        threading.current_thread().vpn_stop = stop      # lets _set() tell a replaced connection from the current one
        s = self.settings
        attempt = 0
        tried = {profile["id"]}
        while not stop.is_set():
            self._set(state="connecting" if attempt == 0 else "reconnecting", profile_id=profile["id"],
                      profile=profile["name"], protocol=profile["protocol"], attempt=attempt)
            reason = "connection lost"
            was_up = False
            try:
                was_up = self._session(profile, stop)
            except FatalError as e:
                self.log.add("error", str(e))
                self._set(state="error", message=str(e), error_kind=e.kind)
                return
            except ConnectError as e:
                reason = str(e)
                self.log.add("error", reason)
            except Exception as e:  # noqa: BLE001
                reason = "internal error: %s" % e
                self.log.add("error", reason)
            if stop.is_set():
                return
            if was_up:
                attempt = 0
            if not s.get("connection.reconnect"):
                self._set(state="error", message=reason)
                return
            attempt += 1
            if persistent and not s.get("connection.reconnect"):
                persistent = False
            if attempt > s.get("connection.retry_max") and not persistent:
                nxt = self._next_candidate(profile, tried) if s.get("connection.failover") else None
                if not nxt:
                    self._set(state="error", message="gave up: " + reason)
                    self.log.add("error", "Giving up after %d attempts (%s)" % (attempt - 1, reason))
                    return
                self.log.add("warn", "Failing over to %s" % nxt["name"])
                profile, attempt = nxt, 0
                tried.add(nxt["id"])
                continue
            delay = s.get("connection.retry_delay")
            if persistent and attempt > s.get("connection.retry_max"):
                delay = max(delay, 15)       # back off while waiting for the network
            self._set(state="reconnecting", message="%s - retry %d in %ds" % (reason, attempt, delay))
            self.log.add("warn", "Reconnecting in %ds (attempt %d)" % (delay, attempt))
            if stop.wait(delay):
                return

    def failover_order(self, current, tried=()):
        """Servers to try after `current` fails: its own failover list (in order), then its group, then favourites."""
        profiles = self.store.list()
        by_id = {p["id"]: p for p in profiles}
        order = [by_id[i] for i in current.get("failover") or [] if i in by_id]
        if self.settings.get("connection.failover_group") and current.get("group"):
            order += [p for p in profiles if p.get("group") == current["group"]]
        order += [p for p in profiles if p.get("favorite")]
        seen, out = set(tried) | {current["id"]}, []
        for p in order:
            if p["id"] not in seen and not p.get("blacklisted"):
                seen.add(p["id"])
                out.append(p)
        return out

    def _next_candidate(self, current, tried):
        order = self.failover_order(current, tried)
        return order[0] if order else None

    def _ifname_for(self, backend, profile):
        """Standard interface names: tun0, tun1, ... (tapN for OpenVPN tap, wgN for WireGuard on BSD).

        The first index that no live interface and no other connection uses is chosen.
        """
        fam = plat.os_family()
        if fam == "linux":
            if not backend.named_iface:
                return None
            prefix = backend.iface_prefix(profile, self.store.dir_of(profile))
        elif backend.id in ("wireguard", "amneziawg"):
            prefix = "wg"             # BSD wg(4) only accepts wgN
        else:
            return None
        used = set(plat.list_interfaces()) | set(self._reserved_ifnames)
        for i in range(256):
            if "%s%d" % (prefix, i) not in used:
                return "%s%d" % (prefix, i)
        return None

    def _session(self, profile, stop):
        """One connection attempt.  Returns True if the tunnel was ever up."""
        s = self.settings
        backend = backends.get(profile["protocol"])
        problems = backend.validate(profile)
        if problems:
            raise FatalError("%s: %s" % (profile["name"], "; ".join(problems)))
        oneshot = backend.mode == "oneshot"
        workdir = os.path.join(paths.run_dir(), "conn", profile["id"])
        shutil.rmtree(workdir, ignore_errors=True)
        os.makedirs(workdir, mode=0o700)
        ctx = backends.Context(profile, self.store.dir_of(profile), workdir,
                               self._ifname_for(backend, profile), s)
        if ctx.ifname:
            self._reserved_ifnames.add(ctx.ifname)
        up = False
        ready = threading.Event()
        proc = None
        reader = None
        tproc = None
        treader = None
        routes_added = []
        carrier = False
        try:
            # --- endpoints & lock (before anything touches the network)
            ips = set()
            ctx.state["resolved"] = {}
            for host, _port, _proto in backend.endpoints(profile):
                got = resolve_host(host, self._ep_cache)
                if not got:
                    self.log.add("warn", "Could not resolve %s" % host)
                else:
                    ctx.state["resolved"][host] = got[0]
                ips.update(got)
            self._lock_endpoints = ips
            if self.proxy.carrier_wanted():
                # the VPN is reached through the proxy: the kill switch lets only the proxy server through
                try:
                    self._lock_endpoints = self.proxy.carrier_ips()
                except xray.ProxyError as e:
                    raise (FatalError if e.fatal else ConnectError)("Proxy: %s" % e)
                carrier = True
            self._refresh_route_hosts(apply=False)       # names given as "skip the VPN" addresses, before the lock
            if self._lock_wanted():
                try:
                    self._lock_apply()
                except Exception as e:  # noqa: BLE001
                    raise FatalError("Network lock could not be engaged: %s - refusing to connect unprotected" % e)
            self._hook("pre_connect", ctx)
            if stop.is_set():
                return False
            if stunnel.settings_of(profile):
                tproc, treader = self._start_stunnel(profile, ctx, stop)
                if stop.is_set():
                    return False
            if carrier:
                try:
                    self.proxy.start_carrier(backend, profile, ctx, stop)
                except xray.ProxyError as e:
                    raise (FatalError if e.fatal else ConnectError)("Proxy: %s" % e)
                if stop.is_set():
                    return False
            gw, gwif = plat.default_gateway()
            orig_dns = system_dns(gw)
            before = set(plat.list_interfaces())
            self.log.add("info", "Connecting to %s (%s)" % (profile["name"], backend.label))
            self._set(message="Connecting")
            try:
                backend.prepare(ctx)
                for note in ctx.state.get("notes", []):
                    self.log.add("info", note)
                if not oneshot:
                    cmd = backend.connect_cmd(ctx)
            except CredentialsRequired as e:
                raise FatalError("%s: %s" % (profile["name"], e), "auth")
            except ValueError as e:
                raise FatalError("%s: %s" % (profile["name"], e))
            started = time.time()
            if oneshot:
                for cmd in backend.connect_cmds(ctx):
                    if stop.is_set():
                        return False                 # switched away while setting up: the cleanup below undoes it
                    self.log.add("debug", "$ " + _safe_cmd(cmd))
                    rc, out = plat.run(cmd, timeout=s.get("connection.timeout") + 30)
                    for line in out.splitlines():
                        self.log.add("tool", line)
                        backend.parse_line(line, ctx)
                    if rc:
                        raise ConnectError("%s exited with status %d" % (os.path.basename(cmd[0]), rc))
                ready.set()
            else:
                self.log.add("debug", "$ " + _safe_cmd(cmd))
                data = backend.stdin_data(ctx)
                try:
                    proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE if data else subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, cwd=backend.cwd(ctx), start_new_session=True,
                        text=True, bufsize=1, errors="replace",
                        env=dict(os.environ, PATH=os.pathsep.join(plat.EXTRA_PATH + [os.environ.get("PATH", "")])))
                except OSError as e:
                    raise FatalError("cannot start %s: %s" % (cmd[0], e))
                self._proc = proc
                if data:
                    try:
                        proc.stdin.write(data)
                        proc.stdin.close()
                    except OSError:
                        pass
                reader = threading.Thread(target=self._read_output, args=(proc, backend, ctx, ready), daemon=True)
                reader.start()
                timeout = s.get("connection.timeout")
                while not ready.is_set():
                    if stop.is_set():
                        return False
                    if proc.poll() is not None:
                        reader.join(2)
                        if ctx.state.get("fatal"):
                            # retrying with the same bad credentials only hammers the server (and can get the
                            # account locked), so stop and say what is wrong
                            raise FatalError(ctx.state["fatal"], ctx.state.get("fatal_kind"))
                        raise ConnectError("%s exited with status %s" % (os.path.basename(cmd[0]), proc.returncode))
                    if time.time() - started > timeout:
                        raise ConnectError("timed out after %ds" % timeout)
                    if backend.iface_fallback and time.time() - started > 3 and \
                            set(plat.list_interfaces()) - before:
                        ready.set()
                    time.sleep(0.25)
            if stop.is_set():
                return False

            # --- tunnel is up
            if oneshot and not ctx.iface and ctx.ifname and (backend.named_iface or backend.id.endswith("wireguard")):
                ctx.iface = ctx.ifname
            if oneshot and backend.iface_fallback:
                for _ in range(20):
                    if set(plat.list_interfaces()) - before:
                        break
                    time.sleep(0.5)
            new = set(plat.list_interfaces()) - before
            ifaces = {ctx.iface} if ctx.iface else new
            ifaces = {i for i in ifaces if i and i != "lo"}
            primary = sorted(ifaces)[0] if ifaces else None
            self._lock_ifaces = ifaces
            if self._lock_wanted():
                if not ifaces:
                    self.log.add("warn", "No tunnel interface detected - kill switch will only allow the VPN endpoint. %s"
                                 % backend.lock_note)
                try:
                    self._lock_apply()
                except Exception as e:  # noqa: BLE001
                    raise ConnectError("Network lock update failed: %s" % e)
            self._apply_dns(ctx, primary)
            self._current = (ctx, primary)
            routes_added = self._apply_routes(gw)
            self._routes_added = routes_added
            self._split_ctx = (gw, gwif, orig_dns)
            self._split_sync()
            self._share_sync(ifaces)
            self._proxy_sync_safe(vpn_up=True)          # proxy inside the VPN: now that the tunnel carries traffic
            up = True
            self._set(state="connected", iface=primary, since=time.time(), message="", attempt=0)
            self._hist_cur = {"profile": profile["name"], "protocol": profile["protocol"], "start": time.time(),
                              "rx": 0, "tx": 0}
            self.log.add("info", "Connected to %s via %s" % (profile["name"], primary or "(no interface)"))
            self._hook("connected", ctx)
            threading.Thread(target=self._check_ip, args=(stop,), daemon=True).start()

            # --- monitor
            last = None
            while not stop.is_set():
                if stop.wait(1):
                    break
                if proc is not None and proc.poll() is not None:
                    self.log.add("warn", "%s terminated (status %s)" % (backend.label, proc.returncode))
                    break
                if tproc is not None and tproc.poll() is not None:
                    self.log.add("warn", "stunnel terminated (status %s)" % tproc.returncode)
                    break
                if carrier and not self.proxy.carrier_alive():
                    self.log.add("warn", "The proxy in front of the VPN terminated")
                    break
                if oneshot and primary and not plat.iface_exists(primary):
                    self.log.add("warn", "Tunnel interface %s disappeared" % primary)
                    break
                st = sum_stats(ifaces)
                if st:
                    now = time.time()
                    rate = (0, 0)
                    if last:
                        dt = max(now - last[0], 0.001)
                        rate = (max(st[0] - last[1], 0) / dt, max(st[1] - last[2], 0) / dt)
                    last = (now, st[0], st[1])
                    self._set(rx=st[0], tx=st[1], rx_rate=rate[0], tx_rate=rate[1])
                    if self._hist_cur:
                        self._hist_cur.update(rx=st[0], tx=st[1])
            return up
        finally:
            self._proc = None
            self._current = None
            self._reserved_ifnames.discard(ctx.ifname)
            if proc is not None and proc.poll() is None:
                _terminate(proc)
            if reader:
                reader.join(2)
            if proc is not None and proc.stdout:
                proc.stdout.close()
            if tproc is not None:
                if tproc.poll() is None:
                    _terminate(tproc)
                if treader:
                    treader.join(2)
                if tproc.stdout:
                    tproc.stdout.close()
            if oneshot or ctx.state:
                try:
                    for cmd in backend.disconnect_cmds(ctx):
                        rc, out = plat.run(cmd, timeout=30)
                        for line in out.splitlines():
                            self.log.add("tool", line)
                except Exception as e:  # noqa: BLE001
                    self.log.add("warn", "cleanup failed: %s" % e)
            self.proxy.stop_carrier()
            self._remove_routes(routes_added)
            cur, self._hist_cur = self._hist_cur, None
            if cur and up:
                try:
                    self.history.add(cur["profile"], cur["protocol"], cur["start"], rx=cur["rx"], tx=cur["tx"],
                                     reason="Disconnected" if stop.is_set() else "Connection lost")
                except OSError as e:
                    self.log.add("warn", "Could not save connection history: %s" % e)
            self._split_ctx = None
            self._share_sync(())
            self._split_sync()              # stays up for the whitelisted apps if the kill switch is still engaged
            self._proxy_sync_safe(vpn_up=False)    # a proxy that ran inside the VPN stops with it
            self._dns.restore()
            if up:
                self._hook("disconnected", ctx)
            self._lock_ifaces = set()
            if self._lock_wanted() and self.lock_engaged and not stop.is_set():
                try:
                    self._lock_apply()      # tunnel gone: drop iface allowance, keep endpoint for reconnect
                except Exception as e:  # noqa: BLE001
                    self.log.add("error", "Network lock update failed: %s" % e)
            shutil.rmtree(workdir, ignore_errors=True)

    def _start_stunnel(self, profile, ctx, stop):
        """Launch the stunnel sidecar and wait until it is configured."""
        st = stunnel.settings_of(profile)
        port = stunnel.free_port()
        conf, warns = stunnel.config(profile, ctx.profile_dir, ctx.workdir, port)
        for w in warns:
            self.log.add("warn", w)
        path = ctx.write("stunnel.conf", conf)
        ips = ctx.state.get("resolved", {}).get(st["host"])
        ctx.state["stunnel"] = {"port": port, "ip": ips}
        cmd = [stunnel.binary(), path]
        self.log.add("info", "Starting stunnel to %s:%s" % (st["host"], st.get("port") or 443))
        self.log.add("debug", "$ " + _safe_cmd(cmd))
        try:
            tproc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True, text=True,
                                     bufsize=1, errors="replace")
        except OSError as e:
            raise FatalError("cannot start stunnel: %s" % e)
        up = threading.Event()

        def pump():
            try:
                for line in tproc.stdout:
                    line = line.rstrip()
                    if line:
                        self.log.add("stunnel", line)
                        if stunnel.READY_RE.search(line):
                            up.set()
            except (OSError, ValueError):
                pass
        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        end = time.time() + 15
        while not up.is_set():
            if stop.is_set():
                return tproc, reader
            if tproc.poll() is not None:
                reader.join(2)
                raise ConnectError("stunnel exited with status %s" % tproc.returncode)
            if time.time() > end:
                _terminate(tproc)
                raise ConnectError("stunnel did not start in time")
            time.sleep(0.1)
        return tproc, reader

    def _read_output(self, proc, backend, ctx, ready):
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                self.log.add("tool", line)
                backend.parse_line(line, ctx)
                if backend.ready_re and backend.ready_re.search(line):
                    ready.set()
        except (OSError, ValueError):
            pass

    # ------------------------------------------------------------ DNS / routes
    def _apply_dns(self, ctx, iface):
        s = self.settings
        if not s.get("dns.force"):
            return
        servers = s.get("dns.servers") or ctx.profile.get("dns") or ctx.dns
        if servers:
            try:
                self.log.add("info", self._dns.apply(servers, iface))
            except OSError as e:
                self.log.add("warn", "DNS change failed: %s" % e)

    def reapply_dns(self):
        """Switch DNS on the live tunnel after the user changed the setting."""
        cur = self._current
        if cur and self._status["state"] == "connected":
            self._dns.restore()
            self._apply_dns(*cur)

    # ---------------------------------------------------------- app bypass
    def _split_context(self):
        """(gateway, device, dns) the bypassed apps should use, or None when no bypass is needed right now.

        It is needed while the tunnel is up and while the kill switch is engaged: the whitelisted apps are
        exempt from the lock, so they keep working when the VPN drops or is switched off."""
        sp = self.settings.get("split")
        if not sp["enabled"] or not sp["apps"]:
            return None
        if self._split_ctx:
            return self._split_ctx
        if self.lock_engaged:
            gw, dev = plat.default_gateway()
            if dev:
                return (gw, dev, system_dns(gw))
        return None

    def _split_sync(self):
        """Bring the app bypass in line with the connection / kill switch state (idempotent)."""
        with self._mlock:
            was = (self._split.active, self._split_cur)
            ctx = self._split_context()
            mode = self.settings.get("split.mode")
            if not ctx:
                if self._split.active:
                    self._split.stop()
                    self._split_cur = None
                    self.log.add("info", "App bypass stopped")
            elif not (self._split.active and self._split_cur == ctx[:2] + (mode,)):
                try:
                    self._split.start(*ctx, mode=mode)
                    self._split_cur = ctx[:2] + (mode,)
                    apps = ", ".join(a["name"] for a in self.settings.get("split.apps"))
                    self.log.add("info", "%s: %s%s" % (
                        "Only these apps use the VPN" if mode == "include" else "App bypass active for", apps,
                        "" if self._split_ctx else " (VPN down, network lock keeps them online)"))
                except Exception as e:  # noqa: BLE001
                    self._split_cur = None
                    self.log.add("warn", "App bypass unavailable: %s" % e)
            if self._split.active:
                self._split.ensure_rule_first()     # a VPN that came up after us (wg-quick) must not outrank us
            if (self._split.active, self._split_cur) != was and self.lock_engaged:
                try:
                    self._lock_apply()          # let the kill switch pass (or stop passing) the bypassed traffic
                except Exception as e:  # noqa: BLE001
                    self.log.add("error", "Network lock update failed: %s" % e)
        self._proxy_sync_safe()

    def _proxy_sync_safe(self, **kw):
        try:
            self.proxy.sync(**kw)
        except Exception as e:  # noqa: BLE001
            self.log.add("warn", "Proxy: %s" % e)

    def _split_stop(self):
        with self._mlock:
            if self._split.active:
                self._split.stop()
                self._split_cur = None
                self.log.add("info", "App bypass stopped")

    def split_changed(self):
        """The whitelist changed: apply it now."""
        self._split_sync()

    def split_status(self):
        ok, why = split.supported()
        sp = self.settings.get("split")
        return {"supported": ok, "reason": why, "active": self._split.active, "enabled": sp["enabled"],
                "apps": sp["apps"], "moved": len(self._split.moved), "mode": sp.get("mode", "exclude"),
                "routes": [r.get("ip") or r.get("host") for r in self.settings.get("routes") if r.get("action") == "out"]}

    def split_set(self, apps=None, enabled=None, mode=None):
        tree = {}
        if mode is not None:
            if mode not in ("exclude", "include"):
                raise ProfileError("mode must be 'exclude' (listed apps skip the VPN) or 'include' (only listed apps use it)")
            tree["mode"] = mode
        if enabled is not None:
            tree["enabled"] = bool(enabled)
        if apps is not None:
            clean = []
            for a in apps:
                m = [str(x) for x in a.get("match", []) if str(x).strip()]
                if not m or not a.get("name"):
                    raise ProfileError("every app needs a name and at least one program name")
                clean.append({"id": str(a.get("id") or "custom:" + m[0]), "name": str(a["name"]), "match": m,
                              "icon": str(a.get("icon") or "")})
            tree["apps"] = clean
        self.settings.update({"split": tree})
        self.split_changed()
        return self.split_status()

    # ------------------------------------------------------------ schedule
    def schedule_status(self):
        sc = self.settings.get("schedule")
        t = time.localtime()
        out = []
        for e in sc["entries"]:
            nxt = schedule.next_start(e, t)
            out.append(dict(e, active=schedule.is_active(e, t), next_in=nxt, summary=schedule.describe(e)))
        return {"enabled": sc["enabled"], "entries": out, "owned": self.scheduler.owned}

    def schedule_set(self, entries=None, enabled=None):
        tree = {}
        if enabled is not None:
            tree["enabled"] = bool(enabled)
        if entries is not None:
            try:
                tree["entries"] = [schedule.clean(e) for e in entries]
            except (ValueError, TypeError) as e:
                raise ProfileError(str(e))
        self.settings.update({"schedule": tree})
        return self.schedule_status()

    def _route_nets(self):
        """IPv4 networks that must skip the VPN: the CIDRs/IPs the user listed plus the addresses of listed names
        (from the cache - never resolved here, because this runs while the kill switch may be up)."""
        nets = []
        for r in self.settings.get("routes"):
            if r.get("action") != "out":
                continue
            cands = []
            if r.get("ip"):
                cands = [r["ip"]]
            elif r.get("host"):
                cands = self._host_ips.get(r["host"], [])
            for c in cands:
                try:
                    net = ipaddress.ip_network(str(c), strict=False)
                except ValueError:
                    continue
                if net.version == 4 and str(net) not in nets:
                    nets.append(str(net))
        return nets

    def _refresh_route_hosts(self, apply=True):
        """Resolve the names in the bypass list; when an address changed, re-route (apply=True)."""
        hosts = [r["host"] for r in self.settings.get("routes") if r.get("action") == "out" and r.get("host")]
        self._host_checked = time.time()
        changed = False
        for h in hosts:
            ips = [i for i in resolve_host(h, {}) if ":" not in i]
            if ips and sorted(ips) != sorted(self._host_ips.get(h, [])):
                self._host_ips[h] = ips
                changed = True
        for h in list(self._host_ips):
            if h not in hosts:
                del self._host_ips[h]
                changed = True
        if changed and apply:
            self._reapply_routes()
        return changed

    def _apply_routes(self, gw):
        added = []
        for net in self._route_nets():
            if not gw:
                break
            if plat.os_family() == "linux":
                cmd = ["ip", "route", "replace", net, "via", gw]
            else:
                cmd = ["route", "-q", "add", "-net", net, gw]
            rc, out = plat.run(cmd)
            if rc == 0:
                added.append(net)
            else:
                self.log.add("warn", "route %s failed: %s" % (net, out.strip()))
        return added

    def _reapply_routes(self, gw=None):
        """Re-create the bypass routes (list changed, or the gateway changed) and let the kill switch know."""
        with self._mlock:
            live = self._status.get("state") == "connected"
            if live:
                gw = gw or plat.default_gateway()[0]
                self._remove_routes(self._routes_added)
                self._routes_added[:] = self._apply_routes(gw)
            if self.lock_engaged:
                try:
                    self._lock_apply()
                except Exception as e:  # noqa: BLE001
                    self.log.add("error", "Network lock update failed: %s" % e)

    def routes_set(self, entries):
        clean = []
        for e in entries:
            text = str(e.get("ip") or e.get("host") or e).strip() if isinstance(e, dict) else str(e).strip()
            if not text:
                continue
            try:
                net = ipaddress.ip_network(text, strict=False)
                if net.version != 4:
                    raise ProfileError("only IPv4 networks can skip the VPN: %s" % text)
                clean.append({"ip": str(net), "action": "out"})
            except ValueError:
                if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", text) or "." not in text:
                    raise ProfileError("not an IP address, network (10.0.0.0/8) or domain name: %s" % text)
                clean.append({"host": text.lower(), "action": "out"})
        self.settings.update({"routes": clean})
        self._refresh_route_hosts(apply=False)
        self._reapply_routes()
        self._proxy_sync_safe()
        return self.settings.get("routes")

    # ------------------------------------------------------------- networks
    def _start_network_monitor(self):
        self._net_stop = threading.Event()
        threading.Thread(target=self._net_loop, args=(self._net_stop,), daemon=True, name="net-monitor").start()

    def _net_loop(self, stop):
        last = time.time()
        while not stop.is_set():
            for name, job in (("network", self.network_tick), ("hotspot", self.hotspot_tick), ("proxy", self.proxy.watch),
                              ("blocks", self.blocks.expire)):
                try:
                    job()
                except Exception as e:  # noqa: BLE001  (one failing job must not starve the others)
                    self.log.add("debug", "%s monitor: %s" % (name, e))
            now = time.time()
            if now - last > RESUME_GAP:                 # this loop wakes every 3 s: a long gap is a suspend (or a stall)
                self.log.add("info", "The computer woke up (after %d s)" % (now - last))
                self.reconnect_if_up("the computer woke up", wait_for_network=True)
            last = now
            stop.wait(3)

    def reconnect_if_up(self, reason, wait_for_network=False):
        """The tunnel (or its attempt) belongs to a network that is gone or asleep: start it again at once instead of
        waiting for the VPN program to notice.  Runs in the background; at most once every 15 seconds."""
        if not self.settings.get("connection.reconnect_on_change"):
            return False
        with self._mlock:
            st = dict(self._status)
        if st.get("state") not in ("connected", "connecting", "reconnecting") or not st.get("profile_id"):
            return False
        if time.monotonic() - self._reconnected_at < 15:
            return False
        self._reconnected_at = time.monotonic()

        def work():
            try:
                if wait_for_network:                    # Wi-Fi needs a few seconds after waking up
                    end = time.monotonic() + 40
                    while time.monotonic() < end and not (network.current().get("device")):
                        time.sleep(1.5)
                with self._mlock:
                    now = dict(self._status)
                if now.get("profile_id") != st["profile_id"] or now.get("state") == "disconnected":
                    return                              # the user changed or ended the connection meanwhile
                self.log.add("info", "Reconnecting to %s because %s" % (st.get("profile"), reason))
                self.connect(st["profile_id"])
            except Exception as e:  # noqa: BLE001
                self.log.add("warn", "Reconnect after %s failed: %s" % (reason, e))
        threading.Thread(target=work, daemon=True, name="net-reconnect").start()
        return True

    def network_status(self):
        cur = self._net or network.current()
        return dict(cur, trusted=network.is_trusted(cur["id"], self.settings.get("network.trusted")),
                    rule=self.network_rule(cur["id"]), rules=list(self.settings.get("network.rules") or []))

    def network_tick(self, cur=None):
        """One look at the network.  Acts only when something changed (gateway, device or network name)."""
        cur = cur or network.current()
        key = (cur["gateway"], cur["device"], cur["id"])
        first = self._net_key is None
        changed = key != self._net_key
        self._net_key, self._net = key, cur
        if self._net_owned and self._status.get("state") == "disconnected":
            self._net_owned = False
        if time.time() - self._host_checked > 300:
            self._refresh_route_hosts()
        if not changed or not cur["device"]:
            return
        if cur["device"] == self._status.get("iface"):
            return                              # the tunnel became the default route: not a new network
        if not first:
            self.log.add("info", "Network changed: %s via %s" % (cur["name"] or "unknown", cur["device"]))
        prev = self._net_prev
        self._net_prev = (cur["gateway"], cur["device"])
        self._follow_network(cur)
        self._network_rules(cur, first)
        if not first and prev and prev != (cur["gateway"], cur["device"]):
            self.reconnect_if_up("the network changed")

    def _follow_network(self, cur):
        """Rebuild what was built against the old gateway: the app bypass and the bypass routes."""
        ctx = self._split_ctx
        if ctx and (cur["gateway"], cur["device"]) != ctx[:2] and self._status.get("state") == "connected":
            self._split_ctx = (cur["gateway"], cur["device"], [cur["gateway"]] if cur["gateway"] else [])
            self._split_sync()
        if cur["gateway"]:
            self.proxy.follow_gateway(cur["gateway"])
        if self._status.get("state") == "connected" and cur["gateway"]:
            self._reapply_routes(cur["gateway"])
        elif self.lock_engaged and not ctx:
            self._split_sync()

    def network_rule(self, net_id):
        for r in self.settings.get("network.rules") or []:
            if net_id and str(r.get("network", "")).lower() == str(net_id).lower():
                return r
        return None

    def network_rule_set(self, network_id, server="", netproxy="", xray_proxy=""):
        """Remember what to do on one network: connect to ``server`` (a profile), switch the network proxy
        (``netproxy``: "", "on", "off") and/or use one of the Xray proxies (``xray_proxy``: "", "off", a proxy)."""
        net = network_id or (self._net or network.current())["id"]
        if not net:
            raise ProfileError("no network detected - join one first")
        if netproxy not in ("", "on", "off"):
            raise ProfileError("netproxy must be on, off or empty")
        sid = self.store.find(server)["id"] if server else ""
        xid = ""
        if xray_proxy:
            xid = "off" if xray_proxy == "off" else self.proxy.store.find(xray_proxy)["id"]
        rules = [r for r in self.settings.get("network.rules") or [] if str(r.get("network", "")).lower() != net.lower()]
        if sid or netproxy or xid:
            rules.append({"network": net, "server": sid, "netproxy": netproxy, "xray": xid})
        self.settings.update({"network": {"rules": rules}})
        return self.network_status()

    def _apply_rule(self, rule, cur):
        """What this network's rule asks for.  Returns True when it chose the server (the generic untrusted-network
        action must then stay out of the way)."""
        if rule.get("netproxy") in ("on", "off"):
            try:
                self.proxy.net_configure(enabled=rule["netproxy"] == "on")
                self.log.add("info", "Network '%s': network proxy %s" % (cur["name"], rule["netproxy"]))
            except ProfileError as e:
                self.log.add("warn", "Network '%s': cannot switch the network proxy: %s" % (cur["name"], e))
        if rule.get("xray"):
            try:
                if rule["xray"] == "off":
                    self.proxy.configure(enabled=False)
                else:
                    self.proxy.configure(selected=rule["xray"], enabled=True)
                self.log.add("info", "Network '%s': proxy %s" % (cur["name"], "off" if rule["xray"] == "off" else "chosen"))
            except (ProfileError, KeyError) as e:
                self.log.add("warn", "Network '%s': cannot set the proxy: %s" % (cur["name"], e))
        if rule.get("server"):
            if self._status.get("profile_id") == rule["server"] and self._status.get("state") in (
                    "connecting", "connected", "reconnecting"):
                return True
            try:
                self.log.add("info", "Network '%s': connecting to the server chosen for it" % cur["name"])
                self.connect(rule["server"])
                self._net_owned = True
            except Exception as e:  # noqa: BLE001
                self.log.add("error", "Network '%s': could not connect: %s" % (cur["name"], e))
            return True
        return False

    def _network_rules(self, cur, first):
        cfg = self.settings.get("network")
        if not cur["id"] or (first and self.settings.get("connection.autoconnect") != "off"):
            return
        trusted = network.is_trusted(cur["id"], cfg["trusted"])
        active = self._status.get("state") in ("connecting", "connected", "reconnecting")
        prof = cfg.get("profile") or "last"
        rule = None if trusted else self.network_rule(cur["id"])
        if rule and self._apply_rule(rule, cur):
            return
        if not trusted and cfg["untrusted_action"] == "connect" and not active:
            self.log.add("info", "Untrusted network '%s' - connecting the VPN" % cur["name"])
            try:
                self.connect(None if prof in ("", "last", "fastest") else prof, fastest=(prof == "fastest"),
                             last=(prof in ("", "last")), persistent=True)
                self._net_owned = True
            except Exception as e:  # noqa: BLE001
                self.log.add("error", "Could not connect on an untrusted network: %s" % e)
        elif trusted and cfg["trusted_action"] == "disconnect" and self._net_owned and active:
            self.log.add("info", "Trusted network '%s' - disconnecting the VPN" % cur["name"])
            self._net_owned = False
            self.disconnect()

    def network_trust(self, name=None, trusted=True):
        net = name or (self._net or network.current())["id"]
        if not net:
            raise ProfileError("no network detected - connect to one first")
        cur = [t for t in self.settings.get("network.trusted") if str(t).lower() != net.lower()]
        if trusted:
            cur.append(net)
        self.settings.update({"network": {"trusted": cur}})
        return self.network_status()

    def _remove_routes(self, routes):
        for net in routes:
            if plat.os_family() == "linux":
                plat.run(["ip", "route", "del", net])
            else:
                plat.run(["route", "-q", "delete", "-net", net])

    # ---------------------------------------------------------------- misc
    def _hook(self, name, ctx):
        cmd = self.settings.get("events.%s" % name)
        if not cmd:
            return
        env = dict(os.environ, VPNMAN_EVENT=name, VPNMAN_PROFILE=ctx.profile["name"],
                   VPNMAN_PROTOCOL=ctx.profile["protocol"], VPNMAN_IFACE=ctx.iface or "")
        self.log.add("info", "Running %s hook" % name)
        try:
            rc = subprocess.run(["/bin/sh", "-c", cmd], env=env, timeout=60, capture_output=True, text=True)
            for line in (rc.stdout + rc.stderr).splitlines():
                self.log.add("hook", line)
        except (OSError, subprocess.SubprocessError) as e:
            self.log.add("warn", "%s hook failed: %s" % (name, e))

    def _check_ip(self, stop):
        if not self.settings.get("checks.tunnel"):
            return
        url = self.settings.get("checks.url")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vpnman/" + __version__})
            with urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()) as r:
                body = r.read(2048).decode("utf-8", "replace")
            ip = leaktest.parse_ip_answer(body)
            if not ip:
                self.log.add("warn", "Public IP check: %s did not answer with an address" % url)
            elif not stop.is_set() and stop is self._stop:
                self._set(public_ip=ip)
                self.log.add("info", "Public IP is now %s%s" % (ip, " (a Cloudflare address)" if leaktest.is_cloudflare(ip)
                                                                else ""))
        except Exception as e:  # noqa: BLE001
            self.log.add("warn", "Public IP check failed: %s" % e)

    def latency(self, ids=None):
        profiles = [p for p in self.store.list() if not ids or p["id"] in ids]

        def probe(p):
            try:
                backend = backends.get(p["protocol"])
                eps = backend.endpoints(p)
            except KeyError:
                return p["id"], None
            if not eps:
                return p["id"], None
            host, port, proto = eps[0]
            ips = resolve_host(host, self._ep_cache)
            if not ips:
                return p["id"], None
            return p["id"], tcp_or_ping(ips[0], port, proto)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            return dict(ex.map(probe, profiles))

    # ---------------------------------------------------------------- profiles
    def import_profile(self, name, text, files=None, protocol=None, filename=None, fields=None, options=None):
        filename = filename or name
        protocol = protocol or backends.sniff(filename, text)
        if not protocol:
            raise ProfileError("could not detect the VPN protocol of %s; specify one" % filename)
        backend = backends.get(protocol)
        from .profiles import new_profile
        p = new_profile(re.sub(r"\.(ovpn|conf|yml|yaml)$", "", name, flags=re.I), protocol)
        info = backend.parse(filename, text)
        opts = info.pop("options", {})
        p.update(info)
        p["options"].update(opts)
        for k, v in (fields or {}).items():
            if k in p and k not in ("id", "created", "config"):
                p[k] = v
        p["options"].update(options or {})
        cfg = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
        if not cfg.lower().endswith(tuple(backend.extensions) or ("",)) and backend.extensions:
            cfg += backend.extensions[0]
        p["config"] = cfg
        allfiles = {cfg: text}
        for fn, b64 in (files or {}).items():
            import base64
            allfiles[fn] = base64.b64decode(b64)
        with self._import_lock:             # two imports of the same name racing must not both pick the same name
            self._unique_name(p)
            self.store.save(p, allfiles)
        self.log.add("info", "Imported profile %s (%s)" % (p["name"], backend.label))
        warnings = backend.lint(text, self.store.dir_of(p))
        for w in warnings:
            self.log.add("warn", "%s: %s" % (p["name"], w))
        return dict(public_view(p), warnings=warnings)

    def add_profile(self, name, protocol, fields=None, options=None, files=None):
        from .profiles import new_profile
        backends.get(protocol)
        p = new_profile(name, protocol)
        for k, v in (fields or {}).items():
            if k in p and k not in ("id", "created"):
                p[k] = v
        p["options"].update(options or {})
        self._unique_name(p)
        import base64
        self.store.save(p, {fn: base64.b64decode(b) for fn, b in (files or {}).items()})
        return public_view(p)

    def set_profile_file(self, ident, name, b64):
        import base64
        p = self.store.find(ident)
        self.store.save(p, {name: base64.b64decode(b64)})
        return public_view(p)

    # ------------------------------------------------------------ backup
    def backup_export(self):
        import base64
        data = backup.export_archive(os.path.dirname(self.store.root), self.settings.path)
        return {"data": base64.b64encode(data).decode(), "size": len(data)}

    def backup_import(self, data, replace=False, restore_settings=None):
        """Restore profiles from a backup.  merge (default): add what is missing, never touch existing profiles or
        settings.  replace: make this machine match the backup (settings included unless restore_settings=False)."""
        import base64
        import binascii
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raise ProfileError("the backup data is not valid")
        try:
            manifest, profiles, new_settings, proxies = backup.read_archive(raw, with_proxies=True)
        except backup.BackupError as e:
            raise ProfileError(str(e))
        existing = {p["id"] for p in self.store.list()}
        removed = 0
        if replace:
            removed = len(self.remove_profiles(sorted(existing))["removed"])
            existing = set()
            self.proxy.remove([q["id"] for q in self.proxy.store.list()])
        added = skipped = 0
        for pid, files in sorted(profiles.items()):
            if pid in existing:
                skipped += 1
                continue
            backup.write_profile(self.store.root, pid, files)
            added += 1
        have = {q["id"] for q in self.proxy.store.list()}
        proxies_added = 0
        for pid, files in sorted(proxies.items()):
            if pid not in have:
                backup.write_profile(self.proxy.store.root, pid, files)
                proxies_added += 1
        do_settings = new_settings is not None and (restore_settings if restore_settings is not None else replace)
        if do_settings:
            from .settings import DEFAULTS, _merge
            with self.settings._lock:
                self.settings.data = _merge(DEFAULTS, new_settings)
                self.settings.save()
            self.split_changed()
            self.proxy.changed()
        self.log.add("info", "Backup restored: %d profile(s) added, %d already present%s%s" % (
            added, skipped, ", %d replaced" % removed if replace else "", ", settings restored" if do_settings else ""))
        return {"added": added, "skipped": skipped, "removed": removed, "settings": bool(do_settings),
                "proxies": proxies_added,
                "created": manifest.get("created"), "version": manifest.get("vpnman")}

    def leak_test(self):
        """Self-test of the live connection (tunnel, public IP, kill switch, DNS, IPv6)."""
        st = self.status()
        px = self.proxy.status()
        sel = self.proxy.selected()
        px["server_ips"] = ([px["server_ip"]] if px.get("server_ip") else []) + \
            [i for i in (self.proxy.ips(sel, live=False) if sel else []) if i != px.get("server_ip")]
        return leaktest.run(st, self.settings, bool(self.settings.get("netlock.block_ipv6")), proxy=px)

    def remove_profiles(self, idents):
        """Delete several profiles; a live connection to one of them is dropped first.  Never stops half-way:
        returns {"removed": [names], "failed": [{"id", "error"}]}."""
        removed, failed = [], []
        for ident in idents:
            try:
                p = self.store.find(ident)
                with self._mlock:
                    live = self._status.get("profile_id") == p["id"] and self._status.get("state") != "disconnected"
                if live:
                    self.disconnect()
                self.store.remove(p["id"])
                removed.append(p["name"])
            except (ProfileError, KeyError, OSError) as e:
                failed.append({"id": ident, "error": str(e.args[0] if isinstance(e, KeyError) and e.args else e)})
        if removed:
            self.log.add("info", "Removed %d profile(s): %s" % (len(removed), ", ".join(removed)))
        return {"removed": removed, "failed": failed}

    def update_profiles(self, idents, changes):
        """Apply the same edit to several profiles.  `changes` may hold group, username, password and
        stunnel: {"mode": "set"|"off", "host", "port", "sni", "verify"}.  Everything not named stays as it is.
        Never stops half-way: returns {"updated": [names], "skipped": [{"name", "reason"}], "failed": [...]}."""
        from . import stunnel as stun
        allowed = {"group", "username", "password"}
        unknown = set(changes) - allowed - {"stunnel"}
        if unknown:
            raise ProfileError("cannot change %s on several profiles at once" % ", ".join(sorted(unknown)))
        plain = {k: changes[k] for k in allowed if k in changes}
        st = changes.get("stunnel")
        if st:
            if st.get("mode") not in ("set", "off"):
                raise ProfileError("stunnel mode must be 'set' or 'off'")
            if st["mode"] == "set":
                host = str(st.get("host") or "").strip()
                if not host or not stun._SAFE.match(host):
                    raise ProfileError("the stunnel server host is missing or invalid")
                try:
                    port = int(st.get("port") or 443)
                    if not 0 < port < 65536:
                        raise ValueError
                except (TypeError, ValueError):
                    raise ProfileError("the stunnel port must be between 1 and 65535")
        updated, skipped, failed = [], [], []
        for ident in idents:
            try:
                p = self.store.find(ident)
            except (ProfileError, KeyError) as e:
                failed.append({"id": ident, "error": str(e.args[0] if isinstance(e, KeyError) and e.args else e)})
                continue
            ch = dict(plain)
            if st:
                if p["protocol"] != "openvpn":
                    skipped.append({"name": p["name"], "reason": "the SSL tunnel is for OpenVPN profiles only"})
                    if not plain:
                        continue
                else:
                    opts = dict(p.get("options") or {})
                    cur = dict(opts.get("stunnel") or {})
                    if st["mode"] == "off":
                        if cur:
                            cur["enabled"] = False
                    else:
                        cur.update(enabled=True, host=host, port=port)
                        if st.get("sni") is not None:
                            cur["sni"] = str(st["sni"]).strip()
                        if st.get("verify"):
                            cur["verify"] = st["verify"]
                    opts["stunnel"] = cur
                    ch["options"] = opts
            try:
                self.store.update(p["id"], ch)
                updated.append(p["name"])
            except (ProfileError, OSError) as e:
                failed.append({"id": p["id"], "error": str(e)})
        if updated:
            self.log.add("info", "Edited %d profile(s): %s" % (len(updated), ", ".join(updated)))
        return {"updated": updated, "skipped": skipped, "failed": failed}

    def _unique_name(self, p):
        names = {q["name"] for q in self.store.list()}
        base, n = p["name"], 2
        while p["name"] in names:
            p["name"] = "%s (%d)" % (base, n)
            n += 1

    def profiles(self):
        return [public_view(p) for p in self.store.list()]


def system_dns(gw=None):
    """The resolvers in use before the tunnel comes up (what bypassed apps should keep using)."""
    found = []
    try:
        with open(os.environ.get("VPNMAN_RESOLV_CONF", "/etc/resolv.conf")) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        ip = ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    if ip.version == 4 and not ip.is_loopback and parts[1] not in found:
                        found.append(parts[1])
    except OSError:
        pass
    return found or ([gw] if gw else [])


def sum_stats(ifaces):
    rx = tx = 0
    got = False
    for i in ifaces:
        st = plat.iface_stats(i)
        if st:
            rx, tx, got = rx + st[0], tx + st[1], True
    return (rx, tx) if got else None


def tcp_or_ping(ip, port, proto):
    if (proto or "").startswith("tcp") or (port and port in (443, 80, 8443)):
        t0 = time.time()
        try:
            with socket.create_connection((ip, port or 443), timeout=3):
                return round((time.time() - t0) * 1000, 1)
        except OSError:
            return None
    ping = plat.which("ping")
    if ping:
        flags = ["-c", "1", "-W", "2"] if plat.os_family() != "openbsd" else ["-c", "1", "-w", "2"]
        rc, out = plat.run([ping] + flags + [ip], timeout=5)
        m = re.search(r"time[=<]([\d.]+)\s*ms", out)
        if rc == 0 and m:
            return float(m.group(1))
    return None


def _terminate(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.wait()


def _safe_cmd(cmd):
    """Command line for the log with secrets masked."""
    out, hide = [], False
    for a in cmd:
        if hide:
            out.append("***")
            hide = False
        elif a.startswith("--authkey="):
            out.append("--authkey=***")
        else:
            out.append(a)
            hide = a in ("--password", "--authkey", "--setup-key", "--passwd")
    return " ".join(out)
