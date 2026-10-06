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

from . import __version__, backends, dns, leaktest, netlock, network, paths, schedule, split, stunnel
from . import platform as plat
from .backends.base import CredentialsRequired
from .profiles import ProfileError, ProfileStore, public_view
from .settings import Settings


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
        self._status = self._blank_status()
        self._state_cache = {}
        self._current = None      # (ctx, iface) of the live tunnel
        self._reserved_ifnames = set()
        self._split = split.SplitTunnel(lambda: split.names_from_settings(self.settings.get("split")), self.log.add)
        self._split_ctx = None    # (gateway, device, dns) of the live session, while the tunnel is up
        self._split_cur = None    # (gateway, device) the running bypass was built for
        self.scheduler = schedule.Scheduler(self)
        self._net = None          # last seen network (network.current())
        self._net_key = None
        self._net_owned = False   # the current connection was started by the trusted-network rules
        self._net_stop = threading.Event()
        self._routes_added = []   # networks routed around the tunnel right now (mutated in place on network change)
        self._host_ips = {}       # domain -> IPv4 list, for "addresses that skip the VPN" given as names
        self._host_checked = 0.0

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
        s["version"] = __version__
        s["uptime"] = int(time.time() - s["since"]) if s.get("since") and s["state"] == "connected" else 0
        return s

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
        spec = netlock.Spec.from_settings(self.settings, self._lock_endpoints, self._lock_ifaces,
                                          split.MARK if self._split.active else 0, extra_out=self._route_nets())
        self._firewall().apply(spec)
        if not self.lock_engaged:
            self.log.add("info", "Network lock engaged (%s)" % self._fw.name)
        self.lock_engaged = True

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

    def connect(self, ident=None, fastest=False, last=False, persistent=False):
        profiles = self.store.list()
        if not profiles:
            raise ProfileError("no profiles - import one first")
        if last or (not ident and not fastest):
            lid = self._load_state().get("last_profile")
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
                self._stop = stop = threading.Event()
                self._status = self._blank_status()
                self._set(state="connecting", profile_id=p["id"], profile=p["name"], protocol=p["protocol"],
                          message="Switching server" if self._thread and self._thread.is_alive() else "Starting")
            self._cancel(old_stop)
            with self._mlock:
                self._thread = threading.Thread(target=self._run, args=(p, stop, persistent), daemon=True,
                                                name="vpn-conn")
                self._thread.start()
            self._save_state(last_profile=p["id"])
        return {"profile": p["name"], "id": p["id"]}

    def _fastest(self, profiles):
        cands = [p for p in profiles if not p.get("blacklisted")]
        if not cands:
            raise ProfileError("every profile is blacklisted")
        lat = self.latency([p["id"] for p in cands])
        scored = sorted(cands, key=lambda p: (lat.get(p["id"]) is None, lat.get(p["id"]) or 0))
        return scored[0]

    def _cancel(self, stop=None):
        t = self._thread
        (stop or self._stop).set()
        proc = self._proc
        if proc and proc.poll() is None:
            _terminate(proc)
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=25)
        self._thread = None

    def disconnect(self, release_lock=True):
        with self._oplock:
            self._cancel()
            with self._mlock:
                was = self._status["state"]
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

    def _next_candidate(self, current, tried):
        for p in self.store.list():
            if p["id"] not in tried and p.get("favorite") and not p.get("blacklisted"):
                return p
        return None

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
            up = True
            self._set(state="connected", iface=primary, since=time.time(), message="", attempt=0)
            self.log.add("info", "Connected to %s via %s" % (profile["name"], primary or "(no interface)"))
            self._hook("connected", ctx)
            threading.Thread(target=self._check_ip, args=(stop,), daemon=True).start()

            # --- monitor
            last = None
            while not stop.is_set():
                time.sleep(1)
                if proc is not None and proc.poll() is not None:
                    self.log.add("warn", "%s terminated (status %s)" % (backend.label, proc.returncode))
                    break
                if tproc is not None and tproc.poll() is not None:
                    self.log.add("warn", "stunnel terminated (status %s)" % tproc.returncode)
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
            self._remove_routes(routes_added)
            self._split_ctx = None
            self._split_sync()              # stays up for the whitelisted apps if the kill switch is still engaged
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
        return self.settings.get("routes")

    # ------------------------------------------------------------- networks
    def _start_network_monitor(self):
        self._net_stop = threading.Event()
        threading.Thread(target=self._net_loop, args=(self._net_stop,), daemon=True, name="net-monitor").start()

    def _net_loop(self, stop):
        while not stop.is_set():
            try:
                self.network_tick()
            except Exception as e:  # noqa: BLE001
                self.log.add("debug", "network monitor: %s" % e)
            stop.wait(3)

    def network_status(self):
        cur = self._net or network.current()
        return dict(cur, trusted=network.is_trusted(cur["id"], self.settings.get("network.trusted")))

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
        self._follow_network(cur)
        self._network_rules(cur, first)

    def _follow_network(self, cur):
        """Rebuild what was built against the old gateway: the app bypass and the bypass routes."""
        ctx = self._split_ctx
        if ctx and (cur["gateway"], cur["device"]) != ctx[:2] and self._status.get("state") == "connected":
            self._split_ctx = (cur["gateway"], cur["device"], [cur["gateway"]] if cur["gateway"] else [])
            self._split_sync()
        if self._status.get("state") == "connected" and cur["gateway"]:
            self._reapply_routes(cur["gateway"])
        elif self.lock_engaged and not ctx:
            self._split_sync()

    def _network_rules(self, cur, first):
        cfg = self.settings.get("network")
        if not cur["id"] or (first and self.settings.get("connection.autoconnect") != "off"):
            return
        trusted = network.is_trusted(cur["id"], cfg["trusted"])
        active = self._status.get("state") in ("connecting", "connected", "reconnecting")
        prof = cfg.get("profile") or "last"
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
            m = re.search(r'"ip"\s*:\s*"([^"]+)"', body) or re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,})", body)
            if m and not stop.is_set() and stop is self._stop:
                self._set(public_ip=m.group(1))
                self.log.add("info", "Public IP is now %s" % m.group(1))
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
        return public_view(p)

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

    def leak_test(self):
        """Self-test of the live connection (tunnel, public IP, kill switch, DNS, IPv6)."""
        st = self.status()
        return leaktest.run(st, self.settings, bool(self.settings.get("netlock.block_ipv6")))

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
