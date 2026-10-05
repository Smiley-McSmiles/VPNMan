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

from . import __version__, backends, dns, netlock, paths, stunnel
from . import platform as plat
from .profiles import ProfileError, ProfileStore, public_view
from .settings import Settings


class ConnectError(Exception):
    """A connection attempt failed (retryable)."""


class FatalError(ConnectError):
    """Configuration problem - retrying cannot help."""


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

    # ------------------------------------------------------------------ status
    @staticmethod
    def _blank_status():
        return {"state": "disconnected", "profile_id": None, "profile": None, "protocol": None,
                "iface": None, "public_ip": None, "since": None, "message": "", "attempt": 0,
                "rx": 0, "tx": 0, "rx_rate": 0, "tx_rate": 0}

    def _set(self, **kw):
        with self._mlock:
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
        spec = netlock.Spec.from_settings(self.settings, self._lock_endpoints, self._lock_ifaces)
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
        return self.netlock_status()

    def netlock_disable(self):
        with self._mlock:
            self.lock_manual = False
            self._save_state(lock_manual=False)
            self._lock_remove()
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

    # --------------------------------------------------------------- start / stop
    def startup(self):
        """Called once by the daemon: crash recovery and boot-time behaviour."""
        dns.restore_resolv_conf()
        st = self._load_state()
        self.lock_manual = bool(st.get("lock_manual"))
        if self.lock_manual or self.settings.get("netlock.persist"):
            try:
                self._lock_apply()
            except Exception as e:  # noqa: BLE001
                self.log.add("error", "Could not restore network lock: %s" % e)
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
        self.disconnect()

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
        self._cancel()
        with self._mlock:
            self._stop = threading.Event()
            self._status = self._blank_status()
            self._set(state="connecting", profile_id=p["id"], profile=p["name"], protocol=p["protocol"],
                      message="Starting")
            self._thread = threading.Thread(target=self._run, args=(p, self._stop, persistent), daemon=True,
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

    def _cancel(self):
        t = self._thread
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            _terminate(proc)
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=25)
        self._thread = None

    def disconnect(self, release_lock=True):
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
                self._set(state="error", message=str(e))
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
            before = set(plat.list_interfaces())
            self.log.add("info", "Connecting to %s (%s)" % (profile["name"], backend.label))
            self._set(message="Connecting")
            try:
                backend.prepare(ctx)
                if not oneshot:
                    cmd = backend.connect_cmd(ctx)
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

    def _apply_routes(self, gw):
        added = []
        for r in self.settings.get("routes"):
            if r.get("action") != "out" or not gw:
                continue
            try:
                net = str(ipaddress.ip_network(r["ip"], strict=False))
            except (ValueError, KeyError):
                continue
            if ":" in net:
                continue
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
            if m and not stop.is_set():
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

    def _unique_name(self, p):
        names = {q["name"] for q in self.store.list()}
        base, n = p["name"], 2
        while p["name"] in names:
            p["name"] = "%s (%d)" % (base, n)
            n += 1

    def profiles(self):
        return [public_view(p) for p in self.store.list()]


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
