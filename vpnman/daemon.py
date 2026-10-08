"""vpnmand - the privileged daemon."""

import json
import os
import signal
import socketserver
import sys
import threading
import traceback

from . import __version__, access, backends, conntable, ipc, paths
from . import platform as plat
from .manager import Manager
from .blocks import BlockError
from .profiles import ProfileError, public_view
from .settings import Settings


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        mgr = self.server.manager
        if ipc.peercred_supported() and plat.is_root():
            uid = ipc.peer_uid(self.request)
            if uid is None or not access.authorized(uid, mgr.settings):
                mgr.log.add("warn", "Denied connection from uid %s" % uid)
                try:
                    self.wfile.write((json.dumps({"id": None, "ok": False, "error":
                        "permission denied - you need an active local session or membership of the vpnman group"})
                        + "\n").encode())
                except OSError:
                    pass
                return
        try:
            line = self.rfile.readline(40 * 1024 * 1024)
            if not line:
                return
            req = json.loads(line.decode())
            method, params = req["method"], req.get("params") or {}
            fn = self.server.methods.get(method)
            if fn is None:
                raise ProfileError("unknown method: %s" % method)
            result = fn(mgr, **params)
            resp = {"id": req.get("id"), "ok": True, "result": result}
        except (ProfileError, BlockError, KeyError, ValueError, TypeError, RuntimeError, OSError) as e:
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            resp = {"id": None, "ok": False, "error": str(msg)}
            if not isinstance(e, (ProfileError, KeyError, ValueError)):
                mgr.log.add("debug", traceback.format_exc().strip().splitlines()[-1])
        except Exception as e:  # noqa: BLE001
            mgr.log.add("error", "RPC failure: %s" % e)
            resp = {"id": None, "ok": False, "error": "internal error: %s" % e}
        try:
            self.wfile.write((json.dumps(resp) + "\n").encode())
        except OSError:
            pass


def _changed(m, key, result):
    if key.startswith("dns"):
        m.reapply_dns()
    elif key.startswith("split"):
        m.split_changed()
    elif key.startswith("proxy"):
        m.proxy.changed()
    return result


def _remove_one(m, ident):
    p = m.store.find(ident)
    res = m.remove_profiles([p["id"]])
    if res["failed"]:
        raise ProfileError(res["failed"][0]["error"])
    return public_view(p)


def _import(m, **kw):
    return m.import_profile(**kw)


METHODS = {
    "ping": lambda m: "pong",
    "version": lambda m: __version__,
    "status": lambda m: m.status(),
    "protocols": lambda m: backends.describe(),
    "profiles.list": lambda m: m.profiles(),
    "profiles.get": lambda m, ident: public_view(m.store.find(ident)),
    "profiles.import": _import,
    "profiles.add": lambda m, name, protocol, fields=None, options=None, files=None: m.add_profile(
        name, protocol, fields, options, files),
    "profiles.setfile": lambda m, ident, name, data: m.set_profile_file(ident, name, data),
    "profiles.update": lambda m, ident, changes: public_view(m.store.update(ident, changes)),
    "profiles.remove": lambda m, ident: _remove_one(m, ident),
    "profiles.remove_many": lambda m, ids: m.remove_profiles(ids),
    "profiles.update_many": lambda m, ids, changes: m.update_profiles(ids, changes),
    "latency": lambda m, ids=None: m.latency(ids),
    "connect": lambda m, ident=None, fastest=False, last=False: m.connect(ident, fastest, last),
    "disconnect": lambda m: m.disconnect(),
    "netlock.status": lambda m: m.netlock_status(),
    "netlock.enable": lambda m: m.netlock_enable(),
    "netlock.disable": lambda m: m.netlock_disable(),
    "settings.get": lambda m, key=None: m.settings.get(key),
    "settings.set": lambda m, key, value: _changed(m, key, m.settings.set(key, value)),
    "settings.update": lambda m, tree: (m.settings.update(tree), _changed(m, "dns" if "dns" in tree else "", None),
                                        m.settings.get())[2],
    "split.status": lambda m: m.split_status(),
    "split.set": lambda m, apps=None, enabled=None, mode=None: m.split_set(apps, enabled, mode),
    "routes.set": lambda m, entries: m.routes_set(entries),
    "proxy.list": lambda m: m.proxy.list(),
    "proxy.status": lambda m: m.proxy.status(),
    "proxy.sources": lambda m: m.proxy.sources(),
    "proxy.import": lambda m, text, source="", group="", name=None: m.proxy.import_text(text, source, group, name),
    "proxy.remove": lambda m, ids: m.proxy.remove(ids),
    "proxy.update": lambda m, ident, changes: m.proxy.update(ident, changes),
    "proxy.select": lambda m, ident: m.proxy.select(ident),
    "proxy.set": lambda m, **kw: m.proxy.configure(**kw),
    "proxy.latency": lambda m, ids=None: m.proxy.latency(ids),
    "proxy.fastest": lambda m, group=None: m.proxy.fastest(group),
    "proxy.link": lambda m, ident: m.proxy.link(ident),
    "proxy.info": lambda m, ident: m.proxy.info(ident),
    "blocks.status": lambda m: m.blocks.status(),
    "blocks.add": lambda m, kind, value, proto="any", note="", minutes=0, until_reboot=False:
        m.blocks.add(kind, value, proto, note, minutes, until_reboot),
    "blocks.update": lambda m, ident, enabled=None, note=None: m.blocks.update(ident, enabled, note),
    "blocks.remove": lambda m, ids: m.blocks.remove(ids),
    "blocks.set": lambda m, enabled: m.blocks.set_enabled(enabled),
    "connections.close": lambda m, proto, local, lport, remote, rport: m.blocks.close_row(proto, local, lport, remote, rport),
    "connections": lambda m, listening=False, local=False, resolve=False: conntable.snapshot(
        bool(listening), bool(local), resolve=bool(resolve)),
    "network.status": lambda m: m.network_status(),
    "network.trust": lambda m, name=None, trusted=True: m.network_trust(name, trusted),
    "backup.export": lambda m: m.backup_export(),
    "backup.import": lambda m, data, replace=False, restore_settings=None: m.backup_import(data, replace, restore_settings),
    "history": lambda m, limit=50: m.history.list(limit),
    "history.clear": lambda m: m.history.clear() or True,
    "leaktest": lambda m: m.leak_test(),
    "schedule.status": lambda m: m.schedule_status(),
    "schedule.set": lambda m, entries=None, enabled=None: m.schedule_set(entries, enabled),
    "logs": lambda m, since=0, limit=1000: dict(zip(("entries", "last"), m.log.since(since, limit))),
    "discover.networkmanager": lambda m: backends.NetworkManager.discover(),
    "system": lambda m: {"os": plat.os_family(), "distro": plat.distro()[1], "init": plat.init_system(),
                         "firewall": _fw_name()},
}


def _fw_name():
    from . import netlock
    try:
        return netlock.pick_backend("auto").name
    except RuntimeError as e:
        return "none (%s)" % e


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path, manager):
        self.manager = manager
        self.methods = METHODS
        super().__init__(path, Handler)


def run(foreground=True):
    if not plat.is_root() and "VPNMAN_ALLOW_UNPRIVILEGED" not in os.environ:
        print("vpnmand must run as root (it manages interfaces and firewall rules).", file=sys.stderr)
        return 1
    os.makedirs(paths.run_dir(), mode=0o755, exist_ok=True)
    os.makedirs(paths.config_dir(), mode=0o700, exist_ok=True)
    sock = paths.socket_path()
    if ipc.Client(sock, timeout=2).alive():
        print("vpnmand is already running.", file=sys.stderr)
        return 1
    try:
        os.unlink(sock)
    except FileNotFoundError:
        pass
    mgr = Manager(settings=Settings())
    mgr.log.open_file(paths.log_file())
    server = Server(sock, mgr)
    grp = ipc.secure_socket(sock)
    with open(paths.pidfile(), "w") as fh:
        fh.write(str(os.getpid()))
    mgr.log.add("info", "vpnmand %s started (%s, init: %s, access: %s)"
                % (__version__, plat.distro()[1], plat.init_system(), grp))

    def stop(signum, _frame):
        mgr.log.add("info", "Signal %d received, shutting down" % signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, lambda *_: mgr.settings.load())
    threading.Thread(target=mgr.startup, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        mgr.shutdown()
        server.server_close()
        for f in (sock, paths.pidfile()):
            try:
                os.unlink(f)
            except OSError:
                pass
    return 0
