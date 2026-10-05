"""vpnman command line: scriptable sub-commands plus an interactive menu."""

import argparse
import getpass
import json
import os
import sys
import time

from . import __version__, backends, platform as plat, profiles as prof
from .ipc import Client, DaemonUnavailable, RpcError

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def c(text, code):
    return "\033[%sm%s\033[0m" % (code, text) if USE_COLOR else text


def bold(t): return c(t, "1")
def dim(t): return c(t, "2")
def red(t): return c(t, "31")
def green(t): return c(t, "32")
def yellow(t): return c(t, "33")
def cyan(t): return c(t, "36")


def human(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024


def hms(sec):
    sec = int(sec)
    return "%d:%02d:%02d" % (sec // 3600, sec % 3600 // 60, sec % 60)


STATE_STYLE = {"connected": green, "connecting": yellow, "reconnecting": yellow, "error": red,
               "disconnected": dim}


def format_status(st):
    lines = []
    state = st["state"]
    lines.append("%s %s" % (bold("State:      "), STATE_STYLE.get(state, str)(state.upper())))
    if st.get("profile"):
        lines.append("%s %s (%s)" % (bold("Server:     "), st["profile"], st.get("protocol")))
    if state == "connected":
        lines.append("%s %s" % (bold("Interface:  "), st.get("iface") or "-"))
        lines.append("%s %s" % (bold("Public IP:  "), st.get("public_ip") or "checking..."))
        lines.append("%s %s" % (bold("Uptime:     "), hms(st.get("uptime", 0))))
        lines.append("%s down %s (%s/s)   up %s (%s/s)" % (
            bold("Traffic:    "), human(st["rx"]), human(st["rx_rate"]), human(st["tx"]), human(st["tx_rate"])))
    if st.get("message"):
        lines.append("%s %s" % (bold("Message:    "), st["message"]))
    nl = st["netlock"]
    lines.append("%s %s%s" % (bold("Network lock:"), green("ENGAGED") if nl["engaged"] else dim("off"),
                              " (%s)" % nl["backend"] if nl["engaged"] and nl["backend"] else ""))
    return "\n".join(lines)


class Cli:
    def __init__(self):
        self.client = Client()

    def call(self, method, **kw):
        return self.client.call(method, **kw)

    # ------------------------------------------------------------ commands
    def cmd_status(self, a):
        st = self.call("status")
        print(json.dumps(st, indent=2) if a.json else format_status(st))
        return 0 if st["state"] == "connected" else 3

    def cmd_list(self, a):
        ps = self.call("profiles.list")
        lat = self.call("latency") if a.latency else {}
        if a.json:
            print(json.dumps(ps, indent=2))
            return 0
        if not ps:
            print("No profiles yet. Import one with: vpnman import FILE")
            return 0
        w = max(len(p["name"]) for p in ps)
        for p in ps:
            flags = ("★" if p["favorite"] else " ") + ("⊘" if p["blacklisted"] else " ")
            ms = lat.get(p["id"])
            extra = ("  %6.1f ms" % ms) if ms else ("  %9s" % "-" if a.latency else "")
            print("%s %-*s  %-12s %s%s" % (flags, w, p["name"], p["protocol"],
                                            dim("%s:%s" % (p["server"], p["port"]) if p["server"] else ""), extra))
        return 0

    def cmd_connect(self, a):
        mark = self.call("logs", since=0, limit=1)["last"]
        self.call("connect", ident=a.profile, fastest=a.fastest, last=a.last or (not a.profile and not a.fastest))
        if a.no_wait:
            print("Connecting...")
            return 0
        return self.wait_connected(a.timeout, mark)

    def wait_connected(self, timeout=90, seen=None):
        end = time.time() + timeout
        if seen is None:
            seen = self.call("logs", since=0, limit=1)["last"]
        last_state = None
        while time.time() < end:
            st = self.call("status")
            logs = self.call("logs", since=seen, limit=200)
            for e in logs["entries"]:
                if e["level"] in ("info", "warn", "error"):
                    print("  " + self.fmt_log(e))
            seen = logs["last"]
            if st["state"] != last_state:
                last_state = st["state"]
            if st["state"] == "connected":
                time.sleep(1.5)
                print(format_status(self.call("status")))
                return 0
            if st["state"] in ("error", "disconnected"):
                print(red("Failed: %s" % (st.get("message") or "disconnected")), file=sys.stderr)
                return 1
            time.sleep(0.5)
        print(red("Timed out waiting for the tunnel."), file=sys.stderr)
        return 1

    def cmd_disconnect(self, a):
        self.call("disconnect")
        print("Disconnected.")
        return 0

    def cmd_import(self, a):
        targets = []
        for path in a.paths:
            if os.path.isdir(path):
                for root, _d, files in os.walk(path):
                    for f in sorted(files):
                        if f.lower().endswith((".ovpn", ".conf", ".swanctl", ".vpnc", ".fortivpn", ".yml", ".yaml")):
                            targets.append(os.path.join(root, f))
            else:
                targets.append(path)
        if not targets:
            print("Nothing to import.", file=sys.stderr)
            return 1
        fields = {}
        if a.user:
            fields["username"] = a.user
            fields["password"] = getpass.getpass("Password for %s: " % a.user) if a.ask_password else (a.password or "")
        options = {}
        if a.stunnel:
            options["stunnel"] = self.stunnel_opts(a.stunnel, a.stunnel_sni, a.stunnel_verify)
        ok = 0
        for path in targets:
            try:
                text, files = prof.collect_files(path)
                name = a.name if (a.name and len(targets) == 1) else os.path.splitext(os.path.basename(path))[0]
                p = self.call("profiles.import", name=name, text=text, files=files, protocol=a.protocol,
                              filename=os.path.basename(path), fields=fields, options=options)
                if a.stunnel_ca and a.stunnel:
                    self.upload_ca(p["id"], a.stunnel_ca)
                print("%s %s  (%s)" % (green("imported"), p["name"], p["protocol"]))
                ok += 1
            except (RpcError, OSError) as e:
                print("%s %s: %s" % (red("skipped"), path, e), file=sys.stderr)
        return 0 if ok else 1

    @staticmethod
    def stunnel_opts(target, sni=None, verify=None):
        host, _, port = target.rpartition(":") if ":" in target else (target, "", "")
        st = {"enabled": True, "host": host or target, "port": int(port) if port.isdigit() else 443}
        if sni:
            st["sni"] = sni
        if verify:
            st["verify"] = verify
        return st

    def upload_ca(self, ident, path):
        import base64
        with open(path, "rb") as fh:
            self.call("profiles.setfile", ident=ident, name="stunnel-ca.pem", data=base64.b64encode(fh.read()).decode())
        p = self.call("profiles.get", ident=ident)
        st = dict(p["options"].get("stunnel", {}), ca="stunnel-ca.pem", verify="ca")
        self.call("profiles.update", ident=ident, changes={"options": dict(p["options"], stunnel=st)})

    def cmd_add(self, a):
        fields = {"server": a.server or "", "port": a.port or 0, "username": a.user or ""}
        if a.ask_password:
            fields["password"] = getpass.getpass("Password: ")
        opts = {}
        for kv in a.option or []:
            k, _, v = kv.partition("=")
            opts[k] = v
        p = self.call("profiles.add", name=a.name, protocol=a.protocol, fields=fields, options=opts)
        print("Added %s (%s)" % (p["name"], p["protocol"]))
        return 0

    def cmd_remove(self, a):
        for n in a.profiles:
            print("Removed %s" % self.call("profiles.remove", ident=n)["name"])
        return 0

    def cmd_edit(self, a):
        ch = {}
        cur = None
        for kv in a.changes:
            k, _, v = kv.partition("=")
            if k.startswith("stunnel"):
                cur = cur or self.call("profiles.get", ident=a.profile)
                opts = ch.setdefault("options", dict(cur["options"]))
                st = dict(opts.get("stunnel", {}))
                if k == "stunnel":
                    if v.lower() in ("", "off", "none", "false"):
                        st["enabled"] = False
                    else:
                        st.update(self.stunnel_opts(v))
                elif k == "stunnel_sni":
                    st["sni"] = v
                elif k == "stunnel_verify":
                    st["verify"] = v
                elif k == "stunnel_ca":
                    self.upload_ca(cur["id"], v)
                    st.update(ca="stunnel-ca.pem", verify="ca")
                    cur = self.call("profiles.get", ident=a.profile)
                opts["stunnel"] = st
                continue
            if k in ("favorite", "blacklisted"):
                v = v.lower() in ("1", "true", "yes", "on")
            elif k == "dns":
                v = [x.strip() for x in v.split(",") if x.strip()]
            elif k == "port":
                v = int(v)
            ch[k] = v
        self.call("profiles.update", ident=a.profile, changes=ch)
        print("Updated.")
        return 0

    def _flag(self, a, **ch):
        for n in a.profiles:
            self.call("profiles.update", ident=n, changes=ch)
        print("Done.")
        return 0

    def cmd_fav(self, a): return self._flag(a, favorite=True)
    def cmd_unfav(self, a): return self._flag(a, favorite=False)
    def cmd_block(self, a): return self._flag(a, blacklisted=True)
    def cmd_unblock(self, a): return self._flag(a, blacklisted=False)

    def cmd_ping(self, a):
        ps = self.call("profiles.list")
        ids = [self.call("profiles.get", ident=n)["id"] for n in a.profiles] if a.profiles else None
        lat = self.call("latency", ids=ids)
        for p in ps:
            if p["id"] in lat:
                ms = lat[p["id"]]
                print("%-30s %s" % (p["name"], ("%.1f ms" % ms) if ms else red("unreachable")))
        return 0

    def cmd_lock(self, a):
        if a.action == "on":
            self.call("netlock.enable")
            print(green("Network lock engaged: only the VPN, LAN and whitelisted hosts are reachable."))
        elif a.action == "off":
            self.call("netlock.disable")
            print("Network lock released.")
        else:
            nl = self.call("netlock.status")
            print("Network lock: %s" % (green("ENGAGED") if nl["engaged"] else "off"))
            if nl["engaged"]:
                print("  backend:   %s\n  interfaces: %s\n  endpoints: %s" % (
                    nl["backend"], ", ".join(nl["ifaces"]) or "-", ", ".join(nl["endpoints"]) or "-"))
        return 0

    def cmd_dns(self, a):
        from .settings import DNS_PRESETS
        if not a.choice:
            d = self.call("settings.get", key="dns")
            if not d["force"]:
                print("DNS: left unchanged while connected")
            else:
                print("DNS: %s" % (", ".join(d["servers"]) if d["servers"] else "the VPN provider's servers"))
            print("\nPresets:")
            for name, ips in DNS_PRESETS:
                print("  %-30s %s" % (name, ", ".join(ips)))
            print("\nvpnman dns <preset name | IP[,IP...] | provider | off>")
            return 0
        text = " ".join(a.choice)
        low = text.lower()
        if low in ("provider", "default", "vpn"):
            tree = {"force": True, "servers": []}
        elif low in ("off", "none", "system"):
            tree = {"force": False}
        else:
            hit = [ips for name, ips in DNS_PRESETS if low in name.lower()]
            ips = hit[0] if hit else [x.strip() for x in text.replace(";", ",").replace(" ", ",").split(",") if x.strip()]
            tree = {"force": True, "servers": ips}
        self.call("settings.update", tree={"dns": tree})
        print("DNS updated (applied immediately if connected).")
        return 0

    def cmd_get(self, a):
        v = self.call("settings.get", key=a.key)
        if a.key and not isinstance(v, (dict, list)):
            print(v)
        else:
            print(json.dumps(v, indent=2))
        return 0

    def cmd_set(self, a):
        print("%s = %s" % (a.key, self.call("settings.set", key=a.key, value=a.value)))
        return 0

    @staticmethod
    def fmt_log(e):
        col = {"error": red, "warn": yellow, "info": green, "tool": dim, "debug": dim}.get(e["level"], str)
        return "%s %s %s" % (dim(time.strftime("%H:%M:%S", time.localtime(e["time"]))),
                             col("%-5s" % e["level"]), e["msg"])

    def cmd_logs(self, a):
        seen = 0
        r = self.call("logs", since=0, limit=a.lines)
        for e in r["entries"]:
            print(self.fmt_log(e))
        seen = r["last"]
        while a.follow:
            time.sleep(1)
            r = self.call("logs", since=seen)
            for e in r["entries"]:
                print(self.fmt_log(e), flush=True)
            seen = r["last"]
        return 0

    def cmd_protocols(self, a):
        info = self.call("protocols") if self.client.alive() else backends.describe()
        for p in info:
            mark = green("✔") if p["available"] else red("✘")
            print("%s %-15s %s" % (mark, p["id"], p["label"]))
            print("    %s" % dim(p["description"]))
            if p["missing"]:
                print("    %s %s" % (yellow("install:"), ", ".join(p["missing"])))
        return 0

    def cmd_doctor(self, a):
        print(bold("VPNMan %s" % __version__))
        print("OS:        %s" % plat.distro()[1])
        print("Init:      %s" % plat.init_system())
        alive = self.client.alive()
        print("Daemon:    %s" % (green("running") if alive else red("not running")))
        if alive:
            sysinfo = self.call("system")
            print("Firewall:  %s" % sysinfo["firewall"])
        else:
            from . import netlock
            try:
                print("Firewall:  %s" % netlock.pick_backend().name)
            except RuntimeError as e:
                print("Firewall:  %s" % red(str(e)))
        print("Root:      %s" % ("yes" if plat.is_root() else "no"))
        print()
        return self.cmd_protocols(a)

    def cmd_service(self, a):
        from . import service
        if not plat.is_root():
            print("Run as root: sudo vpnman service %s" % a.action, file=sys.stderr)
            return 1
        init = plat.init_system()
        if a.action == "install":
            print("Installed %s service definition." % service.install(init))
            return 0
        if a.action == "uninstall":
            service.uninstall(init)
            print("Removed.")
            return 0
        if a.action == "enable":
            service.install(init)     # idempotent: makes "enable" work even if the definition is missing
        ok, out = service.control(a.action, init)
        print(out)
        return 0 if ok else 1

    def cmd_daemon(self, a):
        from . import daemon
        return daemon.run()

    def cmd_gui(self, a):
        from .gui.app import run
        return run()


# ------------------------------------------------------------------ interactive

def ask(prompt, default=None):
    try:
        v = input(prompt + (" [%s]" % default if default else "") + ": ").strip()
    except EOFError:
        raise KeyboardInterrupt
    return v or (default or "")


def pick(items, label, render):
    for i, it in enumerate(items, 1):
        print("  %s %s" % (cyan("%2d)" % i), render(it)))
    v = ask(label + " (number or name, empty to cancel)")
    if not v:
        return None
    if v.isdigit() and 1 <= int(v) <= len(items):
        return items[int(v) - 1]
    for it in items:
        if v.lower() in it["name"].lower():
            return it
    print(red("No match."))
    return None


def interactive(cli):
    menu = [("c", "Connect"), ("f", "Connect to fastest"), ("d", "Disconnect"), ("s", "Servers / profiles"),
            ("l", "Network lock (kill switch)"), ("i", "Import profile(s)"), ("p", "Preferences"),
            ("g", "View log"), ("x", "System check"), ("q", "Quit")]
    while True:
        try:
            print("\n" + bold("VPNMan %s" % __version__))
            print(format_status(cli.call("status")))
            print()
            print("  " + "   ".join("%s %s" % (cyan("[%s]" % k), v) for k, v in menu[:5]))
            print("  " + "   ".join("%s %s" % (cyan("[%s]" % k), v) for k, v in menu[5:]))
            ch = ask("\n>").lower()[:1]
            if ch in ("q", "") and ch == "q":
                return 0
            elif ch == "c":
                p = pick(cli.call("profiles.list"), "Connect to", _render_profile)
                if p:
                    cli.call("connect", ident=p["id"])
                    cli.wait_connected()
            elif ch == "f":
                cli.call("connect", fastest=True)
                cli.wait_connected()
            elif ch == "d":
                cli.call("disconnect")
            elif ch == "s":
                _servers_menu(cli)
            elif ch == "l":
                nl = cli.call("netlock.status")
                if nl["engaged"] and nl["manual"] or nl["engaged"]:
                    if ask("Network lock is ENGAGED. Release it? (y/N)").lower() == "y":
                        cli.call("netlock.disable")
                elif ask("Engage the network lock now? (y/N)").lower() == "y":
                    cli.call("netlock.enable")
            elif ch == "i":
                path = ask("Path to config file or directory")
                if path:
                    ns = argparse.Namespace(paths=[os.path.expanduser(path)], name=None, protocol=None,
                                            user=None, password=None, ask_password=False, stunnel=None,
                                            stunnel_sni=None, stunnel_ca=None, stunnel_verify=None)
                    user = ask("Username (empty if none)")
                    if user:
                        ns.user, ns.ask_password = user, True
                    cli.cmd_import(ns)
            elif ch == "p":
                _settings_menu(cli)
            elif ch == "g":
                cli.cmd_logs(argparse.Namespace(lines=40, follow=False))
            elif ch == "x":
                cli.cmd_doctor(None)
        except (DaemonUnavailable, RpcError) as e:
            print(red(str(e)))
        except KeyboardInterrupt:
            print()
            return 0


def _render_profile(p):
    return "%s%s %-28s %s" % ("★" if p["favorite"] else " ", "⊘" if p["blacklisted"] else " ", p["name"],
                              dim("%s  %s" % (p["protocol"], p["server"])))


def _servers_menu(cli):
    p = pick(cli.call("profiles.list"), "Select profile", _render_profile)
    if not p:
        return
    print("  [f] toggle favourite  [b] toggle blacklist  [u] set credentials  [r] rename  [x] remove")
    ch = ask("action").lower()
    if ch == "f":
        cli.call("profiles.update", ident=p["id"], changes={"favorite": not p["favorite"]})
    elif ch == "b":
        cli.call("profiles.update", ident=p["id"], changes={"blacklisted": not p["blacklisted"]})
    elif ch == "u":
        user = ask("Username", p.get("username"))
        pw = getpass.getpass("Password (empty keeps current): ")
        ch = {"username": user}
        if pw:
            ch["password"] = pw
        cli.call("profiles.update", ident=p["id"], changes=ch)
    elif ch == "r":
        cli.call("profiles.update", ident=p["id"], changes={"name": ask("New name", p["name"])})
    elif ch == "x" and ask("Really remove %s? (y/N)" % p["name"]).lower() == "y":
        cli.call("profiles.remove", ident=p["id"])


def _flatten(tree, prefix=""):
    for k, v in tree.items():
        if isinstance(v, dict):
            yield from _flatten(v, prefix + k + ".")
        else:
            yield prefix + k, v


def _settings_menu(cli):
    items = [{"name": k, "value": v} for k, v in _flatten(cli.call("settings.get")) if k != "routes"]
    p = pick(items, "Change setting", lambda i: "%-32s %s" % (i["name"], cyan(json.dumps(i["value"]))))
    if p:
        new = ask("New value for %s" % p["name"], json.dumps(p["value"]) if not isinstance(p["value"], str) else p["value"])
        try:
            cli.call("settings.set", key=p["name"], value=new)
            print(green("Saved."))
        except RpcError as e:
            print(red(str(e)))


# ----------------------------------------------------------------------- parser

def build_parser():
    ap = argparse.ArgumentParser(prog="vpnman", description="Multi-protocol VPN manager with kill switch.")
    ap.add_argument("--version", action="version", version="vpnman " + __version__)
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")

    def add(name, help, **kw):
        return sub.add_parser(name, help=help, **kw)

    s = add("status", "show connection status"); s.add_argument("--json", action="store_true")
    s = add("list", "list profiles", aliases=["ls"]); s.add_argument("--latency", "-l", action="store_true")
    s.add_argument("--json", action="store_true")
    s = add("connect", "connect to a profile", aliases=["up"])
    s.add_argument("profile", nargs="?"); s.add_argument("--fastest", action="store_true")
    s.add_argument("--last", action="store_true"); s.add_argument("--no-wait", action="store_true")
    s.add_argument("--timeout", type=int, default=90)
    add("disconnect", "disconnect", aliases=["down"])
    s = add("import", "import config files or a directory of them")
    s.add_argument("paths", nargs="+"); s.add_argument("--name"); s.add_argument("--protocol", choices=list(backends.REGISTRY))
    s.add_argument("--user"); s.add_argument("--password"); s.add_argument("--ask-password", action="store_true")
    s.add_argument("--stunnel", metavar="HOST[:PORT]", help="carry OpenVPN over TLS via stunnel (default port 443)")
    s.add_argument("--stunnel-sni", metavar="NAME"); s.add_argument("--stunnel-ca", metavar="FILE")
    s.add_argument("--stunnel-verify", choices=["none", "system", "ca"])
    s = add("add", "create a profile without a config file")
    s.add_argument("name"); s.add_argument("--protocol", required=True, choices=list(backends.REGISTRY))
    s.add_argument("--server"); s.add_argument("--port", type=int); s.add_argument("--user")
    s.add_argument("--ask-password", action="store_true"); s.add_argument("--option", "-o", action="append", metavar="K=V")
    s = add("remove", "delete profiles", aliases=["rm"]); s.add_argument("profiles", nargs="+")
    s = add("edit", "change profile fields (name, username, password, server, port, dns, notes, group, "
                 "stunnel=HOST:PORT|off, stunnel_sni, stunnel_ca=FILE, stunnel_verify)")
    s.add_argument("profile"); s.add_argument("changes", nargs="+", metavar="KEY=VALUE")
    for n, h in (("fav", "mark favourite"), ("unfav", "unmark favourite"), ("block", "blacklist"),
                 ("unblock", "remove from blacklist")):
        s = add(n, h); s.add_argument("profiles", nargs="+")
    s = add("ping", "measure latency to profiles"); s.add_argument("profiles", nargs="*")
    s = add("lock", "network lock (kill switch)"); s.add_argument("action", choices=["on", "off", "status"], nargs="?", default="status")
    s = add("dns", "choose the DNS servers used while connected"); s.add_argument("choice", nargs="*")
    s = add("get", "show settings"); s.add_argument("key", nargs="?")
    s = add("set", "change a setting"); s.add_argument("key"); s.add_argument("value")
    s = add("logs", "show daemon log"); s.add_argument("-f", "--follow", action="store_true")
    s.add_argument("-n", "--lines", type=int, default=50)
    add("protocols", "list supported protocols and whether their tools are installed")
    add("doctor", "check the system")
    s = add("service", "install/control the background service")
    s.add_argument("action", choices=["install", "uninstall", "enable", "disable", "start", "stop", "restart", "status"])
    add("daemon", "run the daemon in the foreground (root)")
    add("gui", "open the GTK4/libadwaita app")
    add("shell", "interactive menu", aliases=["menu"])
    return ap


ALIASES = {"ls": "list", "up": "connect", "down": "disconnect", "rm": "remove", "menu": "shell"}


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    cmd = ALIASES.get(a.cmd, a.cmd)
    cli = Cli()
    try:
        if cmd is None:
            if sys.stdin.isatty() and sys.stdout.isatty():
                return interactive(cli)
            a.json = False
            return cli.cmd_status(a)
        if cmd == "shell":
            return interactive(cli)
        if cmd == "protocols" and not cli.client.alive():
            return cli.cmd_protocols(a)
        return getattr(cli, "cmd_" + cmd)(a)
    except DaemonUnavailable as e:
        print(red("error: ") + str(e), file=sys.stderr)
        print("Start it with: sudo vpnman service enable   (or: sudo vpnman daemon)", file=sys.stderr)
        return 2
    except RpcError as e:
        print(red("error: ") + str(e), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
