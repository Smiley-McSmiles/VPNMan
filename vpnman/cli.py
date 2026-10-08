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


STATE_STYLE = {"connected": green, "connecting": yellow, "reconnecting": yellow, "disconnecting": yellow, "error": red,
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
    px = st.get("proxy")
    net = (px or {}).get("net") or {}
    if net.get("enabled"):
        servers = ", ".join("%s %s:%s" % (k.upper(), net[k]["host"], net[k]["port"])
                            for k in ("http", "https", "ftp", "socks") if net.get(k, {}).get("host"))
        lines.append("%s %s %s%s" % (bold("Net proxy:  "), green("ACTIVE") if net.get("active") else yellow("on"),
                                     servers or "-", red("  " + net["error"]) if net.get("error") else ""))
    if px and (px["enabled"] or px["running"]):
        lines.append("%s %s via %s (%s, %s)%s" % (bold("Proxy:      "), green("RUNNING") if px["running"] else yellow("on"),
                                                 px["name"] or "-", px["order"], px["mode"],
                                                 red("  " + px["error"]) if px["error"] else ""))
    return "\n".join(lines)


def parse_minutes(text):
    """'30m', '2h', '1d', '1h30m', '90' (minutes) -> minutes."""
    import re
    t = str(text).strip().lower()
    if re.fullmatch(r"\d+", t):
        return int(t)
    parts = re.findall(r"(\d+)\s*([dhm])", t)
    if not parts or re.sub(r"\d+\s*[dhm]", "", t).strip():
        raise RpcError("cannot read the duration %r (use 30m, 2h, 1d or 1h30m)" % text)
    return sum(int(n) * {"d": 1440, "h": 60, "m": 1}[u] for n, u in parts)


class Cli:
    def __init__(self):
        self.client = Client()

    def call(self, method, **kw):
        return self.client.call(method, **kw)

    # ------------------------------------------------------------ commands
    def cmd_status(self, a):
        st = self.call("status")
        try:
            st["proxy"] = self.call("proxy.status")
        except RpcError:
            st["proxy"] = None                      # an older daemon without proxies
        print(json.dumps(st, indent=2) if a.json else format_status(st))
        return 0 if st["state"] == "connected" else 3

    def cmd_list(self, a):
        ps = self.call("profiles.list")
        if getattr(a, "names", False):
            for p in ps:
                print(p["name"])
            return 0
        if getattr(a, "sort", None) == "latency":
            a.latency = True
        lat = self.call("latency") if a.latency else {}
        if getattr(a, "sort", None):
            key = {"name": lambda p: p["name"].lower(), "group": lambda p: ((p.get("group") or "~").lower(), p["name"].lower()),
                   "latency": lambda p: (lat.get(p["id"]) is None, lat.get(p["id"]) or 0, p["name"].lower())}[a.sort]
            ps = sorted(ps, key=key)
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
            grp = ("  [%s]" % p["group"]) if p.get("group") else ""
            print("%s %-*s  %-12s %s%s%s" % (flags, w, p["name"], p["protocol"],
                                              dim("%s:%s" % (p["server"], p["port"]) if p["server"] else ""), extra,
                                              dim(grp)))
        return 0

    def cmd_connect(self, a):
        mark = self.call("logs", since=0, limit=1)["last"]
        self.call("connect", ident=a.profile, fastest=a.fastest, last=a.last or (not a.profile and not a.fastest))
        if a.no_wait:
            print("Connecting...")
            return 0
        rc = self.wait_connected(a.timeout, mark)
        for _ in range(3):
            st = self.call("status")
            if rc == 0 or st.get("state") != "error" or st.get("error_kind") != "auth" or not sys.stdin.isatty():
                break
            # wrong or missing credentials: ask right here instead of sending the user off to edit the profile
            pid = st["profile_id"]
            cur = self.call("profiles.get", ident=pid)
            print(yellow("The server rejected the login for %s." % st["profile"]))
            user = ask("Username", cur.get("username") or None)
            pw = getpass.getpass("Password: ")
            if not user or not pw:
                break
            self.call("profiles.update", ident=pid, changes={"username": user, "password": pw})
            mark = self.call("logs", since=0, limit=1)["last"]
            self.call("connect", ident=pid)
            rc = self.wait_connected(a.timeout, mark)
        return rc

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
        targets, groups = [], {}
        for path in a.paths:
            if os.path.isdir(path):
                top = os.path.abspath(path)
                for root, _d, files in os.walk(path):
                    for f in sorted(files):
                        if f.lower().endswith((".ovpn", ".conf", ".swanctl", ".vpnc", ".fortivpn", ".yml", ".yaml")):
                            full = os.path.join(root, f)
                            targets.append(full)
                            rel = os.path.relpath(os.path.abspath(root), top)
                            if rel != ".":                    # files in sub-folders: the folder name becomes the group
                                groups[full] = rel.replace(os.sep, " / ")
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
                              filename=os.path.basename(path), fields=dict(fields, **({"group": groups[path]}
                                                                              if path in groups and "group" not in fields else {})),
                              options=options)
                if a.stunnel_ca and a.stunnel:
                    self.upload_ca(p["id"], a.stunnel_ca)
                print("%s %s  (%s)" % (green("imported"), p["name"], p["protocol"]))
                for w in p.get("warnings", []):
                    print("  %s %s" % (yellow("note:"), w))
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

    def cmd_autostart(self, a):
        """Boot-time VPN (daemon) and login-time tray app (per user)."""
        from . import autostart
        if a.login_app:
            if a.login_app == "on":
                print("Tray app will start at login: %s" % autostart.enable())
            else:
                autostart.disable()
                print("Tray app will no longer start at login.")
            if not a.target:
                return 0
        if a.target:
            t = a.target.lower()
            if t in ("off", "none", "no"):
                val = "off"
            elif t in ("last", "fastest"):
                val = t
            else:
                val = self.call("profiles.get", ident=a.target)["id"]
            self.call("settings.set", key="connection.autoconnect", value=val)
        cur = self.call("settings.get", key="connection.autoconnect")
        if cur in ("off", ""):
            print("VPN at system start: off")
        elif cur in ("last", "fastest"):
            print("VPN at system start: %s server" % cur)
        else:
            try:
                cur = self.call("profiles.get", ident=cur)["name"]
            except RpcError:
                pass
            print("VPN at system start: %s" % cur)
        print("Tray app at login:   %s" % ("on" if autostart.is_enabled() else "off"))
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

    # ------------------------------------------------------- app bypass / schedule
    def cmd_bypass(self, a):
        from . import apps as appmod
        act, rest = a.action or "list", a.items
        st = self.call("split.status")
        cur = st["apps"]
        if act == "list":
            print("App bypass: %s%s%s" % ("on" if st["enabled"] else "off", " (active)" if st["active"] else "",
                                    "  [only the listed apps use the VPN]" if st["mode"] == "include" else ""))
            if not st["supported"]:
                print(yellow("  not available here: %s" % st["reason"]))
            for ap in cur:
                print("  %-28s %s" % (ap["name"], dim(", ".join(ap["match"]))))
            if not cur:
                print("  no apps - add one with: vpnman bypass add firefox steam")
            return 0
        if act in ("on", "off"):
            self.call("split.set", enabled=(act == "on"))
            print("App bypass %s." % ("enabled" if act == "on" else "disabled"))
            return 0
        if act == "mode":
            if not rest or rest[0] not in ("exclude", "include"):
                print("Mode: %s  (exclude = listed apps skip the VPN, include = ONLY listed apps use it)" % st["mode"])
                return 0
            self.call("split.set", mode=rest[0])
            print("Mode set to %s." % rest[0])
            return 0
        if act == "available":
            flt = " ".join(rest).lower()
            for ap in appmod.discover():
                if flt in ap["name"].lower() or any(flt in m.lower() for m in ap["match"]):
                    print("  %-32s %s" % (ap["name"], dim(", ".join(ap["match"]))))
            return 0
        if not rest:
            raise RpcError("name one or more apps (see: vpnman bypass available)")
        if act == "add":
            installed = appmod.discover()
            for want in rest:
                low = want.lower()
                hit = [x for x in installed if low == x["name"].lower() or low in [m.lower() for m in x["match"]]] \
                    or [x for x in installed if low in x["name"].lower()][:1]
                entry = ({k: hit[0][k] for k in ("id", "name", "match", "icon")} if hit else appmod.custom_entry(want))
                if all(c["id"] != entry["id"] for c in cur):
                    cur.append(entry)
                print("  + %s (%s)" % (entry["name"], ", ".join(entry["match"])))
        elif act in ("remove", "rm"):
            for want in rest:
                low = want.lower()
                keep = [c for c in cur if low not in (c["name"].lower(), c["id"].lower()) and low not in
                        [m.lower() for m in c["match"]]]
                if len(keep) == len(cur):
                    print(yellow("  not in the list: %s" % want))
                cur = keep
        else:
            raise RpcError("unknown action %r (list, add, remove, available, on, off)" % act)
        self.call("split.set", apps=cur)
        print("Saved. Programs are moved out of the VPN within a couple of seconds of the tunnel coming up.")
        return 0

    def cmd_schedule(self, a):
        act = a.action or "list"
        st = self.call("schedule.status")
        entries = st["entries"]
        keys = ("id", "name", "enabled", "days", "start", "end", "profile")
        if act == "list":
            print("Schedule: %s" % ("on" if st["enabled"] else "off"))
            for e in entries:
                state = green("active now") if e["active"] else (dim("next in %s" % _eta(e["next_in"])) if e["next_in"] else "")
                print("  %-8s %-3s %-22s %-30s %s %s" % (e["id"], "on" if e["enabled"] else "off", e["name"] or "-",
                                                         e["summary"], e["profile"] or "last used", state))
            if not entries:
                print("  nothing scheduled - e.g.: vpnman schedule add --days weekdays --start 08:00 --end 18:00")
            return 0
        if act in ("on", "off"):
            self.call("schedule.set", enabled=(act == "on"))
            print("Schedule %s." % ("enabled" if act == "on" else "disabled"))
            return 0
        if act == "add":
            if not a.start:
                raise RpcError("--start HH:MM is required")
            entries.append({"name": a.name or "", "enabled": True, "days": _parse_days(a.days),
                            "start": a.start, "end": a.end or "", "profile": a.profile or ""})
        elif act in ("remove", "rm", "enable", "disable"):
            if not a.target:
                raise RpcError("give the schedule id or name (see: vpnman schedule)")
            hit = [e for e in entries if a.target in (e["id"], e["name"])]
            if not hit:
                raise RpcError("no schedule %r" % a.target)
            if act in ("remove", "rm"):
                entries = [e for e in entries if e not in hit]
            else:
                for e in hit:
                    e["enabled"] = act == "enable"
        else:
            raise RpcError("unknown action %r (list, add, remove, enable, disable, on, off)" % act)
        self.call("schedule.set", entries=[{k: e[k] for k in keys if k in e} for e in entries])
        print("Saved.")
        return 0

    def cmd_backup(self, a):
        import base64
        if a.action == "export":
            if os.path.exists(a.file) and not a.force:
                raise RpcError("%s exists - use --force to overwrite it" % a.file)
            res = self.call("backup.export")
            fd = os.open(a.file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(base64.b64decode(res["data"]))
            print("Backup written to %s (%s)." % (a.file, human_bytes(res["size"])))
            print(yellow("It contains your passwords and private keys - keep it somewhere safe."))
            return 0
        if not os.path.isfile(a.file):
            raise RpcError("no such file: %s" % a.file)
        with open(a.file, "rb") as fh:
            raw = fh.read()
        if a.replace and sys.stdin.isatty() and ask("This REPLACES every profile on this computer. Continue? (y/N)").lower() != "y":
            return 1
        res = self.call("backup.import", data=base64.b64encode(raw).decode(), replace=a.replace,
                        restore_settings=True if a.settings else None)
        print("Restored: %d profile(s) added, %d already present%s%s." % (
            res["added"], res["skipped"], ", %d removed first" % res["removed"] if a.replace else "",
            ", settings restored" if res["settings"] else ""))
        if res.get("proxies"):
            print("          %d prox%s restored." % (res["proxies"], "y" if res["proxies"] == 1 else "ies"))
        return 0

    def cmd_history(self, a):
        if a.clear:
            self.call("history.clear")
            print("History cleared.")
            return 0
        rows = self.call("history", limit=a.lines)
        if a.json:
            print(json.dumps(rows, indent=2))
            return 0
        if not rows:
            print("No connections recorded yet.")
            return 0
        for r in rows:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["start"]))
            d = r["duration"]
            print("%s  %-28s %8s  down %-10s up %-10s %s" % (when, r["profile"][:28], "%d:%02d:%02d" % (d // 3600, d % 3600 // 60, d % 60),
                                                           human_bytes(r["rx"]), human_bytes(r["tx"]), dim(r["reason"])))
        return 0

    # ------------------------------------------------------------------ proxy (Xray)
    @staticmethod
    def fetch_subscription(url, timeout=15):
        from .xray import fetch
        return fetch(url, timeout)

    def proxy_add(self, sources, name=None, group=None, refresh=False):
        """Import share links, files ('-' is standard input) and subscription URLs.  ``refresh`` keeps the group the
        subscription's proxies already have instead of naming a new one after the host."""
        import re
        total = {"added": 0, "updated": 0, "removed": 0, "skipped": 0, "errors": []}
        for src in sources:
            kw = {}
            if re.match(r"^https?://", src, re.I):
                try:
                    text = self.fetch_subscription(src)
                except (OSError, ValueError) as e:
                    raise RpcError("could not download %s: %s" % (src, e))
                kw = {"source": src,
                      "group": group or ("" if refresh else re.sub(r"^https?://([^/]+).*$", r"\1", src))}
            elif src == "-":
                text, kw = sys.stdin.read(), {"group": group or ""}
            elif os.path.isfile(src):
                with open(src, errors="replace") as fh:
                    text = fh.read()
                kw = {"group": group or ""}
            else:
                text, kw = src, {"group": group or ""}
            res = self.call("proxy.import", text=text, name=name if len(sources) == 1 else None, **kw)
            for k in ("added", "updated", "removed", "skipped"):
                total[k] += res[k]
            total["errors"] += res["errors"]
        return total

    def cmd_proxy(self, a):
        act, items = a.action or "list", a.items
        if act == "list":
            ps = self.call("proxy.list")
            if a.group:
                ps = [p for p in ps if (p.get("group") or "").lower() == a.group.lower()]
            lat = self.call("proxy.latency", ids=[p["id"] for p in ps]) if a.latency and ps else {}
            if a.json:
                print(json.dumps(ps, indent=2))
                return 0
            if not ps:
                print("No proxies in group %s." % a.group if a.group else
                      "No proxies yet. Add share links or a subscription: vpnman proxy add vless://... | https://...")
                return 0
            w = max(len(p["name"]) for p in ps)
            for p in ps:
                ms = lat.get(p["id"])
                extra = ("  %6.1f ms" % ms) if ms else ("  %9s" % "-" if a.latency else "")
                grp = ("  [%s]" % p["group"]) if p.get("group") else ""
                print("%s %-*s  %-12s %s%s%s" % (green("●") if p["selected"] else " ", w, p["name"], p["protocol"],
                                                  dim("%s:%s" % (p["server"], p["port"])), extra, dim(grp)))
            return 0
        if act == "status":
            st = self.call("proxy.status")
            if a.json:
                print(json.dumps(st, indent=2))
                return 0
            order = {"proxy_only": "you -> proxy -> internet", "vpn_proxy": "you -> VPN -> proxy -> internet",
                     "proxy_vpn": "you -> proxy -> VPN -> internet"}.get(st["order"], st["order"])
            print("%s %s" % (bold("Proxy:"), (green("RUNNING") if st["running"] else
                                              (yellow("on, waiting for the VPN") if st["enabled"] and st["order"] == "vpn_proxy"
                                               else ("on" if st["enabled"] else dim("off"))))))
            print("  server:  %s" % (st["name"] or dim("none chosen (vpnman proxy use NAME)")))
            print("  order:   %s   (%s)" % (st["order"], order))
            print("  mode:    %s" % st["mode"])
            if st["socks"]:
                print("  SOCKS5:  127.0.0.1:%d    HTTP: 127.0.0.1:%d" % (st["socks"], st["http"]))
            if st["carrier"]:
                print("  carrying the VPN connection")
            print(dim("  settings: socks_port=%s http_port=%s dns=%s udp=%s" % (
                st["socks_port"], st["http_port"], st["dns"], st["udp"])))
            print("  failover: %s" % ("on" if st.get("failover") else dim("off")))
            lf = st.get("last_failover")
            if lf:
                print(yellow("  switched from %s to %s at %s (%s)" % (lf["from"], lf["to"], time.strftime(
                    "%H:%M", time.localtime(lf["at"])), lf["reason"])))
            if st["error"]:
                print(red("  error:   %s" % st["error"]))
            if not st["installed"]:
                print(yellow("  xray is not installed - install it to use proxies"))
            return 0
        if act == "add":
            if not items:
                raise RpcError("give share links (vless://, vmess://, trojan://, ss://), a file, or a subscription URL")
            res = self.proxy_add(items, a.name, a.group)
            print("%s %d new, %d updated, %d removed, %d already present" % (
                green("proxies:"), res["added"], res["updated"], res["removed"], res["skipped"]))
            for e in res["errors"]:
                print("  %s %s" % (yellow("skipped"), e), file=sys.stderr)
            return 0 if (res["added"] or res["updated"] or res["skipped"]) else 1
        if act == "refresh":
            srcs = items or [s["source"] for s in self.call("proxy.sources")]
            if not srcs:
                print("No subscriptions to refresh (add one: vpnman proxy add https://...)")
                return 0
            res = self.proxy_add(srcs, group=a.group, refresh=True)
            for e in res["errors"]:
                print("  %s %s" % (yellow("skipped"), e), file=sys.stderr)
            print("%s %d new, %d updated, %d removed" % (green("refreshed:"), res["added"], res["updated"], res["removed"]))
            return 0
        if act in ("remove", "rm"):
            ps = self.call("proxy.list")
            if a.all:
                ids = [p["id"] for p in ps]
            elif a.group and not items:
                ids = [p["id"] for p in ps if (p.get("group") or "").lower() == a.group.lower()]
                if not ids:
                    raise RpcError("no proxies in group %s" % a.group)
            elif items:
                ids = [self._proxy_ident(i) for i in items]
            else:
                raise RpcError("name the proxies to remove (or use --group GROUP / --all)")
            if not ids:
                print("No proxies to remove.")
                return 0
            res = self.call("proxy.remove", ids=ids)
            for n in res["removed"]:
                print("Removed %s" % n)
            for f in res["failed"]:
                print(red("failed: %s" % f["error"]), file=sys.stderr)
            return 1 if res["failed"] else 0
        if act == "use":
            if a.fastest and not items:
                p = self.call("proxy.fastest", group=a.group)
                print("Using %s (%.1f ms)." % (p["name"], p["latency"]), end="")
            elif len(items) == 1 and not a.fastest:
                p = self.call("proxy.select", ident=self._proxy_ident(items[0]))
                print("Using %s." % p["name"], end="")
            else:
                raise RpcError("usage: vpnman proxy use NAME | vpnman proxy use --fastest [--group GROUP]")
            print("" if self.call("proxy.status")["enabled"] else " Switch the proxy on with: vpnman proxy on")
            return 0
        if act == "link":
            if len(items) != 1:
                raise RpcError("usage: vpnman proxy link NAME [--qr]")
            res = self.call("proxy.link", ident=self._proxy_ident(items[0]))
            if not res["link"]:
                raise RpcError("%s has no share link (it was imported from an Xray config)" % res["name"])
            if a.qr:
                from . import qr
                try:
                    print(qr.to_text(qr.encode(res["link"])))
                except qr.TooLong as e:
                    raise RpcError(str(e))
            print(res["link"])
            return 0
        if act == "failover":
            if len(items) > 1 or (items and items[0] not in ("on", "off")):
                raise RpcError("usage: vpnman proxy failover [on|off]")
            if items:
                self.call("proxy.set", failover=items[0] == "on")
            on = self.call("proxy.status")["failover"]
            print("Failover is %s." % ("on: when the server stops answering, VPNMan switches to the next favourite "
                                       "proxy (else the next of its group)" if on else "off"))
            return 0
        if act in ("on", "off"):
            st = self.call("proxy.set", enabled=(act == "on"))
            print("Proxy %s%s." % (act, "" if act == "off" or st["running"] or st["order"] == "proxy_vpn" else
                                   " (%s)" % ("it starts when the VPN is connected" if st["order"] == "vpn_proxy"
                                              else st["error"] or "starting")))
            return 0
        if act in ("order", "mode"):
            if len(items) != 1:
                raise RpcError("usage: vpnman proxy %s VALUE" % act)
            self.call("proxy.set", **{act: items[0]})
            print("%s set to %s." % (act.capitalize(), items[0]))
            return 0
        if act == "show":
            if len(items) != 1:
                raise RpcError("usage: vpnman proxy show NAME")
            pid = self._proxy_ident(items[0])
            p = next(p for p in self.call("proxy.list") if p["id"] == pid)
            info = self.call("proxy.info", ident=pid)
            if a.json:
                print(json.dumps(dict(p, info=info), indent=2))
                return 0
            for k, label in (("name", "Name"), ("protocol", "Protocol"), ("server", "Server"), ("port", "Port"),
                             ("group", "Group"), ("source", "Subscription"), ("notes", "Notes")):
                if p.get(k) not in (None, ""):
                    print("%s %s" % (bold("%-13s" % (label + ":")), p[k]))
            print("%s %s" % (bold("Favorite:    "), "yes" if p.get("favorite") else "no"))
            print("%s %s" % (bold("In use:      "), green("yes") if p.get("selected") else "no"))
            print("%s %s" % (bold("Connects to: "), ", ".join(info["ips"]) or yellow("could not resolve %s" % info["address"])))
            print("%s %s%s%s" % (bold("Transport:   "), info["network"], " + %s" % info["security"]
                                 if info["security"] != "none" else " (no encryption layer)",
                                 "".join("  %s=%s" % (k, info[k]) for k in ("sni", "host", "path") if info[k])))
            if info["cloudflare"]:
                print(yellow("Cloudflare:   these are Cloudflare addresses - the server is behind Cloudflare's CDN or runs "
                             "on Cloudflare,\n              so Cloudflare (not the server itself) is what this computer "
                             "talks to."))
            return 0
        if act == "sources":
            srcs = self.call("proxy.sources")
            if a.json:
                print(json.dumps(srcs, indent=2))
            elif not srcs:
                print("No subscriptions (add one: vpnman proxy add https://...)")
            for s in ([] if a.json else srcs):
                print("%4d  %s" % (s["count"], s["source"]))
            return 0
        if act == "set" and not items:
            st = self.call("proxy.status")
            for k in ("order", "mode", "socks_port", "http_port", "dns", "udp"):
                print("%-11s %s" % (k, st[k]))
            return 0
        if act == "set":
            if len(items) != 2:
                raise RpcError("usage: vpnman proxy set KEY VALUE  (socks_port, http_port, dns, udp, order, mode)")
            self.call("proxy.set", **{items[0]: items[1]})
            print("%s = %s" % tuple(items))
            return 0
        if act == "edit":
            if len(items) < 2:
                raise RpcError("usage: vpnman proxy edit NAME KEY=VALUE...  (name, group, notes, favorite)")
            ch = {}
            for kv in items[1:]:
                k, _, v = kv.partition("=")
                ch[k] = v.lower() in ("1", "true", "yes", "on") if k == "favorite" else v
            self.call("proxy.update", ident=self._proxy_ident(items[0]), changes=ch)
            print("Updated.")
            return 0
        if act == "ping":
            ps = self.call("proxy.list")
            ids = [self._proxy_ident(i) for i in items] or None
            lat = self.call("proxy.latency", ids=ids)
            if a.json:
                print(json.dumps({p["name"]: lat[p["id"]] for p in ps if p["id"] in lat}, indent=2))
                return 0
            for p in ps:
                if p["id"] in lat:
                    print("%-30s %s" % (p["name"], ("%.1f ms" % lat[p["id"]]) if lat[p["id"]] else red("unreachable")))
            return 0
        raise RpcError("unknown action %r (list, show, link, add, remove, use, on, off, order, mode, set, edit, status, "
                       "ping, refresh, sources, failover)" % act)

    def _proxy_ident(self, text):
        ps = self.call("proxy.list")
        for p in ps:
            if text in (p["id"], p["name"]):
                return p["id"]
        hits = [p for p in ps if text.lower() in p["name"].lower()]
        if len(hits) == 1:
            return hits[0]["id"]
        raise RpcError("no such proxy: %s" % text if not hits else "'%s' is ambiguous: %s" % (text, ", ".join(h["name"] for h in hits[:6])))

    def cmd_netproxy(self, a):
        """vpnman netproxy [status|on|off|set KIND HOST:PORT|clear KIND|ignore HOST...|apps NAME...|dns IP|udp MODE]"""
        act, items = a.action or "status", a.items
        kinds = ("http", "https", "ftp", "socks")
        if act == "status":
            st = self.call("netproxy.status")
            if a.json:
                print(json.dumps(st, indent=2))
                return 0
            state = green("ACTIVE") if st["active"] else (yellow("on, not running") if st["enabled"] else dim("off"))
            print("%s %s" % (bold("Network proxy:"), state))
            for k in kinds:
                e = st[k]
                if e.get("host"):
                    print("  %-6s %s%s:%s%s" % (k.upper(), e["user"] + "@" if e.get("user") else "", e["host"], e["port"],
                                                dim("  (with password)") if e.get("has_password") else ""))
            if not any(st[k].get("host") for k in kinds):
                print(dim("  no proxy server set - e.g.: vpnman netproxy set http proxy.example.com:3128"))
            print("  ignored: %s" % (", ".join(st["ignore"]) or "-"))
            print("  programs that skip it: %s" % (", ".join(st["apps"]) or "-"))
            print(dim("  dns %s (over TCP through the proxy), other UDP: %s, kill switch: %s" % (
                st["dns"], st["udp"], "on" if st["killswitch"] else "off")))
            if st.get("blocked"):
                print(red("  BLOCKING all traffic until the proxy works again"))
            if st["error"]:
                print(red("  %s" % st["error"]))
            if not st["supported"]:
                print(yellow("  needs Linux with nftables"))
            if not st["installed"]:
                print(yellow("  xray is not installed - install it with: sudo ./install.sh --xray-only"))
            return 0
        if act in ("on", "off"):
            st = self.call("netproxy.set", enabled=act == "on")
            print("Network proxy %s.%s" % (act, " (%s)" % st["error"] if act == "on" and st["error"] else ""))
            return 0
        if act == "set":
            if len(items) != 2 or items[0] not in kinds:
                raise RpcError("usage: vpnman netproxy set http|https|ftp|socks HOST:PORT [--user NAME] [--ask-password]")
            from .gui.sysproxy import clean_host, port_in
            host, port = clean_host(items[1]), port_in(items[1])
            if not host or not port:
                raise RpcError("give HOST:PORT, for example proxy.example.com:3128")
            e = {"host": host, "port": port, "user": a.user or ""}
            if a.ask_password:
                e["password"] = getpass.getpass("Password for %s@%s: " % (a.user or "", host))
            elif not a.user:
                e["password"] = ""
            self.call("netproxy.set", **{items[0]: e})
            print("%s proxy: %s:%d" % (items[0].upper(), host, port))
            return 0
        if act == "clear":
            if not items or any(k not in kinds for k in items):
                raise RpcError("usage: vpnman netproxy clear http|https|ftp|socks...")
            self.call("netproxy.set", **{k: {"host": "", "port": 0, "user": "", "password": ""} for k in items})
            print("Cleared.")
            return 0
        if act in ("ignore", "apps"):
            from .gui.sysproxy import split_hosts
            vals = split_hosts(" ".join(items))
            st = self.call("netproxy.set", **{act: vals})
            print("%s: %s" % ("Ignored hosts" if act == "ignore" else "Programs that skip the proxy",
                              ", ".join(st[act]) or "none"))
            return 0
        if act == "killswitch":
            if len(items) > 1 or (items and items[0] not in ("on", "off")):
                raise RpcError("usage: vpnman netproxy killswitch [on|off]")
            if items:
                self.call("netproxy.set", killswitch=items[0] == "on")
            on = self.call("netproxy.status")["killswitch"]
            print("Kill switch is %s%s." % ("on" if on else "off", ": while the proxy cannot work, all traffic is blocked" if on
                                           else ": if the proxy fails, traffic goes out directly"))
            return 0
        if act in ("dns", "udp"):
            if len(items) != 1:
                raise RpcError("usage: vpnman netproxy %s VALUE" % act)
            self.call("netproxy.set", **{act: items[0]})
            print("%s = %s" % (act, items[0]))
            return 0
        raise RpcError("unknown action %r (status, on, off, set, clear, ignore, apps, dns, udp)" % act)

    def cmd_blocks(self, a):
        from . import blocks
        act, items = a.action or "list", a.items
        if act in ("list", "status"):
            st = self.call("blocks.status")
            if a.json:
                print(json.dumps(st, indent=2))
                return 0
            state = green("ENFORCED") if st["active"] else (yellow("not enforced") if st["enabled"] and st["entries"] else dim("off"))
            print("%s %s%s" % (bold("Blocked connections:"), state, "" if st["enabled"] else dim("  (switched off: vpnman blocks on)")))
            if st["error"]:
                print(red("  %s" % st["error"]))
            if not st["supported"]:
                print(yellow("  %s" % st["reason"]))
            for e in st["entries"]:
                what = {"address": "address", "endpoint": "address:port", "port": "port", "app": "program"}[e["kind"]]
                proto = "" if e.get("proto", "any") == "any" else e["proto"]
                how = blocks.lifetime(e)
                print("  %-8s %s %-13s %-28s %-4s %s" % (e["id"], "on " if e.get("enabled", True) else "off", what, e["value"],
                                                        proto, dim("  ".join(x for x in (
                                                            e.get("note", ""), "" if how == "permanent" else "(%s)" % how) if x))))
            if not st["entries"]:
                print("  nothing blocked - e.g.: vpnman blocks add address 203.0.113.9")
            return 0
        if act in ("on", "off"):
            self.call("blocks.set", enabled=(act == "on"))
            print("Blocking %s." % ("enabled" if act == "on" else "disabled"))
            return 0
        if act == "add":
            if len(items) != 2:
                raise RpcError("usage: vpnman blocks add address|endpoint|port|app VALUE [--proto tcp|udp] [--note TEXT] "
                               "[--for DURATION] [--until-reboot]")
            e = self.call("blocks.add", kind=items[0], value=items[1], proto=a.proto or "any", note=a.note or "",
                          minutes=parse_minutes(a.for_) if a.for_ else 0, until_reboot=a.until_reboot)
            how = blocks.lifetime(e)
            print("%s %s %s%s%s" % (green("blocked"), items[0], e["value"], "" if how == "permanent" else " " + how,
                                  "  (closed %d open connection%s)" % (e["closed"], "" if e["closed"] == 1 else "s") if e.get("closed") else ""))
            return 0
        if act in ("remove", "rm", "enable", "disable"):
            if not items:
                raise RpcError("give the ids shown by 'vpnman blocks'")
            if act in ("remove", "rm"):
                self.call("blocks.remove", ids=items)
                print("Removed.")
            else:
                for i in items:
                    self.call("blocks.update", ident=i, enabled=(act == "enable"))
                print("Done.")
            return 0
        raise RpcError("unknown action %r (list, add, remove, enable, disable, on, off)" % act)

    def cmd_connections(self, a):
        def show():
            res = self.call("connections", listening=a.listening, local=a.local, resolve=a.resolve)
            if a.csv:
                from .conntable import to_csv
                sys.stdout.write(to_csv(res["rows"]))
                return
            if a.json:
                print(json.dumps(res, indent=2))
                return
            if res.get("note"):
                print(yellow(res["note"]))
            print(bold("%-6s %-22s %-5s %-24s %-24s %s" % ("WAY", "APP", "PROTO", "LOCAL", "REMOTE", "STATE")))
            for r in res["rows"]:
                way = {"in": "in", "out": "out", "listen": "listen"}[r["dir"]]
                app = ("%s (%d)" % (r["app"], r["pid"])) if r["pid"] else (r["app"] or "-")
                loc = "%s:%d" % (r["local"], r["lport"])
                rem = "%s:%d" % (r.get("rname") or r["remote"], r["rport"]) if r["rport"] else "-"
                print("%-6s %-22s %-5s %-24s %-24s %s" % (way, app[:22], r["proto"].upper() + ("6" if r["v6"] else ""),
                                                          loc[:24], rem[:24], r["state"]))
            if res.get("truncated"):
                print(dim("(list truncated)"))
        if not a.watch or a.csv:
            show()
            return 0
        while True:
            print("\033[2J\033[H", end="")
            show()
            time.sleep(2)

    def cmd_group(self, a):
        """vpnman group [list] | vpnman group edit GROUP KEY=VALUE...: look at groups, rename one or edit all its servers."""
        profiles = self.call("profiles.list")
        groups = {}
        for p in profiles:
            if p.get("group"):
                groups.setdefault(p["group"], []).append(p)
        act = a.action or "list"
        if act == "list":
            for g in sorted(groups, key=str.lower):
                print("%-28s %d server%s" % (g, len(groups[g]), "" if len(groups[g]) == 1 else "s"))
            if not groups:
                print("No groups yet. Importing a folder makes one per sub-folder, or: vpnman edit PROFILE group=NAME")
            return 0
        if act == "order":
            names = ([a.group] if a.group else []) + list(a.changes)
            cur = self.call("settings.get", key="ui")["group_order"]
            if not names and not a.reset:
                shown = [g for g in cur if g in groups] + sorted((g for g in groups if g not in cur), key=str.lower)
                print("Group order: %s" % (", ".join(shown) or "-"))
                return 0
            order = []
            for n in names:
                hit = [g for g in groups if g.lower() == n.lower()] or [g for g in groups if n.lower() in g.lower()]
                if len(hit) != 1:
                    raise RpcError("no such group: %s" % n if not hit else "'%s' is ambiguous: %s" % (n, ", ".join(hit)))
                if hit[0] not in order:
                    order.append(hit[0])
            self.call("settings.update", tree={"ui": {"group_order": [] if a.reset else order}})
            print("Group order: %s" % (", ".join(order) if order else "alphabetical"))
            return 0
        if act != "edit":
            raise RpcError("unknown action %r (list, edit, order)" % act)
        if not a.group or not a.changes and not a.ask_password:
            raise RpcError("usage: vpnman group edit GROUP KEY=VALUE...  (keys: name, username, password, stunnel, "
                           "stunnel_sni, stunnel_verify)")
        match = [g for g in groups if g.lower() == a.group.lower()] or [g for g in groups if a.group.lower() in g.lower()]
        if len(match) != 1:
            raise RpcError("no such group: %s" % a.group if not match else "'%s' is ambiguous: %s" % (a.group, ", ".join(match)))
        name = match[0]
        ch, st = {}, {}
        for kv in a.changes:
            k, _, v = kv.partition("=")
            if k == "name":
                ch["group"] = v
            elif k in ("username", "password"):
                ch[k] = v
            elif k == "stunnel":
                if v.lower() in ("", "off", "none", "false"):
                    st["mode"] = "off"
                else:
                    o = self.stunnel_opts(v)
                    st.update(mode="set", host=o["host"], port=o["port"])
            elif k == "stunnel_sni":
                st["sni"] = v
            elif k == "stunnel_verify":
                st["verify"] = v
            else:
                raise RpcError("cannot set %r on a group (name, username, password, stunnel, stunnel_sni, stunnel_verify)" % k)
        if a.ask_password:
            ch["password"] = getpass.getpass("New password for all servers in %s: " % name)
        if st:
            if "mode" not in st:
                raise RpcError("stunnel_sni / stunnel_verify need stunnel=HOST[:PORT] as well")
            ch["stunnel"] = st
        res = self.call("profiles.update_many", ids=[p["id"] for p in groups[name]], changes=ch)
        print("%s %d server%s in %s." % (green("edited"), len(res["updated"]), "" if len(res["updated"]) == 1 else "s", name))
        for s in res["skipped"]:
            print("  %s %s: %s" % (yellow("skipped"), s["name"], s["reason"]))
        for f in res["failed"]:
            print("  %s %s" % (red("failed"), f["error"]), file=sys.stderr)
        return 1 if res["failed"] else 0

    def cmd_failover(self, a):
        """vpnman failover PROFILE [SERVER ...] [--clear]: which servers to try, in order, when PROFILE keeps failing."""
        p = self.call("profiles.get", ident=a.profile)
        profiles = {x["id"]: x for x in self.call("profiles.list")}
        if a.clear:
            self.call("profiles.update", ident=p["id"], changes={"failover": []})
            print("Failover list of %s cleared." % p["name"])
            return 0
        if a.servers:
            ids = []
            for name in a.servers:
                t = self.call("profiles.get", ident=name)
                if t["id"] == p["id"]:
                    raise RpcError("a server cannot fail over to itself")
                if t["id"] not in ids:
                    ids.append(t["id"])
            self.call("profiles.update", ident=p["id"], changes={"failover": ids})
            p["failover"] = ids
        chain = [profiles[i]["name"] for i in p.get("failover") or [] if i in profiles]
        print("%s -> %s" % (p["name"], " -> ".join(chain) if chain else dim("(its group, then your favourites)")))
        return 0

    def cmd_update(self, a):
        from . import updates
        try:
            res = updates.check()
        except (OSError, ValueError) as e:
            print(red("error: ") + "could not reach GitHub: %s" % e, file=sys.stderr)
            return 1
        if a.json:
            print(json.dumps(res, indent=2))
        elif res["newer"]:
            print("%s VPNMan %s is available (you have %s): %s" % (green("update:"), res["latest"], res["current"], res["url"]))
        else:
            print("VPNMan %s is the latest version." % res["current"])
        return 0 if not res["newer"] else 10

    def cmd_diagnostics(self, a):
        text = self.call("diagnostics")
        if not a.output or a.output == "-":
            sys.stdout.write(text)
            return 0
        if os.path.exists(a.output) and not a.force:
            raise RpcError("%s exists (use --force to overwrite it)" % a.output)
        with open(a.output, "w") as fh:
            fh.write(text)
        print("Saved %s. Read it before you share it - passwords, user names, server and network names and public "
              "addresses are removed, but check." % a.output)
        return 0

    def cmd_networks(self, a):
        act = a.action or "show"
        if act in ("trust", "untrust"):
            st = self.call("network.trust", name=a.name, trusted=(act == "trust"))
            print("%s %s" % ("Trusted:" if act == "trust" else "No longer trusted:", a.name or st["id"]))
            return 0
        if act == "rule":
            st = self.call("network.rule", network=a.name, server="" if a.clear else (a.server or ""),
                           netproxy="" if a.clear else (a.netproxy or ""), xray_proxy="" if a.clear else (a.xray or ""))
            r = next((x for x in st.get("rules") or [] if x["network"].lower() == (a.name or st["id"] or "").lower()), None)
            print("Rule of %s: %s" % (a.name or st["id"], "removed" if not r else ", ".join(
                x for x in ("connect to the chosen server" if r.get("server") else "", "network proxy " + r["netproxy"]
                            if r.get("netproxy") else "", "Xray proxy " + (r["xray"] if r["xray"] == "off" else "chosen")
                            if r.get("xray") else "") if x)))
            return 0
        if act != "show":
            raise RpcError("unknown action %r (show, trust, untrust, rule)" % act)
        st = self.call("network.status")
        cfg = self.call("settings.get", key="network")
        if st["id"]:
            print("Current network: %s  (%s via %s)  %s" % (st["id"], st["kind"], st["device"],
                  green("trusted") if st["trusted"] else yellow("not trusted")))
        else:
            print("Current network: none detected")
        print("Trusted:   %s" % (", ".join(cfg["trusted"]) or "-"))
        if st.get("rules"):
            profs = {p["id"]: p["name"] for p in self.call("profiles.list")}
            print("Rules:")
            for r in st["rules"]:
                bits = ([("connect to " + profs.get(r["server"], r["server"]))] if r.get("server") else []) + \
                       (["network proxy " + r["netproxy"]] if r.get("netproxy") else []) + \
                       (["Xray proxy " + ("off" if r["xray"] == "off" else "chosen")] if r.get("xray") else [])
                print("  %-24s %s" % (r["network"], ", ".join(bits)))
        print("On an untrusted network: %s    On a trusted network: %s    Server: %s"
              % (cfg["untrusted_action"], cfg["trusted_action"], cfg["profile"]))
        print(dim("Change with: vpnman set network.untrusted_action connect | vpnman set network.trusted_action disconnect"))
        return 0

    def cmd_routes(self, a):
        cur = [r.get("ip") or r.get("host") for r in self.call("settings.get", key="routes") if r.get("action") == "out"]
        act = a.action or "list"
        if act == "list":
            print("Addresses that skip the VPN (and are never blocked by the kill switch):")
            for x in cur:
                print("  " + x)
            if not cur:
                print("  none - e.g.: vpnman routes add 10.0.0.0/8 intranet.example.com")
            return 0
        if act == "add":
            new = cur + [x for x in a.items if x not in cur]
        elif act in ("remove", "rm"):
            new = [x for x in cur if x not in a.items]
        else:
            raise RpcError("unknown action %r (list, add, remove)" % act)
        res = self.call("routes.set", entries=new)
        print("Saved: %s" % (", ".join(r.get("ip") or r.get("host") for r in res) or "nothing"))
        return 0

    def cmd_leaktest(self, a):
        res = self.call("leaktest")
        if a.json:
            print(json.dumps(res, indent=2))
        else:
            mark = {"ok": green("✔"), "warn": yellow("!"), "fail": red("✘"), "info": dim("·")}
            for c in res["checks"]:
                print("%s %-16s %s" % (mark.get(c["status"], "?"), c["name"], c["detail"]))
            print("\n" + {"ok": green("All checks passed."), "warn": yellow("Passed with warnings."),
                          "fail": red("Problems found - see the lines marked ✘.")}[res["summary"]])
        return 1 if res["summary"] == "fail" else 0

    def cmd_cleanup(self, a):
        from . import blocks, netlock, split, xray
        if self.client.alive() and not a.force:
            raise RpcError("the VPNMan service is running and owns these rules - stop it first "
                           "(vpnman disconnect; vpnman lock off), or use --force")
        if os.geteuid() != 0:
            raise RpcError("run as root: sudo vpnman cleanup")
        gone = netlock.cleanup_all()
        if plat.os_family() == "linux":
            split.cleanup()
            if xray.cleanup():
                gone = list(gone) + ["proxy redirect"]
            if blocks.cleanup():
                gone = list(gone) + ["blocked connections"]
        print("Removed: %s" % (", ".join(gone) if gone else "no kill-switch rules"),
              "+ app-bypass rules, routing rule/table and cgroup" if plat.os_family() == "linux" else "")
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
        if getattr(a, "json", False):                 # `doctor` shows the same list and has no --json
            print(json.dumps({"protocols": info, "helpers": backends.helpers()}, indent=2))
            return 0
        for p in info + [None] + backends.helpers():
            if p is None:
                print(bold("Helpers:"))
                continue
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
        from . import desktop, icons
        print("Program:")
        for ok, msg in desktop.bytecode_check():
            print("  %s %s" % (green("✔") if ok else red("✘"), msg))
        print("Launcher & icons:")
        for ok, msg in desktop.check() + icons.check():
            print("  %s %s" % (green("✔") if ok else red("✘"), msg))
        print("Tray:")
        for ok, msg in desktop.tray_check():
            print("  %s %s" % (green("✔") if ok else yellow("!"), msg))
        if getattr(a, "fix", False):
            if not plat.is_root():
                print(red("  --fix needs root: sudo vpnman doctor --fix"))
            else:
                for m in desktop.purge_bytecode() + desktop.link_system_dirs() + icons.fix():
                    print("  " + green("fixed: ") + m)
                print("  Log out and back in (or restart the desktop shell) so it re-reads launchers and icons.")
        from . import xray
        print("Proxy engine:")
        print("  %s xray %s" % (green("✔") if xray.binary() else yellow("!"),
                               xray.binary() or "is not installed (needed for 'vpnman proxy'; install it with: sudo ./install.sh --xray-only, or see https://github.com/XTLS/Xray-core)"))
        print()
        return self.cmd_protocols(a)

    def cmd_service(self, a):
        from . import service
        if not plat.is_root():
            print("Run as root: sudo vpnman service %s" % a.action, file=sys.stderr)
            return 1
        init = a.init or plat.init_system()
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

    def cmd_about(self, a):
        from . import credits
        print(credits.about_text())
        return 0

    def cmd_gui(self, a):
        from .gui.app import run
        return run(["vpnman-gtk"] + (["--background"] if a.background else []))


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


def human_bytes(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024


def _parse_days(text):
    from . import schedule as sch
    t = (text or "all").lower().replace(" ", "")
    named = {"all": range(7), "daily": range(7), "everyday": range(7), "weekdays": range(5), "weekends": (5, 6)}
    if t in named:
        return list(named[t])
    out = []
    for part in t.split(","):
        if "-" in part:
            lo, hi = (sch.DAYS.index(x[:3].capitalize()) for x in part.split("-", 1))
            out += list(range(lo, hi + 1)) if lo <= hi else list(range(lo, 7)) + list(range(0, hi + 1))
        else:
            out.append(sch.DAYS.index(part[:3].capitalize()))
    return sorted(set(out))


def _eta(minutes):
    h, m = divmod(int(minutes), 60)
    d, h = divmod(h, 24)
    return " ".join(x for x in ("%dd" % d if d else "", "%dh" % h if h else "", "%dm" % m if m or not (d or h) else "") if x)


def interactive(cli):
    menu = [("c", "Connect"), ("f", "Connect to fastest"), ("d", "Disconnect"), ("s", "Servers / profiles"),
            ("l", "Network lock (kill switch)"), ("i", "Import profile(s)"), ("p", "Preferences"),
            ("a", "App bypass"), ("t", "Schedule"), ("g", "View log"), ("x", "System check"), ("q", "Quit")]
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
            elif ch in ("a", "t"):
                _sub_menu(cli, ch)
            elif ch == "g":
                cli.cmd_logs(argparse.Namespace(lines=40, follow=False))
            elif ch == "x":
                cli.cmd_doctor(None)
        except (DaemonUnavailable, RpcError) as e:
            print(red(str(e)))
        except KeyboardInterrupt:
            print()
            return 0


def _sub_menu(cli, ch):
    """Tiny prompt wrapper around `vpnman bypass` / `vpnman schedule`."""
    if ch == "a":
        cli.cmd_bypass(argparse.Namespace(action="list", items=[]))
        act = ask("[a]dd  [r]emove  [v] browse installed apps  [o]n/off  (enter = back)").lower()[:1]
        if act == "a":
            cli.cmd_bypass(argparse.Namespace(action="add", items=ask("App name(s), space separated").split()))
        elif act == "r":
            cli.cmd_bypass(argparse.Namespace(action="remove", items=ask("App name(s) to remove").split()))
        elif act == "v":
            cli.cmd_bypass(argparse.Namespace(action="available", items=ask("Filter (optional)").split()))
        elif act == "o":
            on = ask("Turn app bypass on? (Y/n)").lower() != "n"
            cli.cmd_bypass(argparse.Namespace(action="on" if on else "off", items=[]))
    else:
        cli.cmd_schedule(argparse.Namespace(action="list"))
        act = ask("[a]dd  [r]emove  [e]nable/disable one  [o]n/off all  (enter = back)").lower()[:1]
        if act == "a":
            ns = argparse.Namespace(action="add", target=None, name=ask("Name (optional)"),
                                    days=ask("Days (all, weekdays, weekends, mon-fri, mon,wed)", "all"),
                                    start=ask("Connect at (HH:MM)"), end=ask("Disconnect at (HH:MM, empty = stay connected)"),
                                    profile=ask("Profile (empty = last used, or 'fastest')"))
            cli.cmd_schedule(ns)
        elif act == "r":
            cli.cmd_schedule(argparse.Namespace(action="remove", target=ask("Schedule id or name")))
        elif act == "e":
            tgt = ask("Schedule id or name")
            on = ask("Enable? (Y/n)").lower() != "n"
            cli.cmd_schedule(argparse.Namespace(action="enable" if on else "disable", target=tgt))
        elif act == "o":
            on = ask("Turn the schedule on? (Y/n)").lower() != "n"
            cli.cmd_schedule(argparse.Namespace(action="on" if on else "off", target=None))


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

MAIN_EPILOG = """\
getting started:
  vpnman import my.ovpn         add a profile (OpenVPN, WireGuard, ... see: vpnman protocols)
  vpnman connect                connect to the last used profile (or: vpnman connect NAME, --fastest)
  vpnman lock on                engage the kill switch: nothing leaves except through the VPN
  vpnman leaktest               check the tunnel, public IP, kill switch, DNS and IPv6
  vpnman                        with no command in a terminal: an interactive menu
  vpnman gui                    the graphical app (also: vpnman-gtk, or VPNMan in the application menu)

profile names:
  anywhere a PROFILE is expected you can give its id, its exact name, or any unique part of the name.

exit status:
  0 success    1 error or failed check    2 the background service (vpnmand) is not running
  3 `status` only: not connected          10 `update` only: a newer release exists
  130 interrupted

files:
  /etc/vpnman/                profiles, settings.json, state.json, history.json  (root only)
  /run/vpnman/vpnman.sock     the daemon's socket          /var/log/vpnman.log  daemon log file
  ~/.config/vpnman/gui.json   per-user GUI preferences

more: man vpnman     (every command, setting, file, how to uninstall)     https://github.com/Smiley-McSmiles/VPNMan
"""


def build_parser():
    ap = argparse.ArgumentParser(
        prog="vpnman", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=MAIN_EPILOG,
        description="VPNMan - multi-protocol VPN manager with a kill switch.\n\n"
                    "Commands talk to the background service (vpnmand), which owns the tunnels and the firewall.\n"
                    "Run 'vpnman COMMAND --help' for the details and examples of one command.")
    ap.add_argument("--version", action="version", version="vpnman " + __version__)
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")

    def add(name, help, desc=None, examples=None, **kw):
        ep = ("examples:\n" + "\n".join("  " + x for x in examples)) if examples else None
        return sub.add_parser(name, help=help, description=desc or (help[:1].upper() + help[1:] + "."), epilog=ep,
                              formatter_class=argparse.RawDescriptionHelpFormatter, **kw)

    JSON = "print machine-readable JSON instead of text"
    protocols = list(backends.REGISTRY)

    s = add("status", "show connection status",
            "Show the state of the connection: server, interface, public IP, uptime, traffic and the kill switch.\n"
            "Exit status is 0 when connected and 3 when not, so scripts can test it.",
            ["vpnman status", "vpnman status --json", "vpnman status >/dev/null && echo up"])
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("list", "list profiles",
            "List the saved profiles. A star marks favourites; a crossed circle marks blocked profiles (never chosen by\n"
            "--fastest or failover). The group, if any, is shown in brackets.",
            ["vpnman list", "vpnman list --latency --sort latency", "vpnman list --sort group"], aliases=["ls"])
    s.add_argument("--latency", "-l", action="store_true", help="measure and show the latency of every server")
    s.add_argument("--names", action="store_true", help="one profile name per line (used by shell completion)")
    s.add_argument("--sort", choices=["name", "latency", "group"], help="sort order (latency implies --latency)")
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("connect", "connect to a profile",
            "Connect and wait until the tunnel is up. With no profile it reconnects the last used one.\n"
            "A connection that is already up is switched to the new profile. If the server rejects the login\n"
            "you are asked for the username and password right away (in a terminal) and it retries.",
            ["vpnman connect Work", "vpnman connect --fastest", "vpnman connect --no-wait Home"], aliases=["up"])
    s.add_argument("profile", nargs="?", help="profile id or name (default: the last used one)")
    s.add_argument("--fastest", action="store_true", help="measure all servers and use the one with the lowest latency")
    s.add_argument("--last", action="store_true", help="use the last connected profile (the default without a profile)")
    s.add_argument("--no-wait", action="store_true", help="return immediately instead of waiting for the tunnel")
    s.add_argument("--timeout", type=int, default=90, metavar="SECONDS", help="how long to wait (default 90)")
    add("disconnect", "disconnect",
        "Disconnect the VPN. The kill switch stays engaged if it was turned on with 'vpnman lock on' or\n"
        "netlock.persist is set; otherwise it is released.", ["vpnman disconnect"], aliases=["down"])
    s = add("import", "import config files or a directory of them",
            "Import VPN configuration files. The protocol is detected from the file (use --protocol to force it).\n"
            "A directory is searched recursively and each sub-folder name becomes the profile's group.\n"
            "Options in a config that cannot work here (Windows-only options, missing up/down scripts) are listed\n"
            "as notes after the import and ignored when connecting.",
            ["vpnman import work.ovpn", "vpnman import ~/vpn-configs/        # folders become groups",
             "vpnman import --user bob --ask-password *.ovpn", "vpnman import --stunnel vpn.example.com:443 srv.ovpn"])
    s.add_argument("paths", nargs="+", metavar="PATH", help="config file(s) or directories")
    s.add_argument("--name", help="profile name (default: the file name; only with a single file)")
    s.add_argument("--protocol", choices=protocols, help="skip detection and use this protocol")
    s.add_argument("--user", help="username to store with the profile")
    s.add_argument("--password", help="password to store (visible in the process list - prefer --ask-password)")
    s.add_argument("--ask-password", action="store_true", help="prompt for the password instead of putting it on the command line")
    s.add_argument("--stunnel", metavar="HOST[:PORT]", help="carry OpenVPN over TLS via stunnel (default port 443)")
    s.add_argument("--stunnel-sni", metavar="NAME", help="TLS server name to present (SNI)")
    s.add_argument("--stunnel-ca", metavar="FILE", help="CA certificate to verify the stunnel server with")
    s.add_argument("--stunnel-verify", choices=["none", "system", "ca"], help="how to verify the stunnel server")
    s = add("add", "create a profile without a config file",
            "Create a profile by hand, for protocols that need only a server and credentials (OpenConnect, SSTP,\n"
            "PPTP, Tailscale, ...). Extra protocol settings go in with -o KEY=VALUE.",
            ["vpnman add Office --protocol openconnect --server vpn.example.com --user bob --ask-password",
             "vpnman add Mesh --protocol tailscale -o exit_node=100.64.0.1"])
    s.add_argument("name", help="name of the new profile")
    s.add_argument("--protocol", required=True, choices=protocols, help="VPN protocol (see: vpnman protocols)")
    s.add_argument("--server", help="server host name or address")
    s.add_argument("--port", type=int, help="server port")
    s.add_argument("--user", help="username")
    s.add_argument("--ask-password", action="store_true", help="prompt for the password")
    s.add_argument("--option", "-o", action="append", metavar="K=V", help="protocol option (repeatable)")
    s = add("remove", "delete profiles",
            "Delete profiles and their stored credentials. If one of them is connected, the VPN is disconnected.",
            ["vpnman remove OldServer", "vpnman rm srv1 srv2"], aliases=["rm"])
    s.add_argument("profiles", nargs="+", metavar="PROFILE", help="profile id or name (several allowed)")
    s = add("edit", "change profile fields",
            "Change fields of a profile. Fields: name, username, password, server, port, dns (comma separated),\n"
            "notes, group, favorite and blacklisted (true/false), and the stunnel settings: stunnel=HOST:PORT|off,\n"
            "stunnel_sni=NAME, stunnel_ca=FILE, stunnel_verify=none|system|ca.",
            ["vpnman edit Work username=bob group=Office", "vpnman edit Work dns=1.1.1.1,1.0.0.1",
             "vpnman edit Work stunnel=vpn.example.com:443", "vpnman edit Work stunnel=off"])
    s.add_argument("profile", help="profile id or name")
    s.add_argument("changes", nargs="+", metavar="KEY=VALUE", help="field and its new value")
    for n, h, d in (("fav", "mark favourite", "Mark profiles as favourites: they sort first and are the last resort of failover."),
                    ("unfav", "unmark favourite", "Remove the favourite mark."),
                    ("block", "blacklist", "Blacklist profiles: --fastest and failover never pick them."),
                    ("unblock", "remove from blacklist", "Allow --fastest and failover to pick the profiles again.")):
        s = add(n, h, d, ["vpnman %s Work Home" % n])
        s.add_argument("profiles", nargs="+", metavar="PROFILE", help="profile id or name (several allowed)")
    s = add("ping", "measure latency to profiles",
            "Measure the round-trip time to each server: a TCP connect for TCP servers, ICMP ping for UDP ones\n"
            "(all profiles when none is named). Servers that do not answer are shown as unreachable.",
            ["vpnman ping", "vpnman ping Work Home"])
    s.add_argument("profiles", nargs="*", metavar="PROFILE", help="profile id or name (default: all)")
    s = add("lock", "network lock (kill switch)",
            "The kill switch. While engaged, only the VPN tunnel, the VPN server, the local network (if allowed)\n"
            "and the exceptions in netlock.whitelist_out, 'vpnman routes' and 'vpnman bypass' can send or receive\n"
            "traffic. If the VPN drops, nothing leaks. 'on' engages it now; turn it on for good with\n"
            "'vpnman set netlock.enabled true' (engage whenever connecting) or netlock.persist (survive reboots).",
            ["vpnman lock status", "vpnman lock on", "vpnman lock off"])
    s.add_argument("action", choices=["on", "off", "status"], nargs="?", default="status",
                   help="engage, release or show the state (default: status)")
    s = add("autostart", "connect the VPN automatically when the system starts",
            "Choose what the background service connects to at boot, and whether the tray app starts at login.\n"
            "With no arguments it shows the current setting.",
            ["vpnman autostart", "vpnman autostart last", "vpnman autostart Work", "vpnman autostart off",
             "vpnman autostart --login-app on"])
    s.add_argument("target", nargs="?", help="off | last | fastest | profile name")
    s.add_argument("--login-app", choices=["on", "off"], help="start the tray app at login (this user)")
    s = add("dns", "choose the DNS servers used while connected",
            "Choose which DNS servers are used while the VPN is up. With no argument it shows the current choice\n"
            "and the presets. 'provider' uses the servers the VPN pushes, 'off' leaves your DNS settings alone\n"
            "(that can leak queries - see 'vpnman leaktest').",
            ["vpnman dns", "vpnman dns cloudflare", "vpnman dns 9.9.9.9,149.112.112.112", "vpnman dns provider",
             "vpnman dns off"])
    s.add_argument("choice", nargs="*", help="preset name | IP[,IP...] | provider | off")
    s = add("bypass", "apps that skip the VPN (split tunnel)",
            "Applications that keep using your normal connection while the VPN is up (Linux with nft, ip and\n"
            "cgroup v2). They keep working even when the VPN drops under the kill switch.\n\n"
            "  list                 show the state and the apps\n"
            "  available [TEXT]     installed applications (optionally filtered)\n"
            "  add APP...           add apps by name or process name\n"
            "  remove APP...        remove apps\n"
            "  on | off             turn the feature on or off\n"
            "  mode [exclude|include]\n"
            "                       exclude (default): listed apps skip the VPN.\n"
            "                       include (experimental): ONLY listed apps use the VPN.",
            ["vpnman bypass available fire", "vpnman bypass add firefox steam", "vpnman bypass remove steam",
             "vpnman bypass mode include"], aliases=["split"])
    s.add_argument("action", nargs="?", choices=["list", "add", "remove", "rm", "available", "on", "off", "mode"],
                   help="what to do (default: list)")
    s.add_argument("items", nargs="*", metavar="APP", help="application names / process names (or the mode)")
    s = add("schedule", "connect the VPN at set times",
            "Connect (and optionally disconnect) at set times. A window that ends before it starts runs past\n"
            "midnight. A manual disconnect inside a window is respected until the next start or end.\n\n"
            "  list                 show the schedules and when each next fires\n"
            "  add                  create one (--start is required)\n"
            "  remove|enable|disable ID_OR_NAME\n"
            "  on | off             turn the whole scheduler on or off",
            ["vpnman schedule add --days weekdays --start 08:00 --end 18:00 --name Work",
             "vpnman schedule add --days sat,sun --start 22:00 --end 06:00 --profile fastest",
             "vpnman schedule disable Work"])
    s.add_argument("action", nargs="?", choices=["list", "add", "remove", "rm", "enable", "disable", "on", "off"],
                   help="what to do (default: list)")
    s.add_argument("target", nargs="?", help="schedule id or name (remove / enable / disable)")
    s.add_argument("--name", help="label for the schedule")
    s.add_argument("--days", help="all | weekdays | weekends | mon,wed | mon-fri  (default: all)")
    s.add_argument("--start", metavar="HH:MM", help="connect at this time (24-hour clock)")
    s.add_argument("--end", metavar="HH:MM", help="disconnect again at this time")
    s.add_argument("--profile", help="profile name/id, 'fastest' or 'last' (default: last used)")
    s = add("backup", "export or restore all profiles (with credentials) and settings",
            "Write every profile (with its passwords and private keys) and the settings to one file, or restore\n"
            "them. Restoring adds the profiles that are missing and touches nothing else, unless --replace.\n"
            "The file is not encrypted: keep it somewhere safe.",
            ["vpnman backup export ~/vpnman-backup.tar.gz", "vpnman backup import ~/vpnman-backup.tar.gz",
             "vpnman backup import --replace --settings backup.tar.gz   # make this PC match the backup"])
    s.add_argument("action", choices=["export", "import"], help="write a backup, or restore one")
    s.add_argument("file", help="backup file")
    s.add_argument("--replace", action="store_true", help="import: make this computer match the backup (removes other profiles)")
    s.add_argument("--settings", action="store_true", help="import: also restore the settings (always with --replace)")
    s.add_argument("--force", action="store_true", help="export: overwrite an existing file")
    s = add("history", "recent connections: when, how long, how much traffic",
            "The last 200 connections: start time, duration, traffic and why each ended.",
            ["vpnman history", "vpnman history -n 5", "vpnman history --clear"])
    s.add_argument("-n", "--lines", type=int, default=20, help="how many entries to show (default 20)")
    s.add_argument("--json", action="store_true", help=JSON)
    s.add_argument("--clear", action="store_true", help="delete the history")
    s = add("proxy", "proxies (Xray: VLESS, VMess, Trojan, Shadowsocks) in front of, or behind, the VPN",
            "Use a VLESS / VMess / Trojan / Shadowsocks server through Xray, alone or together with the VPN.\n\n"
            "  list [--latency] [--group G]  the proxies\n"
            "  show NAME              everything known about one proxy\n"
            "  add SOURCE...          share links, a file with links ('-' reads standard input), or a subscription\n"
            "                         URL (https://...)\n"
            "  sources                the subscriptions, with how many proxies each holds\n"
            "  refresh [URL...]       download the subscriptions again (new servers appear, gone ones are removed)\n"
            "  remove NAME... | --group G | --all\n"
            "                         delete proxies\n"
            "  edit NAME KEY=VALUE... name, group, notes, favorite\n"
            "  use NAME               choose the proxy to use\n"
            "  use --fastest [--group G]\n"
            "                         choose the quickest server (of the group, else of the favourites, else of all)\n"
            "  link NAME [--qr]       print the share link (and a QR code) to move the proxy to another device\n"
            "  failover [on|off]      switch to the next favourite proxy (else the next of its group) when the server\n"
            "                         stops answering or Xray keeps stopping\n"
            "  on | off               switch the proxy on or off\n"
            "  order proxy_only|vpn_proxy|proxy_vpn\n"
            "                         proxy_only: you -> proxy -> internet.  vpn_proxy: you -> VPN -> proxy -> internet.\n"
            "                         proxy_vpn: you -> proxy -> VPN -> internet (the VPN rides inside the proxy;\n"
            "                         OpenVPN and WireGuard profiles)\n"
            "  mode local|system      local: SOCKS5 + HTTP proxy for applications on 127.0.0.1.\n"
            "                         system (Linux): all TCP and DNS of this computer go through the proxy\n"
            "  set [KEY VALUE]        socks_port, http_port, dns, udp (block|direct); without arguments: show them\n"
            "  status | ping [NAME...]\n\n"
            "Needs the xray program (https://github.com/XTLS/Xray-core).",
            ["vpnman proxy add 'vless://...@example.com:443?security=reality&...#Home'", "vpnman proxy add https://example.com/sub/abc",
             "vpnman proxy use Home && vpnman proxy order vpn_proxy && vpnman proxy on", "vpnman proxy mode system",
             "vpnman proxy status", "vpnman proxy remove --group example.com", "xclip -o | vpnman proxy add -"])
    s.add_argument("action", nargs="?", choices=["list", "show", "link", "add", "remove", "rm", "edit", "use", "on", "off",
                                                  "order", "mode", "set", "status", "ping", "refresh", "sources",
                                                  "failover"], help="default: list")
    s.add_argument("items", nargs="*", metavar="ARG", help="links / URLs / names / values (see the actions above)")
    s.add_argument("--name", help="add: name for a single imported proxy")
    s.add_argument("--group", help="add: group to put the imported proxies in (default: the subscription's host); "
                                   "list, remove, use --fastest: only this group")
    s.add_argument("--all", action="store_true", help="remove: every proxy")
    s.add_argument("--fastest", action="store_true", help="use: the proxy with the quickest server")
    s.add_argument("--qr", action="store_true", help="link: also print a QR code")
    s.add_argument("--latency", "-l", action="store_true", help="list: measure every server")
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("diagnostics", "a report for bug reports, with the private parts removed",
            "Print (or save with -o FILE) a report of this installation: versions, system, tools, state, profiles and\n"
            "settings, firewall tables and the recent log. Passwords, user names, server and network names and public\n"
            "addresses are removed (local addresses stay); share it in a bug report after reading it.",
            ["vpnman diagnostics -o vpnman-report.txt", "vpnman diagnostics | less"])
    s.add_argument("-o", "--output", help="write the report to this file (default: standard output)")
    s.add_argument("--force", action="store_true", help="overwrite an existing file")
    s = add("netproxy", "a proxy server all traffic goes through (after the VPN while one is connected)",
            "Send this computer's traffic through an HTTP or SOCKS5 proxy (Linux, nftables; the engine is xray). With\n"
            "no VPN, programs reach the internet through the proxy; while a VPN is connected, through the VPN to the\n"
            "proxy. Destination port 80 uses the HTTP proxy, 443 the HTTPS proxy, 21 the FTP proxy, anything else the\n"
            "SOCKS proxy (else the HTTPS, HTTP or FTP one). DNS is asked over TCP through the proxy; other UDP is\n"
            "blocked unless 'udp direct'; IPv6 is blocked. While it is on, the Xray proxy (vpnman proxy) is paused.\n\n"
            "  status                      the settings and whether it runs (default)\n"
            "  on | off\n"
            "  set KIND HOST:PORT          KIND is http, https, ftp or socks (--user NAME, --ask-password)\n"
            "  clear KIND...               remove a proxy server\n"
            "  ignore HOST...              hosts that go direct: addresses, networks, domains (replaces the list)\n"
            "  apps NAME...                programs that go direct (replaces the list; needs cgroup v2)\n"
            "  dns IP                      the DNS server asked through the proxy (default 1.1.1.1)\n"
            "  udp block|direct            UDP other than DNS: drop it, or let it out directly\n"
            "  killswitch [on|off]         while the proxy cannot work (down, restarting, a wrong address) block all\n"
            "                              traffic instead of letting it out directly (default on; ignored hosts and\n"
            "                              the local network still work)",
            ["vpnman netproxy set http proxy.example.com:3128", "vpnman netproxy set https proxy.example.com:3128",
             "vpnman netproxy set socks 10.0.0.5:1080 --user me --ask-password", "vpnman netproxy on",
             "vpnman netproxy ignore localhost 127.0.0.0/8 ::1 '*.corp.example'", "vpnman netproxy apps steam"])
    s.add_argument("action", nargs="?", choices=["status", "on", "off", "set", "clear", "ignore", "apps", "dns", "udp", "killswitch"],
                   help="default: status")
    s.add_argument("items", nargs="*", metavar="ARG", help="see the actions above")
    s.add_argument("--user", help="set: user name for a proxy that needs a login")
    s.add_argument("--ask-password", action="store_true", help="set: ask for the proxy's password")
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("blocks", "addresses, ports and programs that may not use the network",
            "Block connections with the firewall (Linux, nftables). The list is kept across restarts. Blocking also\n"
            "closes the matching connections that are open right now.\n\n"
            "  list                    the blocked things, with the ids used below\n"
            "  add KIND VALUE          KIND is address (IP or network), endpoint (ADDRESS:PORT), port or app\n"
            "  remove ID...            unblock\n"
            "  enable|disable ID...    keep an entry in the list but stop (or resume) enforcing it\n"
            "  on | off                switch the whole list on or off\n\n"
            "A block can be temporary: --for 30m (or 2h, 1d, 90 = minutes) ends it after that long, --until-reboot\n"
            "when the computer restarts. Both together end it at whichever comes first.",
            ["vpnman blocks add address 203.0.113.9", "vpnman blocks add endpoint 203.0.113.9:443 --proto tcp",
             "vpnman blocks add port 6881 --proto udp --note torrents", "vpnman blocks add app steam",
             "vpnman blocks add app steam --for 2h", "vpnman blocks add address 198.51.100.7 --until-reboot",
             "vpnman blocks remove 3f9a1c2b"])
    s.add_argument("action", nargs="?", choices=["list", "status", "add", "remove", "rm", "enable", "disable", "on", "off"],
                   help="default: list")
    s.add_argument("items", nargs="*", metavar="ARG", help="add: KIND VALUE; remove/enable/disable: ids")
    s.add_argument("--proto", choices=["any", "tcp", "udp"], help="add: protocol (endpoint and port entries)")
    s.add_argument("--note", help="add: a reminder of why")
    s.add_argument("--for", dest="for_", metavar="DURATION", help="add: end the block after 30m, 2h, 1d... (minutes "
                                                                   "when there is no unit)")
    s.add_argument("--until-reboot", action="store_true", help="add: end the block when the computer restarts")
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("connections", "live list of connections: which application, port and protocol",
            "Show the network connections of this computer as the daemon sees them: the way (in, out, listen), the\n"
            "application and its pid, the protocol, the local and remote address and port, and the TCP state.\n"
            "Connections that never leave this machine and sockets that only listen are hidden unless asked for.\n"
            "On BSD systems other than FreeBSD the application names are not available.",
            ["vpnman connections", "vpnman connections --listening", "vpnman connections --watch", "vpnman connections --json",
             "vpnman connections --csv > connections.csv"])
    s.add_argument("--listening", "-l", action="store_true", help="also show sockets that wait for connections")
    s.add_argument("--local", action="store_true", help="also show connections within this computer (loopback)")
    s.add_argument("--resolve", "-r", action="store_true",
                   help="show host names instead of addresses where reverse DNS knows them (sends DNS queries)")
    s.add_argument("--watch", "-w", action="store_true", help="refresh every 2 seconds")
    s.add_argument("--csv", action="store_true", help="print CSV with a header line (for spreadsheets)")
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("group", "list groups; rename a group or edit all its servers at once",
            "Servers are grouped by the folder they were imported from (or 'vpnman edit PROFILE group=NAME').\n"
            "'edit' changes every server in a group in one go. Keys: name (renames the group), username,\n"
            "password, stunnel=HOST[:PORT] (or off), stunnel_sni, stunnel_verify. Whatever you do not name stays\n"
            "as it is. The SSL tunnel applies to the OpenVPN servers of the group only.",
            ["vpnman group", "vpnman group edit Germany name=DE", "vpnman group edit DE username=bob --ask-password",
             "vpnman group edit DE stunnel=vpn.example.com:443", "vpnman group edit DE stunnel=off",
             "vpnman group order Work Home Streaming", "vpnman group order --reset"])
    s.add_argument("action", nargs="?", choices=["list", "edit", "order"], help="default: list")
    s.add_argument("group", nargs="?", help="group name (or a unique part of it)")
    s.add_argument("changes", nargs="*", metavar="KEY=VALUE", help="edit: what to change on every server of the group; "
                                                                 "order: more group names, in the order you want")
    s.add_argument("--reset", action="store_true", help="order: back to alphabetical")
    s.add_argument("--ask-password", action="store_true", help="prompt for a new password for all of them")
    s = add("failover", "servers to try, in order, when a profile keeps failing",
            "Show or set the servers tried, in order, when PROFILE keeps failing (after connection.retry_max\n"
            "attempts). After that list come the servers of the same group, then your favourites\n"
            "(see connection.failover and connection.failover_group). Blocked servers are never used.",
            ["vpnman failover Work", "vpnman failover Work Backup1 Backup2", "vpnman failover Work --clear"])
    s.add_argument("profile", help="the profile whose list to show or set")
    s.add_argument("servers", nargs="*", metavar="SERVER", help="fallback profiles, in the order to try them")
    s.add_argument("--clear", action="store_true", help="remove the list")
    s = add("update", "check GitHub for a newer VPNMan release (exit 10 if there is one)",
            "Ask GitHub for the newest release and compare. Runs as you, not through the service; nothing is\n"
            "downloaded or installed. Exit status 10 means a newer version exists.",
            ["vpnman update", "vpnman update --json"])
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("networks", "show the current network; trust/untrust it",
            "Trusted networks are ones where you do not need the VPN (home, office). Combine with\n"
            "'vpnman set network.untrusted_action connect' to connect automatically everywhere else and\n"
            "'vpnman set network.trusted_action disconnect' to disconnect on trusted ones. Wi-Fi is identified\n"
            "by its name (SSID), wired networks by the gateway's hardware address.",
            ["vpnman networks", "vpnman networks trust", "vpnman networks trust \"Home WiFi\"", "vpnman networks untrust",
             "vpnman networks rule --server \"Work\" --netproxy on", "vpnman networks rule \"Cafe\" --server fastest-one",
             "vpnman networks rule --clear"])
    s.add_argument("action", nargs="?", choices=["show", "trust", "untrust", "rule"], help="default: show")
    s.add_argument("name", nargs="?", help="network to trust / untrust / set a rule for (default: the current one)")
    s.add_argument("--server", help="rule: connect to this server when joining the network")
    s.add_argument("--netproxy", choices=["on", "off"], help="rule: turn the network proxy on or off when joining it")
    s.add_argument("--xray", metavar="PROXY|off", help="rule: use this Xray proxy (or turn it off) when joining it")
    s.add_argument("--clear", action="store_true", help="rule: remove the rule of the network")
    s = add("routes", "addresses, networks or domains that skip the VPN",
            "Destinations that always use your normal connection instead of the VPN, and that the kill switch\n"
            "never blocks. Give IP addresses, networks (CIDR) or domain names (re-resolved when needed).",
            ["vpnman routes", "vpnman routes add 10.0.0.0/8 intranet.example.com", "vpnman routes remove 10.0.0.0/8"])
    s.add_argument("action", nargs="?", choices=["list", "add", "remove", "rm"], help="default: list")
    s.add_argument("items", nargs="*", metavar="ADDRESS", help="IP, network (CIDR) or domain name")
    s = add("leaktest", "check the live connection: tunnel, public IP, kill switch, DNS and IPv6 leaks",
            "Test the live connection: that the tunnel is up, what the public IP is, that traffic outside the\n"
            "tunnel is really blocked while the kill switch is engaged, that the DNS servers sit behind the\n"
            "tunnel and that IPv6 cannot bypass it. Exit status 1 if a check fails, so it works in scripts.\n"
            "Connect first.", ["vpnman leaktest", "vpnman leaktest --json"])
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("cleanup", "remove firewall rules, routes and cgroups VPNMan left behind (root)",
            "Remove what VPNMan created in the system: the kill switch rules (nftables table 'inet vpnman',\n"
            "iptables chains VPNMAN_OUT / VPNMAN_IN, or the pf ruleset), the app-bypass table 'inet vpnman_split',\n"
            "its routing rule and table, the cgroups, the proxy's system-wide redirect (table 'inet vpnman_proxy') and\n"
            "the blocked-connections table ('inet vpnman_block').\n"
            "Uninstalling runs this for you. Use it if a crash left\n"
            "you offline with the kill switch stuck on.",
            ["sudo vpnman cleanup", "sudo vpnman cleanup --force     # even though the service is running"])
    s.add_argument("--force", action="store_true", help="even if the service is running")
    s = add("get", "show settings",
            "Show all settings, one section, or one value. Keys are dotted: section.name.",
            ["vpnman get", "vpnman get netlock", "vpnman get netlock.allow_lan"])
    s.add_argument("key", nargs="?", help="setting such as netlock.allow_lan (default: everything)")
    s = add("set", "change a setting",
            "Change one setting; it takes effect immediately and is saved in /etc/vpnman/settings.json.\n"
            "Booleans: true/false/on/off/yes/no. Lists: comma separated. See 'man vpnman' for every setting.",
            ["vpnman set netlock.enabled true", "vpnman set netlock.whitelist_out 192.0.2.10,198.51.100.0/24",
             "vpnman set connection.retry_max 5", "vpnman set events.connected /usr/local/bin/on-vpn-up"])
    s.add_argument("key", help="setting, e.g. connection.retry_max")
    s.add_argument("value", help="new value")
    s = add("logs", "show daemon log",
            "Show the daemon's recent log: connections, tool output, firewall changes, errors.",
            ["vpnman logs", "vpnman logs -n 200", "vpnman logs -f"])
    s.add_argument("-f", "--follow", action="store_true", help="keep running and print new lines")
    s.add_argument("-n", "--lines", type=int, default=50, help="how many lines to show first (default 50)")
    s = add("protocols", "list supported protocols and whether their tools are installed",
            "List every supported VPN protocol, and which program to install for the ones that are missing, then the\n"
            "helper programs: stunnel (OpenVPN over TLS) and xray (proxies).",
            ["vpnman protocols", "vpnman protocols --json"])
    s.add_argument("--json", action="store_true", help=JSON)
    s = add("doctor", "check the system (icons, daemon, protocols)",
            "Report the state of the installation: distribution, init system, daemon, firewall, launcher and\n"
            "icons, tray support, and which protocols have their programs installed. Start here when something\n"
            "does not work (for example the app is missing from the menu).",
            ["vpnman doctor", "sudo vpnman doctor --fix"])
    s.add_argument("--fix", action="store_true", help="link launcher/icons into /usr/share and rebuild icon caches (root)")
    s = add("service", "install/control the background service",
            "Install or control the background service (vpnmand) with the init system of this machine:\n"
            "systemd, runit, OpenRC, SysV init, OpenBSD rc.d or FreeBSD rc.d. Needs root.\n"
            "'enable' installs the definition if needed, enables it at boot and starts it.",
            ["sudo vpnman service enable", "sudo vpnman service restart", "sudo vpnman service status",
             "sudo vpnman service uninstall"])
    s.add_argument("action", choices=["install", "uninstall", "enable", "disable", "start", "stop", "restart", "status"],
                   help="install/uninstall the definition; enable/disable at boot (and start/stop now); or control it")
    s.add_argument("--init", choices=["systemd", "runit", "openrc", "sysv", "openbsd-rc", "bsd-rc"],
                   help="force the init system instead of auto-detecting it")
    add("daemon", "run the daemon in the foreground (root)",
        "Run the background service in the foreground, with logging to the terminal. This is what the init\n"
        "system runs (as 'vpnmand'). Useful for debugging; stop the installed service first.",
        ["sudo vpnman service stop && sudo vpnman daemon"])
    s = add("gui", "open the GTK4/libadwaita app",
            "Open the graphical app (also installed as 'vpnman-gtk' and in the application menu). It needs\n"
            "PyGObject, GTK 4 and libadwaita 1.4+. Closing the window keeps it in the system tray when a tray\n"
            "is available.", ["vpnman gui", "vpnman gui --background"])
    s.add_argument("--background", action="store_true", help="start minimised to the system tray")
    add("about", "credits, license and ways to support the project", "Show the credits, the license and how to support the project.")
    add("shell", "interactive menu", "Open the interactive menu (the same as running 'vpnman' in a terminal).", aliases=["menu"])
    return ap


ALIASES = {"split": "bypass", "ls": "list", "up": "connect", "down": "disconnect", "rm": "remove", "menu": "shell"}


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
        if cmd == "update":
            return cli.cmd_update(a)
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
