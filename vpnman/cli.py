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
        from . import schedule as sch
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

    def cmd_networks(self, a):
        act = a.action or "show"
        if act in ("trust", "untrust"):
            st = self.call("network.trust", name=a.name, trusted=(act == "trust"))
            print("%s %s" % ("Trusted:" if act == "trust" else "No longer trusted:", a.name or st["id"]))
            return 0
        if act != "show":
            raise RpcError("unknown action %r (show, trust, untrust)" % act)
        st = self.call("network.status")
        cfg = self.call("settings.get", key="network")
        if st["id"]:
            print("Current network: %s  (%s via %s)  %s" % (st["id"], st["kind"], st["device"],
                  green("trusted") if st["trusted"] else yellow("not trusted")))
        else:
            print("Current network: none detected")
        print("Trusted:   %s" % (", ".join(cfg["trusted"]) or "-"))
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
        from . import netlock, split
        if self.client.alive() and not a.force:
            raise RpcError("the VPNMan service is running and owns these rules - stop it first "
                           "(vpnman disconnect; vpnman lock off), or use --force")
        if os.geteuid() != 0:
            raise RpcError("run as root: sudo vpnman cleanup")
        gone = netlock.cleanup_all()
        if plat.os_family() == "linux":
            split.cleanup()
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

def build_parser():
    ap = argparse.ArgumentParser(prog="vpnman", description="Multi-protocol VPN manager with kill switch.")
    ap.add_argument("--version", action="version", version="vpnman " + __version__)
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")

    def add(name, help, **kw):
        return sub.add_parser(name, help=help, **kw)

    s = add("status", "show connection status"); s.add_argument("--json", action="store_true")
    s = add("list", "list profiles", aliases=["ls"]); s.add_argument("--latency", "-l", action="store_true")
    s.add_argument("--names", action="store_true", help="one profile name per line (used by shell completion)")
    s.add_argument("--sort", choices=["name", "latency", "group"], help="sort order (latency implies --latency)")
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
    s = add("autostart", "connect the VPN automatically when the system starts")
    s.add_argument("target", nargs="?", help="off | last | fastest | profile name")
    s.add_argument("--login-app", choices=["on", "off"], help="start the tray app at login (this user)")
    s = add("dns", "choose the DNS servers used while connected"); s.add_argument("choice", nargs="*")
    s = add("bypass", "apps that skip the VPN (split tunnel): list|add|remove|available|on|off|mode", aliases=["split"])
    s.add_argument("action", nargs="?"); s.add_argument("items", nargs="*")
    s = add("schedule", "connect the VPN at set times: list|add|remove|enable|disable|on|off")
    s.add_argument("action", nargs="?"); s.add_argument("target", nargs="?")
    s.add_argument("--name"); s.add_argument("--days", help="all | weekdays | weekends | mon,wed | mon-fri")
    s.add_argument("--start", metavar="HH:MM"); s.add_argument("--end", metavar="HH:MM", help="disconnect again at this time")
    s.add_argument("--profile", help="profile name/id, 'fastest' or 'last' (default: last used)")
    s = add("backup", "export or restore all profiles (with credentials) and settings")
    s.add_argument("action", choices=["export", "import"]); s.add_argument("file")
    s.add_argument("--replace", action="store_true", help="import: make this computer match the backup")
    s.add_argument("--settings", action="store_true", help="import: also restore the settings (always with --replace)")
    s.add_argument("--force", action="store_true", help="export: overwrite an existing file")
    s = add("history", "recent connections: when, how long, how much traffic")
    s.add_argument("-n", "--lines", type=int, default=20); s.add_argument("--json", action="store_true")
    s.add_argument("--clear", action="store_true")
    s = add("failover", "servers to try, in order, when a profile keeps failing")
    s.add_argument("profile"); s.add_argument("servers", nargs="*")
    s.add_argument("--clear", action="store_true", help="remove the list")
    s = add("update", "check GitHub for a newer VPNMan release (exit 10 if there is one)")
    s.add_argument("--json", action="store_true")
    s = add("networks", "show the current network; trust/untrust it (auto-connect on untrusted networks)")
    s.add_argument("action", nargs="?", choices=["show", "trust", "untrust"]); s.add_argument("name", nargs="?")
    s = add("routes", "addresses, networks or domains that skip the VPN: list|add|remove")
    s.add_argument("action", nargs="?"); s.add_argument("items", nargs="*")
    s = add("leaktest", "check the live connection: tunnel, public IP, kill switch, DNS and IPv6 leaks")
    s.add_argument("--json", action="store_true")
    s = add("cleanup", "remove firewall rules, routes and cgroups VPNMan left behind (root)")
    s.add_argument("--force", action="store_true", help="even if the service is running")
    s = add("get", "show settings"); s.add_argument("key", nargs="?")
    s = add("set", "change a setting"); s.add_argument("key"); s.add_argument("value")
    s = add("logs", "show daemon log"); s.add_argument("-f", "--follow", action="store_true")
    s.add_argument("-n", "--lines", type=int, default=50)
    add("protocols", "list supported protocols and whether their tools are installed")
    s = add("doctor", "check the system (icons, daemon, protocols)")
    s.add_argument("--fix", action="store_true", help="link launcher/icons into /usr/share and rebuild icon caches (root)")
    s = add("service", "install/control the background service")
    s.add_argument("action", choices=["install", "uninstall", "enable", "disable", "start", "stop", "restart", "status"])
    s.add_argument("--init", choices=["systemd", "runit", "openrc", "sysv", "openbsd-rc", "bsd-rc"],
                   help="force the init system instead of auto-detecting it")
    add("daemon", "run the daemon in the foreground (root)")
    s = add("gui", "open the GTK4/libadwaita app")
    s.add_argument("--background", action="store_true", help="start minimised to the system tray")
    add("about", "credits, license and ways to support the project")
    add("shell", "interactive menu", aliases=["menu"])
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
