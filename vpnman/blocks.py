"""Blocked connections: addresses, ports and applications that may not use the network (Linux, nftables).

The user's list (setting ``blocks``) is enforced by the nftables table ``inet vpnman_block``, whose chains run before the
kill switch and the proxy rules.  An entry is one of:

* ``address``   an IP address or network (CIDR), both directions
* ``endpoint``  an address and a port (``203.0.113.9:443`` / ``[2001:db8::1]:443``) with a protocol
* ``port``      a port with a protocol: outgoing to it, and incoming to a local service on it
* ``app``       a program by name: its processes are kept in a cgroup whose outgoing traffic is dropped

Blocking also closes the matching connections that are open right now (``ss -K``), because dropped packets alone
would let an established TCP connection hang on for minutes.

An entry can be temporary: ``expires`` (a time) and/or ``boot`` (the boot id it was made in - "until restart").  The
daemon drops such entries once they run out.
"""

import ipaddress
import os
import re
import threading
import time
import uuid

from . import conntable, split
from . import platform as plat

NFT_TABLE = "vpnman_block"
CGROUP = "vpnman-blocked"
KINDS = ("address", "endpoint", "port", "app")
PROTOS = ("any", "tcp", "udp")
_APP = re.compile(r"^[A-Za-z0-9._+@-]{1,64}$")
MAX_MINUTES = 366 * 24 * 60
_DAEMON_TOKEN = "daemon-%s" % uuid.uuid4().hex[:12]       # "until restart" when the kernel has no boot id


class BlockError(ValueError):
    pass


# ------------------------------------------------------------------ validation

def _addr(value):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        raise BlockError("not an IP address or network: %s" % value)


def split_endpoint(text):
    """'1.2.3.4:443' / '[::1]:443' -> (ip string, port)."""
    text = str(text).strip()
    m = re.match(r"^\[([0-9a-fA-F:.]+)\]:(\d+)$", text) or re.match(r"^([0-9.]+):(\d+)$", text)
    if not m:
        raise BlockError("use ADDRESS:PORT, for example 203.0.113.9:443 or [2001:db8::1]:443")
    return m.group(1), _port(m.group(2))


def _port(value):
    try:
        p = int(value)
    except (TypeError, ValueError):
        raise BlockError("the port is not a number")
    if not 0 < p < 65536:
        raise BlockError("the port must be between 1 and 65535")
    return p


def clean(kind, value, proto="any", note=""):
    """Validate one entry and return its canonical form (raises BlockError)."""
    kind, proto = str(kind), str(proto or "any").lower()
    if kind not in KINDS:
        raise BlockError("kind must be one of: %s" % ", ".join(KINDS))
    if proto not in PROTOS:
        raise BlockError("protocol must be any, tcp or udp")
    value = str(value).strip()
    if kind == "address":
        value, proto = str(_addr(value)), "any"
    elif kind == "endpoint":
        ip, port = split_endpoint(value)
        net = _addr(ip)
        if net.prefixlen != net.max_prefixlen:
            raise BlockError("an endpoint needs a single address, not a network")
        value = ("[%s]:%d" if net.version == 6 else "%s:%d") % (net.network_address, port)
    elif kind == "port":
        value = str(_port(value))
    else:
        if not _APP.match(value):
            raise BlockError("a program name is letters, digits and . _ + @ - (at most 64 characters)")
        proto = "any"
    return {"kind": kind, "value": value, "proto": proto, "note": str(note or "")[:200]}


def boot_id():
    """Changes with every boot (Linux); a fallback that changes when the daemon restarts."""
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            return fh.read().strip() or _DAEMON_TOKEN
    except OSError:
        return _DAEMON_TOKEN


def new_entry(kind, value, proto="any", note="", minutes=0, until_reboot=False):
    """A validated entry.  ``minutes``: drop it after that long; ``until_reboot``: drop it when the computer restarts."""
    e = clean(kind, value, proto, note)
    try:
        minutes = int(minutes or 0)
    except (TypeError, ValueError):
        raise BlockError("the duration is not a number of minutes")
    if not 0 <= minutes <= MAX_MINUTES:
        raise BlockError("the duration must be between 1 minute and a year")
    now = int(time.time())
    e.update(id=uuid.uuid4().hex[:8], enabled=True, created=now, expires=now + minutes * 60 if minutes else 0,
             boot=boot_id() if until_reboot else "")
    return e


def expired(e, now=None, boot=None):
    if e.get("expires") and e["expires"] <= (now or time.time()):
        return True
    return bool(e.get("boot")) and e["boot"] != (boot or boot_id())


def lifetime(e, now=None):
    """'permanent', 'until restart', 'for 14 more minutes'... (for lists)."""
    left = (e.get("expires") or 0) - (now or time.time())
    parts = []
    if e.get("expires"):
        if left < 2 * 3600:
            m = max(1, round(left / 60))
            parts.append("%d more minute%s" % (m, "" if m == 1 else "s"))
        elif left < 2 * 86400:
            h = round(left / 3600)
            parts.append("%d more hour%s" % (h, "" if h == 1 else "s"))
        else:
            parts.append("%d more days" % round(left / 86400))
        parts[0] = "for " + parts[0]
    if e.get("boot"):
        parts.append("until restart")
    return " or ".join(parts) if parts else "permanent"


# ------------------------------------------------------------------ rules (pure)

def _protos(proto):
    return ("tcp", "udp") if proto == "any" else (proto,)


def ruleset(entries, app_cgroup=CGROUP):
    """nftables text for the enabled entries."""
    out, inn, apps = [], [], False
    for e in entries:
        if not e.get("enabled", True):
            continue
        kind, value, proto = e["kind"], e["value"], e.get("proto", "any")
        if kind == "address":
            net = _addr(value)
            fam = "ip6" if net.version == 6 else "ip"
            out.append("%s daddr %s drop" % (fam, net))
            inn.append("%s saddr %s drop" % (fam, net))
        elif kind == "endpoint":
            ip, port = split_endpoint(value)
            fam = "ip6" if ":" in ip else "ip"
            for p in _protos(proto):
                out.append("%s daddr %s %s dport %d drop" % (fam, ip, p, port))
                inn.append("%s saddr %s %s sport %d drop" % (fam, ip, p, port))
        elif kind == "port":
            port = int(value)
            for p in _protos(proto):
                out.append("%s dport %d drop" % (p, port))
                inn.append("%s dport %d drop" % (p, port))
        elif kind == "app":
            apps = True
    if apps:
        out.append('socket cgroupv2 level 1 "%s" drop' % app_cgroup)
    lines = ["table inet %s" % NFT_TABLE, "delete table inet %s" % NFT_TABLE, "table inet %s {" % NFT_TABLE]
    for name, hook, rules in (("block_out", "output", out), ("block_in", "input", inn)):
        lines.append("  chain %s {" % name)
        lines.append("    type filter hook %s priority -120; policy accept;" % hook)
        lines += ["    " + r for r in rules]
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def matches(entry, row):
    """Does the connection ``row`` (a conntable row) fall under ``entry``?"""
    kind, value, proto = entry["kind"], entry["value"], entry.get("proto", "any")
    if proto != "any" and row["proto"] != proto and kind != "address":
        return False
    if kind == "app":
        return bool(row.get("app")) and row["app"] == value
    if kind == "port":
        return str(row["rport"]) == value or str(row["lport"]) == value
    try:
        remote = ipaddress.ip_address(row["remote"])
    except ValueError:
        return False
    if kind == "address":
        return remote in _addr(value)
    ip, port = split_endpoint(value)
    return remote == ipaddress.ip_address(ip) and row["rport"] == port


# ------------------------------------------------------------------ closing connections

def _hostport(ip, port):
    return ("[%s]:%d" if ":" in ip else "%s:%d") % (ip, port)


def close_connection(row):
    """Destroy one socket with ``ss -K`` (needs a kernel with CONFIG_INET_DIAG_DESTROY).  Returns (ok, message)."""
    ss = plat.which("ss")
    if not ss:
        return False, "ss (iproute2) is not installed"
    cmd = [ss, "-K", "-n", "-t" if row["proto"] == "tcp" else "-u",
           "src", _hostport(row["local"], row["lport"]), "dst", _hostport(row["remote"], row["rport"])]
    rc, out = plat.run(cmd, timeout=10)
    text = out.strip()
    if rc != 0:
        if "not supported" in text.lower() or "operation not" in text.lower():
            return False, "this kernel cannot close connections (CONFIG_INET_DIAG_DESTROY)"
        return False, text or "ss failed"
    return True, text


# ------------------------------------------------------------------ the service

class AppBlocker(split.SplitTunnel):
    """Keeps the processes of the blocked programs in a cgroup (the nftables rule drops that cgroup's packets)."""

    @property
    def path(self):
        root = self.root or split.cgroup_root()
        return os.path.join(root, CGROUP) if root else None

    def begin(self):
        with self._lock:
            self.stop_locked()
            os.makedirs(self.path, exist_ok=True)
            self.active = True
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._loop, args=(self._stop,), daemon=True, name="block-scan")
            self._thread.start()

    def stop_locked(self):
        self._stop.set()
        t, self._thread = self._thread, None
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(3)
        was = self.active
        self.active = False
        if was or (self.path and os.path.isdir(self.path)):
            self._release()
            if self.path and os.path.isdir(self.path):
                try:
                    os.rmdir(self.path)
                except OSError:
                    pass

    def scan_once(self):
        path = self.path
        if not path:
            return []
        added = []
        for pid in split.matching_pids(self.names_fn(), self.proc):
            cur = self._cgroup_of(pid)
            if cur is None or cur.rstrip("/").endswith("/" + CGROUP):
                continue
            if self._move(pid, path):
                self.moved.setdefault(pid, cur)
                added.append(pid)
        return added

    def _loop(self, stop):
        while not stop.is_set():
            try:
                self.scan_once()
            except Exception as e:  # noqa: BLE001
                self.log("warn", "Blocked programs: scan failed: %s" % e)
            stop.wait(split.SCAN_INTERVAL)


def cleanup():
    """Remove the firewall table and the cgroup left by a crashed daemon.  Returns True if something was removed."""
    removed = False
    nft = plat.which("nft")
    if nft and plat.os_family() == "linux":
        rc, _ = plat.run([nft, "list", "table", "inet", NFT_TABLE])
        if rc == 0:
            plat.run([nft, "delete", "table", "inet", NFT_TABLE])
            removed = True
    root = split.cgroup_root()
    if root and os.path.isdir(os.path.join(root, CGROUP)):
        try:
            with open(os.path.join(root, CGROUP, "cgroup.procs")) as fh:
                pids = fh.read().split()
            for pid in pids:
                with open(os.path.join(root, "cgroup.procs"), "w") as out:
                    out.write(pid)
            os.rmdir(os.path.join(root, CGROUP))
            removed = True
        except OSError:
            pass
    return removed


def supported():
    if plat.os_family() != "linux":
        return False, "blocking needs Linux with nftables"
    if not plat.which("nft"):
        return False, "blocking needs nftables (nft)"
    return True, ""


class BlockService:
    def __init__(self, mgr):
        self.m = mgr
        self.lock = threading.RLock()
        self.active = False
        self.error = ""
        self.apps = AppBlocker(self._app_names, lambda lvl, msg: mgr.log.add(lvl, msg))

    # ---- data
    def cfg(self):
        return self.m.settings.get("blocks")

    def _save(self, entries=None, enabled=None):
        tree = {}
        if entries is not None:
            tree["entries"] = entries
        if enabled is not None:
            tree["enabled"] = bool(enabled)
        self.m.settings.update({"blocks": tree})

    def list(self):
        return list(self.cfg()["entries"])

    def _app_names(self):
        return [e["value"] for e in self.cfg()["entries"] if e.get("enabled", True) and e["kind"] == "app"]

    def add(self, kind, value, proto="any", note="", minutes=0, until_reboot=False):
        entry = new_entry(kind, value, proto, note, minutes, until_reboot)
        with self.lock:
            entries = self.list()
            for e in entries:
                if (e["kind"], e["value"], e.get("proto")) == (entry["kind"], entry["value"], entry["proto"]):
                    raise BlockError("already blocked: %s" % self.describe(e))
            entries.append(entry)
            self._save(entries)
        self.m.log.add("info", "Blocked %s%s" % (self.describe(entry), "" if lifetime(entry) == "permanent"
                                                 else " (%s)" % lifetime(entry)))
        self.sync()
        entry["closed"] = self.close_matching(entry)
        return entry

    def update(self, ident, enabled=None, note=None):
        with self.lock:
            entries = self.list()
            hit = [e for e in entries if e["id"] == ident]
            if not hit:
                raise BlockError("no such block: %s" % ident)
            if enabled is not None:
                hit[0]["enabled"] = bool(enabled)
            if note is not None:
                hit[0]["note"] = str(note)[:200]
            self._save(entries)
        self.sync()
        if enabled:
            self.close_matching(hit[0])
        return hit[0]

    def remove(self, ids):
        with self.lock:
            entries = self.list()
            gone = [e for e in entries if e["id"] in set(ids)]
            self._save([e for e in entries if e["id"] not in set(ids)])
        if gone:
            self.m.log.add("info", "Unblocked %s" % ", ".join(self.describe(e) for e in gone))
        self.sync()
        return {"removed": [e["id"] for e in gone]}

    def expire(self):
        """Drop the temporary entries that ran out (called at start and every few seconds).  Returns how many."""
        with self.lock:
            entries = self.list()
            if not any(e.get("expires") or e.get("boot") for e in entries):
                return 0
            now, boot = time.time(), boot_id()
            gone = [e for e in entries if expired(e, now, boot)]
            if not gone:
                return 0
            self._save([e for e in entries if e not in gone])
        self.m.log.add("info", "Block ended: %s" % ", ".join(self.describe(e) for e in gone))
        self.sync()
        return len(gone)

    def set_enabled(self, flag):
        self._save(enabled=flag)
        self.sync()
        return self.status()

    @staticmethod
    def describe(e):
        proto = "" if e.get("proto", "any") == "any" else " (%s)" % e["proto"]
        return {"address": "address %s", "endpoint": "%s", "port": "port %s", "app": "program %s"}[e["kind"]] % e["value"] + proto

    # ---- enforcement
    def sync(self):
        """Make the firewall match the list (idempotent)."""
        with self.lock:
            cfg = self.cfg()
            entries = [e for e in cfg["entries"] if e.get("enabled", True)]
            ok, why = supported()
            self.error = ""
            if not cfg["enabled"] or not entries or not ok:
                self._remove()
                if entries and cfg["enabled"] and not ok:
                    self.error = why
                return
            need_apps = any(e["kind"] == "app" for e in entries)
            if need_apps:
                if split.cgroup_root():
                    try:
                        self.apps.begin()
                    except OSError as e:
                        self.error = "program blocking unavailable: %s" % e
                        need_apps = False
                else:
                    self.error = "blocking programs needs cgroup v2; addresses and ports still work"
                    need_apps = False
            else:
                self.apps.stop()
            usable = [e for e in entries if e["kind"] != "app" or need_apps]
            rc, out = plat.run([plat.which("nft") or "nft", "-f", "-"], input=ruleset(usable))
            if rc:
                self.active = False
                self.error = "nft: %s" % out.strip()
                self.m.log.add("error", "Blocked connections: %s" % self.error)
                return
            self.active = True

    def _remove(self):
        self.apps.stop()
        if self.active or cleanup():
            plat.run([plat.which("nft") or "nft", "delete", "table", "inet", NFT_TABLE])
        self.active = False

    def shutdown(self):
        with self.lock:
            self._remove()

    def status(self):
        ok, why = supported()
        cfg = self.cfg()
        return {"enabled": bool(cfg["enabled"]), "entries": list(cfg["entries"]), "active": self.active, "error": self.error,
                "supported": ok, "reason": why, "apps_supported": ok and bool(split.cgroup_root()),
                "apps_reason": "" if split.cgroup_root() else "blocking programs needs cgroup v2"}

    # ---- connections that are open right now
    def close_matching(self, entry):
        """Close the open connections that fall under ``entry``; returns how many were closed."""
        try:
            rows = conntable.snapshot(listening=False, local=False)["rows"]
        except Exception:  # noqa: BLE001
            return 0
        n = 0
        for row in rows:
            if row["dir"] != "listen" and row["rport"] and matches(entry, row):
                ok, _msg = close_connection(row)
                n += 1 if ok else 0
        return n

    def close_row(self, proto, local, lport, remote, rport):
        """Close one connection the user picked - but only if it really exists right now."""
        row = {"proto": str(proto), "local": str(local), "lport": int(lport), "remote": str(remote), "rport": int(rport)}
        if row["proto"] not in ("tcp", "udp"):
            raise BlockError("unknown protocol")
        for a in (row["local"], row["remote"]):
            ipaddress.ip_address(a)
        live = conntable.snapshot(listening=False, local=True)["rows"]
        if not any((r["proto"], r["local"], r["lport"], r["remote"], r["rport"]) ==
                   (row["proto"], row["local"], row["lport"], row["remote"], row["rport"]) for r in live):
            raise BlockError("that connection is already gone")
        ok, msg = close_connection(row)
        if not ok:
            raise BlockError(msg)
        return {"closed": True}
