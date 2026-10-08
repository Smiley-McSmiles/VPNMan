"""A snapshot of this machine's network connections: which application, which port, which protocol, which way.

Linux reads /proc/net/{tcp,tcp6,udp,udp6} and maps every socket to its process through /proc/<pid>/fd (the daemon
runs as root, so it sees all applications).  FreeBSD uses ``sockstat``; other BSDs fall back to ``netstat`` and show
no application names.
"""

import ipaddress
import os
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import platform as plat

TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
              "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
HIDDEN_STATES = ("TIME_WAIT", "CLOSE")          # nobody owns them any more
LIMIT = 2000


def _addr(hexaddr, v6):
    raw = bytes.fromhex(hexaddr)
    if v6:
        raw = b"".join(struct.pack("<I", struct.unpack(">I", raw[i:i + 4])[0]) for i in range(0, 16, 4))
        ip = ipaddress.IPv6Address(raw)
        return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)
    return socket.inet_ntoa(raw[::-1])


def parse_proc_net(text, proto, v6):
    """Rows of one /proc/net file: [{proto, v6, local, lport, remote, rport, state, inode}]."""
    rows = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            la, lp = f[1].split(":")
            ra, rp = f[2].split(":")
            rows.append({"proto": proto, "v6": v6, "local": _addr(la, v6), "lport": int(lp, 16),
                         "remote": _addr(ra, v6), "rport": int(rp, 16),
                         "state": TCP_STATES.get(f[3].upper(), f[3]) if proto == "tcp" else "", "inode": int(f[9])})
        except ValueError:
            continue
    return rows


def socket_owners(proc="/proc"):
    """{socket inode: (pid, name)} for every process we are allowed to look at."""
    owners = {}
    try:
        pids = [e for e in os.listdir(proc) if e.isdigit()]
    except OSError:
        return owners
    for pid in pids:
        fddir = "%s/%s/fd" % (proc, pid)
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        name = None
        for fd in fds:
            try:
                link = os.readlink("%s/%s" % (fddir, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                if name is None:
                    try:
                        with open("%s/%s/comm" % (proc, pid)) as fh:
                            name = fh.read().strip() or "?"
                    except OSError:
                        name = "?"
                owners[int(link[8:-1])] = (int(pid), name)
    return owners


def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def classify(rows):
    """Add ``dir`` (in / out / listen) and the display state.  A TCP connection is inbound when it was accepted by a
    local listener; an unconnected UDP socket is a listener; a connected UDP socket is outbound."""
    listening = {(r["proto"], r["lport"]) for r in rows if r["proto"] == "tcp" and r["state"] == "LISTEN"}
    out = []
    for r in rows:
        if r["proto"] == "tcp":
            if r["state"] == "LISTEN":
                d = "listen"
            elif ("tcp", r["lport"]) in listening:
                d = "in"
            else:
                d = "out"
            state = r["state"]
        else:
            unconnected = r["rport"] == 0 or r["remote"] in ("0.0.0.0", "::")
            d, state = ("listen", "") if unconnected else ("out", "")
        out.append(dict(r, dir=d, state=state))
    return out


class Resolver:
    """Reverse DNS for the Remote column.  Lookups can take seconds, so they run in a few worker threads and the
    answer shows up in a later snapshot; results (and failures) are cached.  Nothing is looked up unless asked for."""
    TTL, NEG_TTL, MAX = 600, 120, 4096

    def __init__(self, lookup=None, sync=False):
        self.lookup = lookup or self._gethostbyaddr
        self.sync = sync                          # tests: do the lookup in the calling thread
        self._cache, self._pending = {}, set()
        self._lock = threading.Lock()
        self._pool = None

    @staticmethod
    def _gethostbyaddr(ip):
        return socket.gethostbyaddr(ip)[0]

    @staticmethod
    def eligible(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (a.is_loopback or a.is_unspecified or a.is_multicast)

    def names(self, ips):
        """{ip: host name} for what is known now; unknown addresses are queued."""
        now, out = time.time(), {}
        for ip in set(ips):
            if not self.eligible(ip):
                continue
            with self._lock:
                hit = self._cache.get(ip)
            if hit and hit[1] > now:
                if hit[0]:
                    out[ip] = hit[0]
                continue
            if hit and hit[0]:
                out[ip] = hit[0]                  # stale but better than nothing while it is refreshed
            self._queue(ip)
            if self.sync:
                with self._lock:
                    hit = self._cache.get(ip)
                if hit and hit[0]:
                    out[ip] = hit[0]
        return out

    def _queue(self, ip):
        with self._lock:
            if ip in self._pending:
                return
            self._pending.add(ip)
            if not self.sync and self._pool is None:
                self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="rdns")
        if self.sync:
            self._work(ip)
        else:
            self._pool.submit(self._work, ip)

    def _work(self, ip):
        try:
            name = str(self.lookup(ip) or "").rstrip(".")
        except (OSError, ValueError, UnicodeError):
            name = ""
        with self._lock:
            if len(self._cache) >= self.MAX:
                self._cache.clear()
            self._cache[ip] = (name, time.time() + (self.TTL if name else self.NEG_TTL))
            self._pending.discard(ip)


RESOLVER = Resolver()


def snapshot(listening=False, local=False, limit=LIMIT, proc="/proc", resolve=False):
    """{"rows": [...], "supported": bool, "note": str, "truncated": bool}.  ``listening``: include sockets that wait
    for connections; ``local``: include connections that never leave this machine (loopback)."""
    fam = plat.os_family()
    note = ""
    if fam == "linux":
        rows = []
        for name, proto, v6 in (("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False),
                                ("udp6", "udp", True)):
            try:
                with open("%s/net/%s" % (proc, name)) as fh:
                    rows += parse_proc_net(fh.read(), proto, v6)
            except OSError:
                continue
        owners = socket_owners(proc)
        for r in rows:
            pid, app = owners.get(r.pop("inode"), (0, ""))
            r["pid"], r["app"] = pid, app
    elif fam == "freebsd":
        rows = _sockstat()
    else:
        rows, note = _netstat(), "this system does not tell which application owns a connection"
    rows = classify(rows)
    res = []
    for r in rows:
        if r["state"] in HIDDEN_STATES:
            continue
        if r["dir"] == "listen" and not listening:
            continue
        if not local and is_loopback(r["local"]) and (r["dir"] == "listen" or is_loopback(r["remote"])):
            continue
        res.append(r)
    res.sort(key=lambda r: ((r["app"] or "~").lower(), r["dir"], r["lport"], r["rport"]))
    truncated = len(res) > limit
    res = res[:limit]
    if resolve:
        names = RESOLVER.names(r["remote"] for r in res if r["rport"])
        for r in res:
            r["rname"] = names.get(r["remote"], "")
    return {"rows": res, "supported": bool(rows) or fam == "linux", "note": note, "truncated": truncated}


CSV_FIELDS = ("direction", "application", "pid", "protocol", "ip_version", "local_address", "local_port",
              "remote_address", "remote_port", "remote_name", "state")


def to_csv(rows):
    """The rows as CSV text with a header line (spreadsheet friendly; values that look like formulas are quoted
    with a leading apostrophe so a spreadsheet does not run them)."""
    import csv
    import io

    def safe(v):
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@") and not re.match(r"^-?\d", v) else v
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_FIELDS)
    for r in rows:
        w.writerow([safe(x) for x in (r.get("dir"), r.get("app"), r.get("pid") or "", r.get("proto"),
                                      6 if r.get("v6") else 4, r.get("local"), r.get("lport"),
                                      r.get("remote") if r.get("rport") else "", r.get("rport") or "",
                                      r.get("rname", ""), r.get("state"))])
    return buf.getvalue()


# ---------------------------------------------------------------------- BSD

def _split_hostport(text):
    """'1.2.3.4:80', '1.2.3.4.80' (BSD), '::1.443', '*:22' -> (host, port)."""
    text = text.strip()
    if text in ("*:*", "*.*"):
        return "*", 0
    m = re.match(r"^(.*)[:.](\d+)$", text)
    return (m.group(1), int(m.group(2))) if m else (text, 0)


def _sockstat():
    rc, out = plat.run(["sockstat", "-46", "-s"], timeout=10)
    rows = []
    if rc:
        return rows
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 7 or not f[2].isdigit() or f[4] not in ("tcp4", "tcp6", "udp4", "udp6"):
            continue
        try:
            lh, lp = _split_hostport(f[5])
            rh, rp = _split_hostport(f[6])
        except ValueError:
            continue
        rows.append({"proto": f[4][:3], "v6": f[4].endswith("6"), "local": lh, "lport": lp, "remote": rh, "rport": rp,
                     "state": (f[7] if len(f) > 7 else ("LISTEN" if rp == 0 and f[4].startswith("tcp") else "")).upper(),
                     "pid": int(f[2]), "app": f[1]})
    return rows


def _netstat():
    rc, out = plat.run(["netstat", "-an"], timeout=10)
    rows = []
    if rc:
        return rows
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or not re.match(r"^(tcp|udp)[46]?$", f[0]):
            continue
        proto = f[0][:3]
        try:
            lh, lp = _split_hostport(f[3])
            rh, rp = _split_hostport(f[4])
        except ValueError:
            continue
        rows.append({"proto": proto, "v6": f[0].endswith("6"), "local": lh, "lport": lp, "remote": rh, "rport": rp,
                     "state": (f[5] if len(f) > 5 else "").upper(), "pid": 0, "app": ""})
    return rows
