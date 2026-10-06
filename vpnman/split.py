"""Per-application split tunnelling ("VPN bypass" whitelist).

Linux only.  Whitelisted programs - and everything they start - are moved into a dedicated cgroup (v2).  nftables
marks that cgroup's packets, a policy-routing rule sends marked packets out through the physical gateway instead of
the tunnel, and the kill switch lets the marked traffic through.  A background scan finds running programs by name
(and their children), so nothing has to be started in a special way.

The rule generation and process matching are pure functions so they can be tested without privileges.
"""

import ipaddress
import os
import threading
import time

from . import platform as plat

MARK = 0x5652
TABLE = 5652
PRIORITY = 80
CGROUP = "vpnman-bypass"
NFT_TABLE = "vpnman_split"
SCAN_INTERVAL = 2.0


# ----------------------------------------------------------------- rules (pure)

def ruleset(dns=(), mark=MARK, cgroup=CGROUP):
    """nftables text.  `dns`: resolvers the bypassed programs should use instead of the tunnel's."""
    sock = 'socket cgroupv2 level 1 "%s"' % cgroup
    v4 = []
    for d in dns:
        try:
            if ipaddress.ip_address(d).version == 4:
                v4.append(str(d))
        except ValueError:
            continue
    lines = ["table inet %s" % NFT_TABLE, "delete table inet %s" % NFT_TABLE, "table inet %s {" % NFT_TABLE,
             "  chain bypass_mark {", "    type route hook output priority -150; policy accept;",
             "    %s meta mark set 0x%x ct mark set 0x%x" % (sock, mark, mark), "  }"]
    if v4:
        target = v4[0]
        lines += ["  chain bypass_dns {", "    type nat hook output priority -100; policy accept;"]
        for proto in ("udp", "tcp"):
            lines.append("    %s %s dport 53 ip daddr != 127.0.0.0/8 ip daddr != %s dnat ip to %s"
                         % (sock, proto, target, target))
        lines.append("  }")
    lines += ["  chain bypass_post {", "    type nat hook postrouting priority 100; policy accept;",
              '    meta mark 0x%x oifname != "lo" masquerade' % mark, "  }", "}"]
    return "\n".join(lines) + "\n"


def route_commands(gw, dev, link_routes=(), table=TABLE, mark=MARK, priority=PRIORITY):
    """`ip` commands (argv lists, without the binary) that build the bypass routing table."""
    cmds = [["route", "flush", "table", str(table)]]
    for r in link_routes:
        cmds.append(["route", "add", r, "dev", dev, "table", str(table)])
    cmds.append(["route", "add", "default"] + (["via", gw] if gw else []) + ["dev", dev, "table", str(table)])
    cmds.append(["rule", "add", "fwmark", "0x%x" % mark, "lookup", str(table), "priority", str(priority)])
    return cmds


def rule_fix(rules_text, mark=MARK, table=TABLE):
    """(old, new) priorities when another rule would be consulted before ours, else None.

    `ip rule show` text in.  VPN tools (wg-quick) add their rules *below* the lowest-numbered rule that exists when
    they run, so a bypass rule created earlier ends up behind theirs and marked traffic is pulled into the tunnel."""
    ours, others = None, []
    for line in rules_text.splitlines():
        head, _, body = line.partition(":")
        if not head.strip().isdigit():
            continue
        pref = int(head)
        if "fwmark 0x%x" % mark in body and ("lookup %d" % table) in body:
            ours = pref
        elif pref > 0:
            others.append(pref)
    if ours is None or not others or ours < min(others):
        return None
    new = min(others) - 1
    return (ours, new) if new >= 1 else None


# --------------------------------------------------------------- process matching

def _stat(proc, pid):
    """(comm, ppid) from /proc/<pid>/stat, or None.  comm may contain spaces and parentheses."""
    try:
        with open(os.path.join(proc, str(pid), "stat"), "rb") as fh:
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    lp, rp = raw.find("("), raw.rfind(")")
    if lp < 0 or rp < lp:
        return None
    rest = raw[rp + 2:].split()
    try:
        return raw[lp + 1:rp], int(rest[1])
    except (IndexError, ValueError):
        return None


def _argv(proc, pid):
    try:
        with open(os.path.join(proc, str(pid), "cmdline"), "rb") as fh:
            return [a.decode("utf-8", "replace") for a in fh.read(4096).split(b"\0") if a]
    except OSError:
        return []


def _names_of(proc, pid, comm, argv):
    names = {comm}
    if argv:
        a0 = os.path.basename(argv[0].split(" ")[0] if argv[0].startswith("/") and " " in argv[0] else argv[0])
        names.add(a0)
        if a0 in ("sh", "bash", "dash", "zsh", "env", "python3", "python", "perl", "ruby", "java", "node", "wine",
                  "wine64", "gamemoderun", "mangohud", "gamescope") or a0.startswith("python3."):
            for a in argv[1:4]:
                if not a.startswith("-"):
                    names.add(os.path.basename(a))
                    break
        elif a0 in ("bwrap", "flatpak", "snap", "firejail"):
            names.update(os.path.basename(a) for a in argv[1:12])
    try:
        names.add(os.path.basename(os.readlink(os.path.join(proc, str(pid), "exe"))).replace(" (deleted)", ""))
    except OSError:
        pass
    return names


def matching_pids(wanted, proc="/proc", skip=()):
    """PIDs whose program is in `wanted` (names), plus all of their descendants."""
    wanted = {w for w in wanted if w}
    if not wanted:
        return set()
    short = {w[:15] for w in wanted}
    procs, children = {}, {}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        pid = int(entry)
        st = _stat(proc, pid)
        if st:
            procs[pid] = st
            children.setdefault(st[1], []).append(pid)
    me = os.getpid()
    hits = set()
    for pid, (comm, _pp) in procs.items():
        if pid == me or pid in skip:
            continue
        if comm in wanted or comm in short:
            hits.add(pid)
            continue
        argv = _argv(proc, pid)
        names = _names_of(proc, pid, comm, argv)
        if names & wanted or {n[:15] for n in names} & short:
            hits.add(pid)
    out, todo = set(), list(hits)
    while todo:
        p = todo.pop()
        if p in out or p == me or p in skip:
            continue
        out.add(p)
        todo.extend(children.get(p, ()))
    return out


# ------------------------------------------------------------------ runtime

def cgroup_root():
    """/sys/fs/cgroup when it is the pure cgroup v2 hierarchy - nftables resolves `socket cgroupv2` paths against
    exactly that directory, so a hybrid layout (v2 under /sys/fs/cgroup/unified) cannot be used."""
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                f = line.split()
                if len(f) > 2 and f[2] == "cgroup2" and f[1] == "/sys/fs/cgroup":
                    return f[1]
    except OSError:
        pass
    return None


def cleanup():
    """Remove leftovers of a crashed daemon.  Safe to call at any time."""
    nft, ip = plat.which("nft"), plat.which("ip")
    if nft:
        plat.run([nft, "delete", "table", "inet", NFT_TABLE])
    if ip and plat.os_family() == "linux":
        while plat.run([ip, "rule", "del", "fwmark", "0x%x" % MARK, "lookup", str(TABLE)])[0] == 0:
            pass
        plat.run([ip, "route", "flush", "table", str(TABLE)])
    root = cgroup_root()
    if root and os.path.isdir(os.path.join(root, CGROUP)):
        try:
            with open(os.path.join(root, CGROUP, "cgroup.procs")) as fh:
                pids = fh.read().split()
            for pid in pids:
                with open(os.path.join(root, "cgroup.procs"), "w") as out:
                    out.write(pid)
            os.rmdir(os.path.join(root, CGROUP))
        except OSError:
            pass


def supported():
    """(ok, reason)."""
    if plat.os_family() != "linux":
        return False, "app bypass needs Linux (cgroups, nftables and policy routing)"
    if not plat.which("nft"):
        return False, "app bypass needs nftables (nft)"
    if not plat.which("ip"):
        return False, "app bypass needs iproute2 (ip)"
    if not cgroup_root():
        return False, "app bypass needs cgroup v2 (boot without systemd.unified_cgroup_hierarchy=0)"
    return True, ""


class SplitTunnel:
    def __init__(self, names_fn, log=None, proc="/proc", root=None):
        self.names_fn = names_fn
        self.log = log or (lambda level, msg: None)
        self.proc = proc
        self.root = root                    # cgroup mount override (tests)
        self.active = False
        self.moved = {}                     # pid -> original cgroup path
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._rules = False

    @property
    def path(self):
        root = self.root or cgroup_root()
        return os.path.join(root, CGROUP) if root else None

    def start(self, gw, dev, dns=()):
        ok, why = supported()
        if not ok:
            raise RuntimeError(why)
        if not dev:
            raise RuntimeError("no physical network interface to bypass through")
        with self._lock:
            self.stop_locked()
            os.makedirs(self.path, exist_ok=True)
            rc, out = plat.run([plat.which("nft"), "-f", "-"], input=ruleset(dns))
            if rc:
                try:
                    os.rmdir(self.path)                  # do not leave the empty cgroup behind
                except OSError:
                    pass
                raise RuntimeError("nft: " + out.strip())
            self._rules = True
            plat.run([plat.which("ip"), "rule", "del", "fwmark", "0x%x" % MARK, "lookup", str(TABLE)])
            link = []
            rc, out = plat.run([plat.which("ip"), "-4", "route", "show", "dev", dev, "scope", "link"])
            if rc == 0:
                link = [ln.split()[0] for ln in out.splitlines() if ln.split()]
            for cmd in route_commands(gw, dev, link):
                rc, out = plat.run([plat.which("ip")] + cmd)
                if rc and cmd[0] == "route" and cmd[1] == "add" and cmd[2] != "default":
                    continue                                  # a duplicate link route is harmless
                if rc and cmd[1] != "flush":
                    self.stop_locked()
                    raise RuntimeError("ip %s: %s" % (" ".join(cmd), out.strip()))
            self.active = True
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._loop, args=(self._stop,), daemon=True, name="split-scan")
            self._thread.start()

    def stop(self):
        with self._lock:
            self.stop_locked()

    def stop_locked(self):
        self._stop.set()
        t = self._thread
        self._thread = None
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(3)
        self.active = False
        self._release()
        nft, ip = plat.which("nft"), plat.which("ip")
        if self._rules and nft:
            plat.run([nft, "delete", "table", "inet", NFT_TABLE])
        if self._rules and ip:
            while plat.run([ip, "rule", "del", "fwmark", "0x%x" % MARK, "lookup", str(TABLE)])[0] == 0:
                pass
            plat.run([ip, "route", "flush", "table", str(TABLE)])
        self._rules = False
        if self.path and os.path.isdir(self.path):
            try:
                os.rmdir(self.path)
            except OSError:
                pass

    def ensure_rule_first(self):
        """Keep our policy rule ahead of every other one (see rule_fix)."""
        ip = plat.which("ip")
        if not ip or not self.active:
            return
        rc, out = plat.run([ip, "-4", "rule", "show"])
        fix = rule_fix(out) if rc == 0 else None
        if not fix:
            return
        old, new = fix
        sel = ["fwmark", "0x%x" % MARK, "lookup", str(TABLE)]
        rc, msg = plat.run([ip, "rule", "add"] + sel + ["priority", str(new)])
        if rc:
            self.log("warn", "App bypass: could not reorder the routing rule: %s" % msg.strip())
            return
        plat.run([ip, "rule", "del"] + sel + ["priority", str(old)])
        self.log("info", "App bypass: moved its routing rule ahead of the VPN's (priority %d -> %d)" % (old, new))

    # -- process handling
    def _cgroup_of(self, pid):
        try:
            with open(os.path.join(self.proc, str(pid), "cgroup")) as fh:
                for line in fh:
                    if line.startswith("0::"):
                        return line[3:].strip()
        except OSError:
            pass
        return None

    def _move(self, pid, target):
        try:
            with open(os.path.join(target, "cgroup.procs"), "w") as fh:
                fh.write(str(pid))
            return True
        except OSError:
            return False

    def scan_once(self):
        names = self.names_fn()
        path = self.path
        if not path:
            return []
        added = []
        for pid in matching_pids(names, self.proc):
            cur = self._cgroup_of(pid)
            if cur is None or cur.rstrip("/").endswith("/" + CGROUP) or cur == "/" + CGROUP:
                continue
            if self._move(pid, path):
                self.moved.setdefault(pid, cur)
                added.append(pid)
        if added:
            self.log("debug", "App bypass: moved %d process(es) out of the VPN" % len(added))
        return added

    def _release(self):
        """Put every process we moved back where it came from."""
        root = self.root or cgroup_root()
        for pid, orig in list(self.moved.items()):
            if root and self._cgroup_of(pid):
                dest = os.path.join(root, orig.lstrip("/"))
                if not os.path.isdir(dest) or not self._move(pid, dest):
                    self._move(pid, root)
        self.moved.clear()
        # children forked since the last scan are still in our cgroup: hand them to the root cgroup
        path = self.path
        if path and root:
            try:
                with open(os.path.join(path, "cgroup.procs")) as fh:
                    for line in fh.read().split():
                        self._move(line, root)
            except OSError:
                pass

    def _loop(self, stop):
        while not stop.is_set():
            try:
                self.ensure_rule_first()
                self.scan_once()
            except Exception as e:  # noqa: BLE001
                self.log("warn", "App bypass scan failed: %s" % e)
            stop.wait(SCAN_INTERVAL)


def names_from_settings(split):
    out = []
    for a in split.get("apps", []):
        for m in a.get("match", []):
            if isinstance(m, str) and m and m not in out:
                out.append(m)
    return out
