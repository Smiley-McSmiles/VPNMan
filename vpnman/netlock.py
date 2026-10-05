"""Network lock ("kill switch").

While engaged, the host may only talk to: loopback, the VPN endpoint(s), the
tunnel interface(s), and optionally the LAN / DHCP / whitelisted addresses.
Everything else - including DNS - is dropped, so a dropped tunnel cannot leak.

Rule generation is pure (`Spec` -> text/commands) so it can be unit-tested
without privileges; the Firewall classes apply it with the native tool.
"""

import ipaddress
import os
import re

from . import paths
from . import platform as plat

LAN4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"]
LAN6 = ["fc00::/7", "fe80::/10", "ff00::/8"]
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,15}$")


class Spec:
    """Everything the firewall needs to know."""

    def __init__(self, endpoints=(), ifaces=(), allow_lan=True, allow_dhcp=True, allow_ping=False,
                 block_ipv6=True, whitelist_in=(), whitelist_out=()):
        self.endpoints = sorted({_norm(e) for e in endpoints})
        self.ifaces = sorted({i for i in ifaces if IFACE_RE.match(i)})
        self.allow_lan, self.allow_dhcp, self.allow_ping = allow_lan, allow_dhcp, allow_ping
        self.block_ipv6 = block_ipv6
        self.whitelist_in = sorted({_norm(e) for e in whitelist_in})
        self.whitelist_out = sorted({_norm(e) for e in whitelist_out})

    @classmethod
    def from_settings(cls, s, endpoints=(), ifaces=()):
        n = s.get("netlock")
        return cls(endpoints, ifaces, n["allow_lan"], n["allow_dhcp"], n["allow_ping"], n["block_ipv6"],
                   n["whitelist_in"], n["whitelist_out"])


def _norm(addr):
    """Validate an IP or CIDR; return it in canonical text form."""
    return str(ipaddress.ip_network(str(addr).strip(), strict=False))


def _split(addrs):
    v4 = [a for a in addrs if ":" not in a]
    v6 = [a for a in addrs if ":" in a]
    return v4, v6


# --------------------------------------------------------------------- nftables

def nft_ruleset(spec):
    ep4, ep6 = _split(spec.endpoints)
    wo4, wo6 = _split(spec.whitelist_out)
    wi4, wi6 = _split(spec.whitelist_in)
    ifs = ", ".join('"%s"' % i for i in spec.ifaces)
    out, inn = [], []
    out.append('oifname "lo" accept')
    inn.append('iifname "lo" accept')
    if spec.block_ipv6:
        out.append("meta nfproto ipv6 drop")
        inn.append("meta nfproto ipv6 drop")
    inn.append("ct state established,related accept")
    if ifs:
        out.append("oifname { %s } accept" % ifs)
        inn.append("iifname { %s } accept" % ifs)
    for fam, addrs in (("ip", ep4 + wo4), ("ip6", ep6 + wo6)):
        if addrs:
            out.append("%s daddr { %s } accept" % (fam, ", ".join(addrs)))
    for fam, addrs in (("ip", wi4), ("ip6", wi6)):
        if addrs:
            inn.append("%s saddr { %s } accept" % (fam, ", ".join(addrs)))
    if spec.allow_lan:
        out.append("ip daddr { %s } accept" % ", ".join(LAN4))
        inn.append("ip saddr { %s } accept" % ", ".join(LAN4))
        out.append("ip6 daddr { %s } accept" % ", ".join(LAN6))
        inn.append("ip6 saddr { %s } accept" % ", ".join(LAN6))
    if spec.allow_dhcp:
        out.append("udp sport 68 udp dport 67 accept")
        out.append("udp sport 546 udp dport 547 accept")
        inn.append("udp sport 67 udp dport 68 accept")
        inn.append("udp sport 547 udp dport 546 accept")
    if spec.allow_ping:
        out.append("icmp type echo-request accept")
        out.append("icmpv6 type echo-request accept")
        inn.append("icmp type echo-request accept")
        inn.append("icmpv6 type echo-request accept")
    body = ["table inet vpnman", "delete table inet vpnman", "table inet vpnman {"]
    for name, hook, rules in (("input", "input", inn), ("output", "output", out)):
        body.append("  chain %s {" % name)
        body.append("    type filter hook %s priority -100; policy drop;" % hook)
        body += ["    " + r for r in rules]
        body.append("  }")
    body.append("}")
    return "\n".join(body) + "\n"


class NftFirewall:
    name = "nftables"

    @staticmethod
    def usable():
        return plat.os_family() == "linux" and bool(plat.which("nft"))

    def apply(self, spec):
        rc, out = plat.run([plat.which("nft") or "nft", "-f", "-"], input=nft_ruleset(spec))
        if rc:
            raise RuntimeError("nft failed: " + out.strip())

    def remove(self):
        plat.run([plat.which("nft") or "nft", "delete", "table", "inet", "vpnman"])

    def active(self):
        rc, _ = plat.run([plat.which("nft") or "nft", "list", "table", "inet", "vpnman"])
        return rc == 0


# --------------------------------------------------------------------- iptables

def ipt_commands(spec, v6=False):
    """Return a list of argv lists (without the binary) that builds the chains."""
    ep, wo, wi = (_split(x)[1 if v6 else 0] for x in (spec.endpoints, spec.whitelist_out, spec.whitelist_in))
    lan = LAN6 if v6 else LAN4
    O, I = "VPNMAN_OUT", "VPNMAN_IN"
    c = [["-N", O], ["-N", I], ["-F", O], ["-F", I]]
    c.append(["-A", O, "-o", "lo", "-j", "ACCEPT"])
    c.append(["-A", I, "-i", "lo", "-j", "ACCEPT"])
    if spec.block_ipv6 and v6:
        c.append(["-A", O, "-j", "DROP"])
        c.append(["-A", I, "-j", "DROP"])
        return _ipt_wrap(c)
    c.append(["-A", I, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    for i in spec.ifaces:
        c.append(["-A", O, "-o", i, "-j", "ACCEPT"])
        c.append(["-A", I, "-i", i, "-j", "ACCEPT"])
    for a in ep + wo:
        c.append(["-A", O, "-d", a, "-j", "ACCEPT"])
    for a in wi:
        c.append(["-A", I, "-s", a, "-j", "ACCEPT"])
    if spec.allow_lan:
        for a in lan:
            c.append(["-A", O, "-d", a, "-j", "ACCEPT"])
            c.append(["-A", I, "-s", a, "-j", "ACCEPT"])
    if spec.allow_dhcp:
        if v6:
            c.append(["-A", O, "-p", "udp", "--sport", "546", "--dport", "547", "-j", "ACCEPT"])
            c.append(["-A", I, "-p", "udp", "--sport", "547", "--dport", "546", "-j", "ACCEPT"])
        else:
            c.append(["-A", O, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"])
            c.append(["-A", I, "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"])
    if spec.allow_ping:
        icmp = "icmpv6" if v6 else "icmp"
        c.append(["-A", O, "-p", icmp, "--%s-type" % icmp, "echo-request", "-j", "ACCEPT"])
        c.append(["-A", I, "-p", icmp, "--%s-type" % icmp, "echo-request", "-j", "ACCEPT"])
    return _ipt_wrap(c)


def _ipt_wrap(c):
    c.append(["-A", "VPNMAN_OUT", "-j", "DROP"])
    c.append(["-A", "VPNMAN_IN", "-j", "DROP"])
    return c


class IptFirewall:
    name = "iptables"

    @staticmethod
    def usable():
        return plat.os_family() == "linux" and bool(plat.which("iptables"))

    def _bins(self):
        bins = [plat.which("iptables")]
        if plat.which("ip6tables"):
            bins.append(plat.which("ip6tables"))
        return bins

    def _teardown(self):
        for b in self._bins():
            for chain, parent in (("VPNMAN_OUT", "OUTPUT"), ("VPNMAN_IN", "INPUT")):
                while plat.run([b, "-w", "-D", parent, "-j", chain])[0] == 0:
                    pass
                plat.run([b, "-w", "-F", chain])
                plat.run([b, "-w", "-X", chain])

    def apply(self, spec):
        self._teardown()
        try:
            for b in self._bins():
                v6 = "ip6" in os.path.basename(b)
                for args in ipt_commands(spec, v6):
                    rc, out = plat.run([b, "-w"] + args)
                    if rc and args[0] != "-N":
                        raise RuntimeError("%s %s: %s" % (os.path.basename(b), " ".join(args), out.strip()))
                for chain, parent in (("VPNMAN_OUT", "OUTPUT"), ("VPNMAN_IN", "INPUT")):
                    rc, out = plat.run([b, "-w", "-I", parent, "1", "-j", chain])
                    if rc:
                        raise RuntimeError(out.strip())
        except Exception:
            self._teardown()
            raise

    def remove(self):
        self._teardown()

    def active(self):
        rc, _ = plat.run([plat.which("iptables") or "iptables", "-w", "-n", "-L", "VPNMAN_OUT"])
        return rc == 0


# --------------------------------------------------------------------------- pf

def pf_ruleset(spec):
    ep4, ep6 = _split(spec.endpoints)
    wo4, wo6 = _split(spec.whitelist_out)
    wi4, wi6 = _split(spec.whitelist_in)
    r = ["set skip on lo", "block drop all"]
    if spec.block_ipv6:
        r.append("block drop quick inet6 all")
    for i in spec.ifaces:
        r.append("pass out quick on %s all" % i)
        r.append("pass in quick on %s all" % i)
    for fam, addrs in (("inet", ep4 + wo4), ("inet6", ep6 + wo6)):
        if addrs:
            r.append("pass out quick %s to { %s }" % (fam, " ".join(addrs)))
    for fam, addrs in (("inet", wi4), ("inet6", wi6)):
        if addrs:
            r.append("pass in quick %s from { %s }" % (fam, " ".join(addrs)))
    if spec.allow_lan:
        r.append("pass out quick inet to { %s }" % " ".join(LAN4))
        r.append("pass in quick inet from { %s }" % " ".join(LAN4))
        r.append("pass out quick inet6 to { %s }" % " ".join(LAN6))
        r.append("pass in quick inet6 from { %s }" % " ".join(LAN6))
    if spec.allow_dhcp:
        r.append("pass out quick inet proto udp from port 68 to port 67")
        r.append("pass in quick inet proto udp from port 67 to port 68")
        r.append("pass out quick inet6 proto udp from port 546 to port 547")
        r.append("pass in quick inet6 proto udp from port 547 to port 546")
    if spec.allow_ping:
        r.append("pass quick inet proto icmp icmp-type echoreq")
        r.append("pass quick inet6 proto icmp6 icmp6-type echoreq")
    return "\n".join(r) + "\n"


class PfFirewall:
    """OpenBSD/FreeBSD/macOS pf.  Loads a complete lock ruleset and restores
    /etc/pf.conf (or disables pf if it was off) on removal."""

    name = "pf"

    @staticmethod
    def usable():
        return plat.os_family() in ("openbsd", "freebsd", "netbsd", "darwin") and bool(plat.which("pfctl"))

    def _state_path(self):
        return os.path.join(paths.run_dir(), "pf.was_enabled")

    def apply(self, spec):
        pfctl = plat.which("pfctl")
        os.makedirs(paths.run_dir(), mode=0o755, exist_ok=True)
        if not os.path.exists(self._state_path()):
            rc, out = plat.run([pfctl, "-s", "info"])
            with open(self._state_path(), "w") as fh:
                fh.write("1" if "Status: Enabled" in out else "0")
        rules = os.path.join(paths.run_dir(), "pf-lock.conf")
        fd = os.open(rules, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(pf_ruleset(spec))
        rc, out = plat.run([pfctl, "-f", rules])
        if rc:
            raise RuntimeError("pfctl: " + out.strip())
        plat.run([pfctl, "-e"])

    def remove(self):
        pfctl = plat.which("pfctl")
        try:
            with open(self._state_path()) as fh:
                was = fh.read().strip() == "1"
        except OSError:
            return
        if was:
            plat.run([pfctl, "-f", "/etc/pf.conf"])
        else:
            plat.run([pfctl, "-d"])
        os.unlink(self._state_path())

    def active(self):
        return os.path.exists(self._state_path())


BACKENDS = {"nftables": NftFirewall, "iptables": IptFirewall, "pf": PfFirewall}


def pick_backend(name="auto"):
    if name != "auto":
        cls = BACKENDS.get(name)
        if not cls or not cls.usable():
            raise RuntimeError("firewall backend '%s' is not available on this system" % name)
        return cls()
    for cls in (NftFirewall, PfFirewall, IptFirewall):
        if cls.usable():
            return cls()
    raise RuntimeError("no supported firewall found (need nft, iptables or pf)")
