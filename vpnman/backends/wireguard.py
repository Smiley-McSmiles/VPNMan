import ipaddress
import re

from .. import platform as plat
from .base import Backend

_AMNEZIA_KEYS = re.compile(r"^\s*(Jc|Jmin|Jmax|S1|S2|H1|H2|H3|H4)\s*=", re.M)


def parse_wg(text):
    """Parse a wg-quick config into ({iface keys}, [peer dicts]); keys lower-cased."""
    iface, peers, cur = {}, [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower() == "[interface]":
            cur = iface
        elif line.lower() == "[peer]":
            cur = {}
            peers.append(cur)
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            if k in cur and k in ("address", "dns", "allowedips"):
                cur[k] += "," + v
            else:
                cur[k] = v
    return iface, peers


def split_endpoint(ep):
    if ep.startswith("["):
        host, _, port = ep[1:].partition("]:")
        return host, int(port or 0)
    host, _, port = ep.rpartition(":")
    return host, int(port or 0)


class WireGuard(Backend):
    id = "wireguard"
    label = "WireGuard"
    description = "WireGuard (kernel or userspace) - wg-quick .conf files"
    binaries = ("wg",)
    extensions = (".conf",)
    mode = "oneshot"
    named_iface = True
    quick = "wg-quick"
    fields = ()

    @classmethod
    def sniff(cls, filename, text):
        if not re.search(r"^\s*\[Interface\]", text, re.M | re.I):
            return 0
        if _AMNEZIA_KEYS.search(text):
            return 0 if cls.id == "wireguard" else 95
        return 90 if cls.id == "wireguard" else 0

    def parse(self, filename, text):
        iface, peers = parse_wg(text)
        out = {"options": {}}
        eps = []
        for p in peers:
            if "endpoint" in p:
                h, port = split_endpoint(p["endpoint"])
                eps.append([h, port, "udp"])
        if eps:
            out["server"], out["port"], out["transport"] = eps[0]
            out["options"]["remotes"] = eps
        if "dns" in iface:
            out["dns"] = [d.strip() for d in iface["dns"].split(",")
                          if _is_ip(d.strip())]
        return out

    def missing(self):
        miss = []
        if not plat.which(self.binaries[0]):
            miss.append(self.binaries[0])
        if not plat.which(self.quick) and not self._native():
            miss.append(self.quick)
        return miss

    def _native(self):
        return self.id == "wireguard" and plat.os_family() == "openbsd"

    def validate(self, profile):
        problems = super().validate(profile)
        if not profile.get("config"):
            problems.append("profile has no WireGuard config")
        return problems

    # ---- runtime
    def prepare(self, ctx):
        with open("%s/%s" % (ctx.profile_dir, ctx.profile["config"]), errors="replace") as fh:
            text = fh.read()
        res = ctx.state.get("resolved", {})

        def sub(m):
            host, port = split_endpoint(m.group(2).strip())
            ip = res.get(host)
            if not ip:
                return m.group(0)
            return "%s%s" % (m.group(1), ("[%s]:%d" if ":" in ip else "%s:%d") % (ip, port))

        # pre-resolved endpoints keep wg from needing DNS under the kill switch
        text = re.sub(r"^(\s*Endpoint\s*=\s*)(.+)$", sub, text, flags=re.M | re.I)
        fwd = ctx.state.get("xray_fwd")
        if fwd:
            # a proxy (Xray) in front of the VPN: the peer is reached through the local UDP forwarder
            text = re.sub(r"^(\s*Endpoint\s*=\s*)(.+)$", lambda m: "%s127.0.0.1:%d" % (m.group(1), fwd["port"]),
                          text, flags=re.M | re.I)
        if self._native():
            ctx.state["conf"] = text
            return
        # wg-quick calls resolvconf for "DNS =" - we manage DNS ourselves, so drop it.
        kept = [l for l in text.splitlines() if not re.match(r"^\s*DNS\s*=", l, re.I)]
        ctx.state["path"] = ctx.write("%s.conf" % ctx.ifname, "\n".join(kept) + "\n")

    def connect_cmds(self, ctx):
        if self._native():
            return self._bsd_up(ctx)
        return [[self.binary(self.quick), "up", ctx.state["path"]]]

    def disconnect_cmds(self, ctx):
        if self._native():
            cmds = [["ifconfig", ctx.ifname, "destroy"]]
            for h in ctx.state.get("hostroutes", []):
                cmds.append(["route", "-q", "delete", "-host", h])
            return cmds
        return [[self.binary(self.quick), "down", ctx.state["path"]]]

    def connect_cmd(self, ctx):
        return self.connect_cmds(ctx)[0]

    def _bsd_up(self, ctx):
        """OpenBSD has wg(4) in the kernel but no wg-quick; configure with ifconfig(8)."""
        iface, peers = parse_wg(ctx.state["conf"])
        n = ctx.ifname
        cmd = ["ifconfig", n, "create"]
        if "listenport" in iface:
            cmd += ["wgport", iface["listenport"]]
        cmd += ["wgkey", iface.get("privatekey", "")]
        cmds = [cmd]
        gw, _ = plat.default_gateway()
        routes, hostroutes = [], []
        for p in peers:
            pc = ["ifconfig", n, "wgpeer", p.get("publickey", "")]
            if "endpoint" in p:
                h, port = split_endpoint(p["endpoint"])
                pc += ["wgendpoint", h, str(port)]
                if gw and _is_ip(h) and not h.startswith("127."):
                    hostroutes.append(h)
                    cmds.append(["route", "-q", "add", "-host", h, gw])
            if "presharedkey" in p:
                pc += ["wgpsk", p["presharedkey"]]
            if "persistentkeepalive" in p:
                pc += ["wgpka", p["persistentkeepalive"]]
            for aip in p.get("allowedips", "").split(","):
                aip = aip.strip()
                if aip:
                    pc += ["wgaip", aip]
                    routes.append(aip)
            cmds.append(pc)
        addr = None
        for a in iface.get("address", "").split(","):
            a = a.strip()
            if not a:
                continue
            fam = "inet6" if ":" in a else "inet"
            cmds.append(["ifconfig", n, fam, a])
            if fam == "inet" and not addr:
                addr = a.split("/")[0]
        if "mtu" in iface:
            cmds.append(["ifconfig", n, "mtu", iface["mtu"]])
        cmds.append(["ifconfig", n, "up"])
        for r in routes:
            fam = "-inet6" if ":" in r else "-inet"
            if fam == "-inet" and addr:
                if r.endswith("/0"):
                    cmds.append(["route", "-q", "add", fam, "0.0.0.0/1", addr])
                    cmds.append(["route", "-q", "add", fam, "128.0.0.0/1", addr])
                else:
                    cmds.append(["route", "-q", "add", fam, r, addr])
        ctx.state["hostroutes"] = hostroutes
        ctx.iface = n
        return cmds

    def parse_line(self, line, ctx):
        m = re.search(r"interface:\s+(\S+)", line)
        if m:
            ctx.iface = m.group(1)


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class AmneziaWG(WireGuard):
    id = "amneziawg"
    label = "AmneziaWG"
    description = "AmneziaWG - obfuscated WireGuard fork (awg-quick)"
    binaries = ("awg",)
    quick = "awg-quick"
