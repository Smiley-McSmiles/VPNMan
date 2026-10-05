import re

from .. import stunnel
from .base import Backend

_REMOTE = re.compile(r"^\s*remote\s+(\S+)(?:\s+(\d+))?(?:\s+(udp6?|tcp6?(?:-client)?))?", re.M | re.I)


class OpenVPN(Backend):
    id = "openvpn"
    label = "OpenVPN"
    description = "OpenVPN (TLS, UDP/TCP) - .ovpn profiles"
    binaries = ("openvpn",)
    extensions = (".ovpn",)
    ready_re = re.compile(r"Initialization Sequence Completed")
    named_iface = True
    fields = ("username", "password", "key_password")

    @classmethod
    def sniff(cls, filename, text):
        score = 0
        if filename.lower().endswith(".ovpn"):
            score += 60
        if re.search(r"^\s*client\s*$", text, re.M):
            score += 20
        if _REMOTE.search(text):
            score += 20
        if re.search(r"^\[Interface\]", text, re.M | re.I):
            return 0
        return min(score, 100)

    def parse(self, filename, text):
        remotes = []
        default_proto = "udp"
        m = re.search(r"^\s*proto\s+(\S+)", text, re.M)
        if m:
            default_proto = m.group(1)
        default_port = 1194
        m = re.search(r"^\s*(?:port|rport)\s+(\d+)", text, re.M)
        if m:
            default_port = int(m.group(1))
        for host, port, proto in _REMOTE.findall(text):
            remotes.append([host, int(port) if port else default_port, (proto or default_proto).lower()])
        out = {"options": {"remotes": remotes}}
        if remotes:
            out["server"], out["port"], out["transport"] = remotes[0][0], remotes[0][1], remotes[0][2]
        return out

    def validate(self, profile):
        problems = super().validate(profile) + stunnel.validate(profile)
        if not profile.get("config"):
            problems.append("profile has no OpenVPN config")
        return problems

    def endpoints(self, profile):
        wrapped = stunnel.endpoint(profile)
        return wrapped or super().endpoints(profile)

    def iface_prefix(self, profile, profile_dir):
        try:
            with open("%s/%s" % (profile_dir, profile["config"]), errors="replace") as fh:
                return self._dev(fh.read())
        except (OSError, KeyError):
            return "tun"

    def _dev(self, text):
        m = re.search(r"^\s*dev\s+(tun|tap)", text, re.M)
        return m.group(1) if m else "tun"

    def prepare(self, ctx):
        """Write a runtime copy whose ``remote`` hosts are already resolved, so
        OpenVPN never needs DNS while the kill switch is up."""
        with open("%s/%s" % (ctx.profile_dir, ctx.profile["config"]), errors="replace") as fh:
            text = fh.read()
        res = ctx.state.get("resolved", {})

        def sub(m):
            ip = res.get(m.group(2))
            return m.group(1) + ip + m.group(3) if ip else m.group(0)

        text = re.sub(r"^(\s*remote\s+)(\S+)(.*)$", sub, text, flags=re.M)
        tun = ctx.state.get("stunnel")
        if tun:
            # OpenVPN talks TCP to the local stunnel; stunnel carries it over TLS to the server.
            text = re.sub(r"^\s*(remote|remote-random|proto|explicit-exit-notify|http-proxy|socks-proxy)\b.*$\n?",
                          "", text, flags=re.M)
            extra = ["remote 127.0.0.1 %d" % tun["port"], "proto tcp-client", "nobind"]
            if tun.get("ip") and ":" not in tun["ip"]:
                extra.append("route %s 255.255.255.255 net_gateway" % tun["ip"])   # keep stunnel outside the VPN
            text = text.rstrip("\n") + "\n" + "\n".join(extra) + "\n"
        ctx.state["text"] = text
        ctx.state["path"] = ctx.write("runtime.ovpn", text)

    def connect_cmd(self, ctx):
        p = ctx.profile
        text = ctx.state["text"]
        cmd = [self.binary(), "--config", ctx.state["path"], "--cd", ctx.profile_dir, "--verb", "3",
               "--auth-nocache"]
        if ctx.ifname:
            cmd += ["--dev", ctx.ifname, "--dev-type", self._dev(text)]
        if p.get("username"):
            cmd += ["--auth-user-pass", ctx.write("auth", "%s\n%s\n" % (p["username"], p.get("password", "")))]
        elif re.search(r"^\s*auth-user-pass\s*$", text, re.M):
            raise ValueError("this profile needs a username and password")
        if p.get("key_password"):
            cmd += ["--askpass", ctx.write("askpass", p["key_password"] + "\n")]
        cmd += [str(a) for a in ctx.settings.get("connection.openvpn_args")]
        cmd += [str(a) for a in p.get("options", {}).get("extra_args", [])]
        return cmd

    def parse_line(self, line, ctx):
        m = re.search(r"TUN/TAP device (\S+) opened", line)
        if m:
            ctx.iface = m.group(1)
        m = re.search(r"dhcp-option DNS6?\s+([0-9a-fA-F.:]+)", line)
        if m and m.group(1) not in ctx.dns:
            ctx.dns.append(m.group(1))
