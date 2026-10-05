"""Table-style backends for the remaining protocols."""

import re
import shlex

from .. import platform as plat
from .base import Backend


class OpenConnect(Backend):
    id = "openconnect"
    label = "OpenConnect"
    description = "Cisco AnyConnect, Juniper/Pulse, Palo Alto GlobalProtect, F5, Fortinet, Array"
    binaries = ("openconnect",)
    ready_re = re.compile(r"(Connected as |ESP session established|Established DTLS|Connected tun)")
    named_iface = True
    fields = ("server", "username", "password")
    PROTOCOLS = ("anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array")

    def validate(self, profile):
        problems = super().validate(profile)
        if not profile.get("server"):
            problems.append("a server URL is required")
        proto = profile.get("options", {}).get("protocol", "anyconnect")
        if proto not in self.PROTOCOLS:
            problems.append("protocol option must be one of: " + ", ".join(self.PROTOCOLS))
        return problems

    def connect_cmd(self, ctx):
        p, o = ctx.profile, ctx.profile.get("options", {})
        cmd = [self.binary(), "--protocol", o.get("protocol", "anyconnect"), "--non-inter"]
        if ctx.ifname:
            cmd += ["--interface", ctx.ifname]
        if p.get("username"):
            cmd += ["--user", p["username"]]
        if p.get("password"):
            cmd += ["--passwd-on-stdin"]
        if o.get("authgroup"):
            cmd += ["--authgroup", o["authgroup"]]
        if o.get("servercert"):
            cmd += ["--servercert", o["servercert"]]
        cmd += [str(a) for a in o.get("extra_args", [])]
        host = re.sub(r"^[a-z]+://", "", p["server"]).split("/")[0].split(":")[0]
        ip = ctx.state.get("resolved", {}).get(host)
        if ip:
            cmd += ["--resolve", "%s:%s" % (host, ip)]
        return cmd + [p["server"]]

    def stdin_data(self, ctx):
        pw = ctx.profile.get("password")
        return pw + "\n" if pw else None

    def parse_line(self, line, ctx):
        m = re.search(r"Set up tun device (\S+)|Using (?:tun )?interface (\S+)", line)
        if m:
            ctx.iface = m.group(1) or m.group(2)


class OpenFortiVPN(Backend):
    id = "openfortivpn"
    label = "Fortinet SSL VPN"
    description = "FortiGate SSL-VPN via openfortivpn"
    binaries = ("openfortivpn",)
    extensions = (".fortivpn",)
    ready_re = re.compile(r"Tunnel is up and running")
    iface_fallback = True
    fields = ("server", "username", "password")

    @classmethod
    def sniff(cls, filename, text):
        if re.search(r"^\s*host\s*=", text, re.M) and re.search(r"^\s*(trusted-cert|username|realm)\s*=", text, re.M):
            return 85
        return 0

    def parse(self, filename, text):
        out = {}
        m = re.search(r"^\s*host\s*=\s*(\S+)", text, re.M)
        if m:
            out["server"] = m.group(1)
        m = re.search(r"^\s*port\s*=\s*(\d+)", text, re.M)
        out["port"] = int(m.group(1)) if m else 443
        m = re.search(r"^\s*username\s*=\s*(\S+)", text, re.M)
        if m:
            out["username"] = m.group(1)
        return out

    def prepare(self, ctx):
        p = ctx.profile
        text = ""
        if p.get("config"):
            with open("%s/%s" % (ctx.profile_dir, p["config"]), errors="replace") as fh:
                text = fh.read()
        else:
            text = "host = %s\nport = %s\n" % (p["server"], p.get("port") or 443)
        if p.get("username"):
            text += "\nusername = %s\npassword = %s\n" % (p["username"], p.get("password", ""))
        ctx.state["path"] = ctx.write("forti.conf", text)

    def connect_cmd(self, ctx):
        return [self.binary(), "-c", ctx.state["path"]]


class SSTP(Backend):
    id = "sstp"
    label = "SSTP"
    description = "Microsoft Secure Socket Tunneling Protocol (sstpc + pppd)"
    binaries = ("sstpc", "pppd")
    ready_re = re.compile(r"(local\s+IP address|Connection established|Connected)", re.I)
    iface_fallback = True
    named_iface = True
    fields = ("server", "username", "password")

    def prepare(self, ctx):
        p = ctx.profile
        opts = ["name %s" % shlex.quote(p.get("username", "")),
                "password %s" % shlex.quote(p.get("password", "")),
                "usepeerdns", "require-mschap-v2", "noauth", "refuse-eap", "defaultroute", "nodetach"]
        if ctx.ifname and plat.os_family() == "linux":
            opts.append("ifname %s" % ctx.ifname)
        ctx.state["opts"] = ctx.write("ppp-options", "\n".join(opts) + "\n")

    def connect_cmd(self, ctx):
        return [self.binary(), "--log-level", "3", "--log-stderr", "--cert-warn",
                ctx.profile["server"], "--", "file", ctx.state["opts"]]

    def validate(self, profile):
        problems = super().validate(profile)
        if not profile.get("server"):
            problems.append("a server is required")
        return problems


class PPTP(SSTP):
    id = "pptp"
    label = "PPTP"
    description = "Point-to-Point Tunneling Protocol (legacy, insecure - avoid if possible)"
    binaries = ("pppd", "pptp")
    lock_note = "PPTP is cryptographically broken; use only when nothing else is available."

    def prepare(self, ctx):
        p = ctx.profile
        opts = ["name %s" % shlex.quote(p.get("username", "")),
                "password %s" % shlex.quote(p.get("password", "")),
                "remotename PPTP", "require-mppe-128", "usepeerdns", "noauth", "defaultroute",
                "nodetach", "logfd 1"]
        if ctx.ifname and plat.os_family() == "linux":
            opts.append("ifname %s" % ctx.ifname)
        ctx.state["opts"] = ctx.write("ppp-options", "\n".join(opts) + "\n")

    def connect_cmd(self, ctx):
        srv = ctx.profile["server"]
        return [self.binary("pppd"), "pty", "%s %s --nolaunchpppd" % (self.binary("pptp"), shlex.quote(srv)),
                "file", ctx.state["opts"]]


class StrongSwan(Backend):
    id = "ikev2"
    label = "IKEv2 / IPsec"
    description = "IKEv2/IPsec through strongSwan (swanctl.conf)"
    binaries = ("swanctl",)
    extensions = (".swanctl", ".swanctl.conf")
    mode = "oneshot"
    iface_fallback = True
    lock_note = "Policy-based IPsec has no tunnel interface; define an XFRM interface (if_id) so the kill switch can match it."

    @classmethod
    def sniff(cls, filename, text):
        if re.search(r"^\s*connections\s*\{", text, re.M):
            return 90
        return 0

    def parse(self, filename, text):
        out = {"options": {}}
        m = re.search(r"connections\s*\{\s*([A-Za-z0-9_.-]+)\s*\{", text)
        if m:
            out["options"]["ike"] = m.group(1)
        m = re.search(r"children\s*\{\s*([A-Za-z0-9_.-]+)\s*\{", text)
        if m:
            out["options"]["child"] = m.group(1)
        m = re.search(r"remote_addrs\s*=\s*([^\s,]+)", text)
        if m:
            out["server"] = m.group(1)
            out["port"] = 500
            out["transport"] = "udp"
        return out

    def validate(self, profile):
        problems = super().validate(profile)
        if not profile.get("config"):
            problems.append("profile has no swanctl config")
        if not profile.get("options", {}).get("ike"):
            problems.append("option 'ike' (connection name) is required")
        return problems

    def endpoints(self, profile):
        eps = super().endpoints(profile)
        return [(h, 500, "udp") for h, _, _ in eps] + [(h, 4500, "udp") for h, _, _ in eps]

    def connect_cmds(self, ctx):
        o = ctx.profile["options"]
        path = "%s/%s" % (ctx.profile_dir, ctx.profile["config"])
        init = [self.binary(), "--initiate", "--ike", o["ike"]]
        if o.get("child"):
            init += ["--child", o["child"]]
        return [[self.binary(), "--load-all", "--file", path], init]

    def connect_cmd(self, ctx):
        return self.connect_cmds(ctx)[-1]

    def disconnect_cmds(self, ctx):
        return [[self.binary(), "--terminate", "--ike", ctx.profile["options"]["ike"]]]


class VPNC(Backend):
    id = "vpnc"
    label = "Cisco IPsec (vpnc)"
    description = "Legacy Cisco IPsec/PSK concentrators via vpnc"
    binaries = ("vpnc",)
    extensions = (".vpnc", ".pcf")
    ready_re = re.compile(r"VPNC started in foreground")
    iface_fallback = True

    @classmethod
    def sniff(cls, filename, text):
        return 90 if re.search(r"^\s*IPSec gateway\s", text, re.M) else 0

    def parse(self, filename, text):
        m = re.search(r"^\s*IPSec gateway\s+(\S+)", text, re.M)
        return {"server": m.group(1), "port": 500, "transport": "udp"} if m else {}

    def connect_cmd(self, ctx):
        return [self.binary(), "--no-detach", "%s/%s" % (ctx.profile_dir, ctx.profile["config"])]


class Nebula(Backend):
    id = "nebula"
    label = "Nebula"
    description = "Slack Nebula overlay network"
    binaries = ("nebula",)
    extensions = (".yml", ".yaml")
    iface_fallback = True
    lock_note = "Nebula talks to many peers directly; add them to the kill switch whitelist."

    @classmethod
    def sniff(cls, filename, text):
        return 80 if re.search(r"^pki:", text, re.M) and re.search(r"^lighthouse:", text, re.M) else 0

    def connect_cmd(self, ctx):
        return [self.binary(), "-config", "%s/%s" % (ctx.profile_dir, ctx.profile["config"])]


class Tailscale(Backend):
    id = "tailscale"
    label = "Tailscale"
    description = "Tailscale mesh VPN (optionally via an exit node)"
    binaries = ("tailscale",)
    mode = "oneshot"
    fields = ()
    lock_note = "tailscaled needs direct UDP; whitelist your peers/DERP or use an exit node with the kill switch off."

    def connect_cmd(self, ctx):
        o = ctx.profile.get("options", {})
        cmd = [self.binary(), "up", "--accept-dns=false"]
        if o.get("exit_node"):
            cmd.append("--exit-node=%s" % o["exit_node"])
        if o.get("authkey"):
            cmd.append("--authkey=%s" % o["authkey"])
        return cmd

    def disconnect_cmds(self, ctx):
        return [[self.binary(), "down"]]

    def endpoints(self, profile):
        return []

    def prepare(self, ctx):
        ctx.iface = "tailscale0" if plat.os_family() == "linux" else None


class NetBird(Tailscale):
    id = "netbird"
    label = "NetBird"
    description = "NetBird WireGuard-based mesh VPN"
    binaries = ("netbird",)

    def connect_cmd(self, ctx):
        o = ctx.profile.get("options", {})
        cmd = [self.binary(), "up"]
        if o.get("setup_key"):
            cmd += ["--setup-key", o["setup_key"]]
        return cmd

    def prepare(self, ctx):
        ctx.iface = "wt0" if plat.os_family() == "linux" else None


class ZeroTier(Tailscale):
    id = "zerotier"
    label = "ZeroTier"
    description = "ZeroTier virtual networks (profile option: network id)"
    binaries = ("zerotier-cli",)

    def validate(self, profile):
        problems = super().validate(profile)
        if not profile.get("options", {}).get("network"):
            problems.append("option 'network' (16-hex network id) is required")
        return problems

    def connect_cmd(self, ctx):
        return [self.binary(), "join", ctx.profile["options"]["network"]]

    def disconnect_cmds(self, ctx):
        return [[self.binary(), "leave", ctx.profile["options"]["network"]]]

    def prepare(self, ctx):
        pass


class NetworkManager(Backend):
    id = "networkmanager"
    label = "NetworkManager VPN"
    description = "Any VPN already defined in NetworkManager (L2TP/IPsec, strongSwan, Fortinet, vpnc, ...)"
    binaries = ("nmcli",)
    mode = "oneshot"
    iface_fallback = True

    def validate(self, profile):
        problems = super().validate(profile)
        if not profile.get("options", {}).get("nm_name"):
            problems.append("option 'nm_name' (NetworkManager connection name) is required")
        return problems

    def endpoints(self, profile):
        return Backend.endpoints(self, profile)

    def connect_cmd(self, ctx):
        return [self.binary(), "--wait", "30", "connection", "up", "id", ctx.profile["options"]["nm_name"]]

    def disconnect_cmds(self, ctx):
        return [[self.binary(), "connection", "down", "id", ctx.profile["options"]["nm_name"]]]

    @staticmethod
    def discover():
        rc, out = plat.run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
        found = []
        if rc == 0:
            for line in out.splitlines():
                name, _, typ = line.rpartition(":")
                if typ in ("vpn", "wireguard"):
                    found.append({"name": name.replace("\\:", ":"), "type": typ})
        return found


class Custom(Backend):
    id = "custom"
    label = "Custom command"
    description = "Run your own connect/disconnect commands ({config} {dir} {iface} are substituted)"
    binaries = ()

    @property
    def mode(self):  # pragma: no cover - set per instance in manager via options
        return "oneshot"

    def validate(self, profile):
        problems = []
        if not profile.get("options", {}).get("connect_cmd"):
            problems.append("option 'connect_cmd' is required")
        return problems

    def _fmt(self, s, ctx):
        return shlex.split(s.format(config="%s/%s" % (ctx.profile_dir, ctx.profile.get("config", "")),
                                    dir=ctx.profile_dir, iface=ctx.ifname or ""))

    def connect_cmd(self, ctx):
        return self._fmt(ctx.profile["options"]["connect_cmd"], ctx)

    def disconnect_cmds(self, ctx):
        d = ctx.profile["options"].get("disconnect_cmd")
        return [self._fmt(d, ctx)] if d else []
