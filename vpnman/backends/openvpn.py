import os
import re
import shlex
import shutil

from .. import platform as plat
from .. import stunnel
from .base import Backend, CredentialsRequired

# Script hooks that Debian-style configs ship: they either do not exist on this distribution (update-resolv-conf is
# a Debian/Ubuntu file) or fight with vpnman, which sets the DNS servers itself. A missing hook is fatal for OpenVPN
# ("up" failing aborts the connection), so such lines are dropped from the runtime copy.
_HOOKS = ("up", "down", "route-up", "route-pre-down", "ipchange", "up-restart", "client-connect", "client-disconnect")
_DNS_HELPERS = re.compile(r"update-resolv-conf|update-systemd-resolved|resolvconf|openresolv|systemd-resolve|"
                          r"resolved-up|dns-up|dns-down", re.I)
# options that only exist in the Windows build; Linux/BSD openvpn aborts on them.
# block-outside-dns is covered by the kill switch, which drops all DNS outside the tunnel.
_WINDOWS_ONLY = {"register-dns", "dhcp-renew", "dhcp-release", "ip-win32", "tap-sleep", "show-net-up",
                 "show-net", "show-adapters", "route-method", "pause-exit", "service", "win-sys",
                 "allow-nonadmin", "cryptoapicert", "cryptoapicertstore", "dhcp-pre-release",
                 "ip-remove-uses-dhcp", "tap-window", "block-outside-dns"}
_HOOK_LINE = re.compile(r"^\s*(%s)\s+(.+?)\s*$" % "|".join(re.escape(h) for h in _HOOKS), re.I)
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
    probe_cache = {}               # "option value" -> does this openvpn binary accept it?

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

    @staticmethod
    def sanitize_hooks(text, profile_dir):
        """Drop up/down-style script hooks that cannot work here.  Returns (new text, [explanations])."""
        out, notes, inline = [], [], None
        for line in text.splitlines():
            st = line.strip()
            if inline:
                if st.startswith("</" + inline):
                    inline = None
                out.append(line)
                continue
            m = re.match(r"^<([a-z0-9-]+)>$", st)
            if m:
                inline = m.group(1)
                out.append(line)
                continue
            word = st.split(None, 1)[0].lower() if st and not st.startswith(("#", ";")) else ""
            if word in _WINDOWS_ONLY:
                notes.append("Ignoring '%s' from the config: it is a Windows-only option" % word)
                continue
            hook = _HOOK_LINE.match(line) if not st.startswith(("#", ";")) else None
            if hook:
                try:
                    cmd = shlex.split(hook.group(2))
                except ValueError:
                    cmd = hook.group(2).split()
                exe = cmd[0] if cmd else ""
                why = None
                if _DNS_HELPERS.search(exe):
                    why = "vpnman sets the DNS servers itself"
                elif exe and not (os.path.isfile(exe) if os.path.isabs(exe) else
                                  (os.path.isfile(os.path.join(profile_dir, exe)) or shutil.which(exe))):
                    why = "the script does not exist on this system"
                if why:
                    notes.append("Ignoring '%s %s' from the config: %s" % (hook.group(1), exe, why))
                    continue
            out.append(line)
        return "\n".join(out) + ("\n" if text.endswith("\n") else ""), notes

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
        text, notes = self.sanitize_hooks(text, ctx.profile_dir)
        ctx.state["notes"] = notes
        # DNS servers written into the config itself ("dhcp-option DNS x") and a filter that ignores the pushed ones
        for m in re.finditer(r"^\s*dhcp-option\s+DNS6?\s+([0-9a-fA-F.:]+)\s*$", text, re.M | re.I):
            if m.group(1) not in ctx.dns:
                ctx.dns.append(m.group(1))
        ctx.state["ignore_pushed_dns"] = bool(
            re.search(r"^\s*pull-filter\s+ignore\s+[\"']?dhcp-option\s+DNS", text, re.M | re.I))
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

    def _accepts(self, *opt):
        """Does the installed openvpn understand this option?  Probed once (an option error makes it exit non-zero
        before it does anything), so one code path works with OpenVPN 2.4 up to 2.7."""
        key = " ".join(opt)
        if key not in self.probe_cache:
            try:
                rc, _out = plat.run([self.binary()] + list(opt) + ["--verb", "3", "--show-digests"], timeout=10)
            except Exception:  # noqa: BLE001
                rc = 1
            self.probe_cache[key] = rc == 0
        return self.probe_cache[key]

    def connect_cmd(self, ctx):
        p = ctx.profile
        text = ctx.state["text"]
        cmd = [self.binary(), "--config", ctx.state["path"], "--cd", ctx.profile_dir, "--verb", "3",
               "--auth-nocache"]
        if ctx.ifname:
            cmd += ["--dev", ctx.ifname, "--dev-type", self._dev(text)]
        if self._accepts("--dns-updown", "disable"):
            # OpenVPN 2.7 applies pushed DNS itself (resolvconf/systemd-resolved) on top of vpnman's own handling;
            # the two fight on teardown ("resolvconf: signature mismatch"). vpnman owns DNS.
            cmd += ["--dns-updown", "disable"]
        if p.get("username"):
            cmd += ["--auth-user-pass", ctx.write("auth", "%s\n%s\n" % (p["username"], p.get("password", "")))]
        elif re.search(r"^\s*auth-user-pass\s*$", text, re.M):
            raise CredentialsRequired("this profile needs a username and password")
        if p.get("key_password"):
            cmd += ["--askpass", ctx.write("askpass", p["key_password"] + "\n")]
        cmd += [str(a) for a in ctx.settings.get("connection.openvpn_args")]
        cmd += [str(a) for a in p.get("options", {}).get("extra_args", [])]
        return cmd

    def parse_line(self, line, ctx):
        m = re.search(r"AUTH_FAILED(?:,(.*?))?'?$", line) if "AUTH_FAILED" in line else None
        if m:
            reason = (m.group(1) or "").strip(" '")
            ctx.state["fatal_kind"] = "auth"
            ctx.state["fatal"] = ("Authentication failed - the server rejected the username or password%s. "
                                  "Edit the profile and re-enter them (some providers use a separate VPN username "
                                  "or password, not your website login)." % (" (%s)" % reason if reason else ""))
        m = re.search(r"TUN/TAP device (\S+) opened", line)
        if m:
            ctx.iface = m.group(1)
        m = re.search(r"dhcp-option DNS6?\s+([0-9a-fA-F.:]+)", line)
        if m and ctx.state.get("ignore_pushed_dns"):
            m = None                    # the config told OpenVPN to ignore the server's DNS; keep the config's own
        if m and m.group(1) not in ctx.dns:
            ctx.dns.append(m.group(1))
