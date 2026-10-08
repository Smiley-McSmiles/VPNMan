"""Proxy support through Xray (https://github.com/XTLS/Xray-core): VLESS, VMess, Trojan and Shadowsocks servers.

This module is pure data handling plus the process wrapper - it never touches the network configuration:

* ``parse_link`` / ``parse_subscription`` / ``parse_json``  turn what people are given (share links, subscription
  texts, an Xray config) into a *proxy*: ``{"name", "protocol", "server", "port", "outbound", "link"}``.  The Xray
  ``outbound`` object is stored ready to use.
* ``build_config`` writes the Xray configuration for one of the ways VPNMan uses it (see ``Inbound`` helpers).
* ``redirect_ruleset`` is the nftables ruleset of the system-wide mode (Linux).
* ``Runner`` starts and stops the ``xray`` process.
"""

import base64
import binascii
import copy
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.parse

from . import platform as plat

SUPPORTED = ("vless", "vmess", "trojan", "shadowsocks")
MARK = 0x5658                         # socket mark on Xray's own connections (system-wide mode must not catch them)
NFT_TABLE = "vpnman_proxy"
DEFAULT_SOCKS, DEFAULT_HTTP = 10808, 10809
_HOST = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
_NAME_BAD = re.compile(r"[\x00-\x1f\x7f]")


class ProxyError(ValueError):
    """A link or config that cannot be used (the message says why).  ``fatal``: retrying cannot help."""

    def __init__(self, message, fatal=False):
        super().__init__(message)
        self.fatal = fatal


def binary():
    return plat.which("xray")


def missing():
    return [] if binary() else ["xray"]


# ------------------------------------------------------------------ share links

def _b64(text):
    """Decode base64 in any of its dialects (padding or not, URL-safe or not)."""
    s = re.sub(r"\s+", "", text)
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        raise ProxyError("not valid base64")


def _first(q, *keys, default=""):
    for k in keys:
        v = q.get(k)
        if v and v[0] != "":
            return v[0]
    return default


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ProxyError("the port is not a number")
    if not 0 < port < 65536:
        raise ProxyError("the port must be between 1 and 65535")
    return port


def _host(value):
    value = (value or "").strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value or not _HOST.match(value):
        raise ProxyError("the server address is missing or invalid")
    return value


def stream_settings(net, security, q, host):
    """The ``streamSettings`` object for the transport (``net``) and security of a link; ``q`` holds the query-style
    parameters (path, host, sni, fp, alpn, pbk, sid, spx, serviceName, mode, headerType, seed, allowInsecure)."""
    net = {"h2": "http", "mkcp": "kcp", "splithttp": "xhttp", "": "tcp", "raw": "tcp"}.get(net, net)
    if net not in ("tcp", "kcp", "ws", "http", "grpc", "httpupgrade", "xhttp"):
        raise ProxyError("transport '%s' is not supported" % net)
    st = {"network": net, "security": security if security in ("tls", "reality") else "none"}
    hdr = _first(q, "host")
    path = _first(q, "path", default="/") or "/"
    if net == "ws":
        st["wsSettings"] = {"path": path, "headers": {"Host": hdr} if hdr else {}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": _first(q, "serviceName", "path"),
                              "multiMode": _first(q, "mode") == "multi"}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": path, "host": hdr}
    elif net == "xhttp":
        st["xhttpSettings"] = {"path": path, "host": hdr, "mode": _first(q, "mode", default="auto")}
    elif net == "http":
        st["httpSettings"] = {"path": path, "host": [h for h in hdr.split(",") if h]}
    elif net == "kcp":
        st["kcpSettings"] = {"header": {"type": _first(q, "headerType", default="none")}, "seed": _first(q, "seed")}
    elif net == "tcp" and _first(q, "headerType") == "http":
        st["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [p for p in path.split(",") if p] or ["/"], "headers": {"Host": [h for h in hdr.split(",") if h]}}}}
    sni = _first(q, "sni", "peer", "serverName") or hdr or host
    fp = _first(q, "fp", "fingerprint")
    if st["security"] == "tls":
        tls = {"serverName": sni}
        if fp:
            tls["fingerprint"] = fp
        if _first(q, "alpn"):
            tls["alpn"] = [a for a in _first(q, "alpn").split(",") if a]
        if _first(q, "allowInsecure", "insecure") in ("1", "true"):
            tls["allowInsecure"] = True
        st["tlsSettings"] = tls
    elif st["security"] == "reality":
        if not _first(q, "pbk", "publicKey"):
            raise ProxyError("a Reality link needs a public key (pbk)")
        st["realitySettings"] = {"serverName": sni, "fingerprint": fp or "chrome",
                                 "publicKey": _first(q, "pbk", "publicKey"), "shortId": _first(q, "sid", "shortId"),
                                 "spiderX": _first(q, "spx", "spiderX")}
    return st


def _display_name(frag, default):
    name = urllib.parse.unquote(frag or "").strip()
    name = _NAME_BAD.sub("", name)[:100]
    return name or default


def _urlport(u, default=443):
    try:
        return _port(u.port or default)
    except ValueError:                       # urllib raises a plain ValueError for ports outside 0-65535
        raise ProxyError("the port must be between 1 and 65535")


def _split_url(link):
    u = urllib.parse.urlsplit(link)
    if not u.hostname:
        raise ProxyError("the link has no server address")
    return u, urllib.parse.parse_qs(u.query, keep_blank_values=True)


def _parse_vless(link):
    u, q = _split_url(link)
    if not u.username:
        raise ProxyError("the link has no user id")
    host, port = _host(u.hostname), _urlport(u)
    sec = _first(q, "security", default="none")
    user = {"id": urllib.parse.unquote(u.username), "encryption": _first(q, "encryption", default="none")}
    if _first(q, "flow"):
        user["flow"] = _first(q, "flow")
    ob = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
          "streamSettings": stream_settings(_first(q, "type", default="tcp"), sec, q, host)}
    return host, port, ob, _display_name(u.fragment, "%s:%d" % (host, port))


def _parse_vmess(link):
    body = link[len("vmess://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    if "@" in body.split("?")[0]:                      # the uncommon URL form: vmess://uuid@host:port?...
        u, q = _split_url(link)
        host, port = _host(u.hostname), _urlport(u)
        user = {"id": urllib.parse.unquote(u.username or ""), "alterId": int(_first(q, "aid", default="0") or 0),
                "security": _first(q, "encryption", "scy", default="auto")}
        sec = _first(q, "security", default="none")
        net = _first(q, "type", default="tcp")
        name = _display_name(u.fragment, "%s:%d" % (host, port))
    else:
        try:
            data = json.loads(_b64(body))
        except (ValueError, ProxyError):
            raise ProxyError("the vmess link is not valid")
        if not isinstance(data, dict):
            raise ProxyError("the vmess link is not valid")
        host, port = _host(data.get("add")), _port(data.get("port"))
        q = {k: [str(v)] for k, v in data.items() if v is not None}
        q["headerType"] = [str(data.get("type", ""))]            # in vmess links "type" is the header type
        user = {"id": str(data.get("id", "")), "alterId": int(data.get("aid") or 0),
                "security": str(data.get("scy") or "auto")}
        sec = "tls" if str(data.get("tls", "")).lower() == "tls" else "none"
        net = str(data.get("net") or "tcp")
        name = _display_name(data.get("ps") or urllib.parse.unquote(frag), "%s:%d" % (host, port))
    if not user["id"]:
        raise ProxyError("the link has no user id")
    ob = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
          "streamSettings": stream_settings(net, sec, q, host)}
    return host, port, ob, name


def _parse_trojan(link):
    u, q = _split_url(link)
    if not u.username:
        raise ProxyError("the link has no password")
    host, port = _host(u.hostname), _urlport(u)
    ob = {"protocol": "trojan",
          "settings": {"servers": [{"address": host, "port": port, "password": urllib.parse.unquote(u.username)}]},
          "streamSettings": stream_settings(_first(q, "type", default="tcp"), _first(q, "security", default="tls"), q, host)}
    return host, port, ob, _display_name(u.fragment, "%s:%d" % (host, port))


def _parse_ss(link):
    body = link[len("ss://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    q = urllib.parse.parse_qs(query)
    if _first(q, "plugin"):
        raise ProxyError("Shadowsocks plugins are not supported")
    if "@" in body:                                    # SIP002: base64(method:password)@host:port
        userinfo, _, hostport = body.rpartition("@")
        try:
            cred = _b64(userinfo) if ":" not in userinfo else urllib.parse.unquote(userinfo)
        except ProxyError:
            cred = urllib.parse.unquote(userinfo)
    else:                                              # legacy: base64(method:password@host:port)
        decoded = _b64(body)
        cred, _, hostport = decoded.rpartition("@")
    method, _, password = cred.partition(":")
    if not method or not password:
        raise ProxyError("the Shadowsocks link has no method and password")
    hostport = hostport.rstrip("/")
    host, _, port = hostport.rpartition(":")
    host, port = _host(host), _port(port)
    ob = {"protocol": "shadowsocks",
          "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
          "streamSettings": {"network": "tcp", "security": "none"}}
    return host, port, ob, _display_name(frag, "%s:%d" % (host, port))


_PARSERS = {"vless": _parse_vless, "vmess": _parse_vmess, "trojan": _parse_trojan, "ss": _parse_ss}


def parse_link(link):
    """One share link -> proxy dict.  Raises ProxyError."""
    link = (link or "").strip()
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme not in _PARSERS:
        raise ProxyError("unsupported link (expected vless://, vmess://, trojan:// or ss://)")
    try:
        host, port, outbound, name = _PARSERS[scheme](link)
    except ProxyError:
        raise
    except (ValueError, KeyError, IndexError, TypeError):
        raise ProxyError("the link is not valid")
    outbound["tag"] = "proxy"
    return {"name": name, "protocol": outbound["protocol"], "server": host, "port": port, "outbound": outbound,
            "link": link}


def parse_json(text):
    """An Xray config (the first usable outbound of it) or a bare outbound object -> proxy dict."""
    try:
        data = json.loads(text)
    except ValueError:
        raise ProxyError("not valid JSON")
    cands = data.get("outbounds") if isinstance(data, dict) and "outbounds" in data else [data]
    for ob in cands or []:
        if not isinstance(ob, dict) or ob.get("protocol") not in SUPPORTED:
            continue
        st = ob.get("settings") or {}
        node = (st.get("vnext") or st.get("servers") or [{}])[0]
        host, port = node.get("address"), node.get("port")
        if not host or not port:
            continue
        ob = copy.deepcopy(ob)
        ob["tag"] = "proxy"
        return {"name": str(ob.pop("name", "") or "%s:%s" % (host, port))[:100], "protocol": ob["protocol"],
                "server": _host(str(host)), "port": _port(port), "outbound": ob, "link": ""}
    raise ProxyError("no VLESS, VMess, Trojan or Shadowsocks outbound found in the JSON")


def parse_text(text):
    """Anything people paste: share links one per line, a base64 subscription, or an Xray JSON config.
    Returns (proxies, errors) - one broken line never loses the others."""
    text = (text or "").strip()
    if not text:
        raise ProxyError("nothing to import")
    if text.startswith(("{", "[")):
        return [parse_json(text)], []
    if "://" not in text:
        try:
            text = _b64(text).strip()
        except ProxyError:
            raise ProxyError("this is neither a share link, a subscription nor an Xray config")
    proxies, errors = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            proxies.append(parse_link(line))
        except ProxyError as e:
            errors.append("%s: %s" % (line[:48] + ("…" if len(line) > 48 else ""), e))
    if not proxies and not errors:
        raise ProxyError("nothing to import")
    return proxies, errors


def identity(proxy):
    """A key that stays the same when a subscription is refreshed (the name may change, the server rarely does)."""
    ob = proxy.get("outbound") or {}
    st = ob.get("settings") or {}
    node = (st.get("vnext") or st.get("servers") or [{}])[0]
    user = (node.get("users") or [{}])[0]
    return "%s|%s|%s|%s" % (ob.get("protocol"), node.get("address"), node.get("port"),
                            user.get("id") or node.get("password") or "")


# ------------------------------------------------------------------ configuration

def pin_address(outbound, ip):
    """Return the outbound with its server address replaced by an already resolved IP (Xray then never needs DNS,
    which matters while the kill switch is up).  The original name stays the TLS / Host name."""
    ob = copy.deepcopy(outbound)
    st = ob.get("settings") or {}
    node = (st.get("vnext") or st.get("servers") or [{}])[0]
    host = node.get("address")
    if not host or not ip or host == ip:
        return ob
    node["address"] = ip
    ss = ob.setdefault("streamSettings", {})
    for key in ("tlsSettings", "realitySettings"):
        if key in ss:
            ss[key].setdefault("serverName", host)
            ss[key]["serverName"] = ss[key]["serverName"] or host
    ws = ss.get("wsSettings")
    if ws is not None:
        ws.setdefault("headers", {})
        ws["headers"].setdefault("Host", host)
        ws["headers"]["Host"] = ws["headers"]["Host"] or host
    for key in ("httpupgradeSettings", "xhttpSettings"):
        if key in ss:
            ss[key]["host"] = ss[key].get("host") or host
    return ob


def _marked(outbound, mark):
    ob = copy.deepcopy(outbound)
    if mark:
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = mark
    return ob


def build_config(outbound, *, socks=None, http=None, forward=None, redirect=None, dns=None, mark=None,
                 dns_server="1.1.1.1", loglevel="warning"):
    """The Xray configuration.  Every keyword adds one local listener, all on 127.0.0.1:

    socks / http   port of a SOCKS5 / HTTP proxy for applications
    forward        (port, host, port2): a dokodemo-door that carries TCP and UDP to host:port2 (the VPN server)
    redirect       port for TCP connections redirected by the firewall (system-wide mode)
    dns            port for DNS queries redirected by the firewall; answered by ``dns_server`` through the proxy
    mark           socket mark of Xray's own connections
    """
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    inbounds = []
    if socks:
        inbounds.append({"tag": "socks-in", "listen": "127.0.0.1", "port": int(socks), "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": sniff})
    if http:
        inbounds.append({"tag": "http-in", "listen": "127.0.0.1", "port": int(http), "protocol": "http",
                         "settings": {}, "sniffing": sniff})
    if forward:
        port, host, port2 = forward
        inbounds.append({"tag": "forward-in", "listen": "127.0.0.1", "port": int(port), "protocol": "dokodemo-door",
                         "settings": {"address": host, "port": int(port2), "network": "tcp,udp"}})
    if redirect:
        inbounds.append({"tag": "redirect-in", "listen": "127.0.0.1", "port": int(redirect),
                         "protocol": "dokodemo-door",
                         "settings": {"network": "tcp", "followRedirect": True},
                         "streamSettings": {"sockopt": {"tproxy": "redirect"}}, "sniffing": sniff})
    if dns:
        inbounds.append({"tag": "dns-in", "listen": "127.0.0.1", "port": int(dns), "protocol": "dokodemo-door",
                         "settings": {"address": dns_server, "port": 53, "network": "tcp,udp"}})
    if not inbounds:
        raise ProxyError("nothing to listen on")
    out = _marked(outbound, mark)
    out["tag"] = "proxy"
    direct = {"tag": "direct", "protocol": "freedom", "settings": {}}
    if mark:
        direct["streamSettings"] = {"sockopt": {"mark": mark}}
    return {"log": {"loglevel": loglevel}, "inbounds": inbounds, "outbounds": [out, direct],
            "routing": {"domainStrategy": "AsIs",
                        "rules": [{"type": "field", "inboundTag": [i["tag"] for i in inbounds],
                                   "outboundTag": "proxy"}]}}


# ------------------------------------------------------------------ system-wide mode (nftables)

LAN4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"]


def redirect_ruleset(tcp_port, dns_port, *, exclude=(), allow_lan=True, split_mark=0, udp="block"):
    """nftables ruleset that sends this machine's TCP connections and DNS queries to the Xray listeners.

    Skipped (they keep their normal route): Xray's own connections (the socket mark), loopback, the networks in
    ``exclude`` (the VPN server, bypass routes), the local network when ``allow_lan``, and applications of the app
    bypass (``split_mark``).  IPv6 and - with ``udp == "block"`` - all other UDP are dropped so nothing can leave
    around the proxy.  Priorities sit just before the kill switch (-100) so the redirected packets reach loopback
    before it looks at them."""
    skip = ["127.0.0.0/8"] + (LAN4 if allow_lan else []) + [str(ipaddress.ip_network(e, strict=False))
                                                              for e in exclude if ":" not in str(e)]
    skip = sorted(set(skip))
    marks = ["0x%x" % MARK] + (["0x%x" % split_mark] if split_mark else [])
    lines = ["table inet %s" % NFT_TABLE, "delete table inet %s" % NFT_TABLE, "table inet %s {" % NFT_TABLE,
             "  chain redirect_out {",
             "    type nat hook output priority -110; policy accept;"]
    for m in marks:
        lines.append("    meta mark %s return" % m)
    lines += ["    ip daddr { %s } return" % ", ".join(skip),
              "    meta nfproto ipv4 udp dport 53 redirect to :%d" % dns_port,
              "    meta nfproto ipv4 tcp dport 53 redirect to :%d" % dns_port,
              "    meta nfproto ipv4 meta l4proto tcp redirect to :%d" % tcp_port,
              "  }",
              "  chain guard_out {",
              "    type filter hook output priority -105; policy accept;"]
    for m in marks:
        lines.append("    meta mark %s accept" % m)
    lines += ['    oifname "lo" accept',
              "    ip daddr { %s } accept" % ", ".join(skip),
              "    udp dport { 67, 68 } accept",                  # DHCP keeps working (lease renewals)
              "    meta nfproto ipv6 drop"]
    if udp == "block":
        lines.append("    meta l4proto udp drop")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def apply_ruleset(text):
    rc, out = plat.run([plat.which("nft") or "nft", "-f", "-"], input=text)
    if rc:
        raise ProxyError("nft failed: " + out.strip())


def remove_ruleset():
    plat.run([plat.which("nft") or "nft", "delete", "table", "inet", NFT_TABLE])


def cleanup():
    """Remove the firewall objects of the system-wide mode (crash recovery, uninstall)."""
    if plat.os_family() == "linux" and plat.which("nft"):
        rc, _ = plat.run([plat.which("nft"), "list", "table", "inet", NFT_TABLE])
        if rc == 0:
            remove_ruleset()
            return True
    return False


# ------------------------------------------------------------------ the process

def port_open(port, host="127.0.0.1", timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def free_port(avoid=()):
    for _ in range(50):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port not in avoid:
            return port
    raise ProxyError("no free local port")


class Runner:
    """One ``xray`` process.  ``log(level, text)`` receives its output."""

    def __init__(self, log, run_dir):
        self.log = log
        self.dir = os.path.join(run_dir, "proxy")
        self.proc = None
        self._reader = None
        self._tail = []

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def kill_stale(self):
        """An Xray left behind by a daemon that crashed would hold the ports: stop it (only if the pid is still Xray)."""
        pidfile = os.path.join(self.dir, "xray.pid")
        try:
            with open(pidfile) as fh:
                pid = int(fh.read().strip())
            with open("/proc/%d/cmdline" % pid, "rb") as fh:
                cmd = fh.read().split(b"\0")[0]
        except (OSError, ValueError):
            cmd = b""
            pid = 0
        if pid and os.path.basename(cmd.decode(errors="replace")).startswith("xray"):
            try:
                os.killpg(pid, 15)
            except OSError:
                try:
                    os.kill(pid, 15)
                except OSError:
                    pass
            self.log("warn", "Stopped an Xray left behind by a previous run (pid %d)" % pid)
        try:
            os.unlink(pidfile)
        except OSError:
            pass

    def start(self, config, ports, timeout=15):
        """Write the config (root only), start Xray and wait until it listens on every port in ``ports``."""
        exe = binary()
        if not exe:
            raise ProxyError("xray is not installed (see: vpnman doctor)")
        self.stop()
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        path = os.path.join(self.dir, "config.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(config, fh)
        cmd = [exe, "run", "-c", path]
        self.log("debug", "$ " + " ".join(cmd))
        try:
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, start_new_session=True, text=True, bufsize=1,
                                         errors="replace", env=dict(os.environ, PATH=os.pathsep.join(
                                             plat.EXTRA_PATH + [os.environ.get("PATH", "")])))
        except OSError as e:
            raise ProxyError("cannot start xray: %s" % e)
        self._tail = []
        try:
            with open(os.path.join(self.dir, "xray.pid"), "w") as fh:
                fh.write(str(self.proc.pid))
        except OSError:
            pass
        self._reader = threading.Thread(target=self._pump, args=(self.proc,), daemon=True)
        self._reader.start()
        end = time.time() + timeout
        while True:
            if self.proc.poll() is not None:
                self._reader.join(2)
                tail = "; ".join(self._tail[-3:])
                self.proc = None
                raise ProxyError("xray exited immediately%s" % (": " + tail if tail else ""))
            if all(port_open(p) for p in ports):
                return
            if time.time() > end:
                self.stop()
                raise ProxyError("xray did not start listening in time")
            time.sleep(0.1)

    def _pump(self, proc):
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self._tail.append(line)
                    del self._tail[:-20]
                    self.log("proxy", line)
        except (OSError, ValueError):
            pass

    def stop(self):
        proc, self.proc = self.proc, None
        if proc is None:
            return
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, 15)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, 9)
                except OSError:
                    pass
        if self._reader:
            self._reader.join(2)
        try:
            proc.stdout.close()
        except (OSError, ValueError, AttributeError):
            pass
        for name in ("config.json", "xray.pid"):
            try:
                os.unlink(os.path.join(self.dir, name))
            except OSError:
                pass
