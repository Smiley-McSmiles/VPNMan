"""Connection self-test: is traffic really going through the tunnel, and does the kill switch hold?

Every check returns {"id", "name", "status": ok|warn|fail|info, "detail"}.  The pieces that need the network or
the routing table take small callables, so the decision logic is unit-testable without privileges.
"""

import ipaddress
import re
import socket
import urllib.request

from . import platform as plat

PROBE4 = ("1.1.1.1", 443)
PROBE6 = ("2606:4700:4700::1111", 443)


def check(cid, name, status, detail):
    return {"id": cid, "name": name, "status": status, "detail": detail}


def route_dev(addr, family=4):
    """Interface the kernel would use to reach `addr` (None if unroutable / unknown)."""
    ip = plat.which("ip")
    if not ip or plat.os_family() != "linux":
        return None
    rc, out = plat.run([ip, "-6" if family == 6 else "-4", "route", "get", addr])
    if rc != 0:
        return None
    m = re.search(r"\bdev (\S+)", out)
    return m.group(1) if m else None


def nameservers(text):
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in out:
            out.append(parts[1])
    return out


def dns_check(resolv_text, tunnel, dev_of, resolved_dns=None, forced=True):
    """Do the resolvers in use sit behind the tunnel?  `dev_of(addr)` -> interface; `resolved_dns` maps
    link -> [servers] (systemd-resolved), used when /etc/resolv.conf only holds the local stub."""
    if not forced:
        return check("dns", "DNS servers", "info", "Your settings leave DNS unchanged while connected, so the "
                     "servers in use are whatever your network provides.")
    servers = nameservers(resolv_text)
    local = [s for s in servers if _is_loopback(s)]
    remote = [s for s in servers if not _is_loopback(s)]
    leaks = [s for s in remote if dev_of(s) not in (tunnel, None) and dev_of(s) != "lo"]
    if leaks:
        return check("dns", "DNS servers", "fail", "DNS server %s is reached outside the tunnel (DNS leak). "
                     "Turn on 'Change DNS while connected' or choose DNS servers on the Connection page."
                     % ", ".join(leaks))
    if remote and not local:
        return check("dns", "DNS servers", "ok", "%s: reached through %s" % (", ".join(remote), tunnel))
    if local:
        tun_dns = (resolved_dns or {}).get(tunnel)
        if tun_dns:
            return check("dns", "DNS servers", "ok", "systemd-resolved sends queries to %s on %s"
                         % (", ".join(tun_dns), tunnel))
        return check("dns", "DNS servers", "warn", "The system uses a local DNS stub (%s) and no DNS servers are "
                     "set on %s, so queries may go to your normal DNS. Use custom DNS servers to be sure."
                     % (", ".join(local), tunnel))
    return check("dns", "DNS servers", "warn", "No DNS servers found in /etc/resolv.conf")


def _is_loopback(addr):
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def ipv6_check(tunnel, dev_of6, reachable6, locked, blocked_by_lock):
    """IPv6 must either ride the tunnel or not work at all."""
    dev = dev_of6(PROBE6[0])
    if dev is None:
        return check("ipv6", "IPv6", "ok", "This computer has no IPv6 route to the internet, so nothing can leak over it.")
    if dev == tunnel:
        return check("ipv6", "IPv6", "ok", "IPv6 traffic goes through the tunnel (%s)." % tunnel)
    if locked and blocked_by_lock:
        return check("ipv6", "IPv6", "ok", "IPv6 would leave via %s but the network lock blocks all IPv6." % dev)
    if reachable6():
        return check("ipv6", "IPv6", "fail", "IPv6 traffic leaves through %s, outside the VPN. Turn on 'Block IPv6' on "
                     "the Network Lock page or disable IPv6." % dev)
    return check("ipv6", "IPv6", "warn", "IPv6 is routed via %s (outside the VPN) but the test connection failed. "
                 "Turn on 'Block IPv6' to be safe." % dev)


def connect_via(dev, target, timeout=3.0, mark=0):
    """True if a TCP connection bound to interface `dev` succeeds (needs root + Linux).  ``mark``: socket mark, so the
    proxy's system-wide redirect lets the probe reach the kill switch instead of catching it."""
    fam = socket.AF_INET6 if ":" in target[0] else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if mark:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), mark)
        if dev:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), dev.encode() + b"\0")
        s.connect(target)
        return True
    except OSError:
        return False
    finally:
        s.close()


def killswitch_check(engaged, physical, can_leave):
    if not engaged:
        return check("killswitch", "Kill switch", "info", "The network lock is not engaged, so traffic would leave "
                     "unprotected if the VPN dropped. Turn it on from the Network Lock page.")
    if not physical:
        return check("killswitch", "Kill switch", "info", "Could not find a normal network interface to test with.")
    if can_leave():
        return check("killswitch", "Kill switch", "fail", "A connection could leave through %s outside the tunnel, "
                     "so the network lock is NOT blocking it." % physical)
    return check("killswitch", "Kill switch", "ok", "Traffic through %s outside the tunnel is blocked." % physical)


def parse_ip_answer(body):
    """The address in an IP lookup answer: the "ip" field of a JSON reply, or a reply that is nothing but an address.
    Anything else (an HTML error page, a captive portal) gives None - never the first thing that looks like an IP."""
    body = (body or "").strip()
    m = re.search(r'"ip"\s*:\s*"([^"]+)"', body)
    cand = m.group(1) if m else body
    try:
        return str(ipaddress.ip_address(cand.strip()))
    except ValueError:
        return None


# Cloudflare's published ranges (https://www.cloudflare.com/ips/).  Proxies are often put behind its CDN or run on
# its Workers; then the server address - and sometimes the address websites see - is Cloudflare's, not the server's.
CLOUDFLARE = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    # not on that list: where Cloudflare WARP traffic leaves (and its anycast service addresses)
    "104.28.0.0/16", "162.159.0.0/16", "2a09:bac0::/29"))


def is_cloudflare(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in CLOUDFLARE if n.version == a.version)


def public_ip(url, timeout=8, proxy=None):
    """The address websites see; ``proxy`` ("http://127.0.0.1:PORT") asks through that HTTP proxy."""
    req = urllib.request.Request(url, headers={"User-Agent": "vpnman-leaktest"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}))
    with opener.open(req, timeout=timeout) as r:
        body = r.read(2048).decode("utf-8", "replace")
    return parse_ip_answer(body)


def resolved_dns_map():
    """{link: [servers]} from `resolvectl dns`, or {}."""
    exe = plat.which("resolvectl")
    if not exe:
        return {}
    rc, out = plat.run([exe, "dns"])
    res = {}
    for line in out.splitlines():
        m = re.match(r"Link \d+ \((\S+)\):\s*(.*)", line.strip())
        if m and m.group(2).strip():
            res[m.group(1)] = m.group(2).split()
    return res


def proxy_check(px, direct_ip, via_proxy):
    """Is the proxy doing its job?  ``px``: ProxyService.status() plus ``server_ips``; ``direct_ip``: what websites see
    from this computer; ``via_proxy()``: what they see through the local HTTP proxy (local mode).  None when the proxy
    is off."""
    if not px or not px.get("enabled"):
        return None
    name = px.get("name") or "the proxy"
    if not px.get("running"):
        if px.get("order") == "vpn_proxy":
            return check("proxy", "Proxy", "info", "%s starts once the VPN is connected." % name)
        if px.get("order") == "proxy_vpn":
            return check("proxy", "Proxy", "info", "%s starts with the VPN connection it carries." % name)
        return check("proxy", "Proxy", "fail", "%s is switched on but not running%s." % (
            name, ": " + px["error"] if px.get("error") else ""))
    servers = px.get("server_ips") or []
    cf_note = ""
    if servers and all(is_cloudflare(s) for s in servers):
        cf_note = " %s is reached through Cloudflare (%s is a Cloudflare address): the proxy sits behind Cloudflare's CDN " \
                  "or runs on it." % (name, servers[0])
    if px.get("carrier"):
        return check("proxy", "Proxy", "ok", "The VPN connection travels through %s (%s).%s" % (name, ", ".join(servers),
                                                                                                 cf_note))
    if px.get("mode") == "system":
        if not direct_ip:
            return check("proxy", "Proxy", "warn", "System-wide through %s, but the public IP could not be read." % name)
        if direct_ip in servers:
            return check("proxy", "Proxy", "ok", "System-wide: websites see %s, the address of %s.%s" % (
                direct_ip, name, cf_note))
        if is_cloudflare(direct_ip):
            return check("proxy", "Proxy", "ok", "System-wide: websites see %s, a Cloudflare address - %s sends your "
                         "traffic out through Cloudflare (a proxy running on Cloudflare Workers, or one that relays "
                         "through Cloudflare WARP).%s" % (direct_ip, name, cf_note))
        if cf_note:
            return check("proxy", "Proxy", "ok", "System-wide: websites see %s.%s The address websites see is where "
                         "the server behind Cloudflare sends traffic out." % (direct_ip, cf_note))
        return check("proxy", "Proxy", "warn", "System-wide: websites see %s, not the address of %s (%s). That is normal "
                     "when the proxy server sends traffic out from another address (a relay or a CDN); otherwise traffic "
                     "may be going around the proxy." % (direct_ip, name, ", ".join(servers) or "unknown"))
    try:
        via = via_proxy()
    except Exception as e:  # noqa: BLE001
        return check("proxy", "Proxy", "fail", "The local proxy on 127.0.0.1:%s did not work: %s" % (px.get("http"), e))
    if not via:
        return check("proxy", "Proxy", "warn", "Could not read the IP lookup response through the proxy.")
    if direct_ip and via == direct_ip:
        return check("proxy", "Proxy", "warn", "Through the proxy websites still see %s, the same address as without it."
                     % via)
    cf_exit = " That is a Cloudflare address: %s sends traffic out through Cloudflare (Workers or WARP)." % name \
        if is_cloudflare(via) else ""
    return check("proxy", "Proxy", "ok", "Programs that use 127.0.0.1:%s (HTTP) or :%s (SOCKS5) appear as %s%s.%s%s" % (
        px.get("http"), px.get("socks"), via, "; others as %s" % direct_ip if direct_ip else "", cf_exit, cf_note))


def run(status, settings, locked_blocks_ipv6, resolv_path="/etc/resolv.conf", proxy=None):
    """Run every check for the live `status` (Manager.status()); ``proxy``: see proxy_check."""
    results = []
    tunnel = status.get("iface")
    connected = status.get("state") == "connected" and tunnel
    proxied = bool(proxy and proxy.get("running"))
    ip = None
    if not connected:
        results.append(check("tunnel", "VPN tunnel", "info" if proxied else "warn",
                             "Not connected - connect first for a meaningful test."))
    else:
        results.append(check("tunnel", "VPN tunnel", "ok", "Connected to %s via %s" % (status.get("profile"), tunnel)))
    if connected or proxied:
        try:
            ip = public_ip(settings.get("checks.url"))
            results.append(check("ip", "Public IP", "ok" if ip else "warn",
                                 "Websites see %s" % ip if ip else "Could not read the IP lookup response."))
        except Exception as e:  # noqa: BLE001
            results.append(check("ip", "Public IP", "warn", "IP lookup failed: %s" % e))
    pc = proxy_check(proxy, ip, lambda: public_ip(settings.get("checks.url"),
                                                  proxy="http://127.0.0.1:%s" % (proxy or {}).get("http")))
    if pc:
        results.append(pc)
    gw, physical = plat.default_gateway()
    if physical == tunnel:
        physical = None
    linux = plat.os_family() == "linux"
    engaged = bool(status.get("netlock", {}).get("engaged"))
    if linux:
        mark = 0x5658 if proxied and proxy.get("mode") == "system" else 0     # xray.MARK
        results.append(killswitch_check(engaged, physical, lambda: connect_via(physical, PROBE4, mark=mark)))
    else:
        results.append(check("killswitch", "Kill switch", "info", "The kill switch self-test needs Linux."))
    if connected:
        if linux:
            try:
                with open(resolv_path) as fh:
                    text = fh.read()
            except OSError:
                text = ""
            results.append(dns_check(text, tunnel, route_dev, resolved_dns_map(), settings.get("dns.force")))
            results.append(ipv6_check(tunnel, lambda a: route_dev(a, 6), lambda: connect_via(None, PROBE6),
                                      engaged, locked_blocks_ipv6))
        else:
            results.append(check("dns", "DNS servers", "info", "The DNS self-test needs Linux."))
        try:
            socket.getaddrinfo("example.com", 443)
            results.append(check("resolve", "Name resolution", "ok", "Looking up names works."))
        except OSError as e:
            results.append(check("resolve", "Name resolution", "fail", "Looking up names failed: %s" % e))
    worst = "fail" if any(r["status"] == "fail" for r in results) else \
        "warn" if any(r["status"] == "warn" for r in results) else "ok"
    return {"checks": results, "summary": worst}
