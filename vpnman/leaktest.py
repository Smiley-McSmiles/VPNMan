"""Connection self-test: is traffic really going through the tunnel, and does the kill switch hold?

Every check returns {"id", "name", "status": ok|warn|fail|info, "detail"}.  The pieces that need the network or
the routing table take small callables, so the decision logic is unit-testable without privileges.
"""

import ipaddress
import os
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


def connect_via(dev, target, timeout=3.0):
    """True if a TCP connection bound to interface `dev` succeeds (needs root + Linux)."""
    fam = socket.AF_INET6 if ":" in target[0] else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
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


def public_ip(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "vpnman-leaktest"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read(2048).decode("utf-8", "replace")
    m = re.search(r'"ip"\s*:\s*"([^"]+)"', body) or re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,})", body)
    return m.group(1) if m else None


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


def run(status, settings, locked_blocks_ipv6, resolv_path="/etc/resolv.conf"):
    """Run every check for the live `status` (Manager.status())."""
    results = []
    tunnel = status.get("iface")
    connected = status.get("state") == "connected" and tunnel
    if not connected:
        results.append(check("tunnel", "VPN tunnel", "warn", "Not connected - connect first for a meaningful test."))
    else:
        results.append(check("tunnel", "VPN tunnel", "ok", "Connected to %s via %s" % (status.get("profile"), tunnel)))
        try:
            ip = public_ip(settings.get("checks.url"))
            results.append(check("ip", "Public IP", "ok" if ip else "warn",
                                 "Websites see %s" % ip if ip else "Could not read the IP lookup response."))
        except Exception as e:  # noqa: BLE001
            results.append(check("ip", "Public IP", "warn", "IP lookup failed: %s" % e))
    gw, physical = plat.default_gateway()
    if physical == tunnel:
        physical = None
    linux = plat.os_family() == "linux"
    engaged = bool(status.get("netlock", {}).get("engaged"))
    if linux:
        results.append(killswitch_check(engaged, physical, lambda: connect_via(physical, PROBE4)))
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
