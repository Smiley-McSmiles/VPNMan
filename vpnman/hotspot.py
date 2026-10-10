"""Hotspots and shared connections: finding the interfaces other devices connect to, and the kernel details of
redirecting what they send.

A "hotspot" is an interface this computer shares: the Wi-Fi hotspot of GNOME, KDE Plasma and Cinnamon (all are
NetworkManager connections with the IPv4 method "shared"), any Wi-Fi interface in access-point mode (hostapd,
create_ap), or an interface named in the setting ``connection.share_ifaces`` (a libvirt/Docker bridge, a USB tether...).

* ``Scanner.scan()``        {interface: [networks]} of the hotspots that are up right now (cheap: one ``ip`` call
                            per look; NetworkManager is asked only when an interface appears or changes)
* ``route_localnet(...)``   the sysctl that lets traffic redirected to 127.0.0.1 enter from a hotspot (restored later)
* ``flush(networks)``       forget the tracked connections of the devices behind a hotspot, so what they have open
                            starts again over the route that is current now (after the VPN or proxy came or went)
"""

import ipaddress
import json
import os
import re
import socket
import struct

from . import paths
from . import platform as plat

_ADDR = re.compile(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet\s+(\S+)")


def _private(net):
    return net.is_private and not net.is_loopback and not net.is_link_local


def addresses():
    """{interface: [IPv4Network, ...]} for every interface with a private IPv4 address (not loopback)."""
    ip = plat.which("ip")
    if not ip or plat.os_family() != "linux":
        return {}
    rc, out = plat.run([ip, "-o", "-4", "addr", "show"])
    found = {}
    if rc:
        return found
    for line in out.splitlines():
        m = _ADDR.match(line)
        if not m or m.group(1) == "lo":
            continue
        try:
            net = ipaddress.ip_interface(m.group(2)).network
        except ValueError:
            continue
        if _private(net):
            found.setdefault(m.group(1), []).append(net)
    return found


def _nm_shared():
    """Interfaces NetworkManager shares right now: {device} (empty without NetworkManager)."""
    nmcli = plat.which("nmcli")
    if not nmcli:
        return set()
    rc, out = plat.run([nmcli, "-t", "-f", "DEVICE,UUID", "connection", "show", "--active"], timeout=10)
    shared = set()
    if rc:
        return shared
    for line in out.splitlines():
        dev, _, uuid = line.rpartition(":")
        dev = dev.replace("\\:", ":")
        if not dev or dev == "--" or not uuid:
            continue
        rc, method = plat.run([nmcli, "-g", "ipv4.method", "connection", "show", "uuid", uuid], timeout=10)
        if rc == 0 and method.strip() == "shared":
            shared.add(dev)
    return shared


def _access_point(dev):
    iw = plat.which("iw")
    if not iw or not os.path.isdir("/sys/class/net/%s/phy80211" % dev):
        return False
    rc, out = plat.run([iw, "dev", dev, "info"], timeout=5)
    return rc == 0 and bool(re.search(r"^\s*type\s+AP\b", out, re.M))


class Scanner:
    def __init__(self):
        self._seen = {}          # (interface, networks) -> is it a hotspot (asked once while nothing changes)

    def scan(self, extra=(), exclude=()):
        """{interface: [network text, ...]} of the hotspots that are up (``exclude``: tunnel interfaces)."""
        addrs = {i: n for i, n in addresses().items() if i not in set(exclude)}
        extra = {str(e) for e in extra}
        keys = {(i, tuple(map(str, n))) for i, n in addrs.items()}
        self._seen = {k: v for k, v in self._seen.items() if k in keys}
        shared = None
        out = {}
        for i, nets in addrs.items():
            key = (i, tuple(map(str, nets)))
            if i in extra:
                is_hs = True
            elif key in self._seen:
                is_hs = self._seen[key]
            else:
                if shared is None:
                    shared = _nm_shared()
                is_hs = i in shared or _access_point(i)
                self._seen[key] = is_hs
            if is_hs:
                out[i] = [str(n) for n in nets]
        return out


# ------------------------------------------------------------------------------------------ route_localnet

def _state_file():
    return os.path.join(paths.run_dir(), "route_localnet.json")


def _sysctl(dev):
    return "/proc/sys/net/ipv4/conf/%s/route_localnet" % dev


def route_localnet(ifaces):
    """Turn route_localnet on for ``ifaces`` (and back off for the interfaces no longer listed).  Remembers the
    earlier values in a file so a crashed daemon's change is undone at the next start (restore())."""
    try:
        with open(_state_file()) as fh:
            old = json.load(fh)
    except (OSError, ValueError):
        old = {}
    want = set(ifaces)
    for dev in list(old):
        if dev not in want:
            _write(dev, old.pop(dev))
    for dev in want:
        if dev in old or not os.path.exists(_sysctl(dev)):
            continue
        try:
            with open(_sysctl(dev)) as fh:
                old[dev] = fh.read().strip()
        except OSError:
            continue
        _write(dev, "1")
    _save(old)


def restore():
    route_localnet(())


def _write(dev, value):
    try:
        with open(_sysctl(dev), "w") as fh:
            fh.write(str(value))
    except OSError:
        pass            # the interface is gone: its setting went with it


def _save(state):
    try:
        if state:
            os.makedirs(paths.run_dir(), mode=0o755, exist_ok=True)
            with open(_state_file(), "w") as fh:
                json.dump(state, fh)
        elif os.path.exists(_state_file()):
            os.unlink(_state_file())
    except OSError:
        pass


# ------------------------------------------------------------------------------------------ connection tracking

NFNL_CT = 1 << 8
CT_GET, CT_DELETE = 1, 2
NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP = 1, 4, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
CTA_TUPLE_ORIG, CTA_TUPLE_IP, CTA_IP_V4_SRC = 1, 1, 1


def _attrs(data):
    pos = 0
    while pos + 4 <= len(data):
        ln, typ = struct.unpack_from("=HH", data, pos)
        if ln < 4:
            break
        yield typ & 0x3FFF, data[pos:pos + ln], data[pos + 4:pos + ln]
        pos += (ln + 3) & ~3


def _orig_src(payload):
    for typ, _raw, body in _attrs(payload):
        if typ == CTA_TUPLE_ORIG:
            for t2, _r2, b2 in _attrs(body):
                if t2 == CTA_TUPLE_IP:
                    for t3, _r3, b3 in _attrs(b2):
                        if t3 == CTA_IP_V4_SRC and len(b3) == 4:
                            return ipaddress.IPv4Address(b3)
    return None


def _entries(sock, seq=1):
    """(raw CTA_TUPLE_ORIG attribute, its source address) for every tracked IPv4 connection."""
    sock.send(struct.pack("=IHHII", 20, NFNL_CT | CT_GET, NLM_F_REQUEST | NLM_F_DUMP, seq, 0) +
              struct.pack("=BBH", socket.AF_INET, 0, 0))
    found = []
    while True:
        data = sock.recv(1 << 18)
        pos = 0
        while pos + 16 <= len(data):
            ln, typ = struct.unpack_from("=IH", data, pos)
            if ln < 16:
                return found
            if typ == NLMSG_DONE:
                return found
            if typ == NLMSG_ERROR:
                return found
            payload = data[pos + 20:pos + ln]
            for t, raw, _body in _attrs(payload):
                if t == CTA_TUPLE_ORIG:
                    src = _orig_src(payload)
                    if src is not None:
                        found.append((raw, src))
            pos += (ln + 3) & ~3


def flush(networks):
    """Delete the tracked IPv4 connections started by an address in ``networks`` (the devices behind a hotspot).
    Their packets then start new tracking, with the NAT and the route of today.  Returns how many were removed."""
    nets = []
    for n in networks:
        try:
            nets.append(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            continue
    if not nets or plat.os_family() != "linux":
        return 0
    removed = 0
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)          # NETLINK_NETFILTER
        s.settimeout(5)
        try:
            s.bind((0, 0))
            for raw, src in _entries(s):
                if not any(src in n for n in nets):
                    continue
                msg = struct.pack("=BBH", socket.AF_INET, 0, 0) + raw
                s.send(struct.pack("=IHHII", 16 + len(msg), NFNL_CT | CT_DELETE, NLM_F_REQUEST | NLM_F_ACK, 2, 0) + msg)
                reply = s.recv(4096)
                if len(reply) >= 20 and struct.unpack_from("=H", reply, 4)[0] == NLMSG_ERROR \
                        and struct.unpack_from("=i", reply, 16)[0] == 0:
                    removed += 1
        finally:
            s.close()
    except OSError:
        return removed
    return removed


def count(networks):
    """How many tracked connections the devices in ``networks`` have (used by the tests)."""
    nets = [ipaddress.ip_network(str(n), strict=False) for n in networks]
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
    s.settimeout(5)
    try:
        s.bind((0, 0))
        return sum(1 for _raw, src in _entries(s) if any(src in n for n in nets))
    finally:
        s.close()
