"""Sharing the tunnel with other devices: a Wi-Fi hotspot, an Ethernet share, virtual machines or containers.

Their traffic is forwarded through this computer.  With a tunnel up, the nftables table ``inet vpnman_share``
* clamps the TCP segment size of forwarded connections to the tunnel's MTU (a tunnel is smaller than Ethernet or
  Wi-Fi, and without this large downloads and many web pages hang on the other devices: "connected, no internet"),
* turns IPv4 forwarding on for the tunnel interface.  The kernel forwards a packet only if forwarding is on for the
  interface it arrives on, and NetworkManager's hotspot switches it on only for the hotspot and the uplink it knows:
  a tunnel started by VPNMan is new to it, so the answers coming back through the tunnel were silently dropped (the
  devices saw their connections hang: "no internet") although everything on the way out worked,
* masquerades private source addresses leaving through the tunnel, so the VPN server sees the tunnel's own address
  (WireGuard and most servers drop packets from any other source) even when the hotspot software does not do it.
The kill switch (netlock) adds the matching guarantee: forwarded traffic may only leave through the tunnel.
"""

import re

from . import platform as plat

NFT_TABLE = "vpnman_share"
LAN4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def ruleset(ifaces):
    ifs = ", ".join('"%s"' % i for i in sorted(ifaces))
    return "\n".join([
        "table inet %s" % NFT_TABLE, "delete table inet %s" % NFT_TABLE, "table inet %s {" % NFT_TABLE,
        "  chain clamp {", "    type filter hook forward priority -150; policy accept;",
        "    oifname { %s } tcp flags syn tcp option maxseg size set rt mtu" % ifs,
        "  }",
        "  chain masq {", "    type nat hook postrouting priority 90; policy accept;",
        "    meta nfproto ipv4 ip saddr { %s } oifname { %s } masquerade" % (", ".join(LAN4), ifs),
        "  }", "}"]) + "\n"


_IFACE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,15}$")
_was = {}                  # interface -> the forwarding value it had before


def _forwarding_file(dev):
    return "/proc/sys/net/ipv4/conf/%s/forwarding" % dev


def forwarding(ifaces):
    """Forwarding on for ``ifaces``; interfaces handled before and no longer listed get their old value back."""
    want = {i for i in ifaces if _IFACE.match(i)}
    for dev in list(_was):
        if dev not in want:
            _write(dev, _was.pop(dev))
    for dev in want:
        if dev in _was or not plat.os_family() == "linux":
            continue
        try:
            with open(_forwarding_file(dev)) as fh:
                old = fh.read().strip()
        except OSError:
            continue                    # no such interface
        if old != "1":
            _was[dev] = old
            _write(dev, "1")


def _write(dev, value):
    try:
        with open(_forwarding_file(dev), "w") as fh:
            fh.write(str(value))
    except OSError:
        pass                            # the interface is gone: its setting went with it


def supported():
    return plat.os_family() == "linux" and bool(plat.which("nft"))


def active():
    nft = plat.which("nft")
    return bool(nft) and plat.run([nft, "list", "table", "inet", NFT_TABLE])[0] == 0


def apply(ifaces):
    """Install the rules for the tunnel interfaces ``ifaces`` (replaces any earlier version).  Returns an error text
    or ''."""
    forwarding(ifaces)
    if not ifaces:
        remove()
        return ""
    if not supported():
        return ""
    rc, out = plat.run([plat.which("nft"), "-f", "-"], input=ruleset(ifaces))
    return "" if rc == 0 else "could not share the tunnel with other devices: %s" % out.strip()


def remove():
    forwarding(())
    if supported() and active():
        plat.run([plat.which("nft"), "delete", "table", "inet", NFT_TABLE])
        return True
    return False


cleanup = remove
