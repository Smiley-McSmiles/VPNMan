"""Sharing the tunnel with other devices: a Wi-Fi hotspot, an Ethernet share, virtual machines or containers.

Their traffic is forwarded through this computer.  With a tunnel up, the nftables table ``inet vpnman_share``
* clamps the TCP segment size of forwarded connections to the tunnel's MTU (a tunnel is smaller than Ethernet or
  Wi-Fi, and without this large downloads and many web pages hang on the other devices: "connected, no internet"),
* masquerades private source addresses leaving through the tunnel, so the VPN server sees the tunnel's own address
  (WireGuard and most servers drop packets from any other source) even when the hotspot software does not do it.
The kill switch (netlock) adds the matching guarantee: forwarded traffic may only leave through the tunnel.
"""

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


def supported():
    return plat.os_family() == "linux" and bool(plat.which("nft"))


def active():
    nft = plat.which("nft")
    return bool(nft) and plat.run([nft, "list", "table", "inet", NFT_TABLE])[0] == 0


def apply(ifaces):
    """Install the rules for the tunnel interfaces ``ifaces`` (replaces any earlier version).  Returns an error text
    or ''."""
    if not ifaces:
        remove()
        return ""
    if not supported():
        return ""
    rc, out = plat.run([plat.which("nft"), "-f", "-"], input=ruleset(ifaces))
    return "" if rc == 0 else "could not share the tunnel with other devices: %s" % out.strip()


def remove():
    if supported() and active():
        plat.run([plat.which("nft"), "delete", "table", "inet", NFT_TABLE])
        return True
    return False


cleanup = remove
