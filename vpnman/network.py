"""Which network are we on?  Used for trusted-network automation and to notice when the gateway changes.

A network has an id that is stable across reconnects: ``wifi:<SSID>`` or ``wired:<gateway MAC>`` (gateway IPs such as
192.168.1.1 are the same on thousands of networks, the router's MAC is not).  Users see and type the short form: the
SSID for Wi-Fi, ``wired:aa:bb:..`` for cable.
"""

import os
import re

from . import platform as plat


def is_wireless(dev):
    return bool(dev) and (os.path.isdir("/sys/class/net/%s/wireless" % dev) or dev.startswith(("wl", "wlan", "ath", "iwn")))


def wifi_ssid(dev):
    """SSID of the Wi-Fi network `dev` is associated with, or None.  Tries iwgetid, iw, then NetworkManager."""
    tries = []
    if plat.which("iwgetid"):
        tries.append((["iwgetid", "-r", dev], lambda out: out.strip() or None))
    if plat.which("iw"):
        tries.append((["iw", "dev", dev, "link"],
                      lambda out: (re.search(r"^\s*SSID:\s*(.+)$", out, re.M) or [None, None])[1]))
    if plat.which("nmcli"):
        tries.append((["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                      lambda out: next((l.split(":", 1)[1] for l in out.splitlines() if l.startswith("yes:")), None)))
    for cmd, parse in tries:
        rc, out = plat.run(cmd)
        if rc == 0:
            val = parse(out)
            if val:
                return val.strip()
    return None


def gateway_mac(gw, dev=None):
    """MAC of the default gateway from the neighbour table (None if not resolved yet)."""
    if not gw:
        return None
    try:
        with open("/proc/net/arp") as fh:
            next(fh)
            for line in fh:
                f = line.split()
                if len(f) >= 4 and f[0] == gw and f[3] != "00:00:00:00:00:00":
                    return f[3].lower()
    except (OSError, StopIteration):
        pass
    exe = plat.which("arp")
    if exe:
        rc, out = plat.run([exe, "-n", gw])
        m = re.search(r"((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})", out, re.I)
        if m:
            return m.group(1).lower()
    return None


def current():
    """{"id", "name", "kind": wifi|wired|none, "device", "gateway"} for the network the default route uses."""
    gw, dev = plat.default_gateway()
    if not dev:
        return {"id": None, "name": None, "kind": "none", "device": None, "gateway": None}
    if is_wireless(dev):
        ssid = wifi_ssid(dev)
        if ssid:
            return {"id": ssid, "name": ssid, "kind": "wifi", "device": dev, "gateway": gw}
    mac = gateway_mac(gw, dev)
    nid = "wired:%s" % mac if mac else "wired:%s@%s" % (dev, gw)
    return {"id": nid, "name": "Wired network (%s)" % (mac or dev), "kind": "wired", "device": dev, "gateway": gw}


def is_trusted(net_id, trusted):
    return bool(net_id) and any(net_id.lower() == str(t).strip().lower() for t in trusted)
