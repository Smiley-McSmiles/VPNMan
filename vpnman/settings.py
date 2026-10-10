"""Persistent settings with typed defaults (mirrors Eddie's preference groups)."""

import copy
import json
import os
import threading

from . import paths

DEFAULTS = {
    "netlock": {
        "enabled": False,          # engage the kill switch automatically when connecting
        "persist": False,          # keep the lock engaged after disconnecting / across reboots
        "backend": "auto",         # auto | nftables | iptables | pf
        "allow_lan": True,         # allow private/link-local/multicast networks
        "allow_dhcp": True,
        "allow_ping": False,
        "block_ipv6": True,        # drop all IPv6 (prevents v6 leaks on v4-only tunnels)
        "whitelist_in": [],        # IPs/CIDRs allowed to reach this host
        "whitelist_out": [],       # IPs/CIDRs this host may reach outside the tunnel
    },
    "dns": {
        "force": True,             # use the DNS servers pushed by the VPN / listed below
        "servers": [],             # custom DNS servers (override pushed ones)
    },
    "connection": {
        "autoconnect": "off",      # at boot: off | last | fastest | <profile id or name>
        "autoconnect_wait": 120,   # seconds to wait for a network connection before connecting at boot
        "reconnect": True,
        "retry_max": 3,
        "retry_delay": 5,
        "failover": True,          # try another server when one keeps failing
        "failover_group": True,    # ... preferring the servers in the same group
        "timeout": 60,
        "share_tunnel": True,      # hotspots / shared connections / VMs behind this computer use the tunnel (and only it)
        "share_ifaces": [],        # more interfaces to treat as hotspots (a libvirt/Docker bridge, a USB tether...)
        "reconnect_on_change": True,   # reconnect at once when the computer wakes up or the network (gateway) changes
        "openvpn_args": [],        # extra raw arguments appended to OpenVPN
    },
    "access": {
        "mode": "session",         # session: root + groups + active local users | group: root + groups only
        "groups": ["vpnman", "wheel", "sudo"],
    },
    "network": {
        "trusted": [],             # SSIDs / "wired:<gateway mac>" you trust (see network.py)
        "untrusted_action": "off", # off | connect  (when joining a network that is not trusted)
        "trusted_action": "off",   # off | disconnect  (when joining a trusted one - only if we connected automatically)
        "profile": "last",         # what to connect to: last | fastest | <profile id or name>
        "rules": [],               # per network: [{network, server (profile id or ""), netproxy ("", on, off), xray ("", off, <proxy id>)}]
    },
    "schedule": {
        "enabled": True,
        "entries": [],             # see schedule.py: {id, name, enabled, days, start, end, profile}
    },
    "split": {
        "enabled": True,           # apps below keep using the normal connection while the VPN is up
        "mode": "exclude",         # exclude: listed apps skip the VPN | include: ONLY listed apps use the VPN
        "apps": [],                # [{id, name, match: [process names], icon}]
    },
    "routes": [],                  # [{"ip": "10.0.0.0/8", "action": "out"}]  out = bypass the VPN
    "blocks": {
        "enabled": True,           # enforce the list below
        "entries": [],             # [{id, kind: address|endpoint|port|app, value, proto, note, enabled, created,
                                   #   expires (0: never), boot ("": survives restarts)}]
    },
    "proxy": {
        "enabled": False,          # use the selected proxy (see vpnman proxy)
        "selected": "",            # id of the proxy in use
        "order": "proxy_only",     # proxy_only | vpn_proxy (the proxy inside the VPN) | proxy_vpn (the VPN inside the proxy)
        "mode": "local",           # local: SOCKS/HTTP proxy for applications | system: send all TCP and DNS through it
        "socks_port": 10808,
        "http_port": 10809,
        "dns": "1.1.1.1",          # system mode: the resolver that answers queries (asked through the proxy)
        "udp": "block",            # system mode: block | direct - what happens to UDP other than DNS
        "failover": False,         # switch to the next favourite proxy (else the group) when the server stops answering
    },
    "netproxy": {                  # a plain HTTP / SOCKS5 proxy all traffic goes through (after the VPN, if connected)
        "enabled": False,
        "http": {"host": "", "port": 8080, "user": "", "password": ""},
        "https": {"host": "", "port": 0, "user": "", "password": ""},
        "ftp": {"host": "", "port": 0, "user": "", "password": ""},
        "socks": {"host": "", "port": 0, "user": "", "password": ""},
        "ignore": ["localhost", "127.0.0.0/8", "::1"],   # go direct (addresses, networks, domains)
        "apps": [],                # programs that go direct
        "dns": "1.1.1.1",          # answers this computer's DNS, asked over TCP through the proxy
        "udp": "block",            # block | direct - UDP other than DNS (a proxy cannot carry it)
        "killswitch": True,        # while the proxy cannot work (down, restarting, a wrong address) block all traffic
    },
    "events": {
        "pre_connect": "",
        "connected": "",
        "disconnected": "",
    },
    "checks": {
        "tunnel": True,            # look up the public IP after connecting
        "url": "https://api.ipify.org?format=json",
    },
    "ui": {
        "notifications": True,
        "group_order": [],         # server groups in this order (ungrouped servers first, unlisted groups after, by name)
    },
}


# (label, servers) offered by the GUI and `vpnman dns`
DNS_PRESETS = [
    ("Cloudflare", ["1.1.1.1", "1.0.0.1"]),
    ("Cloudflare (blocks malware)", ["1.1.1.2", "1.0.0.2"]),
    ("Google", ["8.8.8.8", "8.8.4.4"]),
    ("Quad9", ["9.9.9.9", "149.112.112.112"]),
    ("OpenDNS", ["208.67.222.222", "208.67.220.220"]),
    ("AdGuard (blocks ads)", ["94.140.14.14", "94.140.15.15"]),
    ("Mullvad", ["194.242.2.2"]),
]


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge(out[k], v)
        elif k in out and type(out[k]) is type(v):
            out[k] = v
        elif k in out and isinstance(out[k], bool) is False and isinstance(out[k], (int, float)) \
                and isinstance(v, (int, float)) and not isinstance(v, bool):
            out[k] = v
    return out


class Settings:
    def __init__(self, path=None):
        self.path = path or paths.settings_file()
        self._lock = threading.RLock()
        self.data = copy.deepcopy(DEFAULTS)
        self.load()

    def load(self):
        try:
            with open(self.path) as fh:
                self.data = _merge(DEFAULTS, json.load(fh))
        except (OSError, ValueError):
            self.data = copy.deepcopy(DEFAULTS)

    def save(self):
        with self._lock:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)

    def get(self, dotted=None):
        with self._lock:
            if not dotted:
                return copy.deepcopy(self.data)
            node = self.data
            for part in dotted.split("."):
                if not isinstance(node, dict) or part not in node:
                    raise KeyError("unknown setting: %s" % dotted)
                node = node[part]
            return copy.deepcopy(node)

    def set(self, dotted, value):
        """Set one value, coercing strings to the default's type."""
        with self._lock:
            parts = dotted.split(".")
            node, dnode = self.data, DEFAULTS
            for part in parts[:-1]:
                if not isinstance(node, dict) or part not in node:
                    raise KeyError("unknown setting: %s" % dotted)
                node, dnode = node[part], dnode[part]
            key = parts[-1]
            if key not in node:
                raise KeyError("unknown setting: %s" % dotted)
            node[key] = coerce(value, dnode[key])
            self.save()
            return node[key]

    def update(self, tree):
        with self._lock:
            self.data = _merge(self.data, tree)
            self.save()


def coerce(value, like):
    if isinstance(like, bool):
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ("1", "true", "yes", "on"):
                return True
            if v in ("0", "false", "no", "off"):
                return False
            raise ValueError("expected a boolean, got %r" % value)
        return bool(value)
    if isinstance(like, int):
        return int(value)
    if isinstance(like, list):
        if isinstance(value, str):
            s = value.strip()
            if s.startswith("["):
                return json.loads(s)
            return [x.strip() for x in s.replace(";", ",").split(",") if x.strip()]
        return list(value)
    return str(value) if isinstance(like, str) else value
