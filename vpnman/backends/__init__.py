"""Protocol backend registry and config-file sniffing."""

from .base import Backend, Context  # noqa: F401
from .openvpn import OpenVPN
from .wireguard import AmneziaWG, WireGuard
from .others import (VPNC, Custom, Nebula, NetBird, NetworkManager, OpenConnect, OpenFortiVPN,
                     PPTP, SSTP, StrongSwan, Tailscale, ZeroTier)

_ALL = [OpenVPN, WireGuard, AmneziaWG, OpenConnect, OpenFortiVPN, StrongSwan, SSTP, PPTP, VPNC,
        Tailscale, NetBird, ZeroTier, Nebula, NetworkManager, Custom]

REGISTRY = {cls.id: cls() for cls in _ALL}


def get(proto):
    try:
        return REGISTRY[proto]
    except KeyError:
        raise KeyError("unknown protocol: %s (known: %s)" % (proto, ", ".join(REGISTRY)))


def sniff(filename, text):
    """Best-guess protocol id for a config file, or None."""
    best, best_score = None, 0
    for cls in _ALL:
        score = cls.sniff(filename, text)
        if score > best_score:
            best, best_score = cls.id, score
    return best if best_score >= 50 else None


def describe():
    from .. import stunnel
    extra = [{"id": "stunnel", "label": "stunnel (TLS wrapper)",
              "description": "Carry OpenVPN over TLS so it looks like HTTPS (enable per OpenVPN profile)",
              "available": bool(stunnel.binary()), "missing": [] if stunnel.binary() else ["stunnel"],
              "mode": "wrapper", "fields": [], "note": ""}]
    return [{"id": b.id, "label": b.label, "description": b.description,
             "available": b.available(), "missing": b.missing(), "mode": b.mode,
             "fields": list(b.fields), "note": b.lock_note}
            for b in REGISTRY.values()]
