"""A diagnostics report for bug reports: versions, system, state, settings, profiles and the recent log - with the
private parts removed (passwords, user names, server names and addresses, network names, public IP addresses).

``build(manager)`` returns the report as text.  The person who saves it should still read it before sharing: the
redaction is thorough for what VPNMan knows about (profiles, proxies, the network) and pattern based for the rest.
"""

import concurrent.futures
import ipaddress
import json
import platform as pyplatform
import re
import shutil
import subprocess
import sys
import time

from . import __version__, backends, netlock, xray
from . import platform as plat

SECRET_KEYS = re.compile(r"pass|secret|token|auth|private|psk|key|link|cookie|sub(?:scription)?_?url", re.I)
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:.])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:.])")     # candidates; ipaddress decides
_URL_CRED = re.compile(r"(\w+://)[^/\s:@]+:[^/\s@]+@")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_LINK = re.compile(r"\b(?:vless|vmess|trojan|ss)://\S+")


def _mask_v4(m):
    try:
        ip = ipaddress.ip_address(m.group(0))
    except ValueError:
        return m.group(0)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return m.group(0)                               # local addresses are useful and say nothing about you
    return "%s.%s.x.x" % (m.group(1), m.group(2))


def _mask_v6(m):
    try:
        ip = ipaddress.ip_address(m.group(1))
    except ValueError:
        return m.group(0)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return m.group(0)
    return ":".join(ip.exploded.split(":")[:2]) + "::x"


def redact(text, names=None):
    """``names``: {private text: placeholder} - replaced literally (longest first) before the patterns run."""
    for secret, repl in sorted((names or {}).items(), key=lambda kv: -len(kv[0])):
        if secret and len(secret) >= 3:
            text = re.sub(re.escape(secret), repl, text, flags=re.I)
    text = _LINK.sub("<share link removed>", text)
    text = _URL_CRED.sub(r"\1<user>:<password>@", text)
    text = _EMAIL.sub("<email>", text)
    text = _UUID.sub("<id>", text)
    text = _IPV4.sub(_mask_v4, text)
    return _IPV6.sub(_mask_v6, text)


def scrub(obj):
    """A copy of a settings tree with every secret-looking value blanked."""
    if isinstance(obj, dict):
        return {k: ("<removed>" if SECRET_KEYS.search(str(k)) and v not in (None, "", [], {}, False, True) else scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    return obj


def _version(cmd):
    exe = shutil.which(cmd[0])
    if not exe:
        return "not installed"
    try:
        out = subprocess.run([exe] + cmd[1:], capture_output=True, text=True, timeout=3, stdin=subprocess.DEVNULL)
        return (out.stdout + out.stderr).strip().splitlines()[0][:100] or "installed"
    except (OSError, subprocess.SubprocessError, IndexError):
        return "installed"


def _names(m):
    """What must not appear in the report: server names, user names, network names."""
    names, n = {}, 0

    def add(text, label):
        nonlocal n
        if text and str(text) not in names:
            n += 1
            names[str(text)] = "<%s-%d>" % (label, n)
    try:
        for p in m.store.list():
            add(p.get("username"), "user")
            add(p.get("name"), "profile")
            try:
                for host, _port, _proto in backends.get(p["protocol"]).endpoints(p):
                    add(host, "server")
            except (KeyError, ValueError, TypeError):
                pass
    except Exception:  # noqa: BLE001
        pass
    try:
        for p in m.proxy.store.list():
            add(p.get("server"), "proxy-server")
            add(p.get("name"), "proxy")
    except Exception:  # noqa: BLE001
        pass
    cfg = m.settings.get("netproxy") or {}
    for k in ("http", "https", "ftp", "socks"):
        add((cfg.get(k) or {}).get("host"), "netproxy-host")
        add((cfg.get(k) or {}).get("user"), "user")
    cur = m._net or {}
    add(cur.get("name"), "network")
    add(cur.get("id"), "network")
    for t in m.settings.get("network.trusted") or []:
        add(t, "trusted-network")
    for r in m.settings.get("network.rules") or []:
        add(r.get("network"), "network")
    return names


def build(m):
    names = _names(m)
    out = []

    def sec(title):
        out.append("")
        out.append("== %s ==" % title)

    out.append("VPNMan diagnostics report - %s" % time.strftime("%Y-%m-%d %H:%M:%S %Z"))
    out.append("Private parts (passwords, user names, server and network names, public addresses) are removed. "
               "Read it before you share it.")
    sec("Program")
    out.append("VPNMan %s, Python %s" % (__version__, sys.version.split()[0]))
    sec("System")
    out.append("OS: %s (%s), kernel %s" % (plat.distro()[1], plat.os_family(), pyplatform.release()))
    out.append("Init system: %s" % plat.init_system())
    try:
        out.append("Firewall: %s" % netlock.pick_backend("auto").name)
    except RuntimeError as e:
        out.append("Firewall: none (%s)" % e)
    out.append("Desktop: %s / %s" % (__import__("os").environ.get("XDG_CURRENT_DESKTOP", "-"),
                                     __import__("os").environ.get("XDG_SESSION_TYPE", "-")))
    sec("Tools")
    tools = (("openvpn", ["openvpn", "--version"]), ("wg", ["wg", "--version"]),
             ("xray", [xray.binary() or "xray", "version"]), ("stunnel", ["stunnel", "-version"]),
             ("nft", ["nft", "--version"]), ("ip", ["ip", "-V"]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tools)) as ex:       # a hung tool must not stall the rest
        for (label, _cmd), ver in zip(tools, ex.map(lambda t: _version(t[1]), tools)):
            out.append("%-8s %s" % (label, ver))
    sec("State")
    st = m.status()
    for k in ("state", "protocol", "iface", "message", "uptime", "attempt", "error_kind"):
        out.append("%-12s %s" % (k, st.get(k)))
    out.append("network lock: %s" % json.dumps(scrub(st.get("netlock") or {})))
    cur = m._net or {}
    out.append("network: kind=%s device=%s gateway=%s" % (cur.get("kind"), cur.get("device"), cur.get("gateway")))
    try:
        out.append("proxy: %s" % json.dumps(scrub({k: v for k, v in m.proxy.status().items() if k not in ("net",)})))
        out.append("network proxy: %s" % json.dumps(scrub(m.proxy.net_status())))
    except Exception as e:  # noqa: BLE001
        out.append("proxy: unavailable (%s)" % e)
    out.append("hotspots: %s" % (", ".join("%s %s" % (k, ",".join(v)) for k, v in sorted(m.hotspots.items())) or "none"))
    try:
        out.append("blocked connections: %d entries" % len(m.blocks.list()))
    except Exception:  # noqa: BLE001
        pass
    sec("Profiles")
    try:
        ps = m.store.list()
        out.append("%d profiles: %s" % (len(ps), ", ".join(sorted({p["protocol"] for p in ps})) or "-"))
        for i, p in enumerate(ps, 1):
            out.append("  %d. %s port=%s group=%s favorite=%s blacklisted=%s stunnel=%s" % (
                i, p["protocol"], p.get("port"), "yes" if p.get("group") else "no", bool(p.get("favorite")),
                bool(p.get("blacklisted")), bool((p.get("options") or {}).get("stunnel", {}).get("enabled"))))
    except Exception as e:  # noqa: BLE001
        out.append("unavailable (%s)" % e)
    sec("Settings (secrets removed)")
    out.append(json.dumps(scrub(m.settings.get(None) if hasattr(m.settings, "get") else {}), indent=1, sort_keys=True,
                          default=str))
    sec("Firewall tables")
    for fam, table in (("inet", "vpnman"), ("inet", "vpnman_split"), ("inet", "vpnman_proxy"), ("inet", "vpnman_block"),
                         ("inet", "vpnman_share")):
        nft = shutil.which("nft")
        if nft and plat.os_family() == "linux":
            rc, _ = plat.run([nft, "list", "table", fam, table])
            out.append("%s %-14s %s" % (fam, table, "present" if rc == 0 else "absent"))
    sec("Recent log (last 300 lines)")
    entries, _last = m.log.since(0, 5000)
    for e in entries[-300:]:
        out.append("%s [%s] %s" % (time.strftime("%H:%M:%S", time.localtime(e["time"])), e["level"], e["msg"]))
    return redact("\n".join(out) + "\n", names)
