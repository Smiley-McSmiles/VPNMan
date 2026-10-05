"""stunnel support: wrap a TCP-based tunnel (OpenVPN over TCP) in TLS so it looks like HTTPS.

The wrapper runs stunnel in client mode on 127.0.0.1:<free port> forwarding to the
remote TLS endpoint.  OpenVPN is then pointed at the local port (see backends/openvpn.py).

Profile options (``profile["options"]["stunnel"]``):
    enabled  bool
    host     remote stunnel/TLS server
    port     remote port (default 443)
    sni      server name to send (defaults to host)
    verify   "none" | "system" | "ca"      (ca = verify against the profile's stunnel_ca file)
    ca       file name of the CA / server certificate stored in the profile directory
"""

import os
import re
import socket

from . import platform as plat

BINARIES = ("stunnel", "stunnel4", "stunnel5")
CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
              "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-bundle.crt",
              "/usr/local/share/certs/ca-root-nss.crt", "/etc/ssl/certs/ca-certificates.pem")
READY_RE = re.compile(r"Configuration successful")
_SAFE = re.compile(r"^[A-Za-z0-9._:-]+$")


def binary():
    for b in BINARIES:
        p = plat.which(b)
        if p:
            return p
    return None


def settings_of(profile):
    st = (profile.get("options") or {}).get("stunnel") or {}
    return st if st.get("enabled") else None


def validate(profile):
    st = settings_of(profile)
    if not st:
        return []
    problems = []
    if not binary():
        problems.append("stunnel is enabled but not installed (install the 'stunnel' package)")
    host = str(st.get("host", ""))
    if not host or not _SAFE.match(host):
        problems.append("stunnel server host is missing or invalid")
    try:
        port = int(st.get("port") or 443)
        if not 0 < port < 65536:
            raise ValueError
    except (TypeError, ValueError):
        problems.append("stunnel port is invalid")
    if st.get("sni") and not _SAFE.match(str(st["sni"])):
        problems.append("stunnel SNI is invalid")
    if st.get("verify") == "ca" and not st.get("ca"):
        problems.append("stunnel verify=ca needs a CA file")
    return problems


def endpoint(profile):
    st = settings_of(profile)
    return [(st["host"], int(st.get("port") or 443), "tcp")] if st else []


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def config(profile, profile_dir, workdir, local_port):
    """Return (stunnel.conf text, list of warnings)."""
    st = settings_of(profile)
    host, port = st["host"], int(st.get("port") or 443)
    sni = st.get("sni") or host
    warn = []
    lines = ["foreground = yes", "syslog = no", "debug = 5",
             "pid = %s" % os.path.join(workdir, "stunnel.pid"), "",
             "[vpnman]", "client = yes", "accept = 127.0.0.1:%d" % local_port,
             "connect = %s:%d" % (host, port), "sslVersionMin = TLSv1.2", "sni = %s" % sni]
    verify = st.get("verify") or ("ca" if st.get("ca") else "none")
    if verify == "ca":
        lines += ["CAfile = %s" % os.path.join(profile_dir, os.path.basename(st["ca"])),
                  "verifyChain = yes", "checkHost = %s" % sni]
    elif verify == "system":
        bundle = next((b for b in CA_BUNDLES if os.path.exists(b)), None)
        if bundle:
            lines += ["CAfile = %s" % bundle, "verifyChain = yes", "checkHost = %s" % sni]
        else:
            warn.append("no system CA bundle found - stunnel will not verify the server certificate")
    else:
        warn.append("stunnel is not verifying the server certificate (the tunnel inside is still authenticated "
                    "by OpenVPN); set a CA file for full verification")
    return "\n".join(lines) + "\n", warn
