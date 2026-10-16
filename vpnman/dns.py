"""DNS switching for the lifetime of a tunnel, init-system agnostic.

* systemd-resolved   -> resolvectl on the tunnel interface (reverted afterwards)
* everything else    -> rewrite /etc/resolv.conf, keeping a backup that is
                        restored on disconnect (and on daemon start after a crash)
"""

import os
import shutil

from . import paths
from . import platform as plat

MARK = "# managed by vpnman"


def _resolv():
    return os.environ.get("VPNMAN_RESOLV_CONF", "/etc/resolv.conf")


def _backup():
    return os.path.join(paths.run_dir(), "resolv.conf.vpnman-backup")


def _linkfile():
    return os.path.join(paths.run_dir(), "resolv.conf.vpnman-link")


class DnsManager:
    def __init__(self):
        self.mode = None
        self.iface = None

    def apply(self, servers, iface=None):
        servers = [s for s in servers if s]
        if not servers:
            return "no DNS servers to apply"
        resolved = plat.which("resolvectl")
        rpath = _resolv()
        if resolved and iface and os.path.realpath(rpath).startswith("/run/systemd/resolve") \
                and plat.iface_exists(iface):
            rc, out = plat.run([resolved, "dns", iface] + servers)
            if rc == 0:
                plat.run([resolved, "domain", iface, "~."])
                plat.run([resolved, "default-route", iface, "yes"])
                self.mode, self.iface = "resolved", iface
                return "DNS set via systemd-resolved: " + ", ".join(servers)
        os.makedirs(paths.run_dir(), mode=0o755, exist_ok=True)
        if not os.path.exists(_backup()) and not os.path.exists(_linkfile()):
            if os.path.islink(rpath):
                with open(_linkfile(), "w") as fh:
                    fh.write(os.readlink(rpath))
                os.unlink(rpath)
                open(_backup(), "w").close()
            elif os.path.exists(rpath):
                shutil.copy2(rpath, _backup())
            else:
                open(_backup(), "w").close()
        tmp = rpath + ".vpnman"
        with open(tmp, "w") as fh:
            fh.write("%s\n" % MARK)
            for s in servers:
                fh.write("nameserver %s\n" % s)
        os.chmod(tmp, 0o644)
        os.replace(tmp, rpath)
        self.mode = "file"
        return "DNS set in %s: %s" % (rpath, ", ".join(servers))

    def restore(self):
        if self.mode == "resolved" and self.iface:
            plat.run([plat.which("resolvectl") or "resolvectl", "revert", self.iface])
        self.mode = self.iface = None
        restore_resolv_conf()


def nss_resolve(path="/etc/nsswitch.conf"):
    """True when programs resolve names through systemd-resolved's NSS module (Fedora, Arch, Ubuntu...): they ask it over a
    local socket, not with DNS packets, so no firewall rule can steer them to another resolver."""
    try:
        with open(path) as fh:
            for line in fh:
                if line.split("#")[0].strip().startswith("hosts:"):
                    return "resolve" in line.split("#")[0].replace("[", " ").replace("]", " ").split()
    except OSError:
        pass
    return False


def original_resolv_lines():
    """The lines of the resolver configuration as it was before VPNMan changed it.  While VPNMan has replaced the file
    (``# managed by vpnman``), they come from the saved copy - or from the file a symlink pointed at - never from the VPN's
    own entries: handing those to the programs that bypass the VPN gives them a resolver they cannot reach."""
    rpath = _resolv()
    try:
        with open(rpath) as fh:
            text = fh.read()
    except OSError:
        return []
    if MARK not in text:
        return text.splitlines()
    for source in (_backup(), _linkfile()):
        try:
            if source == _linkfile():
                with open(source) as fh:
                    target = fh.read().strip()
                source = os.path.join(os.path.dirname(rpath), target)
            with open(source) as fh:
                saved = fh.read()
        except OSError:
            continue
        if saved.strip():
            return saved.splitlines()
    return []


def restore_resolv_conf():
    """Undo a file-based change.  Safe to call at any time."""
    rpath = _resolv()
    try:
        if os.path.exists(_linkfile()):
            with open(_linkfile()) as fh:
                target = fh.read()
            if os.path.lexists(rpath):
                os.unlink(rpath)
            os.symlink(target, rpath)
            os.unlink(_linkfile())
            if os.path.exists(_backup()):
                os.unlink(_backup())
        elif os.path.exists(_backup()):
            shutil.copy2(_backup(), rpath)
            os.unlink(_backup())
    except OSError:
        pass
