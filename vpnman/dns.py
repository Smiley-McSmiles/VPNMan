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
