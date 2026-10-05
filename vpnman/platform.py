"""Host detection: OS family, init system, interfaces, gateways."""

import os
import re
import shutil
import subprocess
import sys

EXTRA_PATH = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin",
              "/usr/pkg/sbin", "/usr/pkg/bin", "/opt/homebrew/bin"]


def os_family():
    p = sys.platform
    for name in ("linux", "openbsd", "freebsd", "netbsd", "darwin"):
        if p.startswith(name):
            return name
    return p


def is_bsd():
    return os_family() in ("openbsd", "freebsd", "netbsd", "darwin")


def distro():
    """Return (id, pretty_name) from os-release, or the kernel name."""
    for f in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            data = {}
            with open(f) as fh:
                for line in fh:
                    if "=" in line:
                        k, v = line.rstrip().split("=", 1)
                        data[k] = v.strip('"')
            return data.get("ID", "linux"), data.get("PRETTY_NAME", data.get("NAME", "Linux"))
        except OSError:
            continue
    return os_family(), os.uname().sysname + " " + os.uname().release


def which(name):
    found = shutil.which(name)
    if found:
        return found
    for d in EXTRA_PATH:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def run(cmd, timeout=30, input=None, check=False):
    """Run a command, returning (rc, combined output).  Never raises on a
    missing binary or timeout - the failure is reported through rc."""
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(EXTRA_PATH + env.get("PATH", "").split(os.pathsep))
    env["LC_ALL"] = "C"
    try:
        cp = subprocess.run(cmd, input=input, capture_output=True, text=True,
                            timeout=timeout, env=env)
        out = (cp.stdout or "") + (cp.stderr or "")
        if check and cp.returncode:
            raise RuntimeError("%s: %s" % (" ".join(cmd), out.strip()))
        return cp.returncode, out
    except FileNotFoundError:
        return 127, "%s: command not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "%s: timed out" % cmd[0]


def init_system():
    """Detect the running init system.

    One of: systemd, openrc, runit, sysv, openbsd-rc, bsd-rc, launchd, unknown.
    """
    fam = os_family()
    if fam == "openbsd":
        return "openbsd-rc"
    if fam in ("freebsd", "netbsd"):
        return "bsd-rc"
    if fam == "darwin":
        return "launchd"
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    try:
        with open("/proc/1/comm") as fh:
            comm = fh.read().strip()
    except OSError:
        comm = ""
    if comm == "runit" or (comm == "runsvdir" or os.path.isdir("/run/runit")):
        return "runit"
    if os.path.isdir("/run/openrc") or os.path.exists("/sbin/openrc-run") or comm == "openrc-init":
        return "openrc"
    if os.path.isdir("/etc/runit") and which("sv") and not os.path.isdir("/etc/init.d"):
        return "runit"
    if os.path.isdir("/etc/init.d"):
        return "sysv"
    if which("sv") and (os.path.isdir("/etc/sv") or os.path.isdir("/var/service")):
        return "runit"
    return "unknown"


def list_interfaces():
    if os_family() == "linux":
        try:
            return sorted(os.listdir("/sys/class/net"))
        except OSError:
            pass
    rc, out = run(["ifconfig", "-l"])
    if rc == 0:
        return sorted(out.split())
    return []


def default_gateway():
    """Return (gateway_ip, interface) of the IPv4 default route or (None, None)."""
    if os_family() == "linux":
        try:
            with open("/proc/net/route") as fh:
                next(fh)
                for line in fh:
                    f = line.split()
                    if f[1] == "00000000" and int(f[3], 16) & 2:
                        gw = ".".join(str(b) for b in reversed(bytes.fromhex(f[2])))
                        return gw, f[0]
        except (OSError, ValueError, StopIteration):
            pass
        return None, None
    rc, out = run(["route", "-n", "get", "default"])
    if rc == 0:
        gw = re.search(r"gateway:\s*(\S+)", out)
        ifc = re.search(r"interface:\s*(\S+)", out)
        return (gw.group(1) if gw else None, ifc.group(1) if ifc else None)
    return None, None


def iface_stats(name):
    """Return (rx_bytes, tx_bytes) for an interface, or None."""
    if os_family() == "linux":
        base = "/sys/class/net/%s/statistics/" % name
        try:
            with open(base + "rx_bytes") as a, open(base + "tx_bytes") as b:
                return int(a.read()), int(b.read())
        except (OSError, ValueError):
            return None
    rc, out = run(["netstat", "-ibn", "-I", name])
    if rc != 0:
        return None
    lines = out.splitlines()
    if len(lines) < 2:
        return None
    hdr = lines[0].split()
    try:
        ib, ob = hdr.index("Ibytes"), hdr.index("Obytes")
    except ValueError:
        return None
    for line in lines[1:]:
        f = line.split()
        if len(f) > max(ib, ob) and f[2].startswith("<Link"):
            return int(f[ib]), int(f[ob])
    return None


def iface_exists(name):
    return name in list_interfaces()


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0
