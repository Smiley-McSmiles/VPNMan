"""Install / control the vpnmand service on systemd, OpenRC, runit, SysV, BSD rc."""

import os
import shutil

from . import platform as plat

SRC_CANDIDATES = ["/usr/share/vpnman/init", "/usr/local/share/vpnman/init",
                  os.path.join(os.path.dirname(__file__), "..", "data", "init")]


def _src(name):
    env = os.environ.get("VPNMAN_DATA_DIR")
    for d in ([os.path.join(env, "init")] if env else []) + SRC_CANDIDATES:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    raise FileNotFoundError("init template %s not found" % name)


def _bindir():
    exe = plat.which("vpnmand")
    return os.path.dirname(exe) if exe else "/usr/local/bin"


def _render(name, dest, mode=0o644):
    with open(_src(name)) as fh:
        text = fh.read().replace("@BINDIR@", _bindir())
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as fh:
        fh.write(text)
    os.chmod(dest, mode)


def runit_dirs():
    svdir = "/etc/sv" if os.path.isdir("/etc/sv") else "/etc/runit/sv"
    for d in ("/var/service", "/etc/service", "/service"):
        if os.path.isdir(d):
            return svdir, d
    return svdir, "/var/service"


def _sh(cmd):
    rc, out = plat.run(cmd, timeout=60)
    return rc == 0, out.strip()


def install(init=None):
    init = init or plat.init_system()
    if init == "systemd":
        _render("vpnmand.service", "/etc/systemd/system/vpnmand.service")
        _sh(["systemctl", "daemon-reload"])
    elif init == "runit":
        svdir, _ = runit_dirs()
        d = os.path.join(svdir, "vpnmand")
        _render("runit/run", os.path.join(d, "run"), 0o755)
        _render("runit/log/run", os.path.join(d, "log", "run"), 0o755)
    elif init == "openrc":
        _render("vpnmand.openrc", "/etc/init.d/vpnmand", 0o755)
    elif init == "sysv":
        _render("vpnmand.sysv", "/etc/init.d/vpnmand", 0o755)
    elif init == "openbsd-rc":
        _render("vpnmand.openbsd", "/etc/rc.d/vpnmand", 0o555)
    elif init == "bsd-rc":
        _render("vpnmand.freebsd", "/usr/local/etc/rc.d/vpnmand", 0o555)
    else:
        raise RuntimeError("unsupported init system: %s" % init)
    return init


def _linked(path, target):
    return os.path.islink(path) and os.path.realpath(path) == os.path.realpath(target)


def control(action, init=None):
    """action: enable | disable | start | stop | restart | status.  Returns (ok, text)."""
    init = init or plat.init_system()
    if init == "systemd":
        if action == "enable":
            return _sh(["systemctl", "enable", "--now", "vpnmand"])
        if action == "disable":
            return _sh(["systemctl", "disable", "--now", "vpnmand"])
        return _sh(["systemctl", action, "vpnmand"])
    if init == "runit":
        svdir, rundir = runit_dirs()
        link, target = os.path.join(rundir, "vpnmand"), os.path.join(svdir, "vpnmand")
        if action == "enable":
            if not os.path.lexists(link):
                os.symlink(target, link)
            return True, "linked %s -> %s (runsvdir starts it within ~5s)" % (link, target)
        if action == "disable":
            _sh(["sv", "down", link])
            if os.path.islink(link):
                os.unlink(link)
            return True, "removed %s" % link
        verb = {"start": "up", "stop": "down", "restart": "restart", "status": "status"}[action]
        return _sh(["sv", verb, link])
    if init in ("openrc", "sysv"):
        script = "/etc/init.d/vpnmand"
        if action in ("enable", "disable"):
            if init == "openrc":
                ok, out = _sh(["rc-update", "add" if action == "enable" else "del", "vpnmand", "default"])
                if action == "enable":
                    _sh([script, "start"])
                return ok, out
            for tool, args in (("update-rc.d", ["vpnmand", "defaults"] if action == "enable" else ["-f", "vpnmand", "remove"]),
                               ("chkconfig", ["--add", "vpnmand"] if action == "enable" else ["--del", "vpnmand"]),
                               ("rc-update", ["add", "vpnmand"] if action == "enable" else ["del", "vpnmand"])):
                if plat.which(tool):
                    ok, out = _sh([plat.which(tool)] + args)
                    if action == "enable":
                        _sh([script, "start"])
                    return ok, out
            if action == "enable":
                for lvl in ("2", "3", "4", "5"):
                    d = "/etc/rc%s.d" % lvl
                    if os.path.isdir(d) and not os.path.lexists(d + "/S90vpnmand"):
                        os.symlink(script, d + "/S90vpnmand")
                _sh([script, "start"])
            else:
                _sh([script, "stop"])
                for lvl in ("2", "3", "4", "5"):
                    try:
                        os.unlink("/etc/rc%s.d/S90vpnmand" % lvl)
                    except OSError:
                        pass
            return True, "enabled via rc.d symlinks" if action == "enable" else "disabled"
        return _sh([script, action])
    if init == "openbsd-rc":
        if action == "enable":
            return _sh(["rcctl", "enable", "vpnmand"])
        if action == "disable":
            return _sh(["rcctl", "disable", "vpnmand"])
        return _sh(["rcctl", {"status": "check"}.get(action, action), "vpnmand"])
    if init == "bsd-rc":
        if action == "enable":
            return _sh(["sysrc", "vpnmand_enable=YES"])
        return _sh(["service", "vpnmand", "one" + action if action in ("start", "stop", "status") else action])
    return False, "unsupported init system: %s" % init


def uninstall(init=None):
    init = init or plat.init_system()
    control("disable", init)
    paths = {"systemd": ["/etc/systemd/system/vpnmand.service"],
             "openrc": ["/etc/init.d/vpnmand"], "sysv": ["/etc/init.d/vpnmand"],
             "openbsd-rc": ["/etc/rc.d/vpnmand"], "bsd-rc": ["/usr/local/etc/rc.d/vpnmand"]}.get(init, [])
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass
    if init == "runit":
        shutil.rmtree(os.path.join(runit_dirs()[0], "vpnmand"), ignore_errors=True)
    if init == "systemd":
        _sh(["systemctl", "daemon-reload"])
