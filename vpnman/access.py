"""Who may talk to the daemon.

The socket is world-connectable on platforms where the kernel tells us the
peer's uid (Linux SO_PEERCRED); every connection is then checked here:

* root, and members of the configured groups (default: vpnman, wheel, sudo)
* ``access.mode = session`` (default): users with an *active local* login
  session - the same trust model desktop network managers use - so a normal
  desktop user needs no group membership and no re-login.
* ``access.mode = group``: only root and group members.
"""

import grp
import os
import pwd
import threading
import time

from . import platform as plat

_cache = {}
_lock = threading.Lock()
TTL = 5.0


def _groups_of(uid):
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return set()
    names = set()
    for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return names


def _active_local_session(uid):
    """True/False when a session manager answers, None when there is none."""
    lc = plat.which("loginctl")
    if not lc:
        return None
    rc, out = plat.run([lc, "list-sessions", "--no-legend"], timeout=5)
    if rc != 0:
        return None
    for line in out.splitlines():
        f = line.split()
        if len(f) < 2 or not f[1].isdigit() or int(f[1]) != uid:
            continue
        rc, o2 = plat.run([lc, "show-session", f[0], "-p", "Remote", "-p", "Active", "-p", "State"], timeout=5)
        props = dict(l.split("=", 1) for l in o2.splitlines() if "=" in l)
        if props.get("Remote", "no") == "no" and (props.get("Active") == "yes"
                                                    or props.get("State") in ("active", "online")):
            return True
    return False


def _regular_user(uid):
    return 1000 <= uid < 60000 or (plat.os_family() == "freebsd" and 1001 <= uid < 65000)


def authorized(uid, settings):
    if uid == 0:
        return True
    now = time.time()
    with _lock:
        hit = _cache.get(uid)
        if hit and hit[0] > now:
            return hit[1]
    ok = False
    if _groups_of(uid) & set(settings.get("access.groups")):
        ok = True
    elif settings.get("access.mode") == "session" and _regular_user(uid):
        sess = _active_local_session(uid)
        # no session manager (runit/sysv without elogind): any regular local user
        ok = True if sess is None else sess
    with _lock:
        _cache[uid] = (now + TTL, ok)
    return ok
