"""Icon health check / repair (the GTK icon cache can hide freshly installed icons)."""

import glob
import os

from . import APP_ID
from . import platform as plat

THEME_DIRS = ["/usr/share/icons/hicolor", "/usr/local/share/icons/hicolor"]


def _our_files(theme):
    return glob.glob(os.path.join(theme, "*", "apps", APP_ID + "*"))


def check():
    """Return a list of (ok, message)."""
    out = []
    pix = [p for p in ("/usr/share/pixmaps", "/usr/local/share/pixmaps")
           if os.path.exists(os.path.join(p, APP_ID + ".svg"))]
    found = False
    for theme in THEME_DIRS:
        files = _our_files(theme)
        cache = os.path.join(theme, "icon-theme.cache")
        if files:
            found = True
            out.append((True, "icons installed in %s (%d files)" % (theme, len(files))))
        if os.path.exists(cache):
            newest = max([os.path.getmtime(f) for f in files] + [os.path.getmtime(theme)])
            if files and os.path.getmtime(cache) < newest:
                out.append((False, "%s is older than the installed icons - GTK may not see them" % cache))
            elif not files and not glob.glob(os.path.join(theme, "*", "*", "*")):
                out.append((False, "%s describes a theme directory with no icons (stale)" % cache))
    out.append((found, "icons present in the system icon theme" if found else "no VPNMan icons in the system icon theme"))
    out.append((bool(pix), "flat fallback icon in %s" % pix[0] if pix else "no flat fallback icon in /usr/share/pixmaps"))
    return out


def fix():
    """Rebuild (or drop) stale icon caches.  Needs root.  Returns messages."""
    msgs = []
    for theme in THEME_DIRS:
        if not os.path.isdir(theme):
            continue
        cache = os.path.join(theme, "icon-theme.cache")
        has_icons = any(f for f in glob.glob(os.path.join(theme, "*", "*", "*")))
        if not has_icons:
            if os.path.exists(cache):
                os.unlink(cache)
                msgs.append("removed stale cache %s" % cache)
            continue
        for tool in ("gtk4-update-icon-cache", "gtk-update-icon-cache"):
            exe = plat.which(tool)
            if exe:
                rc, _ = plat.run([exe, "-q", "-f", "-t", theme])
                if rc == 0:
                    msgs.append("rebuilt %s" % cache)
                    break
        else:
            msgs.append("no gtk-update-icon-cache found for %s" % theme)
    return msgs
