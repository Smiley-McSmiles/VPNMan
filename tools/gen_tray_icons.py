#!/usr/bin/env python3
"""Write the coloured tray icons (data/icons/hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan-tray-MODE.svg).

    python3 tools/gen_tray_icons.py            # write them
    python3 tools/gen_tray_icons.py --check    # fail if the checked-in files differ (the colours live in vpnman/gui/palette.py)

The same shield is drawn in code for panels that take pixels (vpnman/gui/trayicon.py); these files serve the ones that
take an icon name or a path (Cinnamon's XApp status icon, KDE and others).
"""
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from vpnman import APP_ID  # noqa: E402

# gui/palette.py is plain Python: import it without loading the GTK package
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location("palette", os.path.join(ROOT, "vpnman", "gui", "palette.py"))
palette = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(palette)

SHIELD = "M8 1.4 L13.2 3.3 V8 C13.2 10.9 11.1 13.1 8 14.7 C4.9 13.1 2.8 10.9 2.8 8 V3.3 Z"
LINE = 'stroke-linecap="round" stroke-linejoin="round"'


def svg(mode):
    c = palette.hex_color(palette.STATE_COLORS[mode][0])
    if mode in ("vpn", "proxy", "both", "error", "locked"):
        body = '<path d="%s" fill="%s"/>\n  ' % (SHIELD, c)
        if mode in ("error", "locked"):
            body += ('<path d="M8 4.8 L8 9" fill="none" stroke="#ffffff" stroke-width="1.5" %s/>\n  '
                     '<circle cx="8" cy="11.2" r="0.5" fill="#ffffff" stroke="#ffffff" stroke-width="0.5"/>' % LINE)
        else:
            body += '<path d="M5.2 8.2 L7.2 10.2 L10.9 6" fill="none" stroke="#ffffff" stroke-width="1.5" %s/>' % LINE
    else:
        body = '<path d="%s" fill="none" stroke="%s" stroke-width="1.5" %s/>\n  ' % (SHIELD, c, LINE)
        if mode == "busy":
            body += "".join('<circle cx="%s" cy="8.2" r="0.75" fill="%s"/>' % (x, c) for x in ("5.6", "8", "10.4"))
        else:
            body += '<path d="M3.6 2.6 L12.4 13.6" fill="none" stroke="%s" stroke-width="1.6" %s/>' % (c, LINE)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">\n  %s\n</svg>\n' % body)


def path(mode):
    return os.path.join(ROOT, "data", "icons", "hicolor", "scalable", "apps", "%s-tray-%s.svg" % (APP_ID, mode))


def main(argv):
    stale = []
    for mode in palette.MODES:
        want = svg(mode)
        try:
            with open(path(mode), encoding="utf-8") as fh:
                have = fh.read()
        except OSError:
            have = None
        if have != want:
            stale.append(os.path.basename(path(mode)))
            if "--check" not in argv:
                with open(path(mode), "w", encoding="utf-8") as fh:
                    fh.write(want)
    if "--check" in argv and stale:
        print("stale tray icons: %s (run tools/gen_tray_icons.py)" % ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
