"""The tray icon drawn in code: a shield in the state's colour (the same colours as the picture on the main page).

The panel host gets the pixels (StatusNotifierItem ``IconPixmap``) as well as an icon name, so the icon shows even when the
host cannot find the named icon in its theme (the GNOME AppIndicator extension then shows three dots).
"""

from .palette import STATE_COLORS

try:
    import cairo
except ImportError:                                  # pragma: no cover - the GUI needs it anyway
    cairo = None

COLORS = {mode: dark for mode, (dark, _light) in STATE_COLORS.items()}
SIZES = (24, 48)


def _shield(cr):
    """The shield of the app icon (16 x 16 units)."""
    cr.move_to(8, 1.4)
    cr.line_to(13.2, 3.3)
    cr.line_to(13.2, 8)
    cr.curve_to(13.2, 10.9, 11.1, 13.1, 8, 14.7)
    cr.curve_to(4.9, 13.1, 2.8, 10.9, 2.8, 8)
    cr.line_to(2.8, 3.3)
    cr.close_path()


def draw(cr, mode, size):
    r, g, b = COLORS.get(mode, COLORS["off"])
    cr.scale(size / 16.0, size / 16.0)
    cr.set_line_cap(1)
    cr.set_line_join(1)
    if mode in ("vpn", "proxy", "both", "error", "locked"):
        _shield(cr)
        cr.set_source_rgb(r, g, b)
        cr.fill()
        cr.set_source_rgb(1, 1, 1)
        cr.set_line_width(1.5)
        if mode in ("error", "locked"):
            cr.move_to(8, 4.8)
            cr.line_to(8, 9)
            cr.stroke()
            cr.arc(8, 11.2, 0.5, 0, 6.2832)
            cr.fill()
        else:
            cr.move_to(5.2, 8.2)
            cr.line_to(7.2, 10.2)
            cr.line_to(10.9, 6)
            cr.stroke()
        return
    _shield(cr)
    cr.set_source_rgb(r, g, b)
    cr.set_line_width(1.5)
    cr.stroke()
    if mode == "busy":
        for dx in (-2.4, 0, 2.4):
            cr.arc(8 + dx, 8.2, 0.75, 0, 6.2832)
            cr.fill()
    else:                                            # off: a slash through the shield
        cr.set_line_width(1.6)
        cr.move_to(3.6, 2.6)
        cr.line_to(12.4, 13.6)
        cr.stroke()


_cache = {}


def pixmaps(mode, sizes=SIZES):
    """[(width, height, ARGB32 bytes in network order)] for ``mode``, or [] without cairo.  Drawn once per mode: the panel
    asks for the properties one by one, after every change."""
    key = (mode, tuple(sizes))
    if key not in _cache:
        _cache[key] = _draw_all(mode, sizes)
    return _cache[key]


def _draw_all(mode, sizes):
    if cairo is None:
        return []
    out = []
    for size in sizes:
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
        draw(cairo.Context(surface), mode, size)
        surface.flush()
        raw = bytes(surface.get_data())
        argb = bytearray(len(raw))
        for i in range(0, len(raw), 4):                    # cairo: native 0xAARRGGBB; the protocol: A, R, G, B bytes
            b, g, r, a = raw[i:i + 4] if _little() else (raw[i + 3], raw[i + 2], raw[i + 1], raw[i])
            argb[i:i + 4] = bytes((a, r, g, b))
        out.append((size, size, bytes(argb)))
    return out


def _little():
    import sys
    return sys.byteorder == "little"
