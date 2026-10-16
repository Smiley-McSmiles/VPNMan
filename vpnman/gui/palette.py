"""The colours of the VPN / proxy state, shared by the picture on the main page and the tray icon:
red - straight out, blue - VPN, green - proxy only, cyan - VPN + proxy, amber - connecting, red - error.

Values are (dark theme, light theme) as red, green, blue fractions.  The tray icon uses the bright (dark theme) values: they
read on a dark and on a light panel alike."""

STATE_COLORS = {
    "off": ((1.00, 0.36, 0.38), (0.85, 0.23, 0.25)),
    "vpn": ((0.30, 0.55, 1.00), (0.18, 0.44, 0.88)),
    "proxy": ((0.24, 0.81, 0.56), (0.12, 0.60, 0.38)),
    "both": ((0.16, 0.83, 0.90), (0.05, 0.62, 0.70)),
    "busy": ((0.96, 0.70, 0.20), (0.80, 0.52, 0.04)),
    "error": ((1.00, 0.36, 0.38), (0.85, 0.23, 0.25)),
}
MODES = tuple(STATE_COLORS)


def hex_color(rgb):
    return "#%02x%02x%02x" % tuple(round(c * 255) for c in rgb)
