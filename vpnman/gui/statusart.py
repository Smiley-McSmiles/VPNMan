"""The picture on the main page: a computer, rows of chevrons (>>>>> out, <<<<< back) and the internet.

The colour says how the traffic goes: red - straight out, blue - through the VPN, green - through the proxy, cyan -
through both.  Amber chevrons sweep while connecting.  Whenever data moves, the chevrons of that direction light up one
after another (``pulse``), so the picture blinks with the traffic.
"""

import math
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

VIEW_W, VIEW_H = 240.0, 112.0
X0, X1, STEP = 66, 174, 12
TX_Y, RX_Y = 44, 68
WAVE = 0.75            # seconds a chevron takes to flash and fade
LAG = 0.055            # seconds between neighbouring chevrons
IDLE = 0.25            # brightness of a chevron at rest
MIN_RATE = 200         # bytes per second that count as traffic

COLORS = {             # (dark theme, light theme)
    "off": ((1.00, 0.36, 0.38), (0.85, 0.23, 0.25)),
    "vpn": ((0.30, 0.55, 1.00), (0.18, 0.44, 0.88)),
    "proxy": ((0.24, 0.81, 0.56), (0.12, 0.60, 0.38)),
    "both": ((0.16, 0.83, 0.90), (0.05, 0.62, 0.70)),
    "busy": ((0.96, 0.70, 0.20), (0.80, 0.52, 0.04)),
    "error": ((1.00, 0.36, 0.38), (0.85, 0.23, 0.25)),
}
MODES = tuple(COLORS)
POSITIONS = list(range(X0, X1 + 1, STEP))


def mode_for(state, vpn_up, proxy_up):
    """The picture's mode for the daemon's state."""
    if state in ("connecting", "reconnecting", "disconnecting"):
        return "busy"
    if state == "error":
        return "error"
    if vpn_up and proxy_up:
        return "both"
    if vpn_up:
        return "vpn"
    return "proxy" if proxy_up else "off"


def envelope(t):
    """0..1..0 over t in 0..1: fast rise, slower fade."""
    if t <= 0 or t >= 1:
        return 0.0
    return t / 0.25 if t < 0.25 else 1.0 - (t - 0.25) / 0.75


class StatusArt(Gtk.DrawingArea):
    def __init__(self):
        super().__init__(halign=Gtk.Align.CENTER)
        self.set_content_width(240)
        self.set_content_height(112)
        self.mode = "off"
        self.waves = {"tx": None, "rx": None}      # start time of the running wave, or None
        self._tick = 0
        self._busy_from = 0.0
        self.set_draw_func(self._draw)
        self.set_accessible_role(Gtk.AccessibleRole.IMG)
        Adw.StyleManager.get_default().connect("notify::dark", lambda *_: self.queue_draw())

    # ---- what to show
    def set_mode(self, mode):
        mode = mode if mode in COLORS else "off"
        if mode == self.mode:
            return
        self.mode = mode
        self._busy_from = time.monotonic()
        self._animate()
        self.queue_draw()

    def pulse(self, tx=False, rx=False):
        now = time.monotonic()
        for key, on in (("tx", tx), ("rx", rx)):
            if on and self.mode not in ("error",):
                self.waves[key] = now
        if tx or rx:
            self._animate()

    def set_rates(self, rx_rate, tx_rate):
        """Called with every status update: data moved in a direction -> flash that direction."""
        self.pulse(tx=(tx_rate or 0) >= MIN_RATE, rx=(rx_rate or 0) >= MIN_RATE)

    # ---- animation: the frame clock runs only while something is moving
    def _animate(self):
        if not self._tick:
            self._tick = self.add_tick_callback(self._on_tick)

    def _on_tick(self, *_):
        now = time.monotonic()
        running = self.mode == "busy"
        for key, start in self.waves.items():
            if start is None:
                continue
            if now - start > WAVE + LAG * len(POSITIONS):
                self.waves[key] = None
            else:
                running = True
        self.queue_draw()
        if not running:
            self._tick = 0
        return GLib.SOURCE_CONTINUE if running else GLib.SOURCE_REMOVE

    def brightness(self, direction, index, now):
        """0..1 flash of chevron ``index`` (counted along its direction of travel)."""
        if self.mode == "busy":                                 # an endless sweep to the right
            period = WAVE + LAG * len(POSITIONS) + 0.3
            t0 = (now - self._busy_from) % period
            return envelope((t0 - index * LAG) / WAVE) if direction == "tx" else 0.0
        start = self.waves[direction]
        return 0.0 if start is None else envelope((now - start - index * LAG) / WAVE)

    # ---- drawing
    def _draw(self, _area, cr, width, height):
        dark = Adw.StyleManager.get_default().get_dark()
        color = COLORS[self.mode][0 if dark else 1]
        fg = self.get_color()
        scale = min(width / VIEW_W, height / VIEW_H)
        cr.translate((width - VIEW_W * scale) / 2, (height - VIEW_H * scale) / 2)
        cr.scale(scale, scale)
        cr.set_line_cap(1)      # round
        cr.set_line_join(1)
        now = time.monotonic()

        # the computer and the internet, in the neutral foreground colour
        cr.set_line_width(2.2)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.62)
        self._rounded(cr, 12, 34, 34, 22, 3)
        cr.stroke()
        cr.move_to(8, 62)
        cr.rel_line_to(42, 0)
        cr.rel_line_to(-3, -4)
        cr.rel_line_to(-36, 0)
        cr.close_path()
        cr.stroke()
        cx, cy = 214, 50
        cr.new_sub_path()
        cr.arc(cx, cy, 17, 0, 2 * math.pi)
        cr.stroke()
        cr.save()
        cr.translate(cx, cy)
        cr.scale(7, 17)
        cr.new_sub_path()
        cr.arc(0, 0, 1, 0, 2 * math.pi)
        cr.restore()
        cr.stroke()
        for dy, half in ((0, 17), (-9, 14), (9, 14)):
            cr.move_to(cx - half, cy + dy)
            cr.line_to(cx + half, cy + dy)
            cr.stroke()
        cr.set_source_rgba(*color, 0.9)                          # the screen carries the state colour
        cr.move_to(20, 45)
        cr.line_to(38, 45)
        cr.stroke()

        # the chevrons
        count = len(POSITIONS)
        for k, px in enumerate(POSITIONS):
            for direction, y, sign, order in (("tx", TX_Y, 1, k), ("rx", RX_Y, -1, count - 1 - k)):
                b = self.brightness(direction, order, now)
                if b > 0:
                    cr.set_source_rgba(*color, 0.18 * b)         # a soft glow under the lit chevron
                    cr.set_line_width(8)
                    self._chevron(cr, px, y, sign)
                    cr.stroke()
                cr.set_line_width(3.2)
                cr.set_source_rgba(*color, IDLE + (1 - IDLE) * b)
                self._chevron(cr, px, y, sign)
                cr.stroke()

    @staticmethod
    def _chevron(cr, px, y, sign):
        cr.move_to(px - 3 * sign, y - 6)
        cr.rel_line_to(6 * sign, 6)
        cr.rel_line_to(-6 * sign, 6)

    @staticmethod
    def _rounded(cr, x, y, w, h, r):
        cr.new_sub_path()
        cr.arc(x + w - r, y + r, r, -math.pi / 2, 0)
        cr.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
        cr.arc(x + r, y + h - r, r, math.pi / 2, math.pi)
        cr.arc(x + r, y + r, r, math.pi, 3 * math.pi / 2)
        cr.close_path()
