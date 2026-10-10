"""The picture on the main page: a computer, rows of chevrons (>>>>> out, <<<<< back) and the internet.

The colour says how the traffic goes: red - straight out, blue - through the VPN, green - through the proxy, cyan -
through both.  Amber chevrons sweep while connecting.  Every packet is a bright head that runs along the chevrons with a fading
tail, like the lit LED of a chaser light; several can be on their way at once, with dark chevrons between them, so
the picture moves with the traffic: more data, more packets (``set_rates``).  A sustained transfer (a download, an
upload) lights its whole lane, with a glow that pulses along it.
"""

import math
import random
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

VIEW_W, VIEW_H = 280.0, 112.0
COUNT, X0, STEP = 15, 68, 11          # chevrons per lane, where the first one is, the distance between them
TX_Y, RX_Y = 44, 68                  # the two lanes; the icons are centred between them
MID_Y = (TX_Y + RX_Y) / 2
ICON = 1.2                           # icon size relative to the first design
SPEED = 17.0           # chevrons a packet travels per second
TAIL = 2.6             # chevrons of fading glow behind the head
LEAD = 0.5             # ... and a little glow just ahead of it
IDLE = 0.2             # brightness of a chevron at rest
BUSY_EVERY = 0.42      # seconds between packets while connecting
MIN_RATE = 200         # bytes per second that count as traffic
FLOW_RATE = 256 * 1024  # bytes per second that count as a transfer: the whole lane stays lit
FLOW_HOLD = 1.8        # seconds a transfer stays lit after the last update that showed it
PULSE_HZ = 1.1         # glow pulses per second along a lit lane

COLORS = {             # (dark theme, light theme)
    "off": ((1.00, 0.36, 0.38), (0.85, 0.23, 0.25)),
    "vpn": ((0.30, 0.55, 1.00), (0.18, 0.44, 0.88)),
    "proxy": ((0.24, 0.81, 0.56), (0.12, 0.60, 0.38)),
    "both": ((0.16, 0.83, 0.90), (0.05, 0.62, 0.70)),
    "busy": ((0.96, 0.70, 0.20), (0.80, 0.52, 0.04)),
    "error": ((1.00, 0.36, 0.38), (0.85, 0.23, 0.25)),
}
MODES = tuple(COLORS)
POSITIONS = [X0 + k * STEP for k in range(COUNT)]


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


def glow(behind):
    """Brightness of a chevron that is ``behind`` chevrons behind a packet's head (negative: ahead of it)."""
    if behind < -LEAD or behind > TAIL:
        return 0.0
    if behind < 0:
        return 1.0 + behind / LEAD
    return 1.0 - behind / TAIL


def packets_for(rate):
    """How many packets to show per second for ``rate`` bytes per second (0 when there is no traffic)."""
    if not rate or rate < MIN_RATE:
        return 0
    return min(7, 1 + int(math.log10(rate / MIN_RATE) * 1.6))


class StatusArt(Gtk.DrawingArea):
    def __init__(self):
        super().__init__(halign=Gtk.Align.CENTER)
        self.set_content_width(int(VIEW_W))
        self.set_content_height(112)
        self.mode = "off"
        self.packets = {"tx": [], "rx": []}        # start times (monotonic); a packet's head is at (now - start) * SPEED
        self.flow_until = {"tx": 0.0, "rx": 0.0}   # a transfer is on until then
        self.level = {"tx": 0.0, "rx": 0.0}        # 0..1 how fully the lane is lit (eases in and out)
        self._frame = 0.0
        self._tick = 0
        self._busy_next = 0.0
        self.set_draw_func(self._draw)
        self.set_accessible_role(Gtk.AccessibleRole.IMG)
        Adw.StyleManager.get_default().connect("notify::dark", lambda *_: self.queue_draw())

    # ---- what to show
    def set_mode(self, mode):
        mode = mode if mode in COLORS else "off"
        if mode == self.mode:
            return
        self.mode = mode
        self._busy_next = 0.0
        self._animate()
        self.queue_draw()

    def pulse(self, tx=False, rx=False, at=None):
        """One packet in each direction asked for, starting at ``at`` (default: now)."""
        at = time.monotonic() if at is None else at
        for key, on in (("tx", tx), ("rx", rx)):
            if on and self.mode != "error":
                self.packets[key].append(at)
        if tx or rx:
            self._animate()

    def set_rates(self, rx_rate, tx_rate, span=0.9):
        """Called with every status update: spread the packets of the next ``span`` seconds, a few more for more data."""
        now = time.monotonic()
        for key, rate in (("rx", rx_rate), ("tx", tx_rate)):
            if (rate or 0) >= FLOW_RATE and self.mode != "error":
                self.flow_until[key] = now + FLOW_HOLD         # a transfer: light the whole lane instead of single packets
                self._animate()
                continue
            for _ in range(packets_for(rate)):
                self.pulse(tx=key == "tx", rx=key == "rx", at=now + random.uniform(0, span))

    # ---- animation: the frame clock runs only while something is moving
    def _animate(self):
        if not self._tick:
            self._tick = self.add_tick_callback(self._on_tick)

    def _on_tick(self, *_):
        now = time.monotonic()
        life = (len(POSITIONS) + TAIL) / SPEED
        for key in self.packets:
            self.packets[key] = [t for t in self.packets[key] if now - t < life]
        if self.mode == "busy" and now >= self._busy_next:        # connecting: one packet after another, forever
            self.packets["tx"].append(now)
            self._busy_next = now + BUSY_EVERY
        dt = min(now - self._frame, 0.1) if self._frame else 0.0
        self._frame = now
        for key in self.level:                                 # the lane eases fully lit while a transfer runs, then dims
            target = 1.0 if self.flow_until[key] > now else 0.0
            self.level[key] += (target - self.level[key]) * min(1.0, dt * 7)
        running = self.mode == "busy" or any(self.packets.values()) or any(
            self.flow_until[k] > now or self.level[k] > 0.01 for k in self.level)
        if not running:
            self._frame = 0.0
        self.queue_draw()
        if not running:
            self._tick = 0
        return GLib.SOURCE_CONTINUE if running else GLib.SOURCE_REMOVE

    def brightness(self, direction, index, now):
        """0..1 glow of chevron ``index`` (counted along its direction of travel): the brightest of the packets near it."""
        best = 0.0
        level = self.level[direction]
        if level > 0.01:                       # a transfer: lit all along, with a glow that runs down the lane
            wave = 0.5 + 0.5 * math.cos(2 * math.pi * (now * PULSE_HZ - index * 0.11))
            best = level * (0.7 + 0.3 * wave)
        for start in self.packets[direction]:
            if start > now:
                continue
            best = max(best, glow((now - start) * SPEED - index))
        return best

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

        # the computer and the internet, in the neutral foreground colour, centred on the lanes
        cr.set_line_width(2.2 / ICON)
        cr.save()                                                # laptop: 42 x 28 in its own units
        cr.translate(2, MID_Y)
        cr.scale(ICON, ICON)
        cr.translate(0, -14)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.62)
        self._rounded(cr, 4, 0, 34, 22, 3)
        cr.stroke()
        cr.move_to(0, 28)
        cr.rel_line_to(42, 0)
        cr.rel_line_to(-3, -4)
        cr.rel_line_to(-36, 0)
        cr.close_path()
        cr.stroke()
        cr.set_source_rgba(*color, 0.9)                          # the screen carries the state colour
        cr.move_to(12, 11)
        cr.line_to(30, 11)
        cr.stroke()
        cr.restore()
        cr.save()                                                # globe: radius 17
        cr.translate(VIEW_W - 17 * ICON - 2, MID_Y)
        cr.scale(ICON, ICON)
        cr.set_line_width(2.2 / ICON)
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.62)
        cr.new_sub_path()
        cr.arc(0, 0, 17, 0, 2 * math.pi)
        cr.stroke()
        cr.save()
        cr.scale(7, 17)
        cr.new_sub_path()
        cr.arc(0, 0, 1, 0, 2 * math.pi)
        cr.restore()
        cr.stroke()
        for dy, half in ((0, 17), (-9, 14), (9, 14)):
            cr.move_to(-half, dy)
            cr.line_to(half, dy)
            cr.stroke()
        cr.restore()

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
