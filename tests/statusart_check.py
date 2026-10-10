"""The status picture of the main page: modes, flashing with traffic, and a real render of every mode.

Run with a display:   dbus-run-session xvfb-run -a python3 tests/statusart_check.py [out.png]
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import gi  # noqa: E402
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from vpnman.gui import statusart  # noqa: E402


def logic():
    m = statusart.mode_for
    assert m("disconnected", False, False) == "off"
    assert m("connected", True, False) == "vpn"
    assert m("disconnected", False, True) == "proxy"
    assert m("connected", True, True) == "both"
    assert m("connecting", False, False) == m("reconnecting", True, True) == m("disconnecting", True, True) == "busy"
    assert m("error", False, True) == "error"
    assert statusart.glow(0) == 1 and statusart.glow(-1) == 0 and statusart.glow(5) == 0
    assert 0 < statusart.glow(1) < 1 and 0 < statusart.glow(-0.2) < 1


def pixels(widget):
    """RGBA bytes of the widget as drawn."""
    paintable = Gtk.WidgetPaintable.new(widget)
    w, h = widget.get_width(), widget.get_height()
    snap = Gtk.Snapshot()
    paintable.snapshot(snap, w, h)
    node = snap.to_node()
    renderer = widget.get_native().get_renderer()
    return renderer.render_texture(node, None)


N = len(statusart.POSITIONS)


def checks(win, arts):
    logic()
    assert N == 15, "fifteen chevrons per lane"
    a = arts["off"]
    now = time.monotonic()
    assert all(a.brightness("tx", i, now) == 0 for i in range(N)), "nothing lit at rest"
    # two packets 0.3 s apart: two lit groups with dark chevrons between them, like a chaser light
    a.packets = {"tx": [now - 0.50, now - 0.15], "rx": []}
    lit = [a.brightness("tx", i, now) for i in range(N)]
    heads = [i for i in range(1, N - 1) if lit[i] >= lit[i - 1] and lit[i] >= lit[i + 1] and lit[i] > 0.7]
    assert len(heads) == 2, ("two packets are on their way", lit)
    lo, hi = heads
    assert min(lit[lo + 1:hi]) < 0.1, ("with dark chevrons between them", lit)
    assert lit[lo] > lit[lo - 1] > 0.2, ("and a fading tail behind each head", lit)
    # the packets move along the chevrons and the other direction runs the other way
    a.packets = {"tx": [now - 0.1], "rx": []}
    first = [a.brightness("tx", i, now) for i in range(N)]
    later = [a.brightness("tx", i, now + 0.1) for i in range(N)]
    assert later.index(max(later)) > first.index(max(first)), "the head moves on"
    a.packets = {"tx": [], "rx": [now - 0.1]}
    rx = [a.brightness("rx", i, now) for i in range(N)]
    assert rx.index(max(rx)) in (1, 2), "a received packet enters at the internet side"
    # more data, more packets; below the threshold nothing blinks
    assert statusart.packets_for(0) == 0 and statusart.packets_for(50) == 0
    assert statusart.packets_for(300) == 1 < statusart.packets_for(30000) < statusart.packets_for(3000000) <= 7
    # a transfer (a download): the whole incoming lane is lit and pulses; the other lane stays dark
    a.packets = {"tx": [], "rx": []}
    a.set_rates(rx_rate=2 * 1024 * 1024, tx_rate=0)
    assert a.flow_until["rx"] > now and a.flow_until["tx"] == 0 and not a.packets["rx"]
    a.level["rx"] = 1.0
    wave = [[a.brightness("rx", i, now + dt) for i in range(N)] for dt in (0.0, 0.2, 0.4)]
    assert all(min(row) > 0.65 for row in wave), ("the lane is lit all along", wave)
    assert max(max(r) for r in wave) - min(min(r) for r in wave) > 0.1, "... and its glow pulses"
    assert all(a.brightness("tx", i, now) == 0 for i in range(N))
    a.flow_until["rx"], a.level["rx"] = 0.0, 0.0
    a.packets = {"tx": [], "rx": []}
    a.set_rates(rx_rate=5000, tx_rate=10)
    assert len(a.packets["rx"]) >= 2 and not a.packets["tx"]
    assert all(now <= t <= now + 1.0 for t in a.packets["rx"]), "spread over the next second"
    a.set_mode("busy")
    assert a._tick, "the frame clock runs while connecting"
    a.set_mode("off")
    for art in arts.values():
        art.set_rates(900000, 900000)
    GLib.timeout_add(450, lambda: finish(arts))
    return False


def finish(arts):
    out = sys.argv[1] if len(sys.argv) > 1 else None
    box = next(iter(arts.values())).get_parent()
    tex = pixels(box)
    assert tex.get_width() > 100
    if out:
        tex.save_to_png(out)
    # the animation stops by itself once the waves are over
    GLib.timeout_add(2200, lambda: done(arts))
    return False


def done(arts):
    assert all(not a._tick for m, a in arts.items() if m != "busy"), "no frame clock left running"
    assert arts["busy"]._tick, "connecting keeps sweeping"
    print("STATUSART-OK")
    os._exit(0)


def main():
    app = Adw.Application(application_id="io.github.smiley_mcsmiles.VPNManTest")

    def activate(app):
        win = Adw.ApplicationWindow(application=app, default_width=1100, default_height=170)
        box = Gtk.Box(spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12, homogeneous=True)
        arts = {}
        for mode in ("off", "vpn", "proxy", "both", "busy"):
            art = statusart.StatusArt()
            art.set_mode(mode)
            arts[mode] = art
            box.append(art)
        win.set_content(box)
        win.present()

        def go():
            try:
                checks(win, arts)
            except Exception:
                import traceback
                traceback.print_exc()
                os._exit(1)
            return False
        GLib.timeout_add(400, go)
    app.connect("activate", activate)
    app.run([])


if __name__ == "__main__":
    main()
