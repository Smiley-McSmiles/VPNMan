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
    assert statusart.envelope(0) == 0 and statusart.envelope(1) == 0 and statusart.envelope(0.25) == 1
    assert 0 < statusart.envelope(0.1) < 1 and 0 < statusart.envelope(0.6) < 1


def pixels(widget):
    """RGBA bytes of the widget as drawn."""
    paintable = Gtk.WidgetPaintable.new(widget)
    w, h = widget.get_width(), widget.get_height()
    snap = Gtk.Snapshot()
    paintable.snapshot(snap, w, h)
    node = snap.to_node()
    renderer = widget.get_native().get_renderer()
    return renderer.render_texture(node, None)


def checks(win, arts):
    logic()
    a = arts["vpn"]
    # idle: nothing lit; a wave lights the chevrons of its direction one after another, then fades
    assert all(a.brightness("tx", i, time.monotonic()) == 0 for i in range(10))
    a.set_rates(rx_rate=5000, tx_rate=0)
    t = time.monotonic()
    assert a.waves["rx"] is not None and a.waves["tx"] is None
    later = a.waves["rx"] + 0.2
    assert a.brightness("rx", 0, later) > a.brightness("rx", 9, later), "the wave runs along the chevrons"
    a.set_rates(rx_rate=10, tx_rate=10)                      # chatter below the threshold does not blink
    assert a.waves["tx"] is None
    a.set_mode("busy")
    assert a._tick, "the frame clock runs while connecting"
    a.set_mode("vpn")
    seen = {}
    for name, art in arts.items():
        art.set_rates(9000, 9000)
    GLib.timeout_add(250, lambda: finish(arts))
    return False


def finish(arts):
    out = sys.argv[1] if len(sys.argv) > 1 else None
    box = next(iter(arts.values())).get_parent()
    tex = pixels(box)
    assert tex.get_width() > 100
    if out:
        tex.save_to_png(out)
    # the animation stops by itself once the waves are over
    GLib.timeout_add(1800, lambda: done(arts))
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
