"""
Caps Lock hint for password fields.

Highlights a password field in red and notes "Caps Lock is on" while a password field has focus and Caps Lock is active.
Works on X11 and Wayland through Gdk's keyboard device state (no key-event guessing).  Shared with GPGMan
(gpgman/ui/caps_lock.py) - keep the two alike.
"""

from __future__ import annotations

from typing import Callable

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402  (no Libadwaita import: GPGMan's GTK-only prompt shares this module)

HINT_TEXT = "Caps Lock is on"
WARN_CLASS = "caps-lock-warning"

_CSS = b"""
.caps-lock-warning,
.caps-lock-warning:focus-within {
    outline-color: rgb(224, 27, 36);
    box-shadow: inset 0 0 0 2px rgb(224, 27, 36);
    background-color: rgba(224, 27, 36, 0.10);
    border-radius: 8px;
}
"""
_css_installed = False


def _ensure_css() -> None:
    """Install the red-highlight style once (display-wide, so every dialog gets it)."""
    global _css_installed
    if _css_installed:
        return
    display = Gdk.Display.get_default()
    if display is None:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS)
    Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _css_installed = True


def watch_caps_lock(widget: Gtk.Widget, on_change: Callable[[bool], None]) -> None:
    """Call ``on_change(True/False)`` whenever "Caps Lock is on AND the widget has focus" changes."""
    _ensure_css()
    display = widget.get_display()
    seat = display.get_default_seat() if display else None
    keyboard = seat.get_keyboard() if seat else None
    if keyboard is None:
        return

    focus = Gtk.EventControllerFocus.new()
    widget.add_controller(focus)
    last = {"state": None}

    def update(*_args):
        state = bool(keyboard.get_caps_lock_state()) and bool(focus.contains_focus())
        if state != last["state"]:
            last["state"] = state
            if state:
                widget.add_css_class(WARN_CLASS)
            else:
                widget.remove_css_class(WARN_CLASS)
            on_change(state)

    handler = keyboard.connect("notify::caps-lock-state", update)
    focus.connect("notify::contains-focus", update)
    # Don't keep a dead widget alive through the long-lived keyboard device.
    widget.connect("destroy", lambda _w: keyboard.disconnect(handler))
    update()


def attach_caps_lock_hint(row: Gtk.Widget) -> None:
    """For an Adw.PasswordEntryRow: append "· Caps Lock is on" to its floating title while it applies."""
    base_title = row.get_title()

    def on_change(on: bool) -> None:
        row.set_title(f"{base_title} · {HINT_TEXT}" if on else base_title)

    watch_caps_lock(row, on_change)


def make_caps_lock_label(entry: Gtk.Widget) -> Gtk.Label:
    """A small dim label (hidden until needed) to place under a plain Gtk.PasswordEntry."""
    label = Gtk.Label(label=HINT_TEXT, xalign=0, visible=False)
    label.add_css_class("caption")
    label.add_css_class("error")
    watch_caps_lock(entry, label.set_visible)
    return label
