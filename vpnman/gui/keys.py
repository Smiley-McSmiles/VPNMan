"""Keyboard shortcuts shared by the pop-up windows."""

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


def close_keys(window):
    """Escape and Ctrl+W close ``window``.  The shortcut is handled after the focused widget had its chance, so a
    text field or a menu that wants Escape for itself still gets it."""
    ctrl = Gtk.ShortcutController()
    ctrl.set_scope(Gtk.ShortcutScope.LOCAL)
    for combo in ("Escape", "<Control>w"):
        ctrl.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string(combo),
                                           Gtk.CallbackAction.new(lambda w, _a, win=window: (win.close(), True)[1])))
    window.add_controller(ctrl)
    return ctrl
