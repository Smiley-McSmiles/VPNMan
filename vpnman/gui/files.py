"""File open/save dialogs that work on GTK 4.10+ (Gtk.FileDialog) and older GTK 4 (FileChooserNative)."""

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402


def choose_files(parent, title, callback, multiple=True):
    if hasattr(Gtk, "FileDialog"):
        dlg = Gtk.FileDialog(title=title)

        def done(d, res):
            try:
                if multiple:
                    model = d.open_multiple_finish(res)
                    files = [p for p in (model.get_item(i).get_path() for i in range(model.get_n_items())) if p]
                else:
                    f = d.open_finish(res)
                    p = f.get_path() if f else None
                    files = [p] if p else []
            except GLib.Error:
                return
            if files:
                callback(files)
        (dlg.open_multiple if multiple else dlg.open)(parent, None, done)
    else:  # pragma: no cover - GTK < 4.10
        dlg = Gtk.FileChooserNative(title=title, transient_for=parent, action=Gtk.FileChooserAction.OPEN,
                                    select_multiple=multiple)

        def on_resp(d, r):
            if r == Gtk.ResponseType.ACCEPT:
                files = [p for p in (f.get_path() for f in d.get_files()) if p]
                if files:
                    callback(files)
        dlg.connect("response", on_resp)
        dlg.show()
        parent._native = dlg


def save_file(parent, title, name, callback):
    if hasattr(Gtk, "FileDialog"):
        dlg = Gtk.FileDialog(title=title, initial_name=name)

        def done(d, res):
            try:
                f = d.save_finish(res)
                path = f.get_path() if f else None
            except GLib.Error:
                return
            if path:
                callback(path)
        dlg.save(parent, None, done)
    else:  # pragma: no cover - GTK < 4.10
        dlg = Gtk.FileChooserNative(title=title, transient_for=parent, action=Gtk.FileChooserAction.SAVE)
        dlg.set_current_name(name)

        def on_resp(d, r):
            if r == Gtk.ResponseType.ACCEPT:
                f = d.get_file()
                path = f.get_path() if f else None
                if path:
                    callback(path)
        dlg.connect("response", on_resp)
        dlg.show()
        parent._native = dlg
