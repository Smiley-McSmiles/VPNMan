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
                    files = [model.get_item(i).get_path() for i in range(model.get_n_items())]
                else:
                    files = [d.open_finish(res).get_path()]
            except GLib.Error:
                return
            callback(files)
        (dlg.open_multiple if multiple else dlg.open)(parent, None, done)
    else:  # pragma: no cover - GTK < 4.10
        dlg = Gtk.FileChooserNative(title=title, transient_for=parent, action=Gtk.FileChooserAction.OPEN,
                                    select_multiple=multiple)
        dlg.connect("response", lambda d, r: callback([f.get_path() for f in d.get_files()]) if r == Gtk.ResponseType.ACCEPT else None)
        dlg.show()
        parent._native = dlg


def save_file(parent, title, name, callback):
    if hasattr(Gtk, "FileDialog"):
        dlg = Gtk.FileDialog(title=title, initial_name=name)

        def done(d, res):
            try:
                callback(d.save_finish(res).get_path())
            except GLib.Error:
                return
        dlg.save(parent, None, done)
    else:  # pragma: no cover - GTK < 4.10
        dlg = Gtk.FileChooserNative(title=title, transient_for=parent, action=Gtk.FileChooserAction.SAVE)
        dlg.set_current_name(name)
        dlg.connect("response", lambda d, r: callback(d.get_file().get_path()) if r == Gtk.ResponseType.ACCEPT else None)
        dlg.show()
        parent._native = dlg
