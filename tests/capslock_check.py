"""Run under xvfb with xdotool: password fields turn red and say "Caps Lock is on" while Caps Lock is on and they have
the focus (the same behaviour as GPGMan)."""
import os, subprocess, sys, tempfile, time
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import GLib  # noqa: E402
from vpnman.gui import app as A  # noqa: E402
from vpnman.gui.caps_lock import HINT_TEXT, WARN_CLASS  # noqa: E402


def pump(secs=0.4):
    end = time.time() + secs
    ctx = GLib.MainContext.default()
    while time.time() < end:
        ctx.iteration(False)
        time.sleep(0.01)


class App(A.Application):
    def do_activate(self):
        try:
            self.checks()
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)

    def checks(self):
        super().do_activate()
        A.rpc = lambda *a, **kw: None
        prof = {"id": "%012d" % 1, "name": "srv1", "username": "bob", "protocol": "openvpn"}
        dlg = A.CredentialsPrompt(self.win, prof, "The server rejected the login.", lambda *a: None)
        dlg.present()
        pump(1.0)
        row = dlg.password
        base = row.get_title()
        row.grab_focus()
        pump()
        assert not row.has_css_class(WARN_CLASS)
        subprocess.run(["xdotool", "key", "Caps_Lock"], check=True)
        pump(1.0)
        assert row.has_css_class(WARN_CLASS) and row.get_title() == "%s · %s" % (base, HINT_TEXT), row.get_title()
        dlg.user.grab_focus()                       # Caps Lock still on, but the password field lost the focus
        pump()
        assert not row.has_css_class(WARN_CLASS) and row.get_title() == base
        row.grab_focus()
        pump()
        assert row.has_css_class(WARN_CLASS)
        subprocess.run(["xdotool", "key", "Caps_Lock"], check=True)
        pump(1.0)
        assert not row.has_css_class(WARN_CLASS) and row.get_title() == base
        print("CAPSLOCK-OK")
        os._exit(0)


App().run([])
