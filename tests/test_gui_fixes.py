"""Unit tests for GUI, tray, and caps-lock bug fixes."""

import ast
import os
import stat
import tempfile
import types
import unittest
from unittest import mock

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gio, GLib  # noqa: E402

from vpnman.gui import app as gui_app  # noqa: E402
from vpnman.gui import caps_lock  # noqa: E402
from vpnman.gui import files as gui_files  # noqa: E402
from vpnman.gui import proxypage  # noqa: E402
from vpnman.gui import tray  # noqa: E402


GUI_DIR = os.path.dirname(gui_app.__file__)


class TestCallbackReturnValues(unittest.TestCase):
    """Ensure no GLib.idle_add / rpc() callback is a bare tuple-returning lambda."""

    def test_no_bare_tuple_lambdas_in_idle_or_rpc(self):
        targets = ("app.py", "proxypage.py", "pages.py", "connpage.py", "proxyprefs.py")
        offenders = []
        for fname in targets:
            path = os.path.join(GUI_DIR, fname)
            with open(path, "r", encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=fname)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = ""
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name not in ("idle_add", "timeout_add", "timeout_add_seconds", "rpc", "set"):
                    continue
                if name == "set" and not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Attribute)
                                          and func.value.attr == "model"):
                    continue
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    if isinstance(arg, ast.Lambda) and isinstance(arg.body, ast.Tuple):
                        offenders.append(f"{fname}:{arg.lineno}")
        self.assertEqual(offenders, [], f"Found bare tuple-returning lambdas: {offenders}")


class TestCapsLockFix(unittest.TestCase):
    def test_uses_unrealize_instead_of_destroy(self):
        connected_signals = []

        class FakeWidget:
            def get_display(self):
                return fake_display

            def add_controller(self, ctrl):
                self._ctrl = ctrl

            def add_css_class(self, cls):
                pass

            def remove_css_class(self, cls):
                pass

            def connect(self, sig, cb):
                connected_signals.append((sig, cb))
                return len(connected_signals)

        fake_keyboard = mock.MagicMock()
        fake_keyboard.get_caps_lock_state.return_value = False
        fake_keyboard.connect.return_value = 42
        fake_keyboard.handler_is_connected.return_value = True

        fake_seat = mock.MagicMock()
        fake_seat.get_keyboard.return_value = fake_keyboard

        fake_display = mock.MagicMock()
        fake_display.get_default_seat.return_value = fake_seat

        w = FakeWidget()
        with mock.patch.object(caps_lock, "_ensure_css"):
            caps_lock.watch_caps_lock(w, lambda _on: None)

        sigs = [s for s, _cb in connected_signals]
        self.assertIn("unrealize", sigs)
        self.assertNotIn("destroy", sigs)

        # Trigger unrealize callback and verify keyboard handler is disconnected
        unrealize_cb = dict(connected_signals)["unrealize"]
        unrealize_cb(w)
        fake_keyboard.disconnect.assert_called_once_with(42)


class TestAppFixes(unittest.TestCase):
    def test_on_ping_restores_button_on_rpc_failure(self):
        win = gui_app.MainWindow.__new__(gui_app.MainWindow)
        win.ping_btn = mock.MagicMock()
        win.ping_btn.get_sensitive.return_value = True
        win._fail = mock.MagicMock()
        captured = {}

        def fake_rpc(method, ok, fail):
            captured["fail"] = fail

        with mock.patch.object(gui_app, "rpc", side_effect=fake_rpc):
            win.on_ping()

        win.ping_btn.set_sensitive.assert_called_with(False)
        win.ping_btn.set_label.assert_called_with("Testing…")

        captured["fail"]("boom", False)
        win.ping_btn.set_sensitive.assert_called_with(True)
        win.ping_btn.set_label.assert_called_with("Test Latency")
        win._fail.assert_called_once_with("boom", False)

    def test_stunnel_oserror_and_size_cap(self):
        dlg = gui_app.ProfileDialog.__new__(gui_app.ProfileDialog)
        dlg.st_switch = mock.MagicMock()
        dlg.st_switch.get_active.return_value = True
        dlg.st_host = mock.MagicMock()
        dlg.st_host.get_text.return_value = "example.com:443"
        dlg.st_sni = mock.MagicMock()
        dlg.st_sni.get_text.return_value = ""
        dlg.profile = None

        # Missing file raises ValueError
        dlg.st_ca_path = "/nonexistent/ca-file-12345.pem"
        with self.assertRaises(ValueError):
            dlg._stunnel()

        # Oversized file (> 1 MiB) raises ValueError
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"x" * (1024 * 1024 + 10))
            big_path = tf.name
        try:
            dlg.st_ca_path = big_path
            with self.assertRaises(ValueError):
                dlg._stunnel()
        finally:
            os.unlink(big_path)

    def test_update_result_none_app_and_url_scheme_validation(self):
        win = gui_app.MainWindow.__new__(gui_app.MainWindow)
        win.get_application = mock.MagicMock(return_value=None)
        win.toast = mock.MagicMock()

        # Non-error with app=None should not crash
        res = win._update_result({"newer": False, "current": "1.0.0"}, silent=True)
        self.assertFalse(res)

        # Auto update check with app=None should not crash
        self.assertFalse(win._auto_update_check())

        # Malicious URL scheme should not call Gtk.show_uri
        win.toast.reset_mock()
        fake_dlg = mock.MagicMock()
        cbs = {}
        fake_dlg.connect.side_effect = lambda sig, cb: cbs.__setitem__(sig, cb)
        with mock.patch.object(gui_app.Adw, "MessageDialog", return_value=fake_dlg), \
                mock.patch.object(gui_app.Gtk, "show_uri") as mock_show:
            win._update_result({"newer": True, "latest": "2.0.0", "current": "1.0.0", "url": "file:///etc/passwd"}, False)
            cbs["response"](fake_dlg, "open")
            mock_show.assert_not_called()

            win._update_result({"newer": True, "latest": "2.0.0", "current": "1.0.0", "url": "https://example.com/rel"}, False)
            cbs["response"](fake_dlg, "open")
            mock_show.assert_called_once()

    def test_backup_export_uses_nofollow_and_fchmod(self):
        win = gui_app.MainWindow.__new__(gui_app.MainWindow)
        win.toast = mock.MagicMock()
        win._fail = mock.MagicMock()

        fake_dlg = mock.MagicMock()
        cbs = {}
        fake_dlg.connect.side_effect = lambda sig, cb: cbs.__setitem__(sig, cb)

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "backup.tar.gz")
            # Pre-create with overly permissive mode to verify fchmod tightens it to 0o600
            with open(target, "wb") as fh:
                fh.write(b"old")
            os.chmod(target, 0o644)

            with mock.patch.object(gui_app.Adw, "MessageDialog", return_value=fake_dlg), \
                    mock.patch.object(gui_app, "save_file", side_effect=lambda _w, _t, _n, cb: cb(target)), \
                    mock.patch.object(gui_app, "rpc", side_effect=lambda _m, ok, _f: ok({"data": "aGVsbG8="})):
                win.on_backup_export()
                cbs["response"](fake_dlg, "export")

            mode = stat.S_IMODE(os.stat(target).st_mode)
            self.assertEqual(mode, 0o600)
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), b"hello")

            # Symlink target must be rejected by O_NOFOLLOW
            if hasattr(os, "O_NOFOLLOW"):
                link = os.path.join(tmpdir, "link.tar.gz")
                os.symlink(target, link)
                win.toast.reset_mock()
                with mock.patch.object(gui_app.Adw, "MessageDialog", return_value=fake_dlg), \
                        mock.patch.object(gui_app, "save_file", side_effect=lambda _w, _t, _n, cb: cb(link)), \
                        mock.patch.object(gui_app, "rpc", side_effect=lambda _m, ok, _f: ok({"data": "aGVsbG8="})):
                    win.on_backup_export()
                    cbs["response"](fake_dlg, "export")
                self.assertTrue(any("Could not save" in str(c) for c in win.toast.call_args_list))

    def test_markup_escaped_subtitles(self):
        dlg = gui_app.ProfileDialog.__new__(gui_app.ProfileDialog)
        dlg.parent_win = types.SimpleNamespace(profiles=[{"id": "1", "name": "A&B <1>"}])
        dlg.failover = ["1"]
        dlg.fo_row = mock.MagicMock()
        dlg.file_row = mock.MagicMock()
        dlg.name = mock.MagicMock()
        dlg.name.get_text.return_value = "existing"
        dlg.st_ca = mock.MagicMock()

        dlg._failover_subtitle()
        dlg.fo_row.set_subtitle.assert_called_with(GLib.markup_escape_text("A&B <1>"))

        dlg._set_files(["/tmp/my<vpn>&1.ovpn"])
        dlg.file_row.set_subtitle.assert_called_with(GLib.markup_escape_text("my<vpn>&1.ovpn"))

        dlg._set_ca(["/tmp/ca<1>&2.pem"])
        dlg.st_ca.set_subtitle.assert_called_with(GLib.markup_escape_text("ca<1>&2.pem"))


class TestProxyPageAndFilesFixes(unittest.TestCase):
    def test_copy_handles_none_port(self):
        page = proxypage.ProxyPage.__new__(proxypage.ProxyPage)
        page.status = {"socks": None, "socks_port": None}
        page.win = mock.MagicMock()
        page._copy("socks")  # Should not raise TypeError
        page.win.toast.assert_not_called()

    def test_files_ignores_none_get_path(self):
        none_gfile = mock.MagicMock()
        none_gfile.get_path.return_value = None
        local_gfile = mock.MagicMock()
        local_gfile.get_path.return_value = "/tmp/test.conf"

        fake_model = mock.MagicMock()
        fake_model.get_n_items.return_value = 2
        fake_model.get_item.side_effect = [none_gfile, local_gfile]

        fake_dlg = mock.MagicMock()
        fake_dlg.open_multiple_finish.return_value = fake_model
        fake_dlg.open_finish.return_value = none_gfile
        fake_dlg.save_finish.return_value = none_gfile

        def run_open_multiple(_parent, _cancellable, cb):
            cb(fake_dlg, None)

        def run_open_single(_parent, _cancellable, cb):
            cb(fake_dlg, None)

        def run_save(_parent, _cancellable, cb):
            cb(fake_dlg, None)

        fake_dlg.open_multiple.side_effect = run_open_multiple
        fake_dlg.open.side_effect = run_open_single
        fake_dlg.save.side_effect = run_save

        got = []
        with mock.patch.object(gui_files.Gtk, "FileDialog", return_value=fake_dlg):
            gui_files.choose_files(mock.MagicMock(), "Open", got.append, multiple=True)
            self.assertEqual(got, [["/tmp/test.conf"]])

            got.clear()
            gui_files.choose_files(mock.MagicMock(), "Open", got.append, multiple=False)
            self.assertEqual(got, [])

            gui_files.save_file(mock.MagicMock(), "Save", "out.txt", got.append)
            self.assertEqual(got, [])


class TestTrayCleanupFixes(unittest.TestCase):
    def test_tray_stop_and_watcher_appeared_cleanup(self):
        fake_conn = mock.MagicMock()
        fake_conn.register_object.side_effect = [101, 102]
        fake_conn.signal_subscribe.side_effect = [201, 202]

        avail = []
        t = tray.Tray("test.id", "Test", lambda: None, lambda: [], on_availability=avail.append)
        with mock.patch.object(tray.Gio, "bus_own_name_on_connection", return_value=301), \
                mock.patch.object(tray.Gio, "bus_watch_name_on_connection", side_effect=[401, 402]), \
                mock.patch.object(tray.GLib, "timeout_add_seconds", return_value=501):
            self.assertTrue(t.start(bus=fake_conn))

        # _watcher_appeared twice should unsubscribe the first signal_subscribe handle
        t._watcher_appeared(fake_conn, "org.kde.StatusNotifierWatcher", ":1.1")
        t._watcher_appeared(fake_conn, "org.freedesktop.StatusNotifierWatcher", ":1.2")
        fake_conn.signal_unsubscribe.assert_any_call(201)

        with mock.patch.object(tray.Gio, "bus_unown_name") as mock_unown, \
                mock.patch.object(tray.Gio, "bus_unwatch_name") as mock_unwatch, \
                mock.patch.object(tray.GLib, "source_remove") as mock_rm:
            t.stop()

        mock_rm.assert_called_once_with(501)
        fake_conn.signal_unsubscribe.assert_any_call(202)
        mock_unown.assert_called_once_with(301)
        self.assertEqual(mock_unwatch.call_args_list, [mock.call(401), mock.call(402)])
        self.assertEqual(fake_conn.unregister_object.call_args_list, [mock.call(101), mock.call(102)])
        self.assertIsNone(t._conn)

    def test_helper_tray_cleanup_on_stop_and_eof(self):
        ht = tray.HelperTray("test.id", "Test", lambda: None, lambda: [])
        fake_proc = mock.MagicMock()
        fake_proc.stdout.fileno.return_value = 99
        fake_proc.poll.return_value = None
        ht._proc = fake_proc
        ht._watch = 77
        ht._startup_timer = 88

        with mock.patch.object(tray.GLib, "source_remove") as mock_rm:
            ht.stop()

        mock_rm.assert_any_call(88)
        mock_rm.assert_any_call(77)
        fake_proc.stdin.close.assert_called_once()
        fake_proc.stdout.close.assert_called_once()
        self.assertIsNone(ht._proc)
        self.assertEqual(ht._startup_timer, 0)
        self.assertIsNone(ht._watch)

        # On EOF in _on_data, _watch must be cleared before _failed() -> stop()
        ht2 = tray.HelperTray("test.id", "Test", lambda: None, lambda: [], on_failure=mock.MagicMock())
        ht2._proc = mock.MagicMock()
        ht2._watch = 55
        with mock.patch("os.read", return_value=b""), \
                mock.patch.object(tray.GLib, "source_remove") as mock_rm2:
            res = ht2._on_data(99, 0)
        self.assertFalse(res)
        self.assertIsNone(ht2._watch)
        mock_rm2.assert_not_called()
        ht2.on_failure.assert_called_once()


if __name__ == "__main__":
    unittest.main()
