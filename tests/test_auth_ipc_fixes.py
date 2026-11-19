"""Regression tests for auth, IPC, daemon, settings, and systemd init fixes."""

import os
import signal
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

from vpnman import access, daemon, ipc
from vpnman.settings import Settings


class DummySettings:
    def __init__(self, data=None):
        self._data = data or {
            "dns": {"force": True, "servers": []},
            "split": {"enabled": True, "mode": "exclude", "apps": [], "dns": []},
            "proxy": {"enabled": False},
            "netproxy": {"enabled": False, "http": {"host": "127.0.0.1", "port": 8080, "user": "u", "password": "secret"}},
            "access": {"mode": "session", "groups": ["vpnman"]},
        }

    def update(self, tree):
        for k, v in (tree or {}).items():
            if isinstance(v, dict) and isinstance(self._data.get(k), dict):
                self._data[k].update(v)
            else:
                self._data[k] = v

    def get(self, key=None):
        if not key:
            return self._data
        node = self._data
        for part in key.split("."):
            node = node[part]
        return node


class DummyProxy:
    def __init__(self):
        self.changed_calls = 0

    def changed(self):
        self.changed_calls += 1


class DummyManager:
    def __init__(self):
        self.settings = DummySettings()
        self.proxy = DummyProxy()
        self.dns_calls = 0
        self.split_calls = 0

    def reapply_dns(self):
        self.dns_calls += 1

    def split_changed(self):
        self.split_calls += 1


class DaemonFixesTests(unittest.TestCase):
    def test_settings_update_masks_passwords_and_notifies_all_sections(self):
        mgr = DummyManager()
        tree = {
            "dns": {"servers": ["1.1.1.1"]},
            "split": {"enabled": False},
            "proxy": {"enabled": True},
            "netproxy": {"enabled": True, "http": {"password": "topsecret"}},
        }
        res = daemon.METHODS["settings.update"](mgr, tree)
        self.assertEqual(res["netproxy"]["http"]["password"], "********")
        self.assertEqual(mgr.dns_calls, 1)
        self.assertEqual(mgr.split_calls, 1)
        self.assertEqual(mgr.proxy.changed_calls, 2)

    def test_handler_sets_socket_timeout(self):
        req = mock.MagicMock()
        req.makefile.return_value = mock.MagicMock(readline=mock.MagicMock(return_value=b""))
        srv = mock.MagicMock()
        srv.manager = DummyManager()
        with mock.patch("vpnman.ipc.peercred_supported", return_value=False):
            daemon.Handler(req, None, srv)
        req.settimeout.assert_called_once_with(30.0)

    def test_server_bounds_concurrency_and_secures_socket_without_race(self):
        with tempfile.TemporaryDirectory() as td:
            sock_path = os.path.join(td, "test.sock")
            umasks_seen = []
            orig_umask = os.umask

            def spy_umask(mask):
                umasks_seen.append(mask)
                return orig_umask(mask)

            with mock.patch("vpnman.daemon.os.umask", side_effect=spy_umask):
                srv = daemon.Server(sock_path, DummyManager())
            try:
                self.assertTrue(srv.daemon_threads)
                self.assertEqual(srv.max_threads, 64)
                self.assertIn(0o177, umasks_seen)
                # Bound concurrency: when semaphore is exhausted, process_request closes request without spawning
                for _ in range(srv.max_threads):
                    self.assertTrue(srv._sem.acquire(blocking=False))
                try:
                    req = mock.MagicMock()
                    with mock.patch.object(srv._sem, "acquire", return_value=False), \
                         mock.patch.object(srv, "shutdown_request") as mock_shut:
                        srv.process_request(req, None)
                    mock_shut.assert_called_once_with(req)
                finally:
                    for _ in range(srv.max_threads):
                        srv._sem.release()
            finally:
                srv.server_close()

    def test_run_signal_handlers_use_self_pipe(self):
        with tempfile.TemporaryDirectory() as td:
            sock_path = os.path.join(td, "d.sock")
            pid_path = os.path.join(td, "d.pid")
            log_path = os.path.join(td, "d.log")
            mgr = mock.MagicMock()
            mgr.settings = mock.MagicMock()
            mgr.log = mock.MagicMock()

            registered = {}

            def fake_signal(sig, handler):
                registered[sig] = handler

            class FakeServer:
                def __init__(self, path, m):
                    self.socket_access = "test"

                def serve_forever(self, poll_interval=0.5):
                    # Trigger SIGHUP then SIGTERM via the registered handlers
                    registered[signal.SIGHUP](signal.SIGHUP, None)
                    # Wait briefly for worker thread to process SIGHUP
                    import time
                    for _ in range(50):
                        if mgr.settings.load.called:
                            break
                        time.sleep(0.01)
                    registered[signal.SIGTERM](signal.SIGTERM, None)
                    for _ in range(50):
                        if self.shutdown_called.is_set():
                            break
                        time.sleep(0.01)

                shutdown_called = threading.Event()

                def shutdown(self):
                    self.shutdown_called.set()

                def server_close(self):
                    pass

            with mock.patch.dict(os.environ, {"VPNMAN_ALLOW_UNPRIVILEGED": "1"}), \
                 mock.patch("vpnman.paths.run_dir", return_value=td), \
                 mock.patch("vpnman.paths.config_dir", return_value=td), \
                 mock.patch("vpnman.paths.socket_path", return_value=sock_path), \
                 mock.patch("vpnman.paths.log_file", return_value=log_path), \
                 mock.patch("vpnman.paths.pidfile", return_value=pid_path), \
                 mock.patch("vpnman.daemon.Manager", return_value=mgr), \
                 mock.patch("vpnman.daemon.Settings"), \
                 mock.patch("vpnman.daemon.Server", FakeServer), \
                 mock.patch("vpnman.daemon.signal.signal", side_effect=fake_signal):
                rc = daemon.run()
            self.assertEqual(rc, 0)
            self.assertTrue(mgr.settings.load.called)
            # Handler itself should not be the lambda calling mgr.settings.load directly
            self.assertEqual(registered[signal.SIGHUP], registered[signal.SIGTERM])


class AccessFixesTests(unittest.TestCase):
    def setUp(self):
        with access._lock:
            access._cache.clear()
            access._admin_cache.clear()

    def test_loginctl_missing_returns_none(self):
        with mock.patch("vpnman.access.plat.which", return_value=None):
            self.assertIsNone(access._active_local_session(1000))

    def test_loginctl_list_sessions_failure_fails_closed(self):
        with mock.patch("vpnman.access.plat.which", return_value="/usr/bin/loginctl"), \
             mock.patch("vpnman.access.plat.run", return_value=(1, "error")):
            self.assertIs(access._active_local_session(1000), False)
            s = DummySettings({"access": {"mode": "session", "groups": []}})
            with mock.patch("vpnman.access._groups_of", return_value=set()):
                self.assertIs(access.authorized(1000, s), False)

    def test_state_online_without_active_yes_is_rejected(self):
        def fake_run(cmd, timeout=5):
            if "list-sessions" in cmd:
                return 0, "1 1000 alice seat0 tty1\n"
            return 0, "Remote=no\nActive=no\nState=online\n"

        with mock.patch("vpnman.access.plat.which", return_value="/usr/bin/loginctl"), \
             mock.patch("vpnman.access.plat.run", side_effect=fake_run):
            self.assertIs(access._active_local_session(1000), False)

    def test_active_yes_and_remote_no_is_accepted(self):
        def fake_run(cmd, timeout=5):
            if "list-sessions" in cmd:
                return 0, "1 1000 alice seat0 tty1\n"
            return 0, "Remote=no\nActive=yes\nState=active\n"

        with mock.patch("vpnman.access.plat.which", return_value="/usr/bin/loginctl"), \
             mock.patch("vpnman.access.plat.run", side_effect=fake_run):
            self.assertIs(access._active_local_session(1000), True)


class IpcFixesTests(unittest.TestCase):
    def test_client_call_closes_socket_on_connect_error(self):
        fake_sock = mock.MagicMock()
        fake_sock.connect.side_effect = FileNotFoundError("no socket")
        with mock.patch("vpnman.ipc.socket.socket", return_value=fake_sock):
            with self.assertRaises(ipc.DaemonUnavailable):
                ipc.Client("/nonexistent/sock").call("ping")
        fake_sock.close.assert_called_once()

    def test_peer_uid_unpacks_unsigned(self):
        high_uid = 0x80000001
        raw = struct.pack("i2I", 42, high_uid, 1000)
        conn = mock.MagicMock()
        conn.getsockopt.return_value = raw
        self.assertEqual(ipc.peer_uid(conn), high_uid)

    def test_secure_socket_rejects_non_socket(self):
        with tempfile.NamedTemporaryFile() as tf:
            with self.assertRaises(OSError):
                ipc.secure_socket(tf.name)

    def test_secure_socket_non_peercred_sets_0600_before_chown(self):
        with tempfile.TemporaryDirectory() as td:
            sock_path = os.path.join(td, "s.sock")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(sock_path)
            try:
                calls = []
                with mock.patch("vpnman.ipc.peercred_supported", return_value=False), \
                     mock.patch("vpnman.ipc.os.chmod", side_effect=lambda p, m: calls.append(("chmod", m))), \
                     mock.patch("vpnman.ipc.os.chown", side_effect=PermissionError("not root")):
                    res = ipc.secure_socket(sock_path)
                self.assertEqual(res, "root only")
                self.assertEqual(calls[0], ("chmod", 0o600))
            finally:
                s.close()


class SettingsFixesTests(unittest.TestCase):
    def test_load_acquires_lock(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "settings.json")
            s = Settings(path)
            s._lock = mock.MagicMock()
            s.load()
            s._lock.__enter__.assert_called_once()
            s._lock.__exit__.assert_called_once()

    def test_save_handles_bare_filename(self):
        with tempfile.TemporaryDirectory() as td:
            orig_cwd = os.getcwd()
            os.chdir(td)
            try:
                s = Settings("settings.json")
                s.set("connection.timeout", 45)
                self.assertTrue(os.path.exists("settings.json"))
            finally:
                os.chdir(orig_cwd)


class SystemdServiceTests(unittest.TestCase):
    def test_service_starts_before_network_pre(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        svc_path = os.path.join(root, "data", "init", "vpnmand.service")
        with open(svc_path) as fh:
            text = fh.read()
        self.assertNotIn("network-online.target", text)
        self.assertIn("Before=network-pre.target", text)
        self.assertIn("Wants=network-pre.target", text)


if __name__ == "__main__":
    unittest.main()
