"""Unit tests for fixes in profiles, backup, diagnostics, cli, schedule, updates, apps, history, desktop, autostart."""

import base64
import io
import json
import os
import stat
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace

from vpnman import apps, autostart, backup, cli, desktop, diagnostics, history, profiles, schedule, updates


class _DummySettings:
    def __init__(self, data=None):
        self.data = data or {}

    def get(self, key=None):
        if key is None:
            return self.data
        cur = self.data
        for part in key.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur


class _DummyLog:
    def __init__(self):
        self.entries = []

    def add(self, level, msg):
        self.entries.append({"time": time.time(), "level": level, "msg": msg})

    def since(self, _seq, _limit=5000):
        return self.entries, len(self.entries)


class TestProfilesFixes(unittest.TestCase):
    def test_collect_files_rejects_traversal_and_outside_absolute_paths(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "sub")
            os.makedirs(sub)
            outside = os.path.join(d, "secret.key")
            with open(outside, "w") as fh:
                fh.write("SECRET")

            ovpn_rel = os.path.join(sub, "trav.ovpn")
            with open(ovpn_rel, "w") as fh:
                fh.write("client\nremote vpn.example 1194\nca ../secret.key\n")
            with self.assertRaises(profiles.ProfileError):
                profiles.collect_files(ovpn_rel)

            ovpn_abs = os.path.join(sub, "abs.ovpn")
            with open(ovpn_abs, "w") as fh:
                fh.write("client\nremote vpn.example 1194\nca /etc/passwd\n")
            with self.assertRaises(profiles.ProfileError):
                profiles.collect_files(ovpn_abs)

    def test_collect_files_enforces_size_cap(self):
        with tempfile.TemporaryDirectory() as d:
            big = os.path.join(d, "big.crt")
            with open(big, "wb") as fh:
                fh.truncate(profiles.MAX_IMPORT_FILE + 1)
            ovpn = os.path.join(d, "c.ovpn")
            with open(ovpn, "w") as fh:
                fh.write("client\nremote vpn.example 1194\nca big.crt\n")
            with self.assertRaises(profiles.ProfileError):
                profiles.collect_files(ovpn)

    def test_collect_files_handles_quoted_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as d:
            certs = os.path.join(d, "my certs")
            os.makedirs(certs)
            with open(os.path.join(certs, "my ca.crt"), "w") as fh:
                fh.write("CA-DATA")
            with open(os.path.join(certs, "ta key.key"), "w") as fh:
                fh.write("TA-DATA")
            ovpn = os.path.join(d, "sp.ovpn")
            with open(ovpn, "w") as fh:
                fh.write('client\nremote vpn.example 1194\nca "my certs/my ca.crt"\ntls-auth "my certs/ta key.key" 1\n')
            text, files = profiles.collect_files(ovpn)
            self.assertEqual(base64.b64decode(files["my ca.crt"]), b"CA-DATA")
            self.assertEqual(base64.b64decode(files["ta key.key"]), b"TA-DATA")
            self.assertIn("ca 'my ca.crt'", text)
            self.assertIn("tls-auth 'ta key.key' 1", text)

    def test_profile_store_save_tightens_existing_dir_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            st = profiles.ProfileStore(d)
            p = profiles.new_profile("test", "openvpn")
            pdir = st.dir_of(p)
            os.makedirs(pdir, mode=0o755)
            os.chmod(pdir, 0o755)
            st.save(p)
            self.assertEqual(stat.S_IMODE(os.stat(pdir).st_mode), 0o700)


class TestDiagnosticsFixes(unittest.TestCase):
    def test_names_includes_proxy_source_urls(self):
        m = SimpleNamespace(
            store=SimpleNamespace(list=lambda: []),
            proxy=SimpleNamespace(store=SimpleNamespace(list=lambda: [
                {"name": "P1", "server": "1.2.3.4", "source": "https://sub.example/feed?token=topsecret123"}
            ])),
            settings=_DummySettings(),
            _net={},
        )
        names = diagnostics._names(m)
        self.assertIn("https://sub.example/feed?token=topsecret123", names)
        redacted = diagnostics.redact("refreshing https://sub.example/feed?token=topsecret123", names)
        self.assertNotIn("topsecret123", redacted)

    def test_scrub_redacts_user_openvpn_args_and_events(self):
        tree = {
            "netproxy": {"http": {"host": "127.0.0.1", "port": 8080, "user": "ed"}},
            "connection": {"retry_max": 3, "openvpn_args": ["--setenv", "SECRET=1"]},
            "events": {"connected": "https://hooks.example/secret-webhook", "disconnected": ""},
        }
        s = diagnostics.scrub(tree)
        self.assertEqual(s["netproxy"]["http"]["user"], "<removed>")
        self.assertEqual(s["connection"]["openvpn_args"], "<removed>")
        self.assertEqual(s["connection"]["retry_max"], 3)
        self.assertEqual(s["events"]["connected"], "<removed>")
        self.assertEqual(s["events"]["disconnected"], "")

    def test_redact_short_secrets_and_non_ipv6_macs(self):
        out = diagnostics.redact("connected as ed, mac aa:bb:cc:dd:ee:ff, ip 2606:4700::1111", {"ed": "<user-1>"})
        self.assertIn("connected as <user-1>", out)
        self.assertIn("aa:bb:cc:dd:ee:ff", out)
        self.assertIn("2606:4700::x", out)


class TestBackupFixes(unittest.TestCase):
    def test_profile_file_regex_rejects_dot_dotdot_and_trailing_newline(self):
        self.assertIsNone(backup._PROFILE_FILE.match("profiles/0123456789ab/."))
        self.assertIsNone(backup._PROFILE_FILE.match("profiles/0123456789ab/.."))
        self.assertIsNone(backup._PROFILE_FILE.match("profiles/0123456789ab/profile.json\n"))
        self.assertIsNotNone(backup._PROFILE_FILE.match("profiles/0123456789ab/profile.json"))

    def test_read_archive_rejects_non_dict_manifest(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = json.dumps([1, 2, 3]).encode()
            ti = tarfile.TarInfo(backup.MANIFEST)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        with self.assertRaises(backup.BackupError):
            backup.read_archive(buf.getvalue())


class TestCliFixes(unittest.TestCase):
    def _make_cli(self, responses=None):
        c = cli.Cli()
        responses = responses or {}
        c.call = lambda method, **kw: responses[method](**kw) if callable(responses.get(method)) else responses.get(method)
        return c

    def test_backup_export_and_diagnostics_refuse_symlink_and_tighten_perms(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "target.txt")
            with open(target, "w") as fh:
                fh.write("orig")
            sym = os.path.join(d, "sym.tgz")
            os.symlink(target, sym)

            c = self._make_cli({
                "backup.export": {"data": base64.b64encode(b"archive").decode(), "size": 7},
                "diagnostics": "diag-report\n",
            })

            with self.assertRaises(cli.RpcError):
                c.cmd_backup(SimpleNamespace(action="export", file=sym, force=True))
            with self.assertRaises(cli.RpcError):
                c.cmd_diagnostics(SimpleNamespace(output=sym, force=True))

            existing = os.path.join(d, "out.txt")
            with open(existing, "w") as fh:
                fh.write("old")
            os.chmod(existing, 0o644)
            with self.assertRaises(cli.RpcError):
                c.cmd_diagnostics(SimpleNamespace(output=existing, force=False))
            c.cmd_diagnostics(SimpleNamespace(output=existing, force=True))
            self.assertEqual(stat.S_IMODE(os.stat(existing).st_mode), 0o600)

            existing_bk = os.path.join(d, "bk.tgz")
            with open(existing_bk, "w") as fh:
                fh.write("old")
            os.chmod(existing_bk, 0o644)
            with self.assertRaises(cli.RpcError):
                c.cmd_backup(SimpleNamespace(action="export", file=existing_bk, force=False))
            c.cmd_backup(SimpleNamespace(action="export", file=existing_bk, force=True))
            self.assertEqual(stat.S_IMODE(os.stat(existing_bk).st_mode), 0o600)

    def test_cmd_edit_invalid_port_raises_rpc_error(self):
        c = self._make_cli()
        with self.assertRaises(cli.RpcError):
            c.cmd_edit(SimpleNamespace(profile="p1", changes=["port=abc"]))

    def test_parse_days_invalid_raises_rpc_error(self):
        with self.assertRaises(cli.RpcError):
            cli._parse_days("mon,funday")

    def test_cmd_proxy_show_disappeared_raises_rpc_error(self):
        calls = {"n": 0}

        def proxy_list():
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"id": "abcd1234abcd", "name": "MyProxy"}]
            return []

        c = self._make_cli({"proxy.list": proxy_list})
        with self.assertRaises(cli.RpcError):
            c.cmd_proxy(SimpleNamespace(action="show", items=["MyProxy"], json=False))


class TestScheduleFixes(unittest.TestCase):
    def test_tick_does_not_connect_twice_when_two_windows_open(self):
        connects = []
        entries = [
            {"id": "e1", "name": "W1", "enabled": True, "days": [0], "start": "09:00", "end": "10:00", "profile": "p1"},
            {"id": "e2", "name": "W2", "enabled": True, "days": [0], "start": "09:00", "end": "11:00", "profile": "p2"},
        ]
        mgr = SimpleNamespace(
            settings=_DummySettings({"schedule": {"enabled": True, "entries": entries}}),
            status=lambda: {"state": "disconnected"},
            connect=lambda prof, **_kw: connects.append(prof) or {"profile": prof},
            disconnect=lambda: None,
            log=_DummyLog(),
        )
        sch = schedule.Scheduler(mgr)
        t = time.struct_time((2026, 11, 16, 9, 0, 0, 0, 320, 0))  # Monday 09:00
        sch.tick(t)
        self.assertEqual(connects, ["p1"])
        self.assertEqual(sch.owned, "e1")


class TestMiscFixes(unittest.TestCase):
    def test_updates_parse_and_check(self):
        self.assertIsNone(updates.parse("1.2.3garbage"))
        self.assertLess(updates.parse("1.0.0-alpha1"), updates.parse("1.0.0-beta1"))
        self.assertLess(updates.parse("1.0.0-beta1"), updates.parse("1.0.0-rc1"))
        self.assertLess(updates.parse("1.0.0-rc1"), updates.parse("1.0.0-rc2"))
        self.assertLess(updates.parse("1.0.0-rc2"), updates.parse("1.0.0"))

        def bad_opener(_req, timeout=8):
            return io.BytesIO(b'["not-a-dict"]')

        with self.assertRaises(ValueError):
            updates.check(opener=bad_opener)

    def test_apps_snap_flags_and_custom_entry_dots(self):
        self.assertEqual(apps.exec_names("snap run --trace-exec firefox"), ["firefox"])
        for bad in (".", "..", ""):
            with self.assertRaises(ValueError):
                apps.custom_entry(bad)

    def test_history_bare_filename(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            try:
                os.chdir(d)
                h = history.History("history.json")
                h.add("p1", "openvpn", 100, 200)
                self.assertEqual(len(h.list()), 1)
            finally:
                os.chdir(cwd)

    def test_desktop_and_autostart_quoted_exec(self):
        with tempfile.TemporaryDirectory() as d:
            old_xdg_home = os.environ.get("XDG_CONFIG_HOME")
            old_xdg_data = os.environ.get("XDG_DATA_HOME")
            old_home = os.environ.get("HOME")
            old_candidates = desktop.CANDIDATE_SHARES
            try:
                os.environ["XDG_CONFIG_HOME"] = d
                os.environ["XDG_DATA_HOME"] = os.path.join(d, ".local", "share")
                os.environ["HOME"] = d
                desktop.CANDIDATE_SHARES = []
                exe_dir = os.path.join(d, "my bin")
                os.makedirs(exe_dir)
                exe = os.path.join(exe_dir, "vpnman-gtk")
                with open(exe, "w") as fh:
                    fh.write("#!/bin/sh\n")
                os.chmod(exe, 0o755)

                p = autostart.enable(exe)
                with open(p) as fh:
                    content = fh.read()
                self.assertIn('Exec="%s" --background' % exe, content)

                app_dir = os.path.join(d, ".local", "share", "applications")
                os.makedirs(app_dir)
                with open(os.path.join(app_dir, desktop.APP_ID + ".desktop"), "w") as fh:
                    fh.write('[Desktop Entry]\nType=Application\nName=VPNMan\nExec="%s" --background\n' % exe)
                checks = desktop.check()
                self.assertTrue(any(ok and exe in msg and "exists" in msg for ok, msg in checks), checks)
            finally:
                desktop.CANDIDATE_SHARES = old_candidates
                for k, old in (("XDG_CONFIG_HOME", old_xdg_home), ("XDG_DATA_HOME", old_xdg_data), ("HOME", old_home)):
                    if old is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = old


if __name__ == "__main__":
    unittest.main()
