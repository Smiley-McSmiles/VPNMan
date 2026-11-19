import csv
import io
import os
import tempfile
import threading
import unittest
import warnings
from unittest import mock

from vpnman import blocks, conntable, hotspot, proxysvc, share, split, xray


class XrayFixesTests(unittest.TestCase):
    def test_redirect_ruleset_redirects_dns_before_skip_return(self):
        rules = xray.redirect_ruleset(1081, 1082, exclude=["203.0.113.5/32"], allow_lan=True,
                                      split_mark=0x5652, skip_cgroup="vpnman-noproxy", hotspots=["ap0"])
        # Extract redirect_out chain
        out_chain = rules.split("chain redirect_out {")[1].split("\n  }")[0]
        self.assertLess(out_chain.index("meta mark 0x%x return" % xray.MARK),
                        out_chain.index("udp dport 53 redirect to :1082"))
        self.assertLess(out_chain.index("meta mark 0x5652 return"),
                        out_chain.index("udp dport 53 redirect to :1082"))
        self.assertLess(out_chain.index('socket cgroupv2 level 1 "vpnman-noproxy" return'),
                        out_chain.index("udp dport 53 redirect to :1082"))
        self.assertLess(out_chain.index("udp dport 53 redirect to :1082"),
                        out_chain.index("ip daddr {"))
        self.assertLess(out_chain.index("tcp dport 53 redirect to :1082"),
                        out_chain.index("ip daddr {"))
        self.assertLess(out_chain.index("ip daddr {"),
                        out_chain.index("meta l4proto tcp redirect to :1081"))

        # Extract redirect_pre chain
        pre_chain = rules.split("chain redirect_pre {")[1].split("\n  }")[0]
        self.assertLess(pre_chain.index("fib daddr type local return"),
                        pre_chain.index("udp dport 53 dnat ip to 127.0.0.1:1082"))
        self.assertLess(pre_chain.index("udp dport 53 dnat ip to 127.0.0.1:1082"),
                        pre_chain.index("ip daddr {"))
        self.assertLess(pre_chain.index("tcp dport 53 dnat ip to 127.0.0.1:1082"),
                        pre_chain.index("ip daddr {"))

    def test_fetch_rejects_non_http_schemes(self):
        for bad in ("file:///etc/passwd", "ftp://example.com/sub", "javascript:alert(1)", ""):
            with self.assertRaises(xray.ProxyError):
                xray.fetch(bad)

        fake_resp = mock.MagicMock()
        fake_resp.read.return_value = b"vless://11111111-1111-1111-1111-111111111111@example.com:443"
        fake_resp.__enter__.return_value = fake_resp
        with mock.patch("urllib.request.urlopen", return_value=fake_resp) as m_open:
            got = xray.fetch("https://example.com/sub")
        self.assertIn("vless://", got)
        m_open.assert_called_once()

    def test_stream_settings_gates_allow_insecure(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            st = xray.stream_settings("tcp", "tls", {"allowInsecure": ["1"]}, "example.com")
        self.assertNotIn("allowInsecure", st["tlsSettings"])
        self.assertTrue(any("allowInsecure" in str(w.message) for w in caught))

        st_ok = xray.stream_settings("tcp", "tls", {"insecure": ["true"]}, "example.com", allow_insecure=True)
        self.assertTrue(st_ok["tlsSettings"].get("allowInsecure"))

    def test_netproxy_config_brackets_ipv6_dns_server(self):
        up = {"socks": ("127.0.0.1", 1080, "", "")}
        cfg6 = xray.netproxy_config(up, redirect=1081, dns=1082, dns_server="2606:4700:4700::1111")
        self.assertEqual(cfg6["dns"]["servers"], ["tcp://[2606:4700:4700::1111]:53"])

        cfg6_b = xray.netproxy_config(up, redirect=1081, dns=1082, dns_server="[2606:4700:4700::1111]")
        self.assertEqual(cfg6_b["dns"]["servers"], ["tcp://[2606:4700:4700::1111]:53"])

        cfg4 = xray.netproxy_config(up, redirect=1081, dns=1082, dns_server="1.1.1.1")
        self.assertEqual(cfg4["dns"]["servers"], ["tcp://1.1.1.1:53"])

    def test_runner_start_closes_stdout_on_immediate_exit(self):
        with tempfile.TemporaryDirectory() as td:
            runner = xray.Runner(lambda *_: None, td)
            fake_proc = mock.MagicMock()
            fake_proc.pid = 99999
            fake_proc.poll.return_value = 1
            fake_proc.stdout = mock.MagicMock()
            fake_proc.stdout.__iter__.return_value = iter(["boom\n"])
            with mock.patch("vpnman.xray.binary", return_value="/usr/bin/xray"), \
                 mock.patch("subprocess.Popen", return_value=fake_proc):
                with self.assertRaises(xray.ProxyError):
                    runner.start({}, [10808], timeout=0.5)
            fake_proc.stdout.close.assert_called_once()


class ProxySvcFixesTests(unittest.TestCase):
    def test_apply_rules_rolls_back_route_localnet_on_proxy_error(self):
        mgr = mock.MagicMock()
        mgr.hotspots = {"ap0": ["10.42.0.0/24"]}
        mgr.settings.get.return_value = {}
        svc = proxysvc.ProxyService(mgr)
        svc._rules = lambda hs: "bad rules"

        calls = []
        with mock.patch("vpnman.hotspot.route_localnet", side_effect=lambda hs: calls.append(list(hs))), \
             mock.patch("vpnman.xray.apply_ruleset", side_effect=xray.ProxyError("nft failed")):
            with self.assertRaises(xray.ProxyError):
                svc._apply_rules()
        self.assertEqual(calls, [["ap0"], []])

        # When _fw_on was already True with ["ap0"], rollback restores ["ap0"]
        calls.clear()
        svc._fw_on = True
        svc._hs = ("ap0",)
        mgr.hotspots = {"ap0": ["10.42.0.0/24"], "ap1": ["10.43.0.0/24"]}
        with mock.patch("vpnman.hotspot.route_localnet", side_effect=lambda hs: calls.append(list(hs))), \
             mock.patch("vpnman.xray.apply_ruleset", side_effect=xray.ProxyError("nft failed")):
            with self.assertRaises(xray.ProxyError):
                svc._apply_rules()
        self.assertEqual(calls, [["ap0", "ap1"], ["ap0"]])

    def test_fail_over_and_watch_protect_fails_and_deaths_with_lock(self):
        mgr = mock.MagicMock()
        mgr.settings.get.return_value = {}
        svc = proxysvc.ProxyService(mgr)
        lock_acquired = []

        class SpyLock:
            def __init__(self, inner):
                self._inner = inner

            def __enter__(self):
                lock_acquired.append(True)
                return self._inner.__enter__()

            def __exit__(self, *a):
                return self._inner.__exit__(*a)

        svc.lock = SpyLock(threading.RLock())
        svc.owner = "local"
        svc.runner = mock.MagicMock()
        svc.runner.alive.return_value = True
        svc.server_ip = "203.0.113.1"
        svc.selected = lambda: {"id": "p1", "name": "P1", "port": 443}
        svc.settings = lambda: {"failover": True}
        svc._health_at = 0.0
        svc.probe = lambda ip, port: None

        svc.watch()
        self.assertEqual(svc._fails, 1)
        self.assertGreaterEqual(len(lock_acquired), 2)


class SplitAndBlocksFixesTests(unittest.TestCase):
    def test_exec_watcher_closes_socket_on_oserror(self):
        w = split.ExecWatcher(lambda pid: None)
        fake_sock = mock.MagicMock()
        fake_sock.bind.side_effect = OSError("EPERM")
        with mock.patch("socket.socket", return_value=fake_sock):
            self.assertFalse(w.start())
        fake_sock.close.assert_called_once()

    def test_split_cleanup_handles_process_lookup_error_per_pid(self):
        with tempfile.TemporaryDirectory() as root:
            cg = os.path.join(root, split.CGROUP)
            os.makedirs(cg)
            with open(os.path.join(cg, "cgroup.procs"), "w") as fh:
                fh.write("101\n102\n")
            root_procs = os.path.join(root, "cgroup.procs")
            written = []

            real_open = open

            def fake_open(path, mode="r", *args, **kwargs):
                if path == root_procs and "w" in mode:
                    m = mock.MagicMock()

                    def write_pid(p):
                        if p == "101":
                            raise ProcessLookupError("no such process")
                        written.append(p)

                    m.__enter__.return_value.write.side_effect = write_pid
                    return m
                return real_open(path, mode, *args, **kwargs)

            removed_dirs = []
            with mock.patch("vpnman.split.cgroup_root", return_value=root), \
                 mock.patch("vpnman.platform.which", return_value=None), \
                 mock.patch("os.rmdir", side_effect=removed_dirs.append), \
                 mock.patch("builtins.open", side_effect=fake_open):
                split.cleanup()
            self.assertEqual(written, ["102"])
            self.assertIn(cg, removed_dirs)

    def test_blocks_cleanup_handles_process_lookup_error_per_pid(self):
        with tempfile.TemporaryDirectory() as root:
            cg = os.path.join(root, blocks.CGROUP)
            os.makedirs(cg)
            with open(os.path.join(cg, "cgroup.procs"), "w") as fh:
                fh.write("201\n202\n")
            root_procs = os.path.join(root, "cgroup.procs")
            written = []

            real_open = open

            def fake_open(path, mode="r", *args, **kwargs):
                if path == root_procs and "w" in mode:
                    m = mock.MagicMock()

                    def write_pid(p):
                        if p == "201":
                            raise ProcessLookupError("no such process")
                        written.append(p)

                    m.__enter__.return_value.write.side_effect = write_pid
                    return m
                return real_open(path, mode, *args, **kwargs)

            removed_dirs = []
            with mock.patch("vpnman.split.cgroup_root", return_value=root), \
                 mock.patch("vpnman.platform.which", return_value=None), \
                 mock.patch("os.rmdir", side_effect=removed_dirs.append), \
                 mock.patch("builtins.open", side_effect=fake_open):
                self.assertTrue(blocks.cleanup())
            self.assertEqual(written, ["202"])
            self.assertIn(cg, removed_dirs)

    def test_split_ruleset_drops_ipv6_for_marked_packets(self):
        rules = split.ruleset(["192.168.1.1", "2001:db8::1"], mode="exclude")
        self.assertIn("meta mark 0x%x meta nfproto ipv6 drop" % split.MARK, rules)
        self.assertNotIn("2001:db8", rules)

    def test_split_moved_lock_protects_moved_dict(self):
        with tempfile.TemporaryDirectory() as root:
            st = split.SplitTunnel(lambda: ["app"], root=root)
            self.assertTrue(hasattr(st, "_moved_lock"))
            st.active = True
            os.makedirs(st.path, exist_ok=True)
            # _prune, scan_once, _on_exec, _release all work cleanly under _moved_lock
            st.moved[1234] = "/"
            st._prune(st.path)
            self.assertEqual(st.moved, {})


class HotspotAndShareFixesTests(unittest.TestCase):
    def test_hotspot_sysctl_validates_interface_names(self):
        for bad in ("../etc/passwd", "eth0\n", "", "a" * 16, "eth0;id", "eth/0"):
            with self.assertRaises(ValueError):
                hotspot._sysctl(bad)
        self.assertEqual(hotspot._sysctl("wlan0"), "/proc/sys/net/ipv4/conf/wlan0/route_localnet")
        self.assertEqual(hotspot._sysctl("br-lan_0.1"), "/proc/sys/net/ipv4/conf/br-lan_0.1/route_localnet")

    def test_share_ruleset_validates_interface_names(self):
        for bad in ('tun0" }', "../etc", "tun0\n", "", "a" * 16, "tun:0"):
            with self.assertRaises(ValueError):
                share.ruleset([bad])
        self.assertIn('oifname { "tun0", "wg0" }', share.ruleset(["tun0", "wg0"]))

    def test_hotspot_entries_bounds_check(self):
        import struct
        # Header claims length=100, but buffer is only 20 bytes
        fake_sock = mock.MagicMock()
        fake_sock.recv.side_effect = [
            struct.pack("=IHHII", 100, hotspot.NFNL_CT, 0, 1, 0) + b"\x00" * 4,
        ]
        self.assertEqual(hotspot._entries(fake_sock), [])


class ConntableFixesTests(unittest.TestCase):
    def test_resolver_work_discards_pending_on_unexpected_exception_and_shutdown(self):
        def boom(_ip):
            raise RuntimeError("unexpected")

        r = conntable.Resolver(lookup=boom, sync=True)
        with self.assertRaises(RuntimeError):
            r.names(["1.2.3.4"])
        self.assertNotIn("1.2.3.4", r._pending)

        r_async = conntable.Resolver(lookup=lambda ip: "host.example", sync=False)
        r_async.names(["1.2.3.4"])
        self.assertIsNotNone(r_async._pool)
        r_async.shutdown()
        self.assertIsNone(r_async._pool)

    def test_to_csv_defuses_all_formula_prefixes_including_digits(self):
        rows = [
            {"dir": "out", "proto": "tcp", "v6": False, "local": "10.0.0.1", "lport": 1,
             "remote": "1.1.1.1", "rport": 80, "state": "ESTABLISHED", "pid": 1,
             "app": app, "rname": ""}
            for app in ("=1+1", "+1+1", "-1+1", "@SUM(1,1)", "\tcmd", "\rcmd")
        ]
        got = list(csv.reader(io.StringIO(conntable.to_csv(rows))))
        for i, row in enumerate(got[1:], 1):
            self.assertTrue(row[1].startswith("'"), "row %d app %r was not quoted" % (i, row[1]))


if __name__ == "__main__":
    unittest.main()
