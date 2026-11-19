"""Tests for core-vpn bug fixes, security hardening, and OpenVPN AirVPN handling."""

import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from unittest import mock

from vpnman import backends, dns, dnsfwd, leaktest, netlock, paths, stunnel
from vpnman.backends import base as base_backend, openvpn, others, wireguard
from vpnman.manager import FatalError, Manager, _safe_cmd
from vpnman.profiles import ProfileStore, new_profile
from vpnman.settings import Settings


AIRVPN_CONFIG = """\
client
dev tun
remote ca3.vpn.airdns.org 443
resolv-retry infinite
nobind
persist-key
persist-tun
auth-nocache
verb 3
explicit-exit-notify 5
rcvbuf 262144
sndbuf 262144
push-peer-info
setenv UV_IPV6 yes
remote-cert-tls server
data-ciphers AES-256-GCM:AES-192-GCM:AES-128-GCM
data-ciphers-fallback AES-256-GCM
proto udp
auth SHA512
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIB
-----END PRIVATE KEY-----
</key>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
0000
-----END OpenVPN Static key V1-----
</tls-crypt>
"""


class TempEnvMixin:
    def make_env(self):
        self._tmp = tempfile.mkdtemp(prefix="vpnman-core-vpn-")
        self._old_env = {k: os.environ.get(k) for k in (
            "VPNMAN_CONFIG_DIR", "VPNMAN_RUN_DIR", "VPNMAN_RESOLV_CONF", "VPNMAN_NSSWITCH"
        )}
        os.environ["VPNMAN_CONFIG_DIR"] = os.path.join(self._tmp, "cfg")
        os.environ["VPNMAN_RUN_DIR"] = os.path.join(self._tmp, "run")
        os.makedirs(os.environ["VPNMAN_CONFIG_DIR"], exist_ok=True)
        os.makedirs(os.environ["VPNMAN_RUN_DIR"], exist_ok=True)
        self.addCleanup(self._cleanup_env)
        return self._tmp

    def _cleanup_env(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self._tmp, ignore_errors=True)


class TestAirVpnOpenVpn(TempEnvMixin, unittest.TestCase):
    def test_parse_and_restricted_uv_ipv6(self):
        ovpn = openvpn.OpenVPN()
        parsed = ovpn.parse("airvpn.ovpn", AIRVPN_CONFIG)
        self.assertEqual(parsed["server"], "ca3.vpn.airdns.org")
        self.assertEqual(parsed["port"], 443)
        self.assertEqual(parsed["transport"], "udp")
        self.assertFalse(openvpn.restricted("setenv UV_IPV6 yes"))
        self.assertFalse(openvpn.restricted("setenv-safe UV_FOO_1 bar"))
        self.assertTrue(openvpn.restricted("setenv LD_PRELOAD /tmp/evil.so"))
        self.assertTrue(openvpn.restricted("setenv PATH /tmp"))
        self.assertTrue(openvpn.restricted("up /bin/sh"))

    def test_restricted_preserves_uv_ipv6(self):
        tmp = self.make_env()
        store = ProfileStore(os.path.join(tmp, "profiles"))
        mgr = Manager(store=store, settings=Settings(os.path.join(tmp, "settings.json")))
        p = dict(new_profile("AirVPN", "openvpn"), config="air.ovpn", untrusted=True)
        store.save(p, {"air.ovpn": AIRVPN_CONFIG})
        q = mgr._restricted(openvpn.OpenVPN(), p)
        with open(os.path.join(store.dir_of(p), q["config"])) as fh:
            restricted_text = fh.read()
        self.assertIn("setenv UV_IPV6 yes", restricted_text)

    def test_tunnel_dns_drops_v6_when_ipv6_blocked(self):
        tmp = self.make_env()
        s = Settings(os.path.join(tmp, "settings.json"))
        s.set("netlock.block_ipv6", True)
        mgr = Manager(store=ProfileStore(os.path.join(tmp, "profiles")), settings=s)
        mgr.lock_engaged = True
        ctx = base_backend.Context({"dns": []}, tmp, tmp, "tun0", s)
        ctx.dns = ["10.4.0.1", "fde6:7a:7d20:1::1"]
        self.assertEqual(mgr._tunnel_dns(ctx), ["10.4.0.1"])

    def test_session_resolves_endpoint_when_lock_already_engaged(self):
        tmp = self.make_env()
        store = ProfileStore(os.path.join(tmp, "profiles"))
        s = Settings(os.path.join(tmp, "settings.json"))
        s.set("netlock.enabled", True)
        mgr = Manager(store=store, settings=s)
        mgr.lock_engaged = True
        p = dict(
            new_profile("AirVPN", "openvpn"),
            server="ca3.vpn.airdns.org", port=443, transport="udp",
            config="air.ovpn", options={"remotes": [["ca3.vpn.airdns.org", 443, "udp"]]},
        )
        store.save(p, {"air.ovpn": AIRVPN_CONFIG})

        fw = mock.Mock()
        fw.name = "nftables"
        applied_endpoints = []
        fw.apply.side_effect = lambda spec: applied_endpoints.append(list(spec.endpoints))
        mgr._fw = fw

        def fake_resolve(host, cache):
            if host == "ca3.vpn.airdns.org" and any("192.0.2.53" in ep for ep in mgr._lock_endpoints):
                cache[host] = ["198.51.100.42"]
                return ["198.51.100.42"]
            return []

        with mock.patch("vpnman.manager.resolve_host", side_effect=fake_resolve), \
             mock.patch("vpnman.manager.system_dns", return_value=["192.0.2.53"]), \
             mock.patch("vpnman.leaktest.resolved_dns_map", return_value={}), \
             mock.patch("vpnman.platform.default_gateway", return_value=("192.0.2.1", "eth0")), \
             mock.patch("vpnman.platform.list_interfaces", return_value=["eth0"]):
            stop = threading.Event()
            stop.set()
            with mock.patch.object(openvpn.OpenVPN, "validate", return_value=[]):
                # Trigger only up to pre_connect/stop check
                mgr._session(p, stop)

        self.assertTrue(any("192.0.2.53/32" in eps for eps in applied_endpoints))
        self.assertIn("198.51.100.42", mgr._lock_endpoints)
        self.assertNotIn("192.0.2.53", mgr._lock_endpoints)


class TestOthersBackends(unittest.TestCase):
    def test_restricted_regexes(self):
        self.assertTrue(others.OpenFortiVPN.restricted_line("  pppd-plugin = /tmp/evil.so"))
        self.assertTrue(others.OpenFortiVPN.restricted_line("\tca-file = /etc/ssl/cert.pem"))
        self.assertFalse(others.OpenFortiVPN.restricted_line("host = vpn.example.com"))

        self.assertTrue(others.StrongSwan.restricted_line("  updown = /bin/sh"))
        self.assertTrue(others.StrongSwan.restricted_line("include /etc/shadow"))
        self.assertFalse(others.StrongSwan.restricted_line("remote_addrs = 1.2.3.4"))

        self.assertTrue(others.VPNC.restricted_line("  Script /tmp/evil.sh"))
        self.assertFalse(others.VPNC.restricted_line("IPSec gateway 1.2.3.4"))

        self.assertTrue(others.Nebula.restricted_line("  ca: /etc/passwd"))
        self.assertTrue(others.Nebula.restricted_line("  pki: key: /tmp/k"))
        self.assertFalse(others.Nebula.restricted_line("  ca: ca.crt"))

    def test_openfortivpn_prepare_strips_server_newlines(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        ctx = base_backend.Context({"server": "1.2.3.4\npppd-plugin = /evil.so", "port": 443}, tmp, tmp, None, {})
        others.OpenFortiVPN().prepare(ctx)
        with open(ctx.state["path"]) as fh:
            text = fh.read()
        self.assertIn("host = 1.2.3.4 pppd-plugin = /evil.so\n", text)
        self.assertNotIn("\npppd-plugin", text)

    def test_sstp_and_pptp_ppp_options_quoting(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        prof = {"server": "vpn.example.com", "username": "user'1", "password": 'p@ss"\\1\nplugin /evil'}
        for cls in (others.SSTP, others.PPTP):
            ctx = base_backend.Context(prof, tmp, tmp, "ppp0", {})
            cls().prepare(ctx)
            with open(ctx.state["opts"]) as fh:
                content = fh.read()
            self.assertIn('name "user\'1"', content)
            self.assertIn('password "p@ss\\"\\\\1plugin /evil"', content)
            self.assertNotIn("\nplugin /evil", content)


class TestManagerFixes(TempEnvMixin, unittest.TestCase):
    def test_restricted_blocks_custom_backend(self):
        tmp = self.make_env()
        mgr = Manager(store=ProfileStore(os.path.join(tmp, "profiles")),
                      settings=Settings(os.path.join(tmp, "settings.json")))
        p = {"id": "c1", "name": "Custom", "protocol": "custom", "untrusted": True,
             "options": {"connect_cmd": "/bin/id", "disconnect_cmd": "/bin/true"}}
        with self.assertRaises(FatalError):
            mgr._restricted(others.Custom(), p)

    def test_cancel_keeps_thread_when_alive(self):
        tmp = self.make_env()
        mgr = Manager(store=ProfileStore(os.path.join(tmp, "profiles")),
                      settings=Settings(os.path.join(tmp, "settings.json")))
        gate = threading.Event()
        t = threading.Thread(target=gate.wait, daemon=True)
        t.start()
        mgr._thread = t
        mgr._cancel(wait=0.05)
        self.assertIs(mgr._thread, t)
        gate.set()
        t.join(1)

    def test_missing_config_raises_fatal_error(self):
        tmp = self.make_env()
        store = ProfileStore(os.path.join(tmp, "profiles"))
        mgr = Manager(store=store, settings=Settings(os.path.join(tmp, "settings.json")))
        p = dict(new_profile("Missing", "openvpn"), config="missing.ovpn")
        store.save(p, {})
        with mock.patch.object(openvpn.OpenVPN, "validate", return_value=[]), \
             mock.patch("vpnman.platform.default_gateway", return_value=("192.0.2.1", "eth0")), \
             mock.patch("vpnman.platform.list_interfaces", return_value=["eth0"]):
            with self.assertRaises(FatalError):
                mgr._session(p, threading.Event())

    def test_save_state_atomic_and_startup_cleanup(self):
        tmp = self.make_env()
        store = ProfileStore(os.path.join(tmp, "profiles"))
        mgr = Manager(store=store, settings=Settings(os.path.join(tmp, "settings.json")))
        p = dict(new_profile("P1", "openvpn"), config="a.ovpn")
        store.save(p, {"a.ovpn": "client\n", ".restricted-a.ovpn": "stale\n"})
        stale_conn = os.path.join(paths.run_dir(), "conn", p["id"])
        os.makedirs(stale_conn, exist_ok=True)
        with open(os.path.join(stale_conn, "runtime.ovpn"), "w") as fh:
            fh.write("stale")

        mgr._save_state(lock_manual=True, last_profile="p1")
        with open(paths.state_file()) as fh:
            self.assertEqual(json.load(fh), {"lock_manual": True, "last_profile": "p1"})
        self.assertFalse([f for f in os.listdir(paths.config_dir()) if ".tmp." in f])

        with mock.patch("vpnman.dns.restore_resolv_conf"), \
             mock.patch("vpnman.dns.restore_nsswitch"), \
             mock.patch("vpnman.split.cleanup"), \
             mock.patch("vpnman.share.cleanup"), \
             mock.patch("vpnman.hotspot.restore"), \
             mock.patch("vpnman.xray.cleanup", return_value=False), \
             mock.patch("vpnman.blocks.cleanup"), \
             mock.patch.object(mgr.proxy.runner, "kill_stale"), \
             mock.patch.object(mgr.proxy, "sync"), \
             mock.patch.object(mgr.scheduler, "start"), \
             mock.patch.object(mgr, "_start_network_monitor"), \
             mock.patch("vpnman.netlock.cleanup_all", return_value=[]):
            mgr.startup()

        self.assertFalse(os.path.exists(os.path.join(store.dir_of(p), ".restricted-a.ovpn")))
        self.assertFalse(os.path.exists(stale_conn))

    def test_safe_cmd_masks_wg_secrets(self):
        out = _safe_cmd(["ifconfig", "wg0", "create", "wgkey", "SECRET1", "wgpeer", "PUB", "wgpsk", "SECRET2"])
        self.assertNotIn("SECRET1", out)
        self.assertNotIn("SECRET2", out)
        self.assertIn("wgkey ***", out)
        self.assertIn("wgpsk ***", out)


class TestBaseAndWireguard(unittest.TestCase):
    def test_bracketed_ipv6_endpoints(self):
        b = base_backend.Backend()
        self.assertEqual(b.endpoints({"server": "[::1]:443"}), [("::1", 443, "")])
        self.assertEqual(b.endpoints({"server": "[2001:db8::1]"}), [("2001:db8::1", 0, "")])
        self.assertEqual(b.endpoints({"server": "198.51.100.1:51820", "transport": "udp"}),
                         [("198.51.100.1", 51820, "udp")])

    def test_wireguard_bsd_up_ipv6_allowedips(self):
        wg = wireguard.WireGuard()
        ctx = base_backend.Context({}, "", "", "wg0", {})
        ctx.state["conf"] = (
            "[Interface]\n"
            "PrivateKey = PRIV\n"
            "Address = 10.0.0.2/24, fd00::2/64\n"
            "[Peer]\n"
            "PublicKey = PUB\n"
            "Endpoint = 198.51.100.1:51820\n"
            "AllowedIPs = 0.0.0.0/0, ::/0, fd01::/48\n"
        )
        with mock.patch("vpnman.platform.default_gateway", return_value=("192.0.2.1", "em0")):
            cmds = wg._bsd_up(ctx)
        self.assertIn(["route", "-q", "add", "-inet6", "::/1", "fd00::2"], cmds)
        self.assertIn(["route", "-q", "add", "-inet6", "8000::/1", "fd00::2"], cmds)
        self.assertIn(["route", "-q", "add", "-inet6", "fd01::/48", "fd00::2"], cmds)


class TestNetlockFixes(TempEnvMixin, unittest.TestCase):
    def test_ipt_firewall_no_teardown_before_staging_and_active_checks_v6(self):
        fw = netlock.IptFirewall()
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if "-D" in cmd:
                return 1, "No chain/target/match by that name"
            return 0, ""

        with mock.patch("vpnman.platform.which", side_effect=lambda x: "/sbin/" + x if x in ("iptables", "ip6tables") else None), \
             mock.patch("vpnman.platform.run", side_effect=fake_run):
            fw.apply(netlock.Spec(["198.51.100.1"], ["tun0"], share=False))

        insert_idx = next(i for i, c in enumerate(calls) if c[:4] == ["/sbin/iptables", "-w", "-I", "OUTPUT"])
        teardown_old = next(i for i, c in enumerate(calls) if c[:5] == ["/sbin/iptables", "-w", "-D", "OUTPUT", "-j"] and c[5] == "VPNMAN_OUT")
        self.assertLess(insert_idx, teardown_old)
        self.assertIn(["/sbin/iptables", "-w", "-E", "VPNMAN_OUT_N", "VPNMAN_OUT"], calls)

        def v6_only_active(cmd, **kw):
            return (0, "") if "ip6tables" in cmd[0] else (1, "")

        with mock.patch("vpnman.platform.which", side_effect=lambda x: "/sbin/" + x if x in ("iptables", "ip6tables") else None), \
             mock.patch("vpnman.platform.run", side_effect=v6_only_active):
            self.assertTrue(fw.active())

    def test_dhcp_rules_restricted_and_pf_state_not_left_on_failure(self):
        tmp = self.make_env()
        nft_no_share = netlock.nft_ruleset(netlock.Spec(allow_dhcp=True, share=False))
        self.assertIn("255.255.255.255", nft_no_share)
        self.assertNotIn("udp sport 67 udp dport 68", nft_no_share.split("chain output")[1])
        self.assertIn("fe80::/10", nft_no_share)

        pf = netlock.PfFirewall()
        with mock.patch("vpnman.platform.which", return_value="/sbin/pfctl"), \
             mock.patch("vpnman.platform.run", side_effect=[(0, "Status: Disabled\n"), (1, "syntax error")]):
            with self.assertRaises(RuntimeError):
                pf.apply(netlock.Spec())
        self.assertFalse(pf.active())
        self.assertFalse(os.path.exists(os.path.join(tmp, "run", "pf.was_enabled")))


class TestDnsDnsfwdLeaktestStunnel(TempEnvMixin, unittest.TestCase):
    def test_nss_bypass_atomic_and_dns_warn(self):
        tmp = self.make_env()
        real_nss = os.path.join(tmp, "real-nsswitch.conf")
        link_nss = os.path.join(tmp, "nsswitch.conf")
        with open(real_nss, "w") as fh:
            fh.write("hosts: files resolve [!UNAVAIL=return] dns\n")
        os.symlink(real_nss, link_nss)
        os.environ["VPNMAN_NSSWITCH"] = link_nss

        self.assertTrue(dns.nss_bypass(True))
        self.assertTrue(os.path.islink(link_nss))
        with open(real_nss) as fh:
            self.assertNotIn("resolve", fh.read())
        self.assertTrue(dns.nss_overridden())
        self.assertFalse(dns.nss_bypass(False))
        with open(real_nss) as fh:
            self.assertIn("resolve", fh.read())

        rconf = os.path.join(tmp, "resolv.conf")
        with open(rconf, "w") as fh:
            fh.write("nameserver 1.1.1.1\n")
        os.environ["VPNMAN_RESOLV_CONF"] = rconf
        dm = dns.DnsManager()
        msg = dm.apply(["10.8.0.1"], None)
        self.assertIn("warning: NSS resolve", msg)

    def test_dnsfwd_thread_error_stop_tcp_and_udp_source_check(self):
        fwd = dnsfwd.DnsForwarder("127.0.0.1", 0)
        sock_a, sock_b = socket.socketpair()
        with fwd._lock:
            fwd._active_socks.add(sock_a)
        fwd.stop()
        self.assertEqual(sock_a.fileno(), -1)
        sock_b.close()

        # Verify UDP ignores spoofed source and accepts (upstream, 53)
        fwd2 = dnsfwd.DnsForwarder("198.51.100.1", 0)
        fake_up = mock.Mock()
        fake_up.recvfrom.side_effect = [
            (b"\x12\x34spoof", ("203.0.113.9", 53)),
            (b"\x12\x34real", ("198.51.100.1", 53)),
        ]
        fake_local = mock.Mock()
        fwd2._busy.acquire()
        with mock.patch.object(fwd2, "_upstream_socket", return_value=fake_up):
            fwd2._udp_query(fake_local, b"\x12\x34query", ("127.0.0.1", 55555))
        fake_local.sendto.assert_called_once_with(b"\x12\x34real", ("127.0.0.1", 55555))

        # Verify Thread.start() failure releases _busy and closes conn
        fwd3 = dnsfwd.DnsForwarder("198.51.100.1", 0)
        fake_srv = mock.Mock()
        fake_conn = mock.Mock()
        fake_srv.accept.side_effect = [(fake_conn, ("127.0.0.1", 1234)), OSError("done")]
        with mock.patch("threading.Thread.start", side_effect=RuntimeError("no threads")):
            fwd3._tcp_loop(fake_srv)
        fake_conn.close.assert_called_once()
        self.assertTrue(fwd3._busy.acquire(blocking=False))
        fwd3._busy.release()

    def test_leaktest_ipv6_and_non_tunnel_tilde_dot(self):
        res_fail = leaktest.ipv6_check("tun0", lambda a: "eth0", lambda: True, True, True)
        self.assertEqual(res_fail["status"], "fail")
        res_ok = leaktest.ipv6_check("tun0", lambda a: "eth0", lambda: False, True, True)
        self.assertEqual(res_ok["status"], "ok")

        dns_res = leaktest.dns_check(
            "nameserver 127.0.0.53\n",
            "tun0",
            lambda a: None,
            resolved_dns={"tun0": ["10.8.0.1"], "eth0": ["192.168.1.1"]},
            resolved_domains={"tun0": ["~."], "eth0": ["~."]},
        )
        self.assertEqual(dns_res["status"], "fail")
        self.assertIn("192.168.1.1", dns_res["detail"])

    def test_stunnel_ca_and_verify_system_fail_closed(self):
        prof_bad_ca = {"options": {"stunnel": {
            "enabled": True, "host": "vpn.example.com", "port": 443,
            "verify": "ca", "ca": "ca.crt\nexec = /bin/sh"
        }}}
        with mock.patch("vpnman.stunnel.binary", return_value="/usr/bin/stunnel"):
            probs = stunnel.validate(prof_bad_ca)
        self.assertTrue(any("invalid" in x for x in probs))
        with self.assertRaises(ValueError):
            stunnel.config(prof_bad_ca, "/tmp", "/tmp", 12345)

        prof_sys = {"options": {"stunnel": {
            "enabled": True, "host": "vpn.example.com", "port": 443, "verify": "system"
        }}}
        with mock.patch("vpnman.stunnel.binary", return_value="/usr/bin/stunnel"), \
             mock.patch("os.path.exists", return_value=False):
            probs = stunnel.validate(prof_sys)
            self.assertTrue(any("CA bundle" in x for x in probs))
            with self.assertRaises(ValueError):
                stunnel.config(prof_sys, "/tmp", "/tmp", 12345)


if __name__ == "__main__":
    unittest.main()
