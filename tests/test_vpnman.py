import base64
import os
import stat
import tempfile
import threading
import time
import unittest

TMP = tempfile.mkdtemp(prefix="vpnman-test-")
os.environ.update({
    "VPNMAN_CONFIG_DIR": TMP + "/etc", "VPNMAN_RUN_DIR": TMP + "/run", "VPNMAN_LOG_FILE": TMP + "/log",
    "VPNMAN_SOCKET": TMP + "/run/s.sock", "VPNMAN_RESOLV_CONF": TMP + "/resolv.conf",
    "VPNMAN_ALLOW_UNPRIVILEGED": "1",
})
os.makedirs(TMP + "/run")
os.makedirs(TMP + "/bin")
os.environ["PATH"] = TMP + "/bin" + os.pathsep + os.environ["PATH"]

from vpnman import backends, daemon, dns, ipc, netlock, profiles, settings  # noqa: E402
from vpnman.manager import Manager  # noqa: E402

OVPN = "client\ndev tun\nproto udp\nremote vpn.example.net 1194\nremote 192.0.2.7 443 tcp\nca ca.crt\nauth-user-pass\n"
WG = """[Interface]
PrivateKey = AAAA
Address = 10.0.0.2/32
DNS = 10.0.0.1, example.org

[Peer]
PublicKey = BBBB
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.4:51820
"""


class NetlockTests(unittest.TestCase):
    def spec(self, **kw):
        return netlock.Spec(["198.51.100.4", "2001:db8::1"], ["tun0"], **kw)

    def test_nft_contains_essentials(self):
        r = netlock.nft_ruleset(self.spec())
        self.assertIn("policy drop", r)
        self.assertIn('oifname { "tun0" } accept', r)
        self.assertIn("198.51.100.4/32", r)
        self.assertIn("meta nfproto ipv6 drop", r)
        self.assertIn("delete table inet vpnman", r)

    def test_lan_toggle(self):
        self.assertNotIn("192.168.0.0/16", netlock.nft_ruleset(self.spec(allow_lan=False)))
        self.assertIn("192.168.0.0/16", netlock.nft_ruleset(self.spec(allow_lan=True)))
        self.assertNotIn("192.168.0.0/16", netlock.pf_ruleset(self.spec(allow_lan=False)))

    def test_bad_input_rejected(self):
        with self.assertRaises(ValueError):
            netlock.Spec(["1.2.3.4; rm -rf /"])
        self.assertEqual(netlock.Spec([], ["bad iface!", "wg0"]).ifaces, ["wg0"])

    def test_pf_and_ipt(self):
        s = self.spec(block_ipv6=False)
        self.assertIn("block drop all", netlock.pf_ruleset(s))
        self.assertIn("pass out quick on tun0 all", netlock.pf_ruleset(s))
        cmds = netlock.ipt_commands(s)
        self.assertIn(["-A", "VPNMAN_OUT", "-o", "tun0", "-j", "ACCEPT"], cmds)
        self.assertEqual(cmds[-1], ["-A", "VPNMAN_IN", "-j", "DROP"])
        v6 = netlock.ipt_commands(s, v6=True)
        self.assertIn(["-A", "VPNMAN_OUT", "-d", "2001:db8::1/128", "-j", "ACCEPT"], v6)

    def test_ipv6_blocked_chain(self):
        v6 = netlock.ipt_commands(self.spec(block_ipv6=True), v6=True)
        self.assertNotIn(["-A", "VPNMAN_OUT", "-o", "tun0", "-j", "ACCEPT"], v6)


class ImportTests(unittest.TestCase):
    def test_sniff(self):
        self.assertEqual(backends.sniff("a.ovpn", OVPN), "openvpn")
        self.assertEqual(backends.sniff("wg0.conf", WG), "wireguard")
        self.assertEqual(backends.sniff("a.conf", WG + "Jc = 4\nS1 = 10\n"), "amneziawg")
        self.assertEqual(backends.sniff("x.conf", "connections {\n  corp {\n    remote_addrs = 1.2.3.4\n  }\n}\n"), "ikev2")
        self.assertIsNone(backends.sniff("notes.txt", "hello"))

    def test_openvpn_parse(self):
        info = backends.get("openvpn").parse("a.ovpn", OVPN)
        self.assertEqual(info["server"], "vpn.example.net")
        self.assertEqual(info["options"]["remotes"][1], ["192.0.2.7", 443, "tcp"])

    def test_wireguard_parse(self):
        info = backends.get("wireguard").parse("w.conf", WG)
        self.assertEqual((info["server"], info["port"]), ("198.51.100.4", 51820))
        self.assertEqual(info["dns"], ["10.0.0.1"])

    def test_collect_files_rewrites_paths(self):
        d = tempfile.mkdtemp(dir=TMP)
        os.makedirs(d + "/certs")
        open(d + "/certs/ca.crt", "w").write("CA")
        open(d + "/x.ovpn", "w").write("client\nremote a 1\nca certs/ca.crt\n")
        text, files = profiles.collect_files(d + "/x.ovpn")
        self.assertIn("ca ca.crt", text)
        self.assertEqual(base64.b64decode(files["ca.crt"]), b"CA")

    def test_unsafe_filename(self):
        for bad in ("../x", "a/../../b", "", ".."):
            if os.path.basename(bad) in ("", ".."):
                with self.assertRaises(profiles.ProfileError):
                    profiles.safe_filename(bad)
        self.assertEqual(profiles.safe_filename("/etc/passwd"), "passwd")

    def test_store_permissions(self):
        st = profiles.ProfileStore(TMP + "/store")
        p = profiles.new_profile("n", "openvpn")
        st.save(p, {"c.ovpn": "x"})
        mode = stat.S_IMODE(os.stat(TMP + "/store/%s/profile.json" % p["id"]).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(st.find("N")["id"], p["id"])
        self.assertNotIn("password", profiles.public_view(p))


class BackendTests(unittest.TestCase):
    def ctx(self, profile, ifname="vpnmtest"):
        d = tempfile.mkdtemp(dir=TMP)
        pd = tempfile.mkdtemp(dir=TMP)
        open(pd + "/p.ovpn", "w").write(OVPN.replace("auth-user-pass\n", ""))
        open(pd + "/w.conf", "w").write(WG)
        return backends.Context(profile, pd, d, ifname, settings.Settings(TMP + "/s.json"))

    def test_openvpn_cmd(self):
        p = profiles.new_profile("o", "openvpn", config="p.ovpn", username="u", password="pw")
        ctx = self.ctx(p)
        b = backends.get("openvpn")
        ctx.state["resolved"] = {"vpn.example.net": "203.0.113.9"}
        b.prepare(ctx)
        cmd = b.connect_cmd(ctx)
        self.assertIn("--auth-user-pass", cmd)
        self.assertEqual(cmd[cmd.index("--dev") + 1], "vpnmtest")
        runtime = open(ctx.state["path"]).read()
        self.assertIn("remote 203.0.113.9 1194", runtime)
        self.assertEqual(open(os.path.join(ctx.workdir, "auth")).read(), "u\npw\n")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(ctx.workdir, "auth")).st_mode), 0o600)

    def test_openvpn_needs_creds(self):
        p = profiles.new_profile("o", "openvpn", config="p.ovpn")
        ctx = self.ctx(p)
        open(ctx.profile_dir + "/p.ovpn", "w").write(OVPN)
        b = backends.get("openvpn")
        b.prepare(ctx)
        with self.assertRaises(ValueError):
            b.connect_cmd(ctx)

    def test_openvpn_log_parsing(self):
        ctx = self.ctx(profiles.new_profile("o", "openvpn", config="p.ovpn"))
        b = backends.get("openvpn")
        b.parse_line("TUN/TAP device tun3 opened", ctx)
        b.parse_line("PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 10.8.0.2", ctx)
        self.assertEqual(ctx.iface, "tun3")
        self.assertIn("10.8.0.1", ctx.dns)
        self.assertTrue(b.ready_re.search("Initialization Sequence Completed"))

    def test_wireguard_strips_dns_and_resolves(self):
        p = profiles.new_profile("w", "wireguard", config="w.conf")
        ctx = self.ctx(p)
        open(ctx.profile_dir + "/w.conf", "w").write(WG.replace("198.51.100.4", "wg.example.org"))
        ctx.state["resolved"] = {"wg.example.org": "203.0.113.1"}
        b = backends.get("wireguard")
        b.prepare(ctx)
        text = open(ctx.state["path"]).read()
        self.assertNotIn("DNS", text)
        self.assertIn("Endpoint = 203.0.113.1:51820", text)
        self.assertTrue(ctx.state["path"].endswith("vpnmtest.conf"))
        self.assertEqual(b.connect_cmds(ctx)[0][1:2], ["up"])
        self.assertEqual(b.disconnect_cmds(ctx)[0][1], "down")

    def test_openconnect_resolve_and_stdin(self):
        p = profiles.new_profile("c", "openconnect", server="https://gw.example.com", username="u", password="p",
                                 options={"protocol": "gp"})
        ctx = self.ctx(p)
        ctx.state["resolved"] = {"gw.example.com": "203.0.113.5"}
        b = backends.get("openconnect")
        cmd = b.connect_cmd(ctx)
        self.assertIn("gp", cmd)
        self.assertIn("gw.example.com:203.0.113.5", cmd)
        self.assertEqual(b.stdin_data(ctx), "p\n")
        self.assertNotIn("p", [a for a in cmd if a == "p"])

    def test_registry_breadth(self):
        self.assertGreaterEqual(len(backends.REGISTRY), 15)
        for b in backends.REGISTRY.values():
            self.assertTrue(b.label and b.description)

    def test_validation(self):
        self.assertTrue(backends.get("zerotier").validate(profiles.new_profile("z", "zerotier")))
        self.assertTrue(backends.get("custom").validate(profiles.new_profile("c", "custom")))


class AutostartTests(unittest.TestCase):
    def test_login_entry(self):
        from vpnman import autostart
        os.environ["XDG_CONFIG_HOME"] = TMP + "/xdg"
        self.assertFalse(autostart.is_enabled())
        autostart.enable("/usr/bin/vpnman-gtk")
        text = open(autostart.path()).read()
        self.assertIn("Exec=/usr/bin/vpnman-gtk --background", text)
        self.assertIn("X-GNOME-Autostart-enabled=true", text)
        self.assertTrue(autostart.is_enabled())
        autostart.disable()
        self.assertFalse(autostart.is_enabled())
        autostart.disable()   # idempotent

    def test_boot_autoconnect_waits_for_network(self):
        from vpnman import platform as plat
        fake = TMP + "/bin/openvpn"
        if not os.path.exists(fake):
            open(fake, "w").write("#!/bin/sh\necho 'Initialization Sequence Completed'\ntrap 'exit 0' TERM\nwhile :; do sleep 0.1; done\n")
            os.chmod(fake, 0o755)
        s = settings.Settings(TMP + "/boot.json")
        s.set("checks.tunnel", False)
        s.set("connection.autoconnect_wait", 30)
        mgr = Manager(store=profiles.ProfileStore(TMP + "/bootstore"), settings=s)
        mgr.import_profile("boot", OVPN.replace("auth-user-pass\n", ""), filename="boot.ovpn")
        calls = {"n": 0}
        orig = plat.default_gateway

        def gw():
            calls["n"] += 1
            return (None, None) if calls["n"] < 3 else ("192.0.2.1", "eth0")
        plat.default_gateway = gw
        try:
            t0 = time.time()
            mgr._autoconnect("boot")
            self.assertGreater(calls["n"], 2)             # it polled until a gateway appeared
            self.assertGreater(time.time() - t0, 1.5)
            end = time.time() + 10
            while mgr.status()["state"] != "connected" and time.time() < end:
                time.sleep(0.1)
            self.assertEqual(mgr.status()["state"], "connected")
        finally:
            plat.default_gateway = orig
            mgr.disconnect()


class InstallTests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def stage(self, init):
        import subprocess
        dest = tempfile.mkdtemp(dir=TMP)
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", "/usr", "--init", init, "--no-post"],
                           env=dict(os.environ, DESTDIR=dest), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return dest

    def test_icons_system_and_private_copy(self):
        d = self.stage("systemd")
        for base in ("usr/share/icons", "usr/share/vpnman/icons"):
            for rel in ("hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan.svg",
                        "hicolor/symbolic/apps/io.github.smiley_mcsmiles.VPNMan-connected-symbolic.svg"):
                self.assertTrue(os.path.exists(os.path.join(d, base, rel)), base + "/" + rel)
        self.assertTrue(os.path.isdir(os.path.join(d, "etc/vpnman")))
        mode = stat.S_IMODE(os.stat(os.path.join(d, "etc/vpnman")).st_mode)
        self.assertEqual(mode, 0o700)

    def test_strict_umask_still_readable(self):
        import subprocess
        dest = tempfile.mkdtemp(dir=TMP)
        # a root shell with umask 077 (and an executable-bit-less source copy) must not yield an unusable install
        src = tempfile.mkdtemp(dir=TMP)
        subprocess.run(["cp", "-R", os.path.join(self.ROOT, "vpnman"), os.path.join(self.ROOT, "data"),
                        os.path.join(self.ROOT, "install.sh"), src], check=True)
        subprocess.run(["chmod", "-R", "go-rwx", src], check=True)
        r = subprocess.run(["sh", "-c", "umask 077; sh %s/install.sh --prefix /usr --init runit --no-post" % src],
                           env=dict(os.environ, DESTDIR=dest), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        bad = []
        for base, dirs, files in os.walk(os.path.join(dest, "usr")):
            for n in dirs + files:
                p = os.path.join(base, n)
                if not os.path.islink(p) and not os.stat(p).st_mode & stat.S_IROTH:
                    bad.append(p)
        self.assertEqual(bad, [])

    def test_system_links_make_launcher_visible_in_usr_share(self):
        import subprocess
        if os.geteuid() != 0:
            self.skipTest("install.sh needs root")
        prefix, sysshare = tempfile.mkdtemp(dir=TMP), tempfile.mkdtemp(dir=TMP)
        env = dict(os.environ, VPNMAN_SYSTEM_SHARE=sysshare)
        app = "io.github.smiley_mcsmiles.VPNMan"
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post"],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        desktop = os.path.join(sysshare, "applications", app + ".desktop")
        self.assertTrue(os.path.islink(desktop))
        self.assertEqual(os.path.realpath(desktop), os.path.realpath(os.path.join(prefix, "share/applications", app + ".desktop")))
        for rel in ("pixmaps/%s.svg" % app, "icons/hicolor/48x48/apps/%s.png" % app,
                    "icons/hicolor/symbolic/apps/%s-connected-symbolic.svg" % app):
            self.assertTrue(os.path.exists(os.path.join(sysshare, rel)), rel)
        # a package-owned real file must never be replaced
        os.unlink(desktop)
        open(desktop, "w").write("real")
        subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post"],
                       env=env, capture_output=True, text=True)
        self.assertEqual(open(desktop).read(), "real")
        os.unlink(desktop)
        # and --no-system-links really skips them
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post",
                            "--no-system-links"], env=env, capture_output=True, text=True)
        self.assertFalse(os.path.lexists(desktop))
        # uninstall removes our links again
        subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post"],
                       env=env, capture_output=True, text=True)
        self.assertTrue(os.path.islink(desktop))
        subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--uninstall"],
                       env=env, capture_output=True, text=True)
        self.assertFalse(os.path.lexists(desktop))

    def test_check_mode_installs_nothing(self):
        import subprocess
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Checking this machine", r.stdout)

    def test_unknown_option_rejected(self):
        import subprocess
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--bogus"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_icon_fallbacks_installed(self):
        d = self.stage("systemd")
        app = "io.github.smiley_mcsmiles.VPNMan"
        for rel in ("usr/share/pixmaps/%s.svg" % app, "usr/share/icons/hicolor/48x48/apps/%s.png" % app,
                    "usr/share/icons/hicolor/256x256/apps/%s.png" % app):
            self.assertTrue(os.path.exists(os.path.join(d, rel)), rel)
        svg = open(os.path.join(self.ROOT, "data/icons/hicolor/scalable/apps/%s.svg" % app)).read()
        self.assertNotIn("<filter", svg)       # renderer-specific features can make an icon render blank

    def test_icon_doctor(self):
        from vpnman import icons
        self.assertTrue(all(isinstance(m, str) for _ok, m in icons.check()))

    def test_init_files_per_system(self):
        for init, path, needle in (("runit", "etc/sv/vpnmand/run", "exec /usr/bin/vpnmand"),
                                   ("sysv", "etc/init.d/vpnmand", "DAEMON=/usr/bin/vpnmand"),
                                   ("openrc", "etc/init.d/vpnmand", "command=\"/usr/bin/vpnmand\""),
                                   ("systemd", "usr/lib/systemd/system/vpnmand.service", "ExecStart=/usr/bin/vpnmand")):
            d = self.stage(init)
            p = os.path.join(d, path)
            self.assertIn(needle, open(p).read(), init)
            if init != "systemd":
                self.assertTrue(os.access(p, os.X_OK), init)
        self.assertTrue(os.access(os.path.join(self.stage("runit"), "etc/sv/vpnmand/log/run"), os.X_OK))

    def test_sysv_script_is_valid_lsb(self):
        text = open(os.path.join(self.ROOT, "data/init/vpnmand.sysv")).read()
        for key in ("Provides:", "Required-Start:", "Default-Start:", "Short-Description:"):
            self.assertIn(key, text)


class DesktopIntegrationTests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def test_wm_class_matches_launcher(self):
        """Cinnamon/MATE/XFCE (X11) match windows to dock entries via WM_CLASS == StartupWMClass."""
        desktop = open(os.path.join(self.ROOT, "data/io.github.smiley_mcsmiles.VPNMan.desktop")).read()
        wm = [l.split("=", 1)[1].strip() for l in desktop.splitlines() if l.startswith("StartupWMClass=")][0]
        icon = [l.split("=", 1)[1].strip() for l in desktop.splitlines() if l.startswith("Icon=")][0]
        from vpnman import APP_ID
        self.assertEqual(wm, APP_ID)
        self.assertEqual(icon, APP_ID)
        import subprocess
        py = next((p for p in ("python3", "python3.12", "python3.11", "python3.13", "python3.10")
                   if shutil_which(p) and subprocess.run([shutil_which(p), "-c", "import gi;gi.require_version('Gtk','4.0');gi.require_version('Adw','1')"],
                                                          capture_output=True).returncode == 0), None)
        if not py:
            self.skipTest("needs PyGObject with GTK 4 + libadwaita")
        code = ("import sys; sys.path.insert(0, %r)\nfrom gi.repository import GLib\nfrom vpnman.gui import app\n"
                "app.set_process_identity(); print(GLib.get_prgname())" % os.path.abspath(self.ROOT))
        r = subprocess.run([shutil_which(py), "-c", code], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), wm, r.stderr[-500:])


class CreditsTests(unittest.TestCase):
    def test_attribution_and_donation_options(self):
        from vpnman import credits
        self.assertEqual(credits.DEVELOPER_NAME, "WOOSAH")
        self.assertIn("WOOSAH (Lead Architect)", credits.DEVELOPERS)
        self.assertEqual([k for k, _ in credits.DONATION_OPTIONS], ["BTC", "XMR", "CashApp"])
        values = dict(credits.DONATION_OPTIONS)
        self.assertTrue(values["BTC"].startswith("bc1"))
        self.assertEqual(len(values["XMR"]), 95)                 # a Monero main address is 95 characters
        self.assertTrue(values["CashApp"].startswith("$"))
        # the About dialog parses the copyright as markup: a bare "&" would make GTK drop the whole string
        self.assertIn("&amp;", credits.COPYRIGHT_MARKUP)
        self.assertNotIn("&amp;", credits.COPYRIGHT)

    def test_cli_about(self):
        import io
        import contextlib
        from vpnman import cli
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["about"]), 0)
        out = buf.getvalue()
        self.assertIn("WOOSAH (Lead Architect)", out)
        self.assertIn("$SmileyMcSmiles", out)


class GuiTests(unittest.TestCase):
    def test_server_dropdown(self):
        import subprocess
        xvfb = shutil_which("xvfb-run")
        py = next((p for p in ("python3", "python3.12", "python3.11", "python3.13", "python3.10")
                   if shutil_which(p) and subprocess.run([shutil_which(p), "-c", "import gi;gi.require_version('Gtk','4.0');gi.require_version('Adw','1');from gi.repository import Adw"],
                                                          capture_output=True).returncode == 0), None)
        if not xvfb or not py:
            self.skipTest("needs xvfb-run and PyGObject with GTK 4 + libadwaita")
        env = dict(os.environ, GSK_RENDERER="cairo", VPNMAN_SOCKET=TMP + "/none.sock")
        r = subprocess.run([xvfb, "-a", shutil_which(py), os.path.join(os.path.dirname(__file__), "gui_check.py")],
                           capture_output=True, text=True, timeout=90, env=env)
        self.assertIn("GUI OK", r.stdout, r.stdout + r.stderr[-1500:])


class CinnamonTrayTests(unittest.TestCase):
    def test_xapp_helper_against_emulated_panel_applet(self):
        import subprocess
        runner, xvfb = shutil_which("dbus-run-session"), shutil_which("xvfb-run")
        py = None
        for cand in ("python3", "python3.12", "python3.11", "python3.13", "python3.10"):
            exe = shutil_which(cand)
            if exe and subprocess.run([exe, "-c", "import gi;gi.require_version('Gtk','3.0');gi.require_version('XApp','1.0');"
                                       "gi.require_version('Gtk','4.0')"], capture_output=True).returncode != 0:
                # the helper only needs GTK 3 + XApp; the driver needs GTK 4 - probe them separately
                pass
            if exe and subprocess.run([exe, "-c", "import gi;gi.require_version('Gtk','3.0');gi.require_version('XApp','1.0');"
                                       "from gi.repository import XApp"], capture_output=True).returncode == 0:
                py = exe
                break
        if not (runner and xvfb and py):
            self.skipTest("needs dbus-run-session, xvfb-run and PyGObject with GTK 3 + XApp typelibs")
        r = subprocess.run([xvfb, "-a", runner, "--", py, os.path.join(os.path.dirname(__file__), "helper_check.py")],
                           capture_output=True, text=True, timeout=90, env=dict(os.environ, GTK_A11Y="none"))
        self.assertIn("HELPER OK", r.stdout, r.stdout + r.stderr[-1500:])


class TrayTests(unittest.TestCase):
    def test_status_notifier_protocol(self):
        import subprocess
        runner = shutil_which("dbus-run-session")
        py = next((p for p in ("python3", "python3.12", "python3.11", "python3.13", "python3.10")
                   if shutil_which(p) and subprocess.run([shutil_which(p), "-c", "import gi;gi.require_version('Gtk','4.0');from gi.repository import Gtk"],
                                                          capture_output=True).returncode == 0), None)
        if not runner or not py:
            self.skipTest("needs dbus-run-session and PyGObject with GTK 4")
        r = subprocess.run([runner, "--", shutil_which(py), os.path.join(os.path.dirname(__file__), "tray_check.py")],
                           capture_output=True, text=True, timeout=60)
        self.assertIn("TRAY OK", r.stdout, r.stdout + r.stderr)


def shutil_which(name):
    import shutil
    return shutil.which(name)


class IfnameTests(unittest.TestCase):
    def setUp(self):
        from vpnman import platform as plat
        self.plat = plat
        self.saved = (plat.os_family, plat.list_interfaces)
        plat.os_family = lambda: "linux"
        self.mgr = Manager(store=profiles.ProfileStore(TMP + "/ifstore"), settings=settings.Settings(TMP + "/if.json"))

    def tearDown(self):
        self.plat.os_family, self.plat.list_interfaces = self.saved

    def make(self, proto, cfg_text="client\ndev tun\n"):
        p = profiles.new_profile("n", proto, config="c.conf")
        self.mgr.store.save(p, {"c.conf": cfg_text})
        return p

    def test_tun_numbering(self):
        p = self.make("openvpn")
        b = backends.get("openvpn")
        self.plat.list_interfaces = lambda: ["lo", "eth0"]
        self.assertEqual(self.mgr._ifname_for(b, p), "tun0")
        self.plat.list_interfaces = lambda: ["lo", "tun0", "tun1"]
        self.assertEqual(self.mgr._ifname_for(b, p), "tun2")
        self.mgr._reserved_ifnames.add("tun2")
        self.assertEqual(self.mgr._ifname_for(b, p), "tun3")

    def test_tap_and_wireguard(self):
        self.plat.list_interfaces = lambda: ["lo"]
        self.assertEqual(self.mgr._ifname_for(backends.get("openvpn"), self.make("openvpn", "dev tap\n")), "tap0")
        self.assertEqual(self.mgr._ifname_for(backends.get("wireguard"), self.make("wireguard", "[Interface]\n")), "tun0")

    def test_bsd_wireguard_uses_wgN(self):
        self.plat.os_family = lambda: "openbsd"
        self.plat.list_interfaces = lambda: ["lo0", "wg0"]
        self.assertEqual(self.mgr._ifname_for(backends.get("wireguard"), self.make("wireguard")), "wg1")


class StunnelTests(unittest.TestCase):
    def prof(self, **st):
        return profiles.new_profile("s", "openvpn", options={"stunnel": dict({"enabled": True, "host": "h.example.com"}, **st)})

    def test_config_defaults(self):
        from vpnman import stunnel
        conf, warns = stunnel.config(self.prof(), "/pd", "/wd", 12345)
        self.assertIn("accept = 127.0.0.1:12345", conf)
        self.assertIn("connect = h.example.com:443", conf)
        self.assertIn("sni = h.example.com", conf)
        self.assertTrue(warns)   # unverified by default

    def test_config_ca_verification(self):
        from vpnman import stunnel
        conf, warns = stunnel.config(self.prof(ca="srv.pem"), "/pd", "/wd", 1)
        self.assertIn("CAfile = /pd/srv.pem", conf)
        self.assertIn("verifyChain = yes", conf)
        self.assertIn("checkHost = h.example.com", conf)
        self.assertFalse(warns)

    def test_validation(self):
        from vpnman import stunnel
        self.assertTrue(any("host" in p for p in stunnel.validate(self.prof(host="bad host;x"))))
        self.assertTrue(any("CA" in p for p in stunnel.validate(self.prof(verify="ca"))))
        self.assertEqual(stunnel.validate(profiles.new_profile("p", "openvpn")), [])

    def test_endpoint_is_stunnel_server(self):
        b = backends.get("openvpn")
        p = self.prof(port=8443)
        p["options"]["remotes"] = [["vpn.example.net", 1194, "udp"]]
        self.assertEqual(b.endpoints(p), [("h.example.com", 8443, "tcp")])


class SettingsDnsTests(unittest.TestCase):
    def test_coercion(self):
        s = settings.Settings(TMP + "/set.json")
        self.assertEqual(s.set("netlock.allow_lan", "off"), False)
        self.assertEqual(s.set("connection.retry_max", "7"), 7)
        self.assertEqual(s.set("dns.servers", "1.1.1.1, 9.9.9.9"), ["1.1.1.1", "9.9.9.9"])
        with self.assertRaises(KeyError):
            s.set("nope.nothing", 1)
        with self.assertRaises(ValueError):
            s.set("netlock.enabled", "maybe")
        self.assertEqual(settings.Settings(TMP + "/set.json").get("connection.retry_max"), 7)

    def test_resolv_conf_roundtrip(self):
        path = os.environ["VPNMAN_RESOLV_CONF"]
        open(path, "w").write("nameserver 8.8.8.8\n")
        d = dns.DnsManager()
        d.apply(["10.8.0.1"], None)
        self.assertIn("10.8.0.1", open(path).read())
        d.restore()
        self.assertEqual(open(path).read(), "nameserver 8.8.8.8\n")


class EndToEnd(unittest.TestCase):
    """Real daemon + manager + CLI client with a fake `openvpn` executable."""

    @classmethod
    def setUpClass(cls):
        fake = TMP + "/bin/openvpn"
        open(TMP + "/bin/stunnel", "w").write("""#!/bin/sh
cp "$1" "%s/stunnel.conf.copy"
echo "Configuration successful"
trap 'exit 0' TERM
while :; do sleep 0.1; done
""" % TMP)
        os.chmod(TMP + "/bin/stunnel", 0o755)
        open(fake, "w").write("""#!/bin/sh
cp "$2" "%s/last.ovpn"
echo "TUN/TAP device lo opened"
echo "PUSH: dhcp-option DNS 10.8.0.1"
echo "Initialization Sequence Completed"
trap 'exit 0' TERM
while :; do sleep 0.1; done
""" % TMP)
        os.chmod(fake, 0o755)
        s = settings.Settings(TMP + "/etc/settings.json")
        s.set("checks.tunnel", False)
        s.set("connection.reconnect", False)
        cls.mgr = Manager(settings=s)
        cls.server = daemon.Server(os.environ["VPNMAN_SOCKET"], cls.mgr)
        threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
        cls.c = ipc.Client(timeout=15)

    @classmethod
    def tearDownClass(cls):
        cls.mgr.disconnect()
        cls.server.shutdown()
        cls.server.server_close()

    def wait(self, state, secs=10):
        end = time.time() + secs
        while time.time() < end:
            st = self.c.call("status")
            if st["state"] == state:
                return st
            time.sleep(0.1)
        self.fail("never reached %s, last=%s" % (state, self.c.call("status")))

    def test_full_lifecycle(self):
        self.assertEqual(self.c.call("ping"), "pong")
        p = self.c.call("profiles.import", name="lab", text=OVPN.replace("auth-user-pass\n", ""),
                        filename="lab.ovpn", files={})
        self.assertEqual(p["protocol"], "openvpn")
        self.assertNotIn("password", p)
        self.c.call("connect", ident="lab")
        st = self.wait("connected")
        self.assertEqual(st["profile"], "lab")
        self.assertIn("10.8.0.1", open(os.environ["VPNMAN_RESOLV_CONF"]).read())
        logs = self.c.call("logs")
        self.assertTrue(any("Initialization Sequence" in e["msg"] for e in logs["entries"]))
        self.c.call("disconnect")
        self.assertEqual(self.c.call("status")["state"], "disconnected")
        self.assertNotIn("vpnman", open(os.environ["VPNMAN_RESOLV_CONF"]).read())
        self.c.call("profiles.update", ident="lab", changes={"favorite": True})
        self.assertTrue(self.c.call("profiles.get", ident="lab")["favorite"])
        self.c.call("profiles.remove", ident="lab")
        self.assertEqual(self.c.call("profiles.list"), [])

    def test_openvpn_over_stunnel(self):
        opts = {"stunnel": {"enabled": True, "host": "127.0.0.1", "port": 8443, "sni": "cdn.example.com"}}
        self.c.call("profiles.import", name="tls", text=OVPN.replace("auth-user-pass\n", ""),
                    filename="tls.ovpn", options=opts)
        self.c.call("connect", ident="tls")
        self.wait("connected")
        conf = open(TMP + "/stunnel.conf.copy").read()
        self.assertIn("connect = 127.0.0.1:8443", conf)
        self.assertIn("sni = cdn.example.com", conf)
        self.assertIn("client = yes", conf)
        ovpn = open(TMP + "/last.ovpn").read()
        self.assertIn("proto tcp-client", ovpn)
        self.assertRegex(ovpn, r"remote 127\.0\.0\.1 \d+")
        self.assertNotIn("vpn.example.net", ovpn)
        self.assertIn("route 127.0.0.1 255.255.255.255 net_gateway", ovpn)
        self.assertTrue(any(e["level"] == "stunnel" for e in self.c.call("logs")["entries"]))
        self.c.call("disconnect")
        self.c.call("profiles.remove", ident="tls")

    def test_errors(self):
        with self.assertRaises(ipc.RpcError):
            self.c.call("connect", ident="nonexistent")
        with self.assertRaises(ipc.RpcError):
            self.c.call("nonsense")
        with self.assertRaises(ipc.RpcError):
            self.c.call("settings.set", key="bogus", value=1)




class AccessTests(unittest.TestCase):
    def setUp(self):
        from vpnman import access
        self.access = access
        self.s = settings.Settings(TMP + "/acc.json")
        self.s.set("access.mode", "session")
        access._cache.clear()

    def test_root_always(self):
        self.assertTrue(self.access.authorized(0, self.s))

    def test_group_mode_denies_strangers(self):
        self.s.set("access.mode", "group")
        self.assertFalse(self.access.authorized(54321, self.s))

    def test_session_mode(self):
        orig = self.access._active_local_session
        try:
            self.access._active_local_session = lambda uid: True
            self.assertTrue(self.access.authorized(54321, self.s))
            self.access._cache.clear()
            self.access._active_local_session = lambda uid: False
            self.assertFalse(self.access.authorized(54322, self.s))
            self.access._cache.clear()
            self.access._active_local_session = lambda uid: None   # no session manager
            self.assertTrue(self.access.authorized(54323, self.s))
            self.assertFalse(self.access.authorized(33, self.s))   # system accounts never
        finally:
            self.access._active_local_session = orig


if __name__ == "__main__":
    unittest.main()
