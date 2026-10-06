import base64
import os
import sys
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
from vpnman.backends.openvpn import OpenVPN  # noqa: E402

OpenVPN.probe_cache["--dns-updown disable"] = False      # the fake openvpn scripts must never be run as a probe

# Manager.startup() removes stale firewall/bypass rules.  The tests run it, possibly as root on a developer machine
# with a live kill switch or app bypass, so the real cleanups are stubbed out for the whole process.  The tests that
# exercise them use REAL_* with fakes.
from vpnman import split as _split  # noqa: E402
REAL_NETLOCK_CLEANUP, REAL_SPLIT_CLEANUP = netlock.cleanup_all, _split.cleanup
netlock.cleanup_all = lambda: []
_split.cleanup = lambda: None

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
        self.assertTrue(os.path.isfile(desktop) and not os.path.islink(desktop))     # a real copy, not a symlink
        self.assertEqual(open(desktop).read(), open(os.path.join(prefix, "share/applications", app + ".desktop")).read())
        self.assertIn("Exec=%s/bin/vpnman-gtk" % prefix, open(desktop).read())
        for rel in ("pixmaps/%s.svg" % app, "icons/hicolor/48x48/apps/%s.png" % app,
                    "icons/hicolor/symbolic/apps/%s-connected-symbolic.svg" % app):
            self.assertTrue(os.path.exists(os.path.join(sysshare, rel)), rel)
        os.unlink(desktop)
        # and --no-system-links really skips them
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post",
                            "--no-system-links"], env=env, capture_output=True, text=True)
        self.assertFalse(os.path.lexists(desktop))
        # uninstall removes our links again
        subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post"],
                       env=env, capture_output=True, text=True)
        self.assertTrue(os.path.isfile(desktop))
        subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--uninstall"],
                       env=env, capture_output=True, text=True)
        self.assertFalse(os.path.lexists(desktop))

    def test_gui_wrapper_skips_interpreters_without_pygobject(self):
        """A desktop launcher's PATH can put a python3 without PyGObject first; the wrapper must pick one that has it."""
        import subprocess
        prefix = tempfile.mkdtemp(dir=TMP)
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        fake = tempfile.mkdtemp(dir=TMP)
        for n in ("python3", "python3.12"):
            p = os.path.join(fake, n)
            open(p, "w").write("#!/bin/sh\ncase \"$*\" in *gi*) exit 1;; *) echo FAKE >&2; exit 0;; esac\n")
            os.chmod(p, 0o755)
        env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"])
        wrapper = open(os.path.join(prefix, "bin", "vpnman-gtk")).read()
        self.assertIn("NEED_GI", wrapper)
        r = subprocess.run(["sh", "-c", 'sed "s|^exec .*|echo \\$PY|" %s/bin/vpnman-gtk | sh' % prefix],
                           env=env, capture_output=True, text=True)
        chosen = r.stdout.strip()
        self.assertNotEqual(os.path.dirname(chosen), fake, r.stdout + r.stderr)

    def test_upgrade_restarts_service_and_closes_stale_gui(self):
        """The running daemon/GUI keep executing OLD code after an upgrade unless the installer restarts them."""
        text = open(os.path.join(self.ROOT, "install.sh")).read()
        self.assertIn("systemctl restart vpnmand", text)
        self.assertIn("stop_running_gui", text)
        self.assertIn("/etc/init.d/vpnmand restart", text)
        pkg = open(os.path.join(self.ROOT, "package.sh")).read()
        self.assertGreaterEqual(pkg.count("systemctl restart vpnmand"), 2)       # rpm %post and deb postinst
        self.assertGreaterEqual(pkg.count("-m vpnman gui"), 2)

    def test_same_size_upgrade_with_equal_mtime_does_not_keep_old_code(self):
        """Regression: 1.0.0 -> 1.0.2 is the same length and rpm clamps mtimes, so stale __pycache__ kept the old version."""
        import subprocess
        pkg = tempfile.mkdtemp(dir=TMP)
        os.makedirs(pkg + "/p")
        src = pkg + "/p/__init__.py"
        clamp = 1791158400

        def write(v):
            open(src, "w").write('__version__ = "%s"\n' % v)
            os.utime(src, (clamp, clamp))

        def run(extra=()):
            return subprocess.run([sys.executable] + list(extra) + ["-c", "import sys; sys.path.insert(0, %r); import p; print(p.__version__)" % pkg],
                                  capture_output=True, text=True).stdout.strip()
        write("1.0.0")
        self.assertEqual(run(), "1.0.0")
        write("1.0.2")
        self.assertEqual(run(), "1.0.0", "premise: stale bytecode wins")        # the bug being guarded against
        self.assertEqual(run(["-X", "pycache_prefix=" + tempfile.mkdtemp(dir=TMP)]), "1.0.2")   # what the GUI re-exec uses
        import shutil
        shutil.rmtree(pkg + "/p/__pycache__")                                                      # what the packages purge
        self.assertEqual(run(), "1.0.2")

    def test_packages_purge_stale_bytecode_and_do_not_clamp_mtimes(self):
        pkg = open(os.path.join(self.ROOT, "package.sh")).read()
        self.assertIn("%global clamp_mtime_to_source_date_epoch 0", pkg)
        self.assertGreaterEqual(pkg.count("-name __pycache__ -type d -exec rm -rf"), 2)   # rpm %post + deb postinst
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", open(os.path.join(self.ROOT, "install.sh")).read())

    def test_installed_program_never_writes_bytecode_into_the_install_tree(self):
        import subprocess
        if os.geteuid() != 0:
            self.skipTest("install.sh needs root")
        prefix = tempfile.mkdtemp(dir=TMP)
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", prefix, "--init", "none", "--no-post"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        import shutil
        for root, dirs, _f in os.walk(prefix):
            if "__pycache__" in dirs:
                shutil.rmtree(os.path.join(root, "__pycache__"))
        out = subprocess.run([prefix + "/bin/vpnman", "--version"], capture_output=True, text=True)
        self.assertIn("vpnman", out.stdout, out.stderr)
        made = [root for root, dirs, _f in os.walk(prefix) if "__pycache__" in dirs]
        self.assertEqual(made, [], "runtime wrote stale-prone bytecode into the install tree")

    def test_doctor_detects_stale_bytecode(self):
        from vpnman import desktop
        ok, msg = desktop.bytecode_check()[0]
        self.assertTrue(ok, msg)

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


class BackupHistoryTests(unittest.TestCase):
    def _manager(self, name):
        root = tempfile.mkdtemp(dir=TMP)
        from vpnman import profiles as P
        m = Manager(store=P.ProfileStore(root + "/profiles"), settings=settings.Settings(root + "/settings.json"))
        m.history = __import__("vpnman.history", fromlist=["History"]).History(root + "/history.json")
        return m, root

    def _populate(self, m):
        a = m.import_profile("alpha", "client\nremote 192.0.2.1 1194\nca ca.crt\n", files={"ca.crt": "Q0E="},
                             filename="a.ovpn", fields={"username": "bob", "password": "hunter2"})
        b = m.import_profile("beta", "client\nremote 192.0.2.2 1194\n", filename="b.ovpn")
        m.settings.update({"dns": {"servers": ["9.9.9.9"]}})
        return a, b

    @staticmethod
    def _b64(m):
        return m.backup_export()["data"]

    def test_round_trip_merge_and_replace(self):
        src, _ = self._manager("src")
        a, b = self._populate(src)
        data = self._b64(src)
        dst, droot = self._manager("dst")
        res = dst.backup_import(data)                                      # merge into an empty machine
        self.assertEqual((res["added"], res["skipped"], res["settings"]), (2, 0, False))
        got = {p["name"]: p for p in dst.store.list()}
        self.assertEqual(got["alpha"]["username"], "bob")
        self.assertEqual(got["alpha"]["password"], "hunter2")             # credentials travel with the profile
        self.assertTrue(os.path.isfile(os.path.join(droot, "profiles", a["id"], "ca.crt")))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(droot, "profiles", a["id"], "profile.json")).st_mode), 0o600)
        self.assertEqual(dst.settings.get("dns.servers"), [])             # merge keeps the local settings
        again = dst.backup_import(data)
        self.assertEqual((again["added"], again["skipped"]), (0, 2))      # nothing is duplicated or overwritten
        dst.store.update(a["id"], {"notes": "local edit"})
        dst.backup_import(data)
        self.assertEqual(dst.store.find(a["id"])["notes"], "local edit")
        extra = dst.import_profile("only-here", "client\nremote 192.0.2.3 1194\n", filename="c.ovpn")
        rep = dst.backup_import(data, replace=True)
        self.assertEqual((rep["added"], rep["removed"], rep["settings"]), (2, 3, True))
        self.assertEqual(sorted(p["name"] for p in dst.store.list()), ["alpha", "beta"])
        self.assertEqual(dst.settings.get("dns.servers"), ["9.9.9.9"])
        self.assertNotIn(extra["id"], [p["id"] for p in dst.store.list()])

    def test_hostile_archives_are_rejected(self):
        import base64
        import io
        import tarfile
        from vpnman.profiles import ProfileError
        m, _ = self._manager("evil")

        def archive(members, manifest=True):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                if manifest:
                    body = b'{"format": 1, "vpnman": "x", "created": 1, "profiles": 0}'
                    ti = tarfile.TarInfo("vpnman-backup.json")
                    ti.size = len(body)
                    tf.addfile(ti, io.BytesIO(body))
                for ti, body in members:
                    tf.addfile(ti, io.BytesIO(body) if body is not None else None)
            return base64.b64encode(buf.getvalue()).decode()

        def reg(name, body=b"x"):
            ti = tarfile.TarInfo(name)
            ti.size = len(body)
            return ti, body
        link = tarfile.TarInfo("profiles/aaaaaaaaaaaa/profile.json")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/shadow"
        for label, data in (("traversal", archive([reg("../../etc/cron.d/evil")])),
                            ("absolute", archive([reg("/etc/passwd")])),
                            ("deep path", archive([reg("profiles/aaaaaaaaaaaa/sub/dir/file")])),
                            ("bad id", archive([reg("profiles/../../x/profile.json")])),
                            ("symlink", archive([(link, None)])),
                            ("no manifest", archive([], manifest=False)),
                            ("damaged profile", archive([reg("profiles/aaaaaaaaaaaa/profile.json", b"{}")])),
                            ("not a tar", base64.b64encode(b"hello").decode())):
            with self.assertRaises(ProfileError, msg=label):
                m.backup_import(data)
        with self.assertRaises(ProfileError):
            m.backup_import("%%%not base64%%%")
        self.assertEqual(m.store.list(), [])

    def test_history_records_and_trims(self):
        from vpnman.history import History
        h = History(tempfile.mkdtemp(dir=TMP) + "/h.json", limit=3)
        for i in range(5):
            h.add("srv%d" % i, "openvpn", 1000 + i, end=1060 + i, rx=i, tx=2 * i, reason="Disconnected")
        rows = h.list()
        self.assertEqual([r["profile"] for r in rows], ["srv4", "srv3", "srv2"])      # newest first, oldest dropped
        self.assertEqual((rows[0]["duration"], rows[0]["rx"], rows[0]["tx"]), (60, 4, 8))
        self.assertEqual(stat.S_IMODE(os.stat(h.path).st_mode), 0o600)
        h.clear()
        self.assertEqual(h.list(), [])


class NetworkTests(unittest.TestCase):
    def _mgr(self, **net):
        s = settings.Settings(TMP + "/net-%d.json" % id(net))
        s.update({"network": net, "connection": {"autoconnect": "off"}})
        m = Manager(settings=s)
        m.calls = []
        m.connect = lambda ident=None, fastest=False, last=False, persistent=False: m.calls.append(
            ("connect", ident, fastest, last)) or {"profile": "p"}
        m.disconnect = lambda release_lock=True: m.calls.append(("disconnect",))
        return m

    @staticmethod
    def net(nid, dev="wlan0", gw="192.168.1.1"):
        return {"id": nid, "name": nid, "kind": "wifi", "device": dev, "gateway": gw}

    def test_current_network_ids(self):
        from vpnman import network, platform as plat
        real = (plat.default_gateway, network.wifi_ssid, network.gateway_mac, network.is_wireless)
        try:
            plat.default_gateway = lambda: ("192.168.1.1", "wlan0")
            network.is_wireless = lambda d: d.startswith("wl")
            network.wifi_ssid = lambda d: "HomeNet"
            self.assertEqual(network.current()["id"], "HomeNet")
            plat.default_gateway = lambda: ("192.168.1.1", "enp3s0")
            network.gateway_mac = lambda gw, dev=None: "aa:bb:cc:dd:ee:ff"
            cur = network.current()
            self.assertEqual((cur["id"], cur["kind"]), ("wired:aa:bb:cc:dd:ee:ff", "wired"))
            plat.default_gateway = lambda: (None, None)
            self.assertIsNone(network.current()["id"])
        finally:
            plat.default_gateway, network.wifi_ssid, network.gateway_mac, network.is_wireless = real
        self.assertTrue(network.is_trusted("homenet", ["HomeNet"]))
        self.assertFalse(network.is_trusted("Cafe", ["HomeNet"]))
        self.assertFalse(network.is_trusted(None, ["HomeNet"]))

    def test_connects_on_untrusted_and_disconnects_on_trusted_only_if_it_connected(self):
        m = self._mgr(trusted=["Home"], untrusted_action="connect", trusted_action="disconnect", profile="fastest")
        m.network_tick(self.net("Cafe"))
        self.assertEqual(m.calls, [("connect", None, True, False)])
        self.assertTrue(m._net_owned)
        m._status["state"] = "connected"
        m.network_tick(self.net("Cafe"))                      # nothing changed: nothing happens
        self.assertEqual(len(m.calls), 1)
        m.network_tick(self.net("Home"))
        self.assertEqual(m.calls[-1], ("disconnect",))
        # a connection the user made by hand is never dropped by the trusted rule
        m.calls.clear()
        m._net_owned = False
        m._status["state"] = "connected"
        m.network_tick(self.net("Cafe"))
        m.network_tick(self.net("Home"))
        self.assertEqual(m.calls, [])

    def test_rules_are_off_by_default_and_skip_the_first_look_when_autoconnect_is_set(self):
        m = self._mgr()
        m.network_tick(self.net("Cafe"))
        self.assertEqual(m.calls, [])
        m = self._mgr(untrusted_action="connect")
        m.settings.update({"connection": {"autoconnect": "last"}})
        m.network_tick(self.net("Cafe"))                       # boot: the boot-time auto-connect owns this
        self.assertEqual(m.calls, [])
        m.network_tick(self.net("Other", gw="10.0.0.1"))       # a later change is ours
        self.assertEqual(len(m.calls), 1)

    def test_gateway_change_rebuilds_the_bypass_and_routes_but_the_tunnel_does_not_count(self):
        m = self._mgr()
        seen = []
        m._split_sync = lambda: seen.append(("split", m._split_ctx[:2]))
        m._reapply_routes = lambda gw=None: seen.append(("routes", gw))
        m._status.update(state="connected", iface="tun0")
        m._split_ctx = ("192.168.1.1", "eno1", ["192.168.1.1"])
        m.network_tick(self.net("A", dev="eno1"))                        # first look: same gateway as the session
        m.network_tick(self.net("B", dev="wlan0", gw="10.1.1.1"))
        self.assertIn(("split", ("10.1.1.1", "wlan0")), seen)
        self.assertIn(("routes", "10.1.1.1"), seen)
        n = len(seen)
        m.network_tick(self.net("tunnel", dev="tun0", gw="10.8.0.1"))      # def1-less redirect: default is the tunnel
        self.assertEqual(len(seen), n)

    def test_trust_toggle_and_listing(self):
        m = self._mgr()
        m._net = self.net("Home")
        self.assertTrue(m.network_trust(None, True)["trusted"])
        self.assertEqual(m.settings.get("network.trusted"), ["Home"])
        self.assertFalse(m.network_trust("home", False)["trusted"])
        self.assertEqual(m.settings.get("network.trusted"), [])


class BypassAddressTests(unittest.TestCase):
    def test_validation_and_normalisation(self):
        from vpnman.profiles import ProfileError
        s = settings.Settings(TMP + "/routes.json")
        m = Manager(settings=s)
        m._reapply_routes = lambda gw=None: None
        m._refresh_route_hosts = lambda apply=True: False
        out = m.routes_set(["10.0.0.5", "192.168.0.0/16", "Example.COM", {"host": "intranet.example.org"}])
        self.assertEqual([r.get("ip") or r.get("host") for r in out],
                         ["10.0.0.5/32", "192.168.0.0/16", "example.com", "intranet.example.org"])
        for bad in ("not a host", "fe80::/10", "localhost", "-bad-.com"):
            with self.assertRaises(ProfileError):
                m.routes_set([bad])

    def test_nets_include_cached_domain_addresses_and_reach_the_kill_switch(self):
        s = settings.Settings(TMP + "/routes2.json")
        m = Manager(settings=s)
        m._reapply_routes = lambda gw=None: None
        s.update({"routes": [{"ip": "10.0.0.0/8", "action": "out"}, {"host": "files.example.net", "action": "out"},
                             {"ip": "172.16.0.0/12", "action": "in"}]})
        self.assertEqual(m._route_nets(), ["10.0.0.0/8"])                 # a name is only used once it is resolved
        m._host_ips["files.example.net"] = ["203.0.113.7"]
        self.assertEqual(m._route_nets(), ["10.0.0.0/8", "203.0.113.7/32"])
        spec = netlock.Spec.from_settings(s, extra_out=m._route_nets())
        self.assertIn("203.0.113.7/32", netlock.nft_ruleset(spec))        # never blocked by the kill switch


class LeakTestTests(unittest.TestCase):
    def test_dns_decisions(self):
        from vpnman import leaktest as lt
        via = lambda m: (lambda a: m.get(a))                                    # noqa: E731
        ok = lt.dns_check("nameserver 10.8.0.1\n", "tun0", via({"10.8.0.1": "tun0"}))
        self.assertEqual(ok["status"], "ok")
        leak = lt.dns_check("nameserver 192.168.1.1\nnameserver 10.8.0.1\n", "tun0",
                            via({"192.168.1.1": "eth0", "10.8.0.1": "tun0"}))
        self.assertEqual(leak["status"], "fail")
        self.assertIn("192.168.1.1", leak["detail"])
        stub = lt.dns_check("nameserver 127.0.0.53\n", "tun0", via({}), resolved_dns={"tun0": ["10.8.0.1"]})
        self.assertEqual(stub["status"], "ok")
        self.assertEqual(lt.dns_check("nameserver 127.0.0.53\n", "tun0", via({}), resolved_dns={})["status"], "warn")
        self.assertEqual(lt.dns_check("nameserver 1.1.1.1\n", "tun0", via({}), forced=False)["status"], "info")

    def test_ipv6_decisions(self):
        from vpnman import leaktest as lt
        self.assertEqual(lt.ipv6_check("tun0", lambda a: None, lambda: False, False, False)["status"], "ok")
        self.assertEqual(lt.ipv6_check("tun0", lambda a: "tun0", lambda: False, False, False)["status"], "ok")
        self.assertEqual(lt.ipv6_check("tun0", lambda a: "eth0", lambda: True, False, False)["status"], "fail")
        self.assertEqual(lt.ipv6_check("tun0", lambda a: "eth0", lambda: True, True, True)["status"], "ok")
        self.assertEqual(lt.ipv6_check("tun0", lambda a: "eth0", lambda: False, False, False)["status"], "warn")

    def test_kill_switch_decisions(self):
        from vpnman import leaktest as lt
        self.assertEqual(lt.killswitch_check(False, "eth0", lambda: True)["status"], "info")
        self.assertEqual(lt.killswitch_check(True, "eth0", lambda: False)["status"], "ok")
        self.assertEqual(lt.killswitch_check(True, "eth0", lambda: True)["status"], "fail")
        self.assertEqual(lt.killswitch_check(True, None, lambda: True)["status"], "info")

    def test_run_summary_and_rpc(self):
        from vpnman import leaktest as lt
        st = {"state": "disconnected", "iface": None, "netlock": {"engaged": False}}
        res = lt.run(st, settings.Settings(TMP + "/lt.json"), True, resolv_path=TMP + "/none")
        self.assertEqual(res["checks"][0]["status"], "warn")                     # not connected
        self.assertIn(res["summary"], ("ok", "warn"))
        self.assertIn("leaktest", daemon.METHODS)


class ReleaseToolingTests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def _tool(self, *args):
        import subprocess
        return subprocess.run([sys.executable] + list(args), capture_output=True, text=True, cwd=self.ROOT)

    def test_version_is_the_same_everywhere(self):
        r = self._tool("tools/check_version.py")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self._tool("tools/check_version.py", "v0.0.1")                      # a tag that does not match must fail
        self.assertEqual(r.returncode, 1)
        self.assertIn("wrong", r.stderr)

    def test_release_notes_come_from_the_metainfo(self):
        import vpnman
        r = self._tool("tools/release_notes.py", "v" + vpnman.__version__)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## VPNMan %s" % vpnman.__version__, r.stdout)
        self.assertGreaterEqual(r.stdout.count("\n- "), 1)
        self.assertEqual(self._tool("tools/release_notes.py", "9.9.9").returncode, 1)

    def test_workflows_are_valid_and_wired_to_the_tooling(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        for name in ("ci", "release"):
            wf = yaml.safe_load(open(os.path.join(self.ROOT, ".github", "workflows", name + ".yml")))
            self.assertIn("jobs", wf)
        release = open(os.path.join(self.ROOT, ".github", "workflows", "release.yml")).read()
        for needle in ("tools/check_version.py", "tools/release_notes.py", "./package.sh", "gh release create"):
            self.assertIn(needle, release)
        ci = open(os.path.join(self.ROOT, ".github", "workflows", "ci.yml")).read()
        for needle in ("unittest tests.test_vpnman", "tools/gen_completions.py --check", "./package.sh"):
            self.assertIn(needle, ci)


class PackagingTests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def _pkg(self, *args):
        import subprocess
        return subprocess.run(["bash", os.path.join(self.ROOT, "package.sh")] + list(args), capture_output=True, text=True,
                              timeout=300)

    def test_arch_package_builds_on_any_distribution_without_pacman(self):
        """Regression: makepkg aborted package.sh on Fedora ('failed to initialize alpm library')."""
        import tarfile
        r = self._pkg("arch")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        path = [f for f in os.listdir(os.path.join(self.ROOT, "dist")) if f.endswith("-any.pkg.tar.xz")]
        self.assertEqual(len(path), 1)
        with tarfile.open(os.path.join(self.ROOT, "dist", path[0])) as tf:
            names = tf.getnames()
            self.assertEqual(names[:2], [".PKGINFO", ".INSTALL"])
            for want in ("usr/bin/vpnman", "usr/lib/systemd/system/vpnmand.service",
                         "usr/share/bash-completion/completions/vpnman"):
                self.assertIn(want, names)
            self.assertTrue(all(m.uid == 0 and m.gid == 0 for m in tf.getmembers()))
            info = tf.extractfile(".PKGINFO").read().decode()
            self.assertIn("pkgver = %s-1" % __import__("vpnman").__version__, info)
            self.assertIn("depend = python-gobject", info)
            self.assertIn("pre_remove()", tf.extractfile(".INSTALL").read().decode())

    def test_targets_that_need_foreign_tools_are_skipped_not_fatal(self):
        r = self._pkg("alpine")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)             # 3 = skipped
        self.assertTrue(os.path.isfile(os.path.join(self.ROOT, "dist", "recipes", "alpine", "APKBUILD")))
        self.assertEqual(self._pkg("no-such-target").returncode, 2)

    def test_void_template_has_no_duplicate_lines(self):
        self._pkg("recipes")
        text = open(os.path.join(self.ROOT, "dist", "recipes", "void", "template")).read()
        self.assertEqual(text.count("pkgname="), 1)


class CompletionTests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..")

    def test_checked_in_completions_match_the_parser(self):
        import subprocess
        r = subprocess.run([sys.executable, os.path.join(self.ROOT, "tools", "gen_completions.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_bash_completion_offers_commands_choices_and_profile_option_flags(self):
        import subprocess
        bash = shutil_which("bash")
        if not bash:
            self.skipTest("no bash")
        script = os.path.join(self.ROOT, "data", "completions", "vpnman.bash")

        def complete(*words):
            cmd = 'source %s; COMP_WORDS=(%s); COMP_CWORD=%d; _vpnman; printf "%%s\\n" "${COMPREPLY[@]}"' % (
                script, " ".join("'%s'" % w for w in words), len(words) - 1)
            return subprocess.run([bash, "-c", cmd], capture_output=True, text=True).stdout.split()
        self.assertIn("connect", complete("vpnman", "con"))
        self.assertEqual(sorted(complete("vpnman", "lock", "")), ["off", "on", "status"])
        self.assertIn("--stunnel-sni", complete("vpnman", "import", "--stunnel-s"))
        self.assertEqual(sorted(complete("vpnman", "import", "--stunnel-verify", "")), ["ca", "none", "system"])

    def test_installer_ships_the_completions(self):
        import subprocess
        d = tempfile.mkdtemp(dir=TMP)
        r = subprocess.run(["sh", os.path.join(self.ROOT, "install.sh"), "--prefix", "/usr", "--init", "none", "--no-post"],
                           env=dict(os.environ, DESTDIR=d), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for rel in ("usr/share/bash-completion/completions/vpnman", "usr/share/zsh/site-functions/_vpnman",
                    "usr/share/fish/vendor_completions.d/vpnman.fish"):
            self.assertTrue(os.path.isfile(os.path.join(d, rel)), rel)


class OpenVpnDnsUpdownTests(unittest.TestCase):
    def test_builtin_dns_handling_is_disabled_only_when_openvpn_accepts_it(self):
        from vpnman import backends as B
        from vpnman.backends.openvpn import OpenVPN
        ov = OpenVPN()
        saved = dict(OpenVPN.probe_cache)
        try:
            for accepts in (True, False):
                OpenVPN.probe_cache.clear()
                exe = TMP + "/probe-openvpn-%s" % accepts
                with open(exe, "w") as fh:     # exits 0 like OpenVPN 2.7 does for a known option, 1 like 2.6 does
                    fh.write("#!/bin/sh\n%s\n" % ("exit 0" if accepts else 'case "$*" in *dns-updown*) exit 1;; esac; exit 0'))
                os.chmod(exe, 0o755)
                ov.binary = lambda exe=exe: exe
                d = tempfile.mkdtemp(dir=TMP)
                ctx = B.Context({"id": "x", "name": "x", "config": "c.ovpn", "username": "", "options": {}}, d, d, "tun0",
                                settings.Settings(TMP + "/dnsud.json"))
                ctx.state["text"], ctx.state["path"] = "client\nremote 1.2.3.4\n", d + "/runtime.ovpn"
                cmd = ov.connect_cmd(ctx)
                self.assertEqual("--dns-updown" in cmd, accepts, cmd)
                if accepts:
                    self.assertEqual(cmd[cmd.index("--dns-updown") + 1], "disable")
        finally:
            OpenVPN.probe_cache.clear()
            OpenVPN.probe_cache.update(saved)


class WindowsOnlyOptionTests(unittest.TestCase):
    def test_windows_only_options_removed(self):
        from vpnman.backends.openvpn import OpenVPN
        text = "client\nregister-dns\nblock-outside-dns\n  dhcp-renew\n<ca>\nregister-dns\n</ca>\n"
        out, notes = OpenVPN.sanitize_hooks(text, "/tmp")
        lines = out.splitlines()
        self.assertEqual(lines.count("register-dns"), 1)      # only the one inside <ca> survives
        self.assertNotIn("block-outside-dns", lines)
        self.assertNotIn("  dhcp-renew", lines)
        self.assertEqual(len(notes), 3)


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
    def test_schedule_and_bypass_rpc(self):
        st = self.c.call("schedule.set", entries=[{"name": "Work", "days": [0, 1], "start": "08:00", "end": "17:00"}])
        self.assertEqual(st["entries"][0]["summary"], "Mon, Tue · 08:00 → 17:00")
        with self.assertRaises(ipc.RpcError):
            self.c.call("schedule.set", entries=[{"days": [], "start": "08:00"}])
        self.assertEqual(self.c.call("schedule.set", entries=[])["entries"], [])
        sp = self.c.call("split.set", apps=[{"id": "x", "name": "Steam", "match": ["steam"]}])
        self.assertEqual(sp["apps"][0]["match"], ["steam"])
        with self.assertRaises(ipc.RpcError):
            self.c.call("split.set", apps=[{"name": "bad", "match": []}])
        self.c.call("split.set", apps=[])

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
        from vpnman.backends.openvpn import OpenVPN
        OpenVPN.probe_cache["--dns-updown disable"] = False        # never run the fake as a capability probe
        open(fake, "w").write("""#!/bin/sh
echo run >> "%s/invocations"
if grep -q "# FAIL-AUTH" "$2"; then echo "AUTH: Received control message: AUTH_FAILED"; exit 0; fi
cp "$2" "%s/last.ovpn"
echo "TUN/TAP device lo opened"
echo "PUSH: dhcp-option DNS 10.8.0.1"
echo "Initialization Sequence Completed"
trap 'exit 0' TERM
while :; do sleep 0.1; done
""" % (TMP, TMP))
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

    def test_bypass_starts_with_the_tunnel_and_stops_with_it(self):
        calls = []
        real_start, real_stop = self.mgr._split.start, self.mgr._split.stop

        def fake_start(gw, dev, dns=(), mode="exclude"):
            calls.append(("start", dev))
            self.mgr._split.active = True

        def fake_stop():
            calls.append(("stop",))
            self.mgr._split.active = False

        self.mgr._split.start, self.mgr._split.stop = fake_start, fake_stop
        try:
            self.c.call("profiles.import", name="byp", text=OVPN.replace("auth-user-pass\n", ""), filename="byp.ovpn",
                        files={})
            self.c.call("split.set", apps=[{"id": "s", "name": "Steam", "match": ["steam"]}])
            self.c.call("connect", ident="byp")
            self.wait("connected")
            self.assertEqual([c[0] for c in calls][:1], ["start"])
            self.assertTrue(self.c.call("split.status")["active"])
            self.c.call("split.set", apps=[])                      # emptying the list stops it on the live tunnel
            self.assertFalse(self.c.call("split.status")["active"])
            self.c.call("disconnect")
        finally:
            self.mgr._split.start, self.mgr._split.stop = real_start, real_stop
            self.c.call("split.set", apps=[])
            self.c.call("profiles.remove", ident="byp")

    def test_bypassed_apps_stay_online_when_the_vpn_drops_under_the_kill_switch(self):
        from vpnman import platform as plat
        m = self.mgr
        calls, locks = [], []
        real = (m._split.start, m._split.stop, m._lock_apply, plat.default_gateway, m.lock_engaged)

        def fake_start(gw, dev, dns=(), mode="exclude"):
            calls.append(("start", gw, dev))
            m._split.active = True

        def fake_stop():
            calls.append(("stop",))
            m._split.active = False

        m._split.start, m._split.stop = fake_start, fake_stop
        m._lock_apply = lambda: locks.append(m._split.active)
        plat.default_gateway = lambda: ("192.168.1.1", "eno1")
        try:
            m.settings.update({"split": {"enabled": True, "apps": [{"id": "s", "name": "Web", "match": ["epiphany"]}]}})
            m.lock_engaged, m._split_ctx = True, None
            m._split_sync()                                   # no tunnel, kill switch engaged -> apps stay online
            self.assertEqual(calls, [("start", "192.168.1.1", "eno1")])
            self.assertEqual(locks, [True])                   # and the lock was told to let them through
            m._split_sync()
            self.assertEqual(len(calls), 1)                   # idempotent
            m.lock_engaged = False                            # kill switch released, nothing connected
            m._split_sync()
            self.assertEqual(calls[-1], ("stop",))
            self.assertEqual(locks, [True])                   # lock already gone: nothing to update
            m.lock_engaged = True
            m._split_sync()
            self.assertEqual(locks, [True, True])
            m.settings.update({"split": {"apps": []}})        # list emptied while locked: stop and close the exemption
            m._split_sync()
            self.assertEqual((calls[-1], locks[-1]), (("stop",), False))
        finally:
            m._split.start, m._split.stop, m._lock_apply, plat.default_gateway, m.lock_engaged = real
            m._split.active, m._split_cur = False, None
            m.settings.update({"split": {"apps": []}})

    DEBIAN_OVPN = """verb 4
client
tls-client
script-security 2
remote-cert-tls server
dev tun
nobind
remote test.example 1196 udp
pull-filter ignore "dhcp-option DNS"
dhcp-option DNS 203.0.113.53
dhcp-option DNS 203.0.113.54
persist-key
persist-tun
redirect-gateway def1 ipv6
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
<ca>
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
</ca>
"""

    def _openvpn_procs(self):
        n = 0
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    cmd = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ")
                except OSError:
                    continue
                if b"bin/openvpn --config" in cmd and b"sleep" not in cmd:
                    n += 1
        return n

    def test_switching_servers_never_leaves_two_tunnels(self):
        base = self._openvpn_procs()                                          # processes of other tests/runs
        a = self.c.call("profiles.import", name="swA", text="client\nremote 192.0.2.1 1194\n", filename="a.ovpn", files={})
        b = self.c.call("profiles.import", name="swB", text="client\nremote 192.0.2.2 1194\n", filename="b.ovpn", files={})
        try:
            self.c.call("connect", ident=a["id"])
            self.wait("connected")
            errs = []

            def go(ident):
                try:
                    ipc.Client(timeout=40).call("connect", ident=ident)      # two clicks racing each other
                except Exception as e:  # noqa: BLE001
                    errs.append(e)
            ts = [threading.Thread(target=go, args=(b["id"],)) for _ in range(2)]
            for t in ts:
                t.start()
            time.sleep(0.05)
            self.assertEqual(self.c.call("status")["profile"], "swB")         # the UI sees the new server at once
            for t in ts:
                t.join()
            self.assertEqual(errs, [])
            st = self.wait("connected")
            self.assertEqual(st["profile"], "swB")
            time.sleep(0.5)
            self.assertEqual(self._openvpn_procs() - base, 1)
            self.c.call("connect", ident=a["id"])                              # and straight back again
            st = self.wait("connected")
            self.assertEqual((st["profile"], self._openvpn_procs() - base), ("swA", 1))
        finally:
            self.c.call("disconnect")
            for ident in (a["id"], b["id"]):
                self.c.call("profiles.remove", ident=ident)
        self.assertEqual(self._openvpn_procs(), base)

    def test_remove_many_drops_a_live_connection_and_reports_failures(self):
        a = self.c.call("profiles.import", name="rmA", text="client\nremote 192.0.2.1 1194\n", filename="a.ovpn", files={})
        b = self.c.call("profiles.import", name="rmB", text="client\nremote 192.0.2.2 1194\n", filename="b.ovpn", files={})
        self.c.call("connect", ident=a["id"])
        self.wait("connected")
        res = self.c.call("profiles.remove_many", ids=[a["id"], "nope-nothing", b["id"]])
        self.assertEqual(sorted(res["removed"]), ["rmA", "rmB"])
        self.assertEqual([f["id"] for f in res["failed"]], ["nope-nothing"])
        self.assertEqual(self.c.call("status")["state"], "disconnected")       # the removed profile's tunnel is gone
        self.assertEqual(self.c.call("profiles.list"), [])

    def test_debian_style_config_runs_without_its_missing_scripts(self):
        """up/down update-resolv-conf exist only on Debian/Ubuntu; a missing 'up' script aborts OpenVPN."""
        p = self.c.call("profiles.import", name="deb", text=self.DEBIAN_OVPN, filename="deb.ovpn", files={})
        try:
            self.c.call("connect", ident=p["id"])
            self.wait("connected")
            runtime = open(TMP + "/last.ovpn").read()
            self.assertNotIn("update-resolv-conf", runtime)
            self.assertIn("pull-filter ignore", runtime)                      # everything else is kept
            logs = " ".join(e["msg"] for e in self.c.call("logs")["entries"])
            self.assertIn("Ignoring 'up /etc/openvpn/update-resolv-conf'", logs)
            # the config's own DNS servers are used, not the ones the server pushes (which the config filters out)
            resolv = open(os.environ["VPNMAN_RESOLV_CONF"]).read()
            self.assertIn("203.0.113.53", resolv)
            self.assertNotIn("10.8.0.1", resolv)
        finally:
            self.c.call("disconnect")
            self.c.call("profiles.remove", ident=p["id"])

    def test_auth_failure_stops_instead_of_retrying(self):
        """AUTH_FAILED is not transient: retrying hammers the server with the same wrong credentials."""
        inv = TMP + "/invocations"
        p = self.c.call("profiles.import", name="badauth", text="client\nremote 192.0.2.9 1194\n# FAIL-AUTH\n",
                        filename="b.ovpn", files={})
        self.c.call("settings.update", tree={"connection": {"reconnect": True, "retry_delay": 1}})
        try:
            before = open(inv).read().count("run") if os.path.exists(inv) else 0
            self.c.call("connect", ident=p["id"])
            st = self.wait("error")
            self.assertIn("Authentication failed", st["message"])
            time.sleep(2.5)                                       # long enough for a retry to have happened
            self.assertEqual(self.c.call("status")["state"], "error")
            self.assertEqual(open(inv).read().count("run") - before, 1)
            logs = " ".join(e["msg"] for e in self.c.call("logs")["entries"])
            self.assertNotIn("Reconnecting in", logs.split("Authentication failed")[-1])
        finally:
            self.c.call("settings.update", tree={"connection": {"reconnect": False, "retry_delay": 5}})
            self.c.call("disconnect")
            self.c.call("profiles.remove", ident=p["id"])

    def test_concurrent_imports_get_distinct_names(self):
        names, errs = [], []

        def imp():
            try:
                names.append(ipc.Client(timeout=20).call("profiles.import", name="twin", text="client\nremote 192.0.2.5 1194\n",
                                                          filename="t.ovpn", files={})["name"])
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=imp) for _ in range(6)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        try:
            self.assertEqual(errs, [])
            self.assertEqual(len(set(names)), 6, names)
        finally:
            for p in self.c.call("profiles.list"):
                if p["name"].startswith("twin"):
                    self.c.call("profiles.remove", ident=p["id"])

    def test_session_is_recorded_in_the_history(self):
        p = self.c.call("profiles.import", name="hist", text="client\nremote 192.0.2.1 1194\n", filename="h.ovpn", files={})
        try:
            self.c.call("history.clear")
            self.c.call("connect", ident=p["id"])
            self.wait("connected")
            time.sleep(1.2)
            self.c.call("disconnect")
            rows = self.c.call("history", limit=5)
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["profile"], rows[0]["reason"]), ("hist", "Disconnected"))
            self.assertGreaterEqual(rows[0]["duration"], 1)
        finally:
            self.c.call("history.clear")
            self.c.call("profiles.remove", ident=p["id"])

    def test_backup_rpc_round_trip(self):
        p = self.c.call("profiles.import", name="bk", text="client\nremote 192.0.2.1 1194\n", filename="k.ovpn", files={})
        data = self.c.call("backup.export")["data"]
        self.c.call("profiles.remove", ident=p["id"])
        res = self.c.call("backup.import", data=data)
        self.assertEqual(res["added"] >= 1, True)
        self.assertIn("bk", [x["name"] for x in self.c.call("profiles.list")])
        self.c.call("profiles.remove", ident=self.c.call("profiles.get", ident="bk")["id"])

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




class ScheduleTests(unittest.TestCase):
    @staticmethod
    def at(wday, h, m):
        return time.struct_time((2026, 1, 1, h, m, 0, wday, 1, -1))

    def test_windows_including_overnight(self):
        from vpnman import schedule as sc
        e = sc.clean({"days": [0, 1, 2, 3, 4], "start": "22:00", "end": "06:00"})
        for args, want in (((0, 23, 0), True), ((1, 5, 59), True), ((1, 6, 0), False), ((5, 1, 0), True),
                           ((5, 23, 0), False), ((6, 1, 0), False), ((0, 21, 59), False)):
            self.assertEqual(sc.is_active(e, self.at(*args)), want, args)
        self.assertEqual(sc.next_start(e, self.at(5, 23, 0)), 2820)         # Saturday 23:00 -> Monday 22:00
        self.assertFalse(sc.is_active(dict(e, enabled=False), self.at(0, 23, 0)))

    def test_validation_and_description(self):
        from vpnman import schedule as sc
        for bad in ({"days": [], "start": "08:00"}, {"days": [7], "start": "08:00"}, {"days": [1], "start": "8am"},
                    {"days": [1], "start": "08:00", "end": "25:00"}):
            with self.assertRaises(ValueError):
                sc.clean(bad)
        e = sc.clean({"days": [5, 6], "start": "9:05"})
        self.assertEqual((e["start"], e["end"]), ("09:05", ""))
        self.assertEqual(sc.describe(e), "Weekends · at 09:05")

    def test_scheduler_acts_on_edges_and_respects_manual_disconnect(self):
        from vpnman import schedule as sc

        class FakeMgr:
            def __init__(self):
                self.settings = settings.Settings(TMP + "/sched.json")
                self.state, self.calls = "disconnected", []
                self.log = type("L", (), {"add": lambda *_: None})()

            def status(self):
                return {"state": self.state}

            def connect(self, ident=None, fastest=False, last=False, persistent=False):
                self.calls.append(("connect", ident, fastest, last))
                self.state = "connected"
                return {"profile": "alpha"}

            def disconnect(self):
                self.calls.append(("disconnect",))
                self.state = "disconnected"

        m = FakeMgr()
        e = sc.clean({"id": "w", "days": [0], "start": "08:00", "end": "09:00", "profile": "fastest"})
        m.settings.update({"schedule": {"enabled": True, "entries": [e]}})
        s = sc.Scheduler(m)
        s.tick(self.at(0, 7, 59))
        self.assertEqual(m.calls, [])
        s.tick(self.at(0, 8, 0))
        self.assertEqual(m.calls, [("connect", "fastest", True, False)])
        s.tick(self.at(0, 8, 30))                                  # inside the window: nothing new
        self.assertEqual(len(m.calls), 1)
        s.tick(self.at(0, 9, 0))                                   # window closed: scheduler-made connection ends
        self.assertEqual(m.calls[-1], ("disconnect",))
        # a connection the user made by hand is never cut off
        m.calls.clear()
        m.state = "connected"
        s.tick(self.at(0, 7, 59))
        s.tick(self.at(0, 8, 0))
        s.tick(self.at(0, 9, 0))
        self.assertEqual(m.calls, [])
        # a manual disconnect inside the window sticks until the next window
        m.state = "disconnected"
        s.tick(self.at(0, 8, 0))
        self.assertEqual(m.calls[-1][0], "connect")
        m.state = "disconnected"
        s.tick(self.at(0, 8, 10))
        s.tick(self.at(0, 8, 20))
        self.assertEqual(len([c for c in m.calls if c[0] == "connect"]), 1)
        m.settings.set("schedule.enabled", False)
        s.tick(self.at(1, 8, 0))
        self.assertEqual(len([c for c in m.calls if c[0] == "connect"]), 1)


class SplitTests(unittest.TestCase):
    def test_ruleset_marks_cgroup_and_routes_around_the_tunnel(self):
        from vpnman import split
        text = split.ruleset(["192.168.1.1", "2001:db8::1"])
        self.assertIn('socket cgroupv2 level 1 "vpnman-bypass" meta mark set 0x5652', text)
        self.assertIn("dnat ip to 192.168.1.1", text)
        self.assertNotIn("2001:db8", text)
        self.assertIn("masquerade", text)
        cmds = split.route_commands("192.168.1.1", "eth0", ["192.168.1.0/24"])
        self.assertIn(["route", "add", "default", "via", "192.168.1.1", "dev", "eth0", "table", "5652"], cmds)
        self.assertEqual(cmds[-1][:4], ["rule", "add", "fwmark", "0x5652"])

    def test_include_mode_marks_everything_except_the_listed_apps(self):
        from vpnman import split
        inc = split.ruleset(["192.168.1.1"], mode="include")
        lines = [l.strip() for l in inc.splitlines()]
        mark = lines.index("meta mark 0 meta mark set 0x5652 ct mark set 0x5652")
        unmark = lines.index('socket cgroupv2 level 1 "vpnman-tunnel" meta mark set 0 ct mark set 0')
        self.assertLess(mark, unmark)                       # mark all, then take the listed apps back out
        self.assertIn("meta mark 0x5652 udp dport 53", inc)  # DNS redirect follows the mark, not the cgroup
        self.assertNotIn('"vpnman-bypass"', inc)
        self.assertNotIn("vpnman-tunnel", split.ruleset(["192.168.1.1"]))
        self.assertEqual(split.cgroup_name("include"), "vpnman-tunnel")
        # packets that already carry a mark (WireGuard's own socket) must be left alone: only mark 0 is rewritten
        self.assertEqual(inc.count("meta mark set 0x5652"), 1)

    def test_split_mode_is_validated_and_restarts_the_bypass(self):
        from vpnman.profiles import ProfileError
        m = Manager(settings=settings.Settings(TMP + "/mode.json"))
        m.split_changed = lambda: None
        self.assertEqual(m.split_set(mode="include")["mode"], "include")
        with self.assertRaises(ProfileError):
            m.split_set(mode="sideways")
        calls = []
        from vpnman import platform as plat
        real = (m._split.start, m._split.stop, plat.default_gateway, m._lock_apply)
        m._split.start = lambda gw, dev, dns=(), mode="exclude": (calls.append(mode), setattr(m._split, "active", True))
        m._split.stop = lambda: (calls.append("stop"), setattr(m._split, "active", False))
        m._lock_apply = lambda: None
        m.settings.update({"split": {"apps": [{"id": "a", "name": "A", "match": ["a"]}]}})
        m.lock_engaged, m._split_ctx = True, None
        plat.default_gateway = lambda: ("192.168.1.1", "eno1")
        try:
            m._split_sync()
            m.settings.update({"split": {"mode": "exclude"}})
            m._split_sync()                                     # same gateway, new mode: rebuilt, not left as it was
            m._split_sync()                                     # and now idempotent again
            self.assertEqual(calls, ["include", "exclude"])
        finally:
            m._split.start, m._split.stop, plat.default_gateway, m._lock_apply = real
            m._split.active = False

    def test_kill_switch_lets_bypassed_traffic_through_only_when_asked(self):
        plain = netlock.nft_ruleset(netlock.Spec(endpoints=["1.2.3.4"], ifaces=["tun0"]))
        marked = netlock.nft_ruleset(netlock.Spec(endpoints=["1.2.3.4"], ifaces=["tun0"], split_mark=0x5652))
        self.assertNotIn("0x5652", plain)
        self.assertIn("meta mark 0x5652 accept", marked)
        self.assertIn("ct mark 0x5652 accept", marked)
        cmds = netlock.ipt_commands(netlock.Spec(ifaces=["tun0"], split_mark=0x5652))
        self.assertIn(["-A", "VPNMAN_OUT", "-m", "mark", "--mark", "0x5652", "-j", "ACCEPT"], cmds)

    def test_rule_is_moved_ahead_of_wg_quick_rules(self):
        from vpnman import split
        bad = ("0:\tfrom all lookup local\n78:\tfrom all lookup main suppress_prefixlength 0\n"
               "79:\tnot from all fwmark 0xca6c lookup 51820\n80:\tfrom all fwmark 0x5652 lookup 5652\n"
               "32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n")
        self.assertEqual(split.rule_fix(bad), (80, 77))               # the exact layout seen on a real Fedora box
        good = bad.replace("78:", "32764:").replace("79:", "32765:")
        self.assertIsNone(split.rule_fix(good))
        self.assertIsNone(split.rule_fix("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n"))
        self.assertIsNone(split.rule_fix("0:\tfrom all lookup local\n1:\tfrom all lookup 9\n"
                                         "2:\tfrom all fwmark 0x5652 lookup 5652\n"))     # no room below: leave it

    def _fake_system(self):
        """Patch platform helpers so SplitTunnel can run unprivileged; returns (recorded commands, undo)."""
        from vpnman import platform as plat, split
        cmds, cg = [], tempfile.mkdtemp(dir=TMP)
        real = (plat.run, plat.which, split.supported, split.cgroup_root)
        state = {"nft_ok": True, "rules": 1}

        def run(cmd, **kw):
            cmds.append(" ".join(cmd[1:]) if cmd[0].startswith("/") else " ".join(cmd))
            joined = " ".join(cmd)
            if "-f -" in joined:
                return (0, "") if state["nft_ok"] else (1, "boom")
            if "rule del" in joined:                          # one rule exists, then none: the cleanup loop must stop
                state["rules"] -= 1
                return (0, "") if state["rules"] >= 0 else (2, "")
            return 0, ""
        plat.run, plat.which = run, lambda n: "/usr/sbin/" + n
        split.supported, split.cgroup_root = (lambda: (True, "")), (lambda: cg)

        def undo():
            plat.run, plat.which, split.supported, split.cgroup_root = real
        return cmds, cg, state, undo

    def test_bypass_removes_everything_it_created(self):
        from vpnman import split
        cmds, cg, state, undo = self._fake_system()
        try:
            st = split.SplitTunnel(lambda: [], proc=tempfile.mkdtemp(dir=TMP))
            st.start("192.168.1.1", "eno1", ["192.168.1.1"])
            self.assertTrue(os.path.isdir(os.path.join(cg, "vpnman-bypass")))
            st.stop()
            joined = "\n".join(cmds)
            self.assertIn("delete table inet vpnman_split", joined)
            self.assertIn("rule del fwmark 0x5652 lookup 5652", joined)
            self.assertIn("route flush table 5652", joined)
            self.assertFalse(os.path.exists(os.path.join(cg, "vpnman-bypass")))
            self.assertFalse(st.active)
        finally:
            undo()

    def test_failed_start_leaves_nothing_behind(self):
        from vpnman import split
        cmds, cg, state, undo = self._fake_system()
        state["nft_ok"] = False
        try:
            st = split.SplitTunnel(lambda: [], proc=tempfile.mkdtemp(dir=TMP))
            with self.assertRaises(RuntimeError):
                st.start("192.168.1.1", "eno1")
            self.assertFalse(os.path.exists(os.path.join(cg, "vpnman-bypass")))
            self.assertFalse(st.active)
        finally:
            undo()

    def test_cleanup_all_and_stale_lock_removed_at_startup(self):
        calls = []

        class Fake:
            def __init__(self, name, usable, active):
                self.name, self._u, self._a = name, usable, active
                outer = self

                class C:
                    @staticmethod
                    def usable():
                        return outer._u

                    def __new__(cls):
                        return outer
                self.cls = C

            def active(self):
                return self._a

            def remove(self):
                calls.append(self.name)
        real = dict(netlock.BACKENDS)
        netlock.BACKENDS.clear()
        for f in (Fake("nftables", True, True), Fake("iptables", True, False), Fake("pf", False, True)):
            netlock.BACKENDS[f.name] = f.cls
        try:
            self.assertEqual(REAL_NETLOCK_CLEANUP(), ["nftables"])    # only usable AND active backends are touched
            self.assertEqual(calls, ["nftables"])
            from vpnman import split
            s = settings.Settings(TMP + "/stale.json")
            m = Manager(settings=s)
            stub_split, stub_net = split.cleanup, netlock.cleanup_all
            split.cleanup = lambda: calls.append("split.cleanup")
            netlock.cleanup_all = lambda: (calls.append("nftables"), ["nftables"])[1]
            try:
                m.startup()                                           # lock not wanted -> stale one is removed
            finally:
                split.cleanup, netlock.cleanup_all = stub_split, stub_net
                m.scheduler.stop()
                m._net_stop.set()
            self.assertEqual(calls.count("nftables"), 2)
            self.assertIn("split.cleanup", calls)
        finally:
            netlock.BACKENDS.clear()
            netlock.BACKENDS.update(real)

    def _fake_proc(self, procs):
        root = tempfile.mkdtemp(dir=TMP)
        for pid, (comm, ppid, argv) in procs.items():
            d = os.path.join(root, str(pid))
            os.makedirs(d)
            open(os.path.join(d, "stat"), "w").write("%d (%s) S %d 1 1 0" % (pid, comm, ppid))
            open(os.path.join(d, "cmdline"), "wb").write(b"\0".join(a.encode() for a in argv) + b"\0")
            open(os.path.join(d, "cgroup"), "w").write("0::/user.slice/app-%d.scope\n" % pid)
        return root

    def test_matching_finds_programs_and_their_children(self):
        from vpnman import split
        root = self._fake_proc({
            100: ("steam", 1, ["/usr/bin/steam"]),
            101: ("steamwebhelper", 100, ["steamwebhelper"]),
            102: ("game", 101, ["/games/game"]),
            200: ("bash", 1, ["/bin/bash", "/usr/bin/firefox"]),          # launcher script
            201: ("Web Content", 200, ["/usr/lib/firefox/firefox", "-contentproc"]),
            300: ("vim", 1, ["vim", "firefox.txt"]),                      # an argument is not a program
            400: ("sleep", 1, ["sleep", "5"]),
        })
        self.assertEqual(split.matching_pids({"steam"}, root), {100, 101, 102})
        self.assertEqual(split.matching_pids({"firefox"}, root), {200, 201})
        self.assertEqual(split.matching_pids({"nothing"}, root), set())
        self.assertEqual(split.matching_pids(set(), root), set())

    def test_scan_moves_matches_into_the_cgroup_and_releases_them(self):
        from vpnman import split
        root = self._fake_proc({100: ("steam", 1, ["steam"]), 101: ("kid", 100, ["kid"]), 5: ("sshd", 1, ["sshd"])})
        cg = tempfile.mkdtemp(dir=TMP)
        os.makedirs(os.path.join(cg, "vpnman-bypass"))
        st = split.SplitTunnel(lambda: ["steam"], proc=root, root=cg)
        self.assertEqual(sorted(st.scan_once()), [100, 101])
        self.assertEqual(st.moved[100], "/user.slice/app-100.scope")
        self.assertNotIn(5, st.moved)
        self.assertEqual(st.scan_once() and 0, 0)
        st._release()                                    # everything goes back where it came from (fake fs: no-op moves)
        self.assertEqual(st.moved, {})
        self.assertEqual(split.names_from_settings({"apps": [{"match": ["a", "b"]}, {"match": ["b", "c"]}]}), ["a", "b", "c"])


class AppsTests(unittest.TestCase):
    def test_exec_names(self):
        from vpnman import apps
        self.assertEqual(apps.exec_names("env GDK_BACKEND=x /usr/bin/firefox %u", "org.mozilla.firefox.desktop"),
                         ["firefox", "org.mozilla.firefox"])
        self.assertIn("com.valvesoftware.Steam", apps.exec_names(
            "flatpak run --branch=stable --arch=x86_64 com.valvesoftware.Steam @@u %U @@", "com.valvesoftware.Steam.desktop"))
        self.assertEqual(apps.exec_names("snap run vlc", "vlc_vlc.desktop")[0], "vlc")

    def test_discover_reads_launchers_and_skips_hidden_ones(self):
        from vpnman import apps
        d = tempfile.mkdtemp(dir=TMP)
        os.makedirs(os.path.join(d, "applications"))
        def w(name, body):
            open(os.path.join(d, "applications", name), "w").write("[Desktop Entry]\nType=Application\n" + body)
        w("steam.desktop", "Name=Steam\nExec=/usr/bin/steam %U\nIcon=steam\n")
        w("hidden.desktop", "Name=Hidden\nExec=hidden\nNoDisplay=true\n")
        w("broken.desktop", "Name=NoExec\n")
        found = apps.discover([d])
        names = [a["name"] for a in found]
        self.assertIn("Steam", names)
        self.assertNotIn("Hidden", names)
        self.assertNotIn("NoExec", names)
        steam = [a for a in found if a["name"] == "Steam"][0]
        self.assertEqual(steam["match"], ["steam"])
        self.assertEqual(apps.custom_entry("/usr/bin/firefox")["match"], ["firefox"])
        with self.assertRaises(ValueError):
            apps.custom_entry("  ")

    def test_cli_day_parsing(self):
        from vpnman import cli
        self.assertEqual(cli._parse_days("weekdays"), [0, 1, 2, 3, 4])
        self.assertEqual(cli._parse_days("mon-wed,sat"), [0, 1, 2, 5])
        self.assertEqual(cli._parse_days("fri-mon"), [0, 4, 5, 6])
        self.assertEqual(cli._parse_days(None), list(range(7)))


class ServersGuiTests(unittest.TestCase):
    @staticmethod
    def _py():
        import subprocess
        return next((p for p in ("python3", "python3.12", "python3.11", "python3.13", "python3.10")
                     if shutil_which(p) and subprocess.run([shutil_which(p), "-c", "import gi;gi.require_version('Gtk','4.0');gi.require_version('Adw','1');from gi.repository import Adw"],
                                                           capture_output=True).returncode == 0), None)

    def _run(self, script, need=()):
        import subprocess
        xvfb, runner, py = shutil_which("xvfb-run"), shutil_which("dbus-run-session"), self._py()
        if not xvfb or not py or not runner or any(not shutil_which(n) for n in need):
            self.skipTest("needs xvfb-run, dbus-run-session, PyGObject (GTK 4 + libadwaita) %s" % " ".join(need))
        # the GUI saves per-user preferences (sort order, ...): keep tests out of the real ~/.config
        env = dict(os.environ, GSK_RENDERER="cairo", GTK_A11Y="none", VPNMAN_SOCKET=TMP + "/none.sock",
                   XDG_CONFIG_HOME=TMP + "/xdg-config")
        return subprocess.run([xvfb, "-a", "-s", "-screen 0 1000x800x24", runner, "--", shutil_which(py),
                               os.path.join(os.path.dirname(__file__), script)],
                              capture_output=True, text=True, timeout=120, env=env)

    def test_multiselect_bulk_remove_and_server_switching(self):
        r = self._run("servers_check.py")
        self.assertIn("SERVERS-OK", r.stdout, r.stdout + r.stderr[-1500:])

    def test_new_dialogs_pages_groups_and_sorting(self):
        r = self._run("features_check.py")
        self.assertIn("FEATURES-OK", r.stdout, r.stdout + r.stderr[-2000:])

    def test_ctrl_and_shift_click_selection(self):
        r = self._run("select_check.py", need=("xdotool",))
        self.assertIn("SELECT-OK", r.stdout, r.stdout + r.stderr[-1500:])


class PagesGuiTests(unittest.TestCase):
    def test_schedule_and_apps_pages(self):
        import subprocess
        xvfb, runner = shutil_which("xvfb-run"), shutil_which("dbus-run-session")
        py = next((p for p in ("python3", "python3.12", "python3.11", "python3.13", "python3.10")
                   if shutil_which(p) and subprocess.run([shutil_which(p), "-c", "import gi;gi.require_version('Gtk','4.0');gi.require_version('Adw','1');from gi.repository import Adw"],
                                                          capture_output=True).returncode == 0), None)
        if not xvfb or not py or not runner:
            self.skipTest("needs xvfb-run, dbus-run-session and PyGObject with GTK 4 + libadwaita")
        env = dict(os.environ, GSK_RENDERER="cairo", GTK_A11Y="none", VPNMAN_SOCKET=TMP + "/none.sock",
                   XDG_CONFIG_HOME=TMP + "/xdg-config")
        r = subprocess.run([xvfb, "-a", runner, "--", shutil_which(py), os.path.join(os.path.dirname(__file__), "pages_check.py")],
                           capture_output=True, text=True, timeout=90, env=env)
        self.assertIn("PAGES-OK", r.stdout, r.stdout + r.stderr[-1500:])


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
