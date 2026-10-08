"""The network proxy in the app: the "Network Proxy" switch (Connection page and Preferences) and its settings in
Preferences → Connection, laid out like GNOME Settings' Network Proxy page.

The proxy itself is run by the daemon (see proxysvc: all TCP and DNS of this computer go through it - after the VPN
while one is connected); the app only shows and changes its settings over the "netproxy.*" calls.
"""

import re

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from . import sysproxy  # noqa: E402

KINDS = (("http", "HTTP Proxy"), ("https", "HTTPS Proxy"), ("ftp", "FTP Proxy"), ("socks", "SOCKS Host"))


def parse_url(text):
    """What was typed into a URL box -> (user, password or None, host, port or None).  'user:pass@host:3128',
    'http://host', '[2001:db8::1]:1080'..."""
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", (text or "").strip())
    user, password = "", None
    if "@" in t.split("/", 1)[0]:
        cred, t = t.split("@", 1)
        user, sep, pw = cred.partition(":")
        password = pw if sep else None
    return user, password, sysproxy.clean_host(t), sysproxy.port_in(t)


def show_url(entry):
    """The URL box text for a stored entry: 'user@host' or 'host' (the password is never shown)."""
    host = entry.get("host") or ""
    if ":" in host:
        host = "[%s]" % host
    return ("%s@%s" % (entry["user"], host)) if entry.get("user") and host else host


def summary(st):
    if not st:
        return "Unknown"
    servers = ["%s %s:%s" % (k.upper(), st[k]["host"], st[k]["port"]) for k, _t in KINDS if (st.get(k) or {}).get("host")]
    if not st.get("enabled"):
        return "Off" + (" – " + ", ".join(servers) if servers else "")
    if st.get("blocked"):
        return "Blocking all traffic until the proxy works again: %s" % (st.get("error") or "not running")
    if st.get("error") and not st.get("active"):
        return "Not running: %s" % st["error"]
    text = "All traffic goes through " + (", ".join(servers) or "–")
    return text + (" (%s)" % st["error"] if st.get("error") else "")


class NetProxyModel:
    """The daemon's network proxy settings, shared by every widget that shows them."""

    def __init__(self, rpc):
        self.rpc = rpc
        self.st = None
        self.listeners = []

    def update(self, st):
        if st is not None and st != self.st:
            self.st = st
            for fn in list(self.listeners):
                fn(st)

    def refresh(self):
        self.rpc("netproxy.status", self.update, None)

    def listen(self, fn):
        self.listeners.append(fn)
        if self.st is not None:
            fn(self.st)

    def unlisten(self, fn):
        if fn in self.listeners:
            self.listeners.remove(fn)

    def set(self, fail=None, **kw):
        self.rpc("netproxy.set", self.update, fail or (lambda *a: None), **kw)


class NetworkProxySwitch:
    """The on/off switch (``.row``, an Adw.SwitchRow - a final class, hence a wrapper) with the state underneath."""

    def __init__(self, model, icon=True, fail=None):
        self.row = Adw.SwitchRow(title="Network Proxy", subtitle="Send all traffic through a proxy server")
        self.model, self.fail, self._quiet = model, fail, False
        if icon:
            self.row.add_prefix(Gtk.Image.new_from_icon_name("preferences-system-network-proxy-symbolic"))
        self.row.connect("notify::active", self._on_toggle)
        model.listen(self.sync)

    def sync(self, st):
        self._quiet = True
        self.row.set_active(bool(st.get("enabled")))
        self._quiet = False
        self.row.set_subtitle(GLib.markup_escape_text(summary(st)))

    def _on_toggle(self, *_):
        if self._quiet:
            return

        def failed(msg, *_):
            self.model.refresh()                       # put the switch back to what is really set
            if self.fail:
                self.fail(msg)
        self.model.set(fail=failed, enabled=self.row.get_active())


class ProxyPreferences:
    """Adds the Network Proxy groups to a preferences page."""

    def __init__(self, page, model, toast=None):
        self.model, self.toast = model, toast or (lambda text: None)
        self._quiet, self._timer, self._dirty = False, 0, set()
        top = Adw.PreferencesGroup(
            title="Network Proxy",
            description="VPNMan sends this computer's traffic through this proxy: straight to it when no VPN is "
                        "connected, and through the VPN to it while one is. Ignored hosts and the programs listed "
                        "below go direct. Needs Linux (nftables) and Xray.")
        self.switch = NetworkProxySwitch(model, icon=False, fail=self.toast)
        top.add(self.switch.row)
        self.kill = Adw.SwitchRow(title="Block traffic if the proxy fails",
                                  subtitle="If the proxy stops working, nothing goes out directly - it waits until the "
                                           "proxy is back (ignored hosts and the local network still work)")
        self.kill.connect("notify::active", self._on_kill)
        top.add(self.kill)
        self.test = Adw.ActionRow(title="Test the proxy", subtitle="Checks that traffic, DNS and IPv6 really go through it")
        self.test_btn = Gtk.Button(label="Test", valign=Gtk.Align.CENTER)
        self.test_btn.connect("clicked", self._run_test)
        self.test.add_suffix(self.test_btn)
        top.add(self.test)
        imp = Adw.ActionRow(title="Copy from the desktop settings",
                            subtitle="Fill in the proxies set in GNOME, Cinnamon or KDE Plasma")
        btn = Gtk.Button(label="Import", valign=Gtk.Align.CENTER)
        btn.connect("clicked", self._import)
        imp.add_suffix(btn)
        top.add(imp)
        page.add(top)
        self.hosts, self.ports = {}, {}
        for kind, title in KINDS:
            g = Adw.PreferencesGroup(title=title)
            host = Adw.EntryRow(title="URL")
            host.set_tooltip_text("Host name or address; user:password@host for a proxy that needs a login")
            host.connect("changed", self._later, kind)
            port = Adw.SpinRow.new_with_range(0, 65535, 1)
            port.set_title("Port")
            port.connect("notify::value", self._on_port, kind)
            g.add(host)
            g.add(port)
            page.add(g)
            self.hosts[kind], self.ports[kind] = host, port
        g = Adw.PreferencesGroup(description="Separate entries with commas. Addresses, networks (10.0.0.0/8) and "
                                             "domains (example.com, *.example.com) go direct.")
        self.ignore = Adw.EntryRow(title="Ignored Hosts")
        self.ignore.connect("changed", self._later, "ignore")
        g.add(self.ignore)
        self.apps = Adw.EntryRow(title="Programs that skip the proxy")
        self.apps.set_tooltip_text("Program names, for example: steam, thunderbird (needs cgroup v2)")
        self.apps.connect("changed", self._later, "apps")
        g.add(self.apps)
        page.add(g)
        model.listen(self.sync)
        model.refresh()

    def _on_kill(self, *_):
        if not self._quiet:
            self.model.set(fail=lambda msg, *_: (self.toast(msg), self.model.refresh()), killswitch=self.kill.get_active())

    def _run_test(self, *_):
        self.test_btn.set_sensitive(False)
        self.test.set_subtitle("Testing…")

        def done(res):
            self.test_btn.set_sensitive(True)
            rows = [c for c in res["checks"] if c["id"].startswith("netproxy")]
            if not rows:
                self.test.set_subtitle("Switch the Network Proxy on first")
                return
            mark = {"ok": "✔", "warn": "!", "fail": "✘", "info": "·"}
            self.test.set_subtitle(GLib.markup_escape_text("\n".join("%s %s: %s" % (mark.get(c["status"], "?"), c["name"], c["detail"])
                                                                     for c in rows)))
        self.model.rpc("leaktest", done, lambda msg, *_: (self.test_btn.set_sensitive(True), self.test.set_subtitle(
            GLib.markup_escape_text(msg))))

    # ---- model -> widgets
    def sync(self, st):
        self._quiet = True
        self.kill.set_active(bool(st.get("killswitch", True)))
        for kind, _t in KINDS:
            e = st.get(kind) or {}
            if kind not in self._dirty:
                user, _pw, host, _p = parse_url(self.hosts[kind].get_text())
                if (user, host) != (e.get("user", ""), e.get("host", "")):
                    self.hosts[kind].set_text(show_url(e))
                if int(self.ports[kind].get_value()) != int(e.get("port") or 0):
                    self.ports[kind].set_value(int(e.get("port") or 0))
        if "ignore" not in self._dirty and sysproxy.split_hosts(self.ignore.get_text()) != st.get("ignore", []):
            self.ignore.set_text(", ".join(st.get("ignore") or []))
        if "apps" not in self._dirty and sysproxy.split_hosts(self.apps.get_text()) != st.get("apps", []):
            self.apps.set_text(", ".join(st.get("apps") or []))
        self._quiet = False

    # ---- widgets -> model
    def _on_port(self, _row, _p, kind):
        if not self._quiet:
            self._dirty.add(kind)
            self._save()

    def _later(self, _row, what):
        """Text boxes are saved half a second after the last key, like GNOME Settings."""
        if self._quiet:
            return
        self._dirty.add(what)
        if self._timer:
            GLib.source_remove(self._timer)
        self._timer = GLib.timeout_add(600, self._save)

    def changes(self):
        """What the edited boxes ask for (only those: the others keep what the daemon has)."""
        ch = {}
        for kind, _t in KINDS:
            if kind in self._dirty:
                user, password, host, port = parse_url(self.hosts[kind].get_text())
                e = {"host": host, "port": port or int(self.ports[kind].get_value()), "user": user}
                if host and not e["port"]:
                    continue                           # not complete yet: wait for the port
                if password is not None:
                    e["password"] = password
                if not host:
                    e.update(user="", password="")
                ch[kind] = e
        if "ignore" in self._dirty:
            ch["ignore"] = sysproxy.split_hosts(self.ignore.get_text())
        if "apps" in self._dirty:
            ch["apps"] = sysproxy.split_hosts(self.apps.get_text())
        return ch

    def _save(self):
        if self._timer:
            GLib.source_remove(self._timer)
        self._timer = 0
        ch = self.changes()
        self._dirty = {k for k, _t in KINDS if k in self._dirty and k not in ch}     # still waiting for a port
        if ch:
            self.model.set(fail=lambda msg, *_: (self.toast(msg), self.model.refresh()), **ch)
        return False

    def flush(self):
        """The window is closing: save what is still waiting for its half second and stop listening."""
        if self._timer:
            self._save()
        self.model.unlisten(self.sync)
        self.model.unlisten(self.switch.sync)

    def _import(self, *_):
        backend, why = sysproxy.detect()
        if not backend:
            self.toast(why)
            return
        try:
            cfg = backend.read()
        except Exception as e:  # noqa: BLE001
            self.toast("Could not read the desktop proxy settings: %s" % e)
            return
        ch = {k: {"host": sysproxy.clean_host(cfg[k][0]), "port": int(cfg[k][1] or 0) if cfg[k][0] else 0,
                  "user": "", "password": ""} for k, _t in KINDS}
        if not any(v["host"] for v in ch.values()):
            self.toast("The desktop has no manual proxy set" + (" (it uses automatic configuration, which VPNMan "
                                                                "cannot follow)" if cfg.get("mode") == "auto" else ""))
            return
        ch["ignore"] = list(cfg.get("ignore") or [])
        self.model.set(fail=lambda msg, *_: self.toast(msg), **ch)
        self.toast("Copied the proxy settings of %s" % backend.name)
