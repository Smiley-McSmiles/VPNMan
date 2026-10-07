"""The proxy side of the daemon: the list of proxies, and when and how Xray runs.

Three orders (setting ``proxy.order``), named after the path your traffic takes:

* ``proxy_only``  you -> proxy -> internet.  Xray runs whenever the proxy is switched on.
* ``vpn_proxy``   you -> VPN -> proxy -> internet.  Xray runs inside the tunnel: it is started once the VPN is
  connected (so its connection to the proxy server goes through the tunnel) and stopped when the VPN goes down.
* ``proxy_vpn``   you -> proxy -> VPN -> internet.  The VPN's own packets travel through the proxy: Xray carries the
  connection to the VPN server (OpenVPN and WireGuard), exactly like the SSL tunnel (stunnel) does.

Two modes: ``local`` gives applications a SOCKS5 and an HTTP proxy on 127.0.0.1; ``system`` (Linux) additionally
redirects all TCP and DNS of this machine into Xray with nftables.
"""

import os
import re
import threading

from . import paths
from . import platform as plat
from . import split, xray
from .profiles import ProfileError, ProfileStore, new_profile

ORDERS = ("proxy_only", "vpn_proxy", "proxy_vpn")
MODES = ("local", "system")
CARRIED = ("openvpn", "wireguard", "amneziawg")          # protocols whose server connection Xray can carry
_HIDDEN = ("outbound", "link")


def _view(p):
    return {k: v for k, v in p.items() if k not in _HIDDEN}


class ProxyService:
    def __init__(self, mgr, store=None):
        self.m = mgr
        self.store = store or ProfileStore(root=paths.proxies_dir())
        self.runner = xray.Runner(lambda level, text: mgr.log.add(level, text), paths.run_dir())
        self.lock = threading.RLock()
        self.error = ""
        self.owner = None            # None | "local" | "carrier"
        self.key = None              # what the running local instance was built from
        self.ports = {}
        self._fw_on = False
        self._routes = []
        self.server_ip = ""

    # ------------------------------------------------------------------ the list
    def list(self):
        sel = self.m.settings.get("proxy.selected")
        out = []
        for p in self.store.list():
            v = _view(p)
            v["selected"] = p["id"] == sel
            out.append(v)
        return out

    def selected(self):
        sel = self.m.settings.get("proxy.selected")
        if not sel:
            return None
        try:
            return self.store.find(sel)
        except ProfileError:
            return None

    def _unique(self, p):
        names = {q["name"] for q in self.store.list()}
        base, n = p["name"], 2
        while p["name"] in names:
            p["name"] = "%s (%d)" % (base, n)
            n += 1

    def import_text(self, text, source="", group="", name=None):
        """Add proxies from share links / a subscription / an Xray config.  With ``source`` (a subscription URL) the
        proxies of that source are brought up to date instead: matching ones are updated, vanished ones removed."""
        try:
            found, errors = xray.parse_text(text)
        except xray.ProxyError as e:
            raise ProfileError(str(e))
        if name and len(found) == 1:
            found[0]["name"] = name
        existing = self.store.list()
        by_id = {xray.identity(p): p for p in existing}
        added = updated = removed = skipped = 0
        keep = set()
        for f in found:
            key = xray.identity(f)
            cur = by_id.get(key)
            if cur and source and cur.get("source") == source:
                cur.update(name=f["name"], outbound=f["outbound"], link=f["link"], server=f["server"], port=f["port"])
                self.store.save(cur)
                keep.add(cur["id"])
                updated += 1
            elif cur:
                skipped += 1
            else:
                p = new_profile(f["name"], f["protocol"], server=f["server"], port=f["port"], group=group or "",
                                transport="tcp")
                p.update(outbound=f["outbound"], link=f["link"], source=source or "")
                self._unique(p)
                self.store.save(p)
                by_id[key] = p
                keep.add(p["id"])
                added += 1
        if source:
            stale = [p["id"] for p in existing if p.get("source") == source and p["id"] not in keep]
            removed = len(self.remove(stale)["removed"]) if stale else 0
        self.m.log.add("info", "Proxies imported: %d new, %d updated, %d removed, %d already present"
                       % (added, updated, removed, skipped))
        return {"added": added, "updated": updated, "removed": removed, "skipped": skipped, "errors": errors}

    def sources(self):
        """Subscription URLs of the imported proxies, with how many proxies each holds."""
        out = {}
        for p in self.store.list():
            if p.get("source"):
                out[p["source"]] = out.get(p["source"], 0) + 1
        return [{"source": s, "count": n} for s, n in sorted(out.items())]

    def remove(self, idents):
        removed, failed = [], []
        sel = self.m.settings.get("proxy.selected")
        for ident in idents:
            try:
                p = self.store.find(ident)
                self.store.remove(p["id"])
                removed.append(p["name"])
                if p["id"] == sel:
                    self.m.settings.update({"proxy": {"selected": "", "enabled": False}})
            except (ProfileError, KeyError, OSError) as e:
                failed.append({"id": ident, "error": str(e.args[0] if isinstance(e, KeyError) and e.args else e)})
        if removed:
            self.m.log.add("info", "Removed %d prox%s: %s" % (len(removed), "y" if len(removed) == 1 else "ies",
                                                              ", ".join(removed)))
            self.sync()
        return {"removed": removed, "failed": failed}

    def update(self, ident, changes):
        bad = set(changes) - {"name", "group", "notes", "favorite"}
        if bad:
            raise ProfileError("cannot change %s" % ", ".join(sorted(bad)))
        return _view(self.store.update(self.store.find(ident)["id"], changes))

    def select(self, ident):
        p = self.store.find(ident)
        self.m.settings.update({"proxy": {"selected": p["id"]}})
        self.sync()
        return _view(p)

    def latency(self, idents=None):
        import time
        out = {}
        for p in self.store.list():
            if idents and p["id"] not in idents:
                continue
            ips = self.ips(p)
            ms = None
            if ips:
                t0 = time.time()
                try:
                    import socket
                    with socket.create_connection((ips[0], int(p["port"])), timeout=3):
                        ms = round((time.time() - t0) * 1000, 1)
                except OSError:
                    ms = None
            out[p["id"]] = ms
        return out

    def ips(self, p, live=True):
        """The server's addresses: resolved now (and remembered), else the remembered ones - the kill switch may be
        blocking DNS."""
        stored = list(p.get("ips") or [])
        if live:
            got = self.m._resolve(p["server"])
            if got:
                if got != stored:
                    p["ips"] = got
                    try:
                        self.store.save(p)
                    except OSError:
                        pass
                return got
        return stored or list(self.m._ep_cache.get(p["server"], []))

    # ------------------------------------------------------------------ settings
    def configure(self, **kw):
        """Change proxy settings with validation (enabled, selected, order, mode, socks_port, http_port, dns, udp)."""
        tree = {}
        for k, v in kw.items():
            if v is None:
                continue
            if k == "order" and v not in ORDERS:
                raise ProfileError("order must be one of: %s" % ", ".join(ORDERS))
            if k == "mode" and v not in MODES:
                raise ProfileError("mode must be one of: %s" % ", ".join(MODES))
            if k == "mode" and v == "system" and not self.system_supported()[0]:
                raise ProfileError(self.system_supported()[1])
            if k == "udp" and v not in ("block", "direct"):
                raise ProfileError("udp must be block or direct")
            if k in ("socks_port", "http_port"):
                v = int(v)
                if not 1024 <= v <= 65535:
                    raise ProfileError("%s must be between 1024 and 65535" % k)
            if k == "selected" and v:
                v = self.store.find(v)["id"]
            if k == "dns":
                import ipaddress
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ProfileError("dns must be an IP address")
            if k not in ("enabled", "selected", "order", "mode", "socks_port", "http_port", "dns", "udp"):
                raise ProfileError("unknown proxy setting: %s" % k)
            tree[k] = v
        if tree:
            if tree.get("enabled") and not (tree.get("selected") or self.m.settings.get("proxy.selected")):
                raise ProfileError("choose a proxy first (vpnman proxy use NAME)")
            ports = (tree.get("socks_port", self.m.settings.get("proxy.socks_port")),
                     tree.get("http_port", self.m.settings.get("proxy.http_port")))
            if ports[0] == ports[1]:
                raise ProfileError("the SOCKS and HTTP ports must differ")
            self.m.settings.update({"proxy": tree})
        self.changed()
        return self.status()

    def changed(self):
        """Settings or the list changed: bring Xray, the firewall rules and the kill switch in line."""
        self.sync()
        with self.m._mlock:
            if self.m.lock_engaged:
                try:
                    self.m._lock_apply()
                except Exception as e:  # noqa: BLE001
                    self.m.log.add("error", "Network lock update failed: %s" % e)

    @staticmethod
    def system_supported():
        if plat.os_family() != "linux":
            return False, "system-wide mode needs Linux (nftables)"
        if not plat.which("nft"):
            return False, "system-wide mode needs nft (nftables)"
        return True, ""

    # ------------------------------------------------------------------ queries
    def settings(self):
        return self.m.settings.get("proxy")

    def lock_ips(self):
        """Proxy server addresses the kill switch must let through while the proxy runs outside the VPN."""
        cfg = self.settings()
        p = self.selected()
        if not (cfg["enabled"] and p and cfg["order"] == "proxy_only"):
            return set()
        return set(self.ips(p, live=False))

    def status(self):
        cfg = self.settings()
        p = self.selected()
        running = self.runner.alive()
        local = running and self.owner == "local"
        return {"enabled": bool(cfg["enabled"]), "selected": p["id"] if p else "", "name": p["name"] if p else "",
                "order": cfg["order"], "mode": cfg["mode"], "running": running,
                "carrier": running and self.owner == "carrier", "error": self.error,
                "socks": self.ports.get("socks") if local else None, "http": self.ports.get("http") if local else None,
                "installed": bool(xray.binary()), "system_ok": self.system_supported()[0],
                "socks_port": cfg["socks_port"], "http_port": cfg["http_port"], "dns": cfg["dns"], "udp": cfg["udp"]}

    # ------------------------------------------------------------------ local proxy (proxy_only, vpn_proxy)
    def _wanted(self, vpn_up):
        cfg = self.settings()
        if not (cfg["enabled"] and self.selected()):
            return False
        if cfg["order"] == "proxy_only":
            return True
        if cfg["order"] == "vpn_proxy":
            return bool(vpn_up)
        return False                                  # proxy_vpn: the VPN session owns Xray

    def sync(self, vpn_up=None):
        with self.lock:
            if self.owner == "carrier":
                return
            if vpn_up is None:
                vpn_up = self.m._status.get("state") == "connected"
            if not self._wanted(vpn_up):
                self._stop_local()
                return
            cfg = self.settings()
            p = self.selected()
            exclude = sorted(self.m._lock_endpoints) + self.m._route_nets()
            key = (p["id"], cfg["order"], cfg["mode"], cfg["socks_port"], cfg["http_port"], cfg["dns"], cfg["udp"],
                   tuple(exclude), bool(self.m.settings.get("netlock.allow_lan")), bool(self.m._split.active))
            if key == self.key and self.runner.alive():
                return
            self._start_local(p, cfg, exclude, key)

    def _start_local(self, p, cfg, exclude, key):
        self._stop_local()
        self.error = ""
        try:
            ips = self.ips(p)
            if not ips:
                raise xray.ProxyError("could not resolve %s" % p["server"])
            outbound = xray.pin_address(p["outbound"], ips[0])
            system = cfg["mode"] == "system"
            if system:
                ok, why = self.system_supported()
                if not ok:
                    raise xray.ProxyError(why)
            socks, http = cfg["socks_port"], cfg["http_port"]
            redirect = dns = None
            if system:
                redirect = xray.free_port({socks, http})
                dns = xray.free_port({socks, http, redirect})
            conf = xray.build_config(outbound, socks=socks, http=http, redirect=redirect, dns=dns,
                                     mark=xray.MARK if system else None, dns_server=cfg["dns"])
            self.m.log.add("info", "Starting the proxy %s (%s, %s)" % (p["name"], cfg["order"], cfg["mode"]))
            self.runner.start(conf, [x for x in (socks, http, redirect, dns) if x])
            self.owner, self.key, self.server_ip = "local", key, ips[0]
            self.ports = {"socks": socks, "http": http}
            if system:
                allow_lan = bool(self.m.settings.get("netlock.allow_lan"))
                xray.apply_ruleset(xray.redirect_ruleset(
                    redirect, dns, exclude=exclude, allow_lan=allow_lan,
                    split_mark=split.MARK if self.m._split.active else 0, udp=cfg["udp"]))
                self._fw_on = True
            self.m.log.add("info", "Proxy up: SOCKS5 127.0.0.1:%d, HTTP 127.0.0.1:%d%s" % (
                socks, http, "; all TCP and DNS of this computer go through it" if system else ""))
        except xray.ProxyError as e:
            self.error = str(e)
            self.m.log.add("error", "Proxy: %s" % e)
            self._stop_local()
            self.error = str(e)

    def _stop_local(self):
        was = self.runner.alive() or self._fw_on
        if self._fw_on:
            xray.remove_ruleset()
            self._fw_on = False
        self.runner.stop()
        self.owner, self.key, self.ports, self.server_ip = None, None, {}, ""
        if was:
            self.error = ""
            self.m.log.add("info", "Proxy stopped")

    def watch(self):
        """Called every second by the daemon: restart a local instance that died."""
        with self.lock:
            if self.owner == "local" and not self.runner.alive():
                self.m.log.add("warn", "Xray terminated unexpectedly - restarting it")
                self.key = None
                self.sync()

    def shutdown(self):
        with self.lock:
            self.owner = None
            self._stop_local()
            self._drop_routes()

    # ------------------------------------------------------------------ the proxy carries the VPN (proxy_vpn)
    def carrier_wanted(self):
        cfg = self.settings()
        return bool(cfg["enabled"] and cfg["order"] == "proxy_vpn" and self.selected())

    def carrier_ips(self):
        """Resolve the proxy server before the kill switch is raised."""
        p = self.selected()
        ips = self.ips(p)
        if not ips:
            raise xray.ProxyError("could not resolve the proxy server %s" % p["server"])
        return set(ips)

    def start_carrier(self, backend, profile, ctx, stop_event):
        """Start Xray so that the VPN connects to ``127.0.0.1:<port>``.  Returns {"port", "proto", "ip"}."""
        p = self.selected()
        if backend.id not in CARRIED:
            raise xray.ProxyError("a proxy in front of the VPN works with OpenVPN and WireGuard profiles; "
                                  "%s is not supported" % backend.label, fatal=True)
        if (profile.get("options") or {}).get("stunnel", {}).get("enabled"):
            raise xray.ProxyError("the SSL tunnel (stunnel) and a proxy in front of the VPN cannot be combined - "
                                  "turn one of them off", fatal=True)
        eps = backend.endpoints(profile)
        if not eps:
            raise xray.ProxyError("this profile has no server address", fatal=True)
        if len({(e[0], int(e[1] or 0)) for e in eps}) > 1:
            if backend.id != "openvpn":
                raise xray.ProxyError("a proxy in front of the VPN needs a profile with a single peer", fatal=True)
            self.m.log.add("warn", "The profile lists several servers; only the first is reached through the proxy")
        host, port, proto = eps[0][0], int(eps[0][1] or 0), (eps[0][2] or "")
        vpn_ip = ctx.state.get("resolved", {}).get(host)
        if not vpn_ip:
            raise xray.ProxyError("could not resolve the VPN server %s" % host)
        if ":" in vpn_ip:
            raise xray.ProxyError("the VPN server only has an IPv6 address, which the proxy path does not support",
                                  fatal=True)
        if not port:
            port = 1194 if backend.id == "openvpn" else 51820
        ips = self.ips(p)
        if not ips:
            raise xray.ProxyError("could not resolve the proxy server %s" % p["server"])
        with self.lock:
            self._stop_local()
            local = xray.free_port()
            conf = xray.build_config(xray.pin_address(p["outbound"], ips[0]), forward=(local, vpn_ip, port))
            self.m.log.add("info", "Starting the proxy %s in front of the VPN (%s:%d)" % (p["name"], vpn_ip, port))
            self.runner.start(conf, [local])
            self.owner, self.server_ip = "carrier", ips[0]
            self.ports = {}
            self.error = ""
        gw, dev = plat.default_gateway()
        if gw and ":" not in ips[0]:
            rc, out = plat.run(["ip", "route", "replace", ips[0] + "/32", "via", gw]) if plat.os_family() == "linux" \
                else plat.run(["route", "-q", "add", "-host", ips[0], gw])
            if rc == 0:
                self._routes.append(ips[0])
            else:
                self.m.log.add("warn", "route to the proxy server failed: %s" % out.strip())
        info = {"port": local, "proto": "tcp" if proto.startswith("tcp") else "udp", "ip": ips[0]}
        ctx.state["xray_fwd"] = info
        return info

    def carrier_alive(self):
        return self.owner != "carrier" or self.runner.alive()

    def stop_carrier(self):
        with self.lock:
            if self.owner == "carrier":
                self.owner = None
                self.runner.stop()
                self.m.log.add("info", "Proxy stopped")
            self._drop_routes()

    def follow_gateway(self, gw):
        """The default gateway changed (Wi-Fi <-> Ethernet): point the proxy server's route at the new one."""
        with self.lock:
            if not self._routes or plat.os_family() != "linux":
                return
            for ip in self._routes:
                plat.run(["ip", "route", "replace", ip + "/32", "via", gw])

    def _drop_routes(self):
        for ip in self._routes:
            if plat.os_family() == "linux":
                plat.run(["ip", "route", "del", ip + "/32"])
            else:
                plat.run(["route", "-q", "delete", "-host", ip])
        self._routes = []
