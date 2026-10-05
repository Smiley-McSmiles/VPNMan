# VPNMan

<p align="center">
  <a href="https://github.com/Smiley-McSmiles/VPNMan/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg?style=flat-square" alt="Version 1.0.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="MIT License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.9%2B-blue.svg?style=flat-square" alt="Python 3.9+"></a>
  <a href="https://gtk.org"><img src="https://img.shields.io/badge/toolkit-GTK4%20%7C%20Libadwaita-red.svg?style=flat-square" alt="GTK4 Libadwaita"></a>
  <a href="https://github.com/Smiley-McSmiles/VPNMan"><img src="https://img.shields.io/badge/kill%20switch-nftables%20%7C%20iptables%20%7C%20pf-orange.svg?style=flat-square" alt="Kill switch: nftables, iptables, pf"></a>
  <a href="https://github.com/Smiley-McSmiles/VPNMan"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20OpenBSD%20%7C%20FreeBSD-lightgrey.svg?style=flat-square" alt="Linux, OpenBSD & FreeBSD"></a>
</p>

A multi-protocol VPN manager with a **GTK4 / libadwaita** app, an **interactive CLI**, and a built-in
**network lock (kill switch)**. Runs on systemd, runit, OpenRC and SysV-init Linux, and on OpenBSD/FreeBSD.

![icon](data/icons/hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan.svg)

## Architecture

```
 vpnman-gtk (GTK4/libadwaita) ─┐
 vpnman (CLI + interactive)  ──┼── Unix socket (JSON) ──►  vpnmand (root daemon)
                               │                              ├─ protocol backends (openvpn, wg-quick, ...)
                               │                              ├─ network lock (nftables | iptables | pf)
                               │                              ├─ DNS switching, routes, hooks, stats, logs
                               │                              └─ profiles + settings in /etc/vpnman (0700)
```

The daemon is the only privileged part. Packages and `install.sh` enable and start it for you; if it is ever
stopped the GUI offers a **Start Service** button (admin password via polkit). On Linux every connection is
authorized by the peer's uid: root, members of `vpnman`/`wheel`/`sudo`, and anyone with an **active local login
session** may use the CLI/GUI - no group setup or re-login needed (`vpnman set access.mode group` restricts it to
groups). On BSD the socket is `root:wheel 0660`. Anyone with access is effectively root (hooks and custom commands
run as root). Pure Python 3.9+ standard library; the GUI additionally needs PyGObject,
GTK 4 and libadwaita ≥ 1.4.

## Protocols

`vpnman protocols` shows what is usable on *your* machine (it checks for the required tools).

| id | Protocol | Needs |
|----|----------|-------|
| `openvpn` | OpenVPN (UDP/TCP, certs, user/pass, key password) | `openvpn` |
| `wireguard` | WireGuard (kernel/userspace); native `ifconfig` path on OpenBSD | `wg`, `wg-quick` |
| `amneziawg` | AmneziaWG (obfuscated WireGuard) | `awg`, `awg-quick` |
| `openconnect` | Cisco AnyConnect, Juniper/Pulse, GlobalProtect, F5, Fortinet, Array | `openconnect` |
| `openfortivpn` | FortiGate SSL-VPN | `openfortivpn` |
| `ikev2` | IKEv2/IPsec (strongSwan swanctl) | `swanctl` |
| `sstp` | Microsoft SSTP | `sstpc`, `pppd` |
| `pptp` | PPTP (legacy) | `pppd`, `pptp` |
| `vpnc` | Cisco IPsec/PSK | `vpnc` |
| `tailscale` / `netbird` / `zerotier` / `nebula` | Mesh/overlay VPNs | their CLIs |
| `networkmanager` | Anything already defined in NetworkManager (L2TP/IPsec, …) | `nmcli` |
| `custom` | Your own connect/disconnect commands | – |
| *stunnel* | Not a protocol of its own: wraps **OpenVPN in TLS** so it looks like HTTPS (per-profile switch) | `stunnel` |

Config files are auto-detected on import (`.ovpn`, WireGuard `.conf`, AmneziaWG, swanctl, vpnc,
openfortivpn, Nebula). OpenVPN files that reference external `ca`/`cert`/`key`/`tls-crypt` files are
imported together with those files.

### OpenVPN over TLS (stunnel)

Turn it on in the profile dialog ("SSL Tunnel (stunnel)": server `host:port`, optional SNI and CA file), or:

```sh
vpnman import work.ovpn --stunnel vpn.example.com:443 --stunnel-sni cdn.example.com --stunnel-ca server.pem
vpnman edit work stunnel=vpn.example.com:443 stunnel_verify=system     # or stunnel=off
```

VPNMan starts stunnel in client mode on a free `127.0.0.1` port, rewrites the runtime copy of the OpenVPN config to
`remote 127.0.0.1 <port>` / `proto tcp-client`, keeps the stunnel server outside the tunnel (`route … net_gateway`), and
lets the kill switch allow only the stunnel server. Without a CA file the TLS layer is not verified (the OpenVPN
session inside is still authenticated); a warning is logged.

## Eddie-style feature set

| Feature | Status |
|---------|--------|
| Server/profile list, favourites, blacklist, search, latency test, "fastest" | ✔ |
| Connect / disconnect / auto-reconnect / fail-over to next favourite | ✔ |
| Auto-connect on start (`off`, `last`, `fastest`, or a profile) | ✔ |
| Network lock: nftables, iptables(+ip6tables), pf; LAN/DHCP/ping/IPv6 toggles; in/out whitelists; persist across reboots | ✔ |
| Lock engaged *before* connecting, kept while reconnecting, endpoint pre-resolved (no DNS needed under lock) | ✔ |
| DNS leak protection + DNS picker (provider, Cloudflare, Google, Quad9, OpenDNS, AdGuard, Mullvad, custom; switches live; `vpnman dns`) | ✔ |
| Custom routes that bypass the tunnel | ✔ (IPv4) |
| Event hooks (pre-connect / connected / disconnected) | ✔ |
| Standard interface names: `tun0`, `tun1`, … (`tapN` for tap, `wgN` for WireGuard on BSD); first free index is used | ✔ |
| Live stats (up/down, rates, duration), public-IP check, log viewer | ✔ |
| Credentials per profile (stored root-only) | ✔ |
| Desktop notifications | ✔ |
| Auto-connect at system start (daemon-side: waits for the network, keeps retrying; `last` / `fastest` / a profile) | ✔ |
| System tray (StatusNotifierItem): status icon, Connect/Disconnect, Network Lock toggle, Show, Quit | ✔ |
| Start the tray app at login (XDG autostart; GNOME, KDE, XFCE, …) | ✔ |
| AirVPN-specific API (server list/keys fetch, per-country scoring) | ✘ – import their generated configs instead |
| Proxy / Tor / SSH / SSL tunnels as transports | ✘ |

## Auto-start and the system tray

* **VPN at boot** – *Connection → Startup* in the app, or `vpnman autostart last|fastest|<profile>|off`. This is done by the
  background service, so the tunnel (and the kill switch, with `netlock.persist`) comes up right after boot, before login.
  It waits up to `connection.autoconnect_wait` seconds for a network and then keeps retrying instead of giving up.
* **App at login** – *Preferences → Tray & Login* or `vpnman autostart --login-app on`. Starts `vpnman-gtk --background`.
* **Tray** – GTK 4 has no tray API, so VPNMan implements the StatusNotifierItem D-Bus protocol (with a dbusmenu menu)
  itself. It works on KDE Plasma, XFCE, Cinnamon, MATE, LXQt, Budgie, Deepin and Pantheon out of the box, and on
  **GNOME with the "AppIndicator and KStatusNotifierItem Support" extension** (preinstalled on Ubuntu; Fedora/Arch:
  `gnome-shell-extension-appindicator`). Closing the window hides it to the tray; the VPN lives in the daemon and is never
  affected. If no tray host exists (stock GNOME), VPNMan detects that and behaves like a normal window app: closing quits
  the GUI, `--background` shows the window instead of hiding it, and if the tray disappears while hidden the window comes back.

## Install

```sh
sudo ./install.sh --install-deps   # optional: pulls dependencies via apt/dnf/pacman/xbps/apk/zypper/pkg_add/pkg
sudo ./install.sh                  # installs to /usr/local, sets up + starts the service for your init system
sudo ./install.sh --prefix /usr --uninstall [--purge]
```

After installing (script, `.deb` or `.rpm`) just open **VPNMan** from your application menu.
`install.sh` is POSIX `sh` (works on OpenBSD's ksh), detects systemd / runit / OpenRC / SysV / OpenBSD rc.d /
FreeBSD rc.d, creates the `vpnman` group, adds `$SUDO_USER` to it, and enables and starts the service.
Init systems were exercised for real: **runit** (under `runsvdir`: enable/start/stop/restart/disable with `svlogd` logging)
and **SysV** (the init script via `start-stop-daemon` and via the plain `nohup` fallback, plus `update-rc.d` enable/disable).
Force a system when auto-detection is wrong: `vpnman service enable --init runit`.
Service control later: `sudo vpnman service enable|disable|start|stop|restart|status|install|uninstall`.

### Packages

```sh
./package.sh            # dist/: .tar.gz, .deb (built by packaging/mkdeb.py - no dpkg needed), .rpm if rpmbuild exists,
                        # Arch pkg if makepkg exists
./package.sh --container rpm   # build the .rpm inside a Fedora container (podman/docker) from ANY distro
                        # dist/recipes/: PKGBUILD, .spec, Void template, Alpine APKBUILD, OpenBSD port skeleton
./package.sh deb        # or pick targets: tar deb rpm arch void alpine openbsd recipes clean
```

## Usage

```sh
vpnman                       # interactive menu (in a terminal)
vpnman import ~/vpn/*.ovpn   # also: vpnman import dir/ ; --user bob --ask-password
vpnman add work --protocol openconnect --server https://vpn.corp.example -o protocol=gp --user bob --ask-password
vpnman list -l               # with latency
vpnman connect "Zurich"      # or: connect --fastest | connect --last
vpnman status [--json]
vpnman lock on               # engage the kill switch now (stays until `lock off`)
vpnman set netlock.enabled true      # lock automatically whenever you connect
vpnman set netlock.persist true      # keep the lock after disconnect and across reboots
vpnman set netlock.whitelist_out 203.0.113.0/24
vpnman set dns.servers 9.9.9.9,149.112.112.112
vpnman set events.connected '/usr/local/bin/my-hook'
vpnman logs -f
vpnman doctor
vpnman-gtk                   # or `vpnman gui`
```

## How the kill switch works

While engaged only these are allowed: loopback, the tunnel interface(s), the VPN server addresses,
and (optionally) LAN, DHCP, ICMP and your whitelist. Everything else, including DNS, is dropped.

* **nftables** – an atomically-replaced `inet vpnman` table (input/output, priority −100, policy drop).
* **iptables** – dedicated `VPNMAN_IN`/`VPNMAN_OUT` chains jumped to first in `INPUT`/`OUTPUT` (v4 and v6).
* **pf** – loads a complete lock ruleset, and restores `/etc/pf.conf` (or disables pf) on release.

If the lock cannot be engaged, VPNMan **refuses to connect** instead of connecting unprotected.
If the tunnel drops the lock stays up and the daemon reconnects; on a user disconnect it is released
unless `netlock.persist` or a manual `vpnman lock on` is active. Stopping the daemon follows the same rule.

Caveats: policy-based IPsec has no tunnel interface, so use an XFRM interface (`if_id`) for IKEv2 under the lock;
mesh VPNs (Tailscale, Nebula) need direct peer traffic, so whitelist peers; protocols other than
OpenVPN/WireGuard/OpenConnect resolve their server name themselves, so use an IP address as `server` if you
want them to start while the lock is engaged.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The suite covers rule generation, importers, command construction, settings, DNS handling and a full
daemon ⇄ client lifecycle against a fake `openvpn`. nftables/iptables application was verified inside a
network namespace; **pf/OpenBSD paths (pf lock, native WireGuard via ifconfig, rc.d) and the runit/OpenRC/FreeBSD
service files are written from the respective documentation but have not been exercised on real hosts** – please report issues.

## License

MIT – see `LICENSE`.
