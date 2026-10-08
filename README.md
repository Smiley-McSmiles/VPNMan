<h1 align="center">VPNMan</h1>

<p align="center">
  <img src="data/icons/hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan.svg" alt="VPNMan icon" width="128" height="128">
</p>

<p align="center">
  <a href="https://github.com/Smiley-McSmiles/VPNMan/releases"><img src="https://img.shields.io/badge/version-1.0.7-blue.svg?style=flat-square" alt="Version 1.0.7"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="MIT License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.9%2B-blue.svg?style=flat-square" alt="Python 3.9+"></a>
  <a href="https://gtk.org"><img src="https://img.shields.io/badge/toolkit-GTK4%20%7C%20Libadwaita-red.svg?style=flat-square" alt="GTK4 Libadwaita"></a>
  <a href="https://github.com/Smiley-McSmiles/VPNMan"><img src="https://img.shields.io/badge/kill%20switch-nftables%20%7C%20iptables%20%7C%20pf-orange.svg?style=flat-square" alt="Kill switch: nftables, iptables, pf"></a>
  <a href="https://github.com/Smiley-McSmiles/VPNMan"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20OpenBSD%20%7C%20FreeBSD-lightgrey.svg?style=flat-square" alt="Linux, OpenBSD & FreeBSD"></a>
</p>

<p align="center">
  A multi-protocol VPN manager with a <b>GTK4 / libadwaita</b> app, an <b>interactive CLI</b>, and a built-in
  <b>network lock (kill switch)</b>.<br>
  Runs on systemd, runit, OpenRC and SysV-init Linux, and on OpenBSD/FreeBSD.
</p>

## 👥 Developers & Attribution

VPNMan is developed and maintained by:
- **WOOSAH** (Lead Architect & Maintainer)
- **Claude** (Engineer)

Project GitHub: [https://github.com/Smiley-McSmiles/VPNMan](https://github.com/Smiley-McSmiles/VPNMan)

The same credits are in the app (*main menu → About VPNMan*) and on the command line (`vpnman about`).

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

### Proxies (Xray)

VPNMan can run a VLESS, VMess, Trojan or Shadowsocks server through [Xray](https://github.com/XTLS/Xray-core) (one
static program; install it from your distribution or from the project's releases). Add share links or a subscription URL
in **Servers → Proxy** (or `vpnman proxy add ...`), choose one, and pick how it combines with the VPN:

| Order | Path of your traffic |
| --- | --- |
| `proxy_only` | you → proxy → internet |
| `vpn_proxy` | you → VPN → proxy → internet (Xray starts once the tunnel is up) |
| `proxy_vpn` | you → proxy → VPN → internet (the VPN connection rides inside the proxy; OpenVPN and WireGuard) |

*Mode* `local` gives applications a SOCKS5 and an HTTP proxy on `127.0.0.1`; `system` (Linux) redirects all TCP and DNS of
the computer into Xray with nftables (IPv6 and other UDP are blocked so nothing goes around it). The kill switch is aware
of the proxy server. See `man vpnman` (PROXIES) for the details and limits.

#### Installing Xray

`sudo ./install.sh --xray-only` downloads the official Xray release for your machine, checks its checksum and installs
it as `/usr/local/bin/xray`. It works with any init system (systemd, runit, OpenRC, s6, BSD rc), because Xray needs no
service: VPNMan starts it. The same steps as a standalone script, if you don't want to download VPNMan first (needs
`bash`, `curl`, `unzip` and `sha256sum`; Linux):

```bash
#!/usr/bin/env bash
# Install the latest Xray release as /usr/local/bin/xray (checksum verified). Run as root.
set -euo pipefail
case "$(uname -m)" in
    x86_64|amd64) arch=64 ;;          i?86) arch=32 ;;
    aarch64|arm64) arch=arm64-v8a ;;  armv7*|armv8l) arch=arm32-v7a ;;
    armv6*) arch=arm32-v6 ;;          riscv64) arch=riscv64 ;;
    ppc64le) arch=ppc64le ;;          s390x) arch=s390x ;;
    loongarch64) arch=loong64 ;;
    *) echo "no Xray build for $(uname -m)" >&2; exit 1 ;;
esac
base=https://github.com/XTLS/Xray-core/releases/latest/download
asset=Xray-linux-$arch.zip
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/$asset.dgst" "$base/$asset.dgst"
want=$(grep -i '256' "$tmp/$asset.dgst" | grep -oiE '[0-9a-f]{64}' | head -n 1)
have=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
if [ -z "$want" ] || [ "${want,,}" != "$have" ]; then echo "checksum mismatch - not installing" >&2; exit 1; fi
unzip -q "$tmp/$asset" xray -d "$tmp"
install -m 755 "$tmp/xray" /usr/local/bin/xray
xray version | head -n 1
```

To remove it again: `sudo rm /usr/local/bin/xray` (`./install.sh --uninstall` removes Xray only if `install.sh`
installed it).

## Feature set

| Feature | Status |
|---------|--------|
| Server/profile list, favourites, blacklist, search, latency test, "fastest"; multi-select (Ctrl+click, Shift+click, Ctrl+A) for bulk remove | ✔ |
| Connect / disconnect / auto-reconnect / fail-over to next favourite | ✔ |
| Auto-connect on start (`off`, `last`, `fastest`, or a profile) | ✔ |
| Network lock: nftables, iptables(+ip6tables), pf; LAN/DHCP/ping/IPv6 toggles; in/out whitelists; persist across reboots | ✔ |
| Lock engaged *before* connecting, kept while reconnecting, endpoint pre-resolved (no DNS needed under lock) | ✔ |
| DNS leak protection + DNS picker (provider, Cloudflare, Google, Quad9, OpenDNS, AdGuard, Mullvad, custom; switches live; `vpnman dns`) | ✔ |
| Custom routes that bypass the tunnel | ✔ (IPv4) |
| Login prompt: when the server rejects the username/password the app asks for them right there and reconnects (no retry loop against a wrong password) | ✔ |
| **Connection test** (GUI "Test connection", `vpnman leaktest`): tunnel, public IP, kill switch really blocking, DNS and IPv6 leaks | ✔ (Linux) |
| **Trusted networks**: connect automatically on Wi-Fi/wired networks you have not marked as trusted; optionally disconnect on trusted ones | ✔ |
| Network change handling: the app bypass and bypass routes follow a new gateway (Wi-Fi ⇄ Ethernet) | ✔ |
| Server groups (folders become groups on import), sort by name / favourites / latency, optional automatic latency test | ✔ |
| Connection history and a live traffic graph | ✔ |
| **Failover lists**: per server, the servers to try in order when it keeps failing, then its group, then favourites (`vpnman failover`) | ✔ |
| Import notes: options in a config that do not work here (Windows-only options, missing `up`/`down` scripts) are listed when you import it | ✔ |
| Update check: *Check for Updates…* in the menu, `vpnman update`, or once a day if you switch it on in Preferences | ✔ |
| **Proxies through Xray** (VLESS, VMess, Trojan, Shadowsocks; Reality, WebSocket, gRPC, ...): share links, files and subscription URLs; a local SOCKS5/HTTP proxy or system-wide (Linux); proxy only, **VPN → proxy** or **proxy → VPN** (`vpnman proxy`, Servers → Proxy) | ✔ (needs `xray`) |
| **Live connection table**: every connection with its application, port, protocol and direction (Connection page, `vpnman connections`) | ✔ (Linux; FreeBSD) |
| **Blocked connections**: right-click a connection to copy it, force-close it, stop its program or block its address / port / program; a *Pop out* window for the live table; a window to manage the blocks (`vpnman blocks`) | ✔ (Linux, nftables) |
| Edit a whole group or a selection at once (group, login, SSL tunnel server) | ✔ |
| Backup and restore of all profiles and proxies (with credentials) and settings | ✔ |
| Shell completions for bash, zsh and fish (profile names included) | ✔ |
| **Schedule**: connect (and optionally disconnect) at set times on chosen days, overnight windows, per-entry server; runs in the daemon | ✔ |
| **App bypass** (per-app split tunnel): whitelist installed apps such as Steam or Firefox so they ignore the VPN | ✔ (Linux: nftables + cgroup v2) |
| Event hooks (pre-connect / connected / disconnected) | ✔ |
| Standard interface names: `tun0`, `tun1`, … (`tapN` for tap, `wgN` for WireGuard on BSD); first free index is used | ✔ |
| Live stats (up/down, rates, duration), public-IP check, log viewer | ✔ |
| Credentials per profile (stored root-only) | ✔ |
| Desktop notifications | ✔ |
| Auto-connect at system start (daemon-side: waits for the network, keeps retrying; `last` / `fastest` / a profile) | ✔ |
| System tray (StatusNotifierItem): status icon, Connect/Disconnect, Network Lock toggle, Show, Quit | ✔ |
| Start the tray app at login (XDG autostart; GNOME, KDE, XFCE, …) | ✔ |
| Proxy / Tor / SSH / SSL tunnels as transports | ✘ |

## Schedule and app bypass

* **Schedule** – the *Schedule* tab (or `vpnman schedule`). Each entry has days, a start time, an optional end time and a
  server (last used, fastest, or a profile). The daemon connects when a window opens and disconnects when it closes
  (only if the schedule made the connection, so a manual connection is never cut off). Windows that end before they start
  run past midnight. Times are the computer's local time.

  ```sh
  vpnman schedule add --days mon-fri --start 08:00 --end 18:00 --profile Zurich --name Work
  vpnman schedule add --days weekends --start 22:00          # connect only, stay connected
  vpnman schedule                                             # list, shows "next in …"
  vpnman schedule disable Work | enable Work | remove Work | off
  ```

* **App bypass** – the *Apps* tab (or `vpnman bypass`). Pick installed applications (read from the `.desktop` launchers,
  including Flatpak and Snap) or type a program name. While the VPN is up, those programs *and everything they start*
  keep using your normal connection; all other traffic stays in the tunnel and under the kill switch.

  ```sh
  vpnman bypass add steam firefox
  vpnman bypass available game        # search installed apps
  vpnman bypass remove steam | on | off
  ```

  How it works (Linux): the daemon moves matching running programs into a dedicated cgroup v2, nftables marks that
  cgroup's packets, a policy-routing rule sends marked packets out of the physical gateway (masqueraded, with the
  system's original DNS), and the kill switch lets the marked traffic through. The apps are exempt from the kill switch
  too: while the lock is engaged they stay online even if the VPN drops or is switched off. No program has to be started specially,
  and programs started later are picked up within about two seconds. Needs `nft`, `ip` and a pure cgroup v2 system
  (`/sys/fs/cgroup` is cgroup2 - the default on Fedora, Ubuntu 22.04+, Debian 11+, Arch, Void with elogind/systemd).
  The Apps tab says so when the machine can't do it. Not available on the BSDs (pf cannot match by program).

  *Only listed apps use the VPN* (experimental): the same machinery inverted - everything on the computer uses the
  normal connection except the listed apps. Switch with the "How the list works" row or `vpnman bypass mode include`.
  Everything else is unprotected in this mode, and the kill switch lets that traffic through; use it deliberately.

* **Addresses that skip the VPN** – IPs, networks (`10.0.0.0/8`) or domain names (resolved periodically) in the Apps tab
  or `vpnman routes add 10.0.0.0/8 nas.example.com`. They use the normal connection and the kill switch never blocks them.

## Networks, tests and backups

* **Trusted networks** – *Preferences → Networks* or `vpnman networks`. Mark home/office Wi-Fi as trusted; on any other
  network VPNMan can connect automatically (`vpnman set network.untrusted_action connect`) and, if you want, disconnect
  again on a trusted one (only when it was the automation that connected). A network is identified by its Wi-Fi name or
  its router's MAC address, so "192.168.1.1" at the cafe is not mistaken for your home.
* **Connection test** – *Connection → Test connection* or `vpnman leaktest`. It checks the tunnel, your public IP, that
  traffic outside the tunnel is blocked while the kill switch is engaged, that DNS servers sit behind the tunnel, and that
  IPv6 does not bypass it. Exit status 1 on a failure, so it can run from a script.
* **History** – the Connection page lists recent sessions with duration and traffic (`vpnman history`); a graph shows the
  last two minutes of traffic while connected.
* **Backup** – main menu *Export Backup… / Restore Backup…* or `vpnman backup export FILE` / `vpnman backup import FILE
  [--replace] [--settings]`. The file contains your passwords and private keys: it is written `0600` and should be kept safe.
  Restoring validates the archive and by default only adds profiles that are missing.
* **Completions** – installed for bash, zsh and fish; profile names complete too. They are generated from the real
  argument parser (`python3 tools/gen_completions.py`) and a test fails if they go stale.

## Auto-start and the system tray

* **VPN at boot** – *Connection → Startup* in the app, or `vpnman autostart last|fastest|<profile>|off`. This is done by the
  background service, so the tunnel (and the kill switch, with `netlock.persist`) comes up right after boot, before login.
  It waits up to `connection.autoconnect_wait` seconds for a network and then keeps retrying instead of giving up.
* **App at login** – *Preferences → Tray & Login* or `vpnman autostart --login-app on`. Starts `vpnman-gtk --background`.
* **Tray** – GTK 4 has no tray API. On **Cinnamon** VPNMan starts a tiny GTK 3 helper that uses `XApp.StatusIcon`, Cinnamon's
  native tray API (needs the `xapp` package and the *XApp Status Applet* on the panel; if the helper cannot start it falls
  back to StatusNotifier). On every other desktop VPNMan implements the StatusNotifierItem D-Bus protocol (with a dbusmenu menu)
  itself. It works on KDE Plasma, XFCE, Cinnamon, MATE, LXQt, Budgie, Deepin and Pantheon out of the box, and on
  **GNOME with the "AppIndicator and KStatusNotifierItem Support" extension** (preinstalled on Ubuntu; Fedora/Arch:
  `gnome-shell-extension-appindicator`). Closing the window hides it to the tray; the VPN lives in the daemon and is never
  affected. **Cinnamon** shows StatusNotifier icons through `xapp-sn-watcher` and its panel *System Tray / XApp Status*
  applet (the `xapp` package; on Void: `xbps-install xapp`) - left-clicking such an icon opens its menu (which has *Show VPNMan*).
  The window class matches the launcher's `StartupWMClass`, so docks/panels on X11 desktops group the running app with its
  launcher instead of showing a second icon. If no tray host exists (stock GNOME), VPNMan detects that and behaves like a normal window app: closing quits
  the GUI, `--background` shows the window instead of hiding it, and if the tray disappears while hidden the window comes back.

## Install

`install.sh` puts the program under `/usr/local` and, because some desktop sessions set `XDG_DATA_DIRS` without
`/usr/local/share` (so the menu/dock never sees the launcher or icon), also **links the launcher and icons into
`/usr/share`** (`--no-system-links` to skip, removed again by `--uninstall`). `vpnman doctor` shows whether your current
session can see the launcher and icons and what your tray environment offers; `sudo vpnman doctor --fix` repairs an older
install without reinstalling.

```sh
sh install.sh --check              # no root needed: report what is missing on this machine (Python, GTK/libadwaita, VPN tools, firewall, init)
sudo sh install.sh --install-deps  # optional: pulls dependencies via apt/dnf/pacman/xbps/apk/zypper/pkg_add/pkg
sudo sh install.sh --xray-only     # optional: downloads Xray (checksum verified) for `vpnman proxy`; no service, any init system
sudo sh install.sh                 # installs to /usr/local, sets up + starts the service for your init system
                                   # (no sudo? use `doas sh install.sh` or `su -c 'sh install.sh'`)
sudo ./install.sh --prefix /usr --uninstall [--purge]
```

The installer is defensive: it sets `umask 022` and fixes file modes (so a strict root umask cannot make the install
unreadable for normal users), extends `PATH` with the `sbin` directories, treats service/group/cache steps as non-fatal
warnings, waits for the daemon to answer and prints diagnostics if it does not, and tells you which dependencies are missing
(with the exact install command for your package manager). On Void: `xbps-install -S python3-gobject gtk4 libadwaita`.

After installing (script, `.deb` or `.rpm`) just open **VPNMan** from your application menu.
`install.sh` is POSIX `sh` (works on OpenBSD's ksh), detects systemd / runit / OpenRC / SysV / OpenBSD rc.d /
FreeBSD rc.d, creates the `vpnman` group, adds `$SUDO_USER` to it, and enables and starts the service.
Init systems were exercised for real: **runit** (under `runsvdir`: enable/start/stop/restart/disable with `svlogd` logging)
and **SysV** (the init script via `start-stop-daemon` and via the plain `nohup` fallback, plus `update-rc.d` enable/disable).
Force a system when auto-detection is wrong: `vpnman service enable --init runit`.
Service control later: `sudo vpnman service enable|disable|start|stop|restart|status|install|uninstall`.

### Packages

```sh
./package.sh                   # everything this machine can build; a missing tool only skips that target
./package.sh arch deb          # or pick targets: tar deb rpm arch void alpine openbsd recipes clean
./package.sh --container rpm   # build the .rpm inside a Fedora container (podman/docker) from ANY distro
```

| Target | Needs | Notes |
|--------|-------|-------|
| `tar` | nothing | source tarball with `install.sh` |
| `deb` | python3 | built by `packaging/mkdeb.py` - no `dpkg` needed |
| `rpm` | `rpmbuild` | or `--container` |
| `arch` | python3 | built by `packaging/mkarch.py` - works on **any** distro, no `makepkg`/`pacman`; install with `pacman -U` |
| `void` | `xbps-create` (Void) | otherwise the template is written to `dist/recipes/void/` |
| `alpine`, `openbsd` | - | recipes only (`APKBUILD`, port skeleton) in `dist/recipes/` |

With no argument, `package.sh` builds every target it can and ends with a summary of what was built, skipped and failed.

GitHub Actions (`.github/workflows`): CI runs the tests and builds every package on each push/PR; pushing a tag
`vX.Y.Z` (which must match the version in the code - checked by `tools/check_version.py`) publishes a release with all
packages, `SHA256SUMS` and notes taken from the metainfo file.

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
vpnman schedule add --days mon-fri --start 08:00 --end 18:00   # timed auto-connect
vpnman bypass add steam firefox      # these apps skip the VPN
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
python3 -m unittest tests.test_vpnman -v        # GUI tests need xvfb-run, dbus-run-session, xdotool (they skip otherwise)
```

The suite covers rule generation, importers, command construction, settings, DNS handling and a full
daemon ⇄ client lifecycle against a fake `openvpn`. nftables/iptables application was verified inside a
network namespace; **pf/OpenBSD paths (pf lock, native WireGuard via ifconfig, rc.d) and the runit/OpenRC/FreeBSD
service files are written from the respective documentation but have not been exercised on real hosts** – please report issues.

## License

MIT – see `LICENSE`.

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 **WOOSAH & Claude**  
Repository: [https://github.com/Smiley-McSmiles/VPNMan](https://github.com/Smiley-McSmiles/VPNMan)
