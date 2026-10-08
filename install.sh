#!/bin/sh
# VPNMan installer - POSIX sh, runs on Linux (systemd, runit, OpenRC, SysV) and the BSDs.
#
#   sudo ./install.sh                  install to /usr/local, set up the service for this machine
#                                      (asks whether to install Xray too, when it is missing)
#   sudo ./install.sh --prefix /usr    choose another prefix
#   DESTDIR=/tmp/stage ./install.sh --init systemd --no-post    stage files for a package
#   sudo ./install.sh --uninstall [--purge]
#   sudo ./install.sh --install-deps   install dependencies with the native package manager first (and Xray)
#   sudo ./install.sh --xray-only      only download and install Xray (the engine of `vpnman proxy`)
#   ./install.sh --check               only check this machine (Python, GTK/libadwaita, VPN tools, firewall, init)
set -eu

# Robustness first: a restrictive root umask must not make the install unreadable for normal users, and
# `su` without a login shell often lacks the sbin directories (groupadd, usermod, ...).
umask 022
PATH="${PATH:-/usr/bin:/bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin"
export PATH

PREFIX=/usr/local
INIT=auto
DO_POST=1
UNINSTALL=0
PURGE=0
DEPS=0
INSTALL_XRAY=0
XRAY_ONLY=0
NO_XRAY=0
CHECK=0
SYSLINKS=1
GROUP=vpnman
WARNINGS=""
SRC=$(cd "$(dirname "$0")" && pwd)
DESTDIR=${DESTDIR:-}

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    cat <<USAGE

Options:
  --prefix DIR        installation prefix (default: /usr/local)
  --init SYSTEM       auto | systemd | sysv | openrc | runit | openbsd | freebsd | all-linux | none
  --no-post           do not create the group, touch caches or enable the service
  --uninstall         remove VPNMan (add --purge to also delete /etc/vpnman profiles/settings)
  --install-deps      install runtime dependencies first (apt, dnf, pacman, xbps, apk, zypper, pkg_add, pkg);
                      also downloads Xray when it is missing (see --install-xray)
  --install-xray      download the official Xray release for this machine (checksum verified) and install it as
                      PREFIX/bin/xray, replacing an older copy; needs curl or wget. Xray is the program behind
                      "vpnman proxy"; it needs no service of its own, so this works on any init system
  --xray-only         do only that, nothing else
  --no-xray           do not offer to install Xray (an interactive install asks when it is missing)
  --check             only report what is missing on this machine; install nothing
  --no-system-links   do not link the launcher/icons into /usr/share when installing under another prefix
  -h, --help          show this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift ;;
        --prefix=*) PREFIX=${1#*=} ;;
        --init) INIT=$2; shift ;;
        --init=*) INIT=${1#*=} ;;
        --no-post|--no-service) DO_POST=0 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        --install-deps) DEPS=1 ;;
        --install-xray) INSTALL_XRAY=1 ;;
        --xray-only) XRAY_ONLY=1; INSTALL_XRAY=1 ;;
        --no-xray) NO_XRAY=1 ;;
        --check) CHECK=1 ;;
        --no-system-links) SYSLINKS=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
# Problems that should not stop the install are collected and summarised at the end.
warn() {
    printf 'warning: %s\n' "$*" >&2
    WARNINGS="$WARNINGS
  - $*"
}
try() { "$@" || warn "command failed: $*"; }

OS=$(uname -s)
LIBDIR=$PREFIX/lib/vpnman
SHAREDIR=$PREFIX/share
BINDIR=$PREFIX/bin
MANDIR=$SHAREDIR/man/man1
[ "$OS" = OpenBSD ] && MANDIR=$PREFIX/man/man1
D=$DESTDIR
if [ -z "$DESTDIR" ] && [ "$CHECK" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    # installing only Xray into a directory the user can write needs no root
    if [ "$XRAY_ONLY" -eq 1 ] && mkdir -p "$BINDIR" 2>/dev/null && [ -w "$BINDIR" ]; then :; else
        die "run as root (try: sudo sh $0 $*   or: doas sh $0 $*   or: su -c 'sh $0 $*')"
    fi
fi

detect_init() {
    case "$OS" in
        OpenBSD) echo openbsd; return ;;
        FreeBSD|NetBSD|DragonFly) echo freebsd; return ;;
        Darwin) echo none; return ;;
    esac
    if [ -d /run/systemd/system ]; then echo systemd
    elif [ "$(cat /proc/1/comm 2>/dev/null)" = runit ] || [ -d /run/runit ]; then echo runit
    elif [ -d /run/openrc ] || [ -x /sbin/openrc-run ]; then echo openrc
    elif [ -d /etc/init.d ]; then echo sysv
    elif have sv && { [ -d /etc/sv ] || [ -d /var/service ]; }; then echo runit
    else echo none
    fi
}

pm_name() {
    for pm in apt-get dnf pacman xbps-install apk zypper pkg_add pkg; do
        if have "$pm"; then echo "$pm"; return; fi
    done
    echo none
}

# gui_hint: the command that installs the GTK4/libadwaita Python dependencies
gui_hint() {
    case "$(pm_name)" in
        apt-get) echo "apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1" ;;
        dnf) echo "dnf install python3-gobject gtk4 libadwaita" ;;
        pacman) echo "pacman -S python-gobject gtk4 libadwaita" ;;
        xbps-install) echo "xbps-install -S python3-gobject gtk4 libadwaita" ;;
        apk) echo "apk add py3-gobject3 gtk4.0 libadwaita" ;;
        zypper) echo "zypper install python3-gobject typelib-1_0-Gtk-4_0 typelib-1_0-Adw-1" ;;
        pkg_add) echo "pkg_add py3-gobject3 gtk4 libadwaita" ;;
        pkg) echo "pkg install py311-gobject3 gtk4 libadwaita" ;;
        *) echo "install PyGObject, GTK 4 and libadwaita (>= 1.4) with your package manager" ;;
    esac
}

pm_install() {  # pm_install <package>...   (returns non-zero when the package manager fails)
    case "$(pm_name)" in
        apt-get) apt-get install -y "$@" ;;
        dnf) dnf install -y "$@" ;;
        pacman) pacman -S --needed --noconfirm "$@" ;;
        xbps-install) xbps-install -y "$@" ;;
        apk) apk add "$@" ;;
        zypper) zypper --non-interactive install "$@" ;;
        pkg_add) pkg_add "$@" ;;
        pkg) pkg install -y "$@" ;;
        *) return 1 ;;
    esac
}

install_deps() {
    say "Installing dependencies with $(pm_name)"
    case "$(pm_name)" in
        apt-get) apt-get update || warn "apt-get update failed"
                 REQ="python3 python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 iproute2"
                 OPT="openvpn wireguard-tools nftables openresolv desktop-file-utils libgtk-4-bin stunnel4 gir1.2-xapp-1.0" ;;
        dnf) REQ="python3 python3-gobject gtk4 libadwaita iproute"
             OPT="openvpn wireguard-tools nftables desktop-file-utils gtk-update-icon-cache stunnel" ;;
        pacman) REQ="python python-gobject gtk4 libadwaita iproute2"
                OPT="openvpn wireguard-tools nftables desktop-file-utils stunnel" ;;
        xbps-install) REQ="python3 python3-gobject gtk4 libadwaita iproute2"
                      OPT="openvpn wireguard-tools nftables polkit desktop-file-utils gtk-update-icon-cache stunnel xapp" ;;
        apk) REQ="python3 py3-gobject3 gtk4.0 libadwaita iproute2"
             OPT="openvpn wireguard-tools nftables desktop-file-utils stunnel" ;;
        zypper) REQ="python3 python3-gobject typelib-1_0-Gtk-4_0 typelib-1_0-Adw-1 iproute2"
                OPT="openvpn wireguard-tools nftables desktop-file-utils stunnel" ;;
        pkg_add) REQ="python3 py3-gobject3 gtk4 libadwaita"; OPT="openvpn wireguard-tools stunnel" ;;
        pkg) REQ="python3 py311-gobject3 gtk4 libadwaita"; OPT="openvpn wireguard-tools stunnel" ;;
        *) die "no supported package manager found; $(gui_hint)" ;;
    esac
    # shellcheck disable=SC2086
    pm_install $REQ || warn "could not install all required packages ($REQ)"
    for p in $OPT; do pm_install "$p" >/dev/null 2>&1 || warn "optional package not installed: $p"; done
    say "Optional protocol tools: openconnect, openfortivpn, sstp-client, pptp, strongswan, vpnc, tailscale, ..."
}

find_python() {
    for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
        if have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            command -v "$c"; return 0
        fi
    done
    return 1
}

# Report everything that could stop VPNMan from working on this machine (never fatal except Python itself).
preflight() {
    PY=$(find_python) || die "Python 3.9 or newer is required (found: $(command -v python3 2>/dev/null || echo none)). $(
        case "$(pm_name)" in xbps-install) echo "xbps-install -S python3";; apt-get) echo "apt install python3";; dnf) echo "dnf install python3";; *) echo "install python3";; esac)"
    say "Python: $PY ($("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])'))"
    if "$PY" -c "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1')" 2>/dev/null; then
        if "$PY" -c "from gi.repository import Adw; import sys; sys.exit(0 if (Adw.MAJOR_VERSION, Adw.MINOR_VERSION) >= (1, 4) else 1)" 2>/dev/null; then
            say "GUI dependencies: OK (PyGObject, GTK 4, libadwaita >= 1.4)"
        else
            warn "libadwaita is older than 1.4 - the GUI needs 1.4+. The CLI and daemon work regardless."
        fi
    else
        warn "GUI dependencies missing (PyGObject, GTK 4, libadwaita). The CLI and daemon still work. Install with: $(gui_hint)   (or rerun with --install-deps)"
    fi
    if have cinnamon || printf '%s' "${XDG_CURRENT_DESKTOP:-}" | grep -qi cinnamon; then
        if ! "$PY" -c "import gi; gi.require_version('Gtk','3.0'); gi.require_version('XApp','1.0')" 2>/dev/null; then
            warn "Cinnamon detected but the XApp/GTK 3 typelibs are missing - the system tray icon will not work. Install xapp (Void: xbps-install -S xapp; Debian/Mint: apt install gir1.2-xapp-1.0)"
        fi
    fi
    if ! have openvpn && ! have wg && ! have wg-quick; then
        warn "no VPN client found yet - install openvpn and/or wireguard-tools (see: vpnman protocols)"
    fi
    if ! have xray; then
        say "Optional: xray is not installed (needed for the proxies and the Network Proxy). Install it with: sudo sh $0 --xray-only"
    fi
    if ! have nft && ! have iptables && ! have pfctl; then
        warn "no firewall tool (nft, iptables or pfctl) - the kill switch will be unavailable until one is installed"
    fi
    if [ -z "$(detect_init | grep -v none)" ]; then
        warn "could not detect your init system; the service will not be set up automatically (use --init to choose one)"
    fi
}

# ---------------------------------------------------------------- Xray (the engine behind `vpnman proxy`)
# Xray is one static program; it needs no service, so the official release archive is all there is to install.
XRAY_BASE=${VPNMAN_XRAY_BASE:-https://github.com/XTLS/Xray-core/releases/latest/download}

xray_asset() {  # the release archive name for this machine (without .zip), or failure
    case "$OS" in
        Linux) xo=linux ;;
        FreeBSD) xo=freebsd ;;
        OpenBSD) xo=openbsd ;;
        *) return 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) xa=64 ;;
        i386|i486|i586|i686) xa=32 ;;
        aarch64|arm64) xa=arm64-v8a ;;
        armv7*|armv8l) xa=arm32-v7a ;;
        armv6*) xa=arm32-v6 ;;
        armv5*) xa=arm32-v5 ;;
        riscv64) xa=riscv64 ;;
        s390x) xa=s390x ;;
        ppc64le) xa=ppc64le ;;
        loongarch64) xa=loong64 ;;
        *) return 1 ;;
    esac
    echo "Xray-$xo-$xa"
}

fetch() {  # fetch <url> <file>
    if have curl; then curl -fsSL --retry 2 --connect-timeout 15 -o "$2" "$1"
    elif have wget; then wget -q -T 30 -O "$2" "$1"
    else return 1
    fi
}

install_xray() {
    asset=$(xray_asset) || { warn "no Xray build is known for $OS/$(uname -m) - install xray by hand (https://github.com/XTLS/Xray-core/releases)"; return 1; }
    have curl || have wget || { warn "curl or wget is needed to download Xray"; return 1; }
    xpy=$(find_python) || { warn "Python is needed to unpack Xray"; return 1; }
    xtmp=$(mktemp -d "${TMPDIR:-/tmp}/vpnman-xray.XXXXXX") || { warn "cannot create a temporary directory"; return 1; }
    say "Downloading Xray ($asset)"
    if ! fetch "$XRAY_BASE/$asset.zip" "$xtmp/xray.zip"; then
        warn "could not download $XRAY_BASE/$asset.zip - download it from https://github.com/XTLS/Xray-core/releases and copy xray to $BINDIR"
        rm -rf "$xtmp"; return 1
    fi
    # the release publishes a checksum file next to the archive: verify it (a mismatch is fatal)
    if fetch "$XRAY_BASE/$asset.zip.dgst" "$xtmp/xray.dgst" 2>/dev/null; then
        xrc=0
        "$xpy" - "$xtmp/xray.zip" "$xtmp/xray.dgst" <<'XRAYPY' || xrc=$?
import hashlib, re, sys
data = open(sys.argv[1], "rb").read()
want = None
for line in open(sys.argv[2], errors="replace"):
    if "256" in line:
        m = re.search(r"\b([0-9a-fA-F]{64})\b", line)
        if m:
            want = m.group(1).lower()
            break
if want is None:
    sys.exit(2)
sys.exit(0 if hashlib.sha256(data).hexdigest() == want else 1)
XRAYPY
        case "$xrc" in
            0) say "Checksum verified" ;;
            1) warn "the downloaded Xray does not match its published checksum - not installing it"; rm -rf "$xtmp"; return 1 ;;
            *) warn "could not read the published checksum - continuing without verifying it" ;;
        esac
    else
        warn "no checksum file was published next to the Xray archive - continuing without verifying it"
    fi
    if ! "$xpy" -m zipfile -e "$xtmp/xray.zip" "$xtmp/out" >/dev/null 2>&1 || [ ! -f "$xtmp/out/xray" ]; then
        warn "the downloaded archive does not contain xray"; rm -rf "$xtmp"; return 1
    fi
    mkdir -p "$D$BINDIR"
    cp "$xtmp/out/xray" "$D$BINDIR/xray.new" && chmod 755 "$D$BINDIR/xray.new" && mv -f "$D$BINDIR/xray.new" "$D$BINDIR/xray" \
        || { warn "could not write $D$BINDIR/xray"; rm -rf "$xtmp"; return 1; }
    rm -rf "$xtmp"
    if [ -z "$DESTDIR" ] && [ "$OS" = Linux ] && have restorecon && [ -d /sys/fs/selinux ]; then
        restorecon "$BINDIR/xray" >/dev/null 2>&1 || true
    fi
    # remember that we installed it, so --uninstall removes it again (and leaves a copy somebody else installed alone)
    mkdir -p "$D$SHAREDIR/vpnman" 2>/dev/null && printf '%s\n' "$BINDIR/xray" > "$D$SHAREDIR/vpnman/xray-installed" 2>/dev/null || true
    say "Installed $BINDIR/xray ($("$D$BINDIR/xray" version 2>/dev/null | head -n 1 || echo 'version unknown'))"
    return 0
}

wrapper() {  # wrapper <path> <python args...>
    out=$1; shift
    mkdir -p "$(dirname "$out")"
    cat > "$out" <<WRAP
#!/bin/sh
# generated by VPNMan install.sh
# A desktop launcher starts us with a different PATH than a terminal does (pyenv, conda, linuxbrew, ~/.local/bin ...),
# so "python3" can be an interpreter that has no PyGObject. Pick one by capability instead of by name.
NEED_GI=0
case "\${1:-$*}" in gui*) NEED_GI=1 ;; esac
case "$*" in gui*) NEED_GI=1 ;; esac
usable() {
    [ -x "\$1" ] || return 1
    "\$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null || return 1
    [ "\$NEED_GI" -eq 0 ] && return 0
    "\$1" -c "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1')" 2>/dev/null
}
PY=\${VPNMAN_PYTHON:-}
if [ -z "\$PY" ]; then
    FIRST=
    for c in "${PY:-}" /usr/bin/python3 /usr/local/bin/python3 /bin/python3 /usr/pkg/bin/python3 /usr/bin/python3.13 \\
             /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3.10 /usr/bin/python3.9 \\
             python3 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
        [ -n "\$c" ] || continue
        case "\$c" in /*) ;; *) c=\$(command -v "\$c" 2>/dev/null) || continue ;; esac
        [ -x "\$c" ] || continue
        [ -n "\$FIRST" ] || FIRST=\$c
        if usable "\$c"; then PY=\$c; break; fi
    done
    PY=\${PY:-\$FIRST}
fi
[ -n "\$PY" ] || { echo "vpnman: no Python 3 interpreter found (install python3)" >&2; exit 127; }
# Never write bytecode caches into the (root-owned) install tree: Python validates them by source mtime + size only,
# so a same-size file with an equal mtime (rpm clamps all mtimes to one date) would keep running the OLD code.
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$LIBDIR\${PYTHONPATH:+:\$PYTHONPATH}"
export VPNMAN_DATA_DIR="$SHAREDIR/vpnman"
exec "\$PY" -m vpnman $* "\$@"
WRAP
    chmod 755 "$out"
}

render() {  # render <template> <dest> <mode>
    mkdir -p "$(dirname "$D$2")"
    sed "s|@BINDIR@|$BINDIR|g" "$1" > "$D$2"
    chmod "$3" "$D$2"
}

systemd_unit_dir() {
    if [ -n "$DESTDIR" ] || [ "$PREFIX" = /usr ]; then echo /usr/lib/systemd/system
    else echo /etc/systemd/system; fi
}

install_init() {
    case "$1" in
        systemd) render "$SRC/data/init/vpnmand.service" "$(systemd_unit_dir)/vpnmand.service" 644 ;;
        sysv) render "$SRC/data/init/vpnmand.sysv" /etc/init.d/vpnmand 755 ;;
        openrc) render "$SRC/data/init/vpnmand.openrc" /etc/init.d/vpnmand 755 ;;
        runit)
            sv=/etc/sv; [ -d /etc/runit/sv ] && [ ! -d /etc/sv ] && sv=/etc/runit/sv
            render "$SRC/data/init/runit/run" "$sv/vpnmand/run" 755
            render "$SRC/data/init/runit/log/run" "$sv/vpnmand/log/run" 755 ;;
        openbsd) render "$SRC/data/init/vpnmand.openbsd" /etc/rc.d/vpnmand 555 ;;
        freebsd) render "$SRC/data/init/vpnmand.freebsd" /usr/local/etc/rc.d/vpnmand 555 ;;
        none) ;;
        *) die "unknown init system: $1" ;;
    esac
}

APPID=io.github.smiley_mcsmiles.VPNMan
SYSTEM_SHARE=${VPNMAN_SYSTEM_SHARE:-/usr/share}      # overridable for tests

refresh_one_cache() {  # refresh_one_cache <hicolor dir>
    theme=$1
    [ -d "$theme" ] || return 0
    if [ -z "$(find "$theme" -type f ! -name 'icon-theme.cache' ! -name index.theme 2>/dev/null | head -n 1)" ]; then
        rm -f "$theme/icon-theme.cache"      # nothing left: a stale cache would advertise icons that are gone
    else
        for t in gtk4-update-icon-cache gtk-update-icon-cache; do
            if have "$t"; then "$t" -q -f -t "$theme" 2>/dev/null && break; fi
        done
    fi
}

refresh_icon_cache() {
    refresh_one_cache "$SHAREDIR/icons/hicolor"
    if [ "$SHAREDIR" != "$SYSTEM_SHARE" ]; then refresh_one_cache "$SYSTEM_SHARE/icons/hicolor"; fi
    for d in "$SHAREDIR/applications" "$SYSTEM_SHARE/applications"; do
        if have update-desktop-database && [ -d "$d" ]; then update-desktop-database -q "$d" 2>/dev/null || true; fi
    done
    return 0
}

# Desktops search $XDG_DATA_DIRS for launchers and icons. The default includes /usr/local/share, but sessions that
# set XDG_DATA_DIRS themselves (common with some display managers / Cinnamon session scripts) leave it out, and the
# launcher and icon then silently never show up. Linking them into /usr/share makes them visible in every case.
link_one() {  # link_one <real file> <path in the system dir>: a plain copy (some desktops ignore symlinked launchers)
    [ -f "$1" ] || return 0
    mkdir -p "$(dirname "$2")" 2>/dev/null || return 1
    rm -f "$2" 2>/dev/null
    cp "$1" "$2" 2>/dev/null && chmod 644 "$2"
}

link_system_dirs() {
    [ "$SYSLINKS" -eq 1 ] && [ "$OS" = Linux ] && [ "$SHAREDIR" != "$SYSTEM_SHARE" ] || return 0
    [ -d "$SYSTEM_SHARE" ] || return 0
    ok=1
    link_one "$SHAREDIR/applications/$APPID.desktop" "$SYSTEM_SHARE/applications/$APPID.desktop" || ok=0
    link_one "$SHAREDIR/metainfo/$APPID.metainfo.xml" "$SYSTEM_SHARE/metainfo/$APPID.metainfo.xml" || ok=0
    link_one "$SHAREDIR/pixmaps/$APPID.svg" "$SYSTEM_SHARE/pixmaps/$APPID.svg" || ok=0
    for f in "$SHAREDIR"/icons/hicolor/*/apps/"$APPID"*; do
        [ -f "$f" ] || continue
        rel=${f#"$SHAREDIR"/icons/hicolor/}
        link_one "$f" "$SYSTEM_SHARE/icons/hicolor/$rel" || ok=0
    done
    if [ "$ok" -eq 1 ]; then
        say "Linked the launcher and icons into $SYSTEM_SHARE (visible to every desktop session)"
    else
        warn "could not link the launcher/icons into $SYSTEM_SHARE (read-only?). If VPNMan is missing from your menu, reinstall with --prefix /usr"
    fi
}

unlink_system_dirs() {
    for l in "$SYSTEM_SHARE/applications/$APPID.desktop" "$SYSTEM_SHARE/metainfo/$APPID.metainfo.xml" \
             "$SYSTEM_SHARE/pixmaps/$APPID.svg" "$SYSTEM_SHARE"/icons/hicolor/*/apps/"$APPID"*; do
        if [ -L "$l" ]; then
            case "$(readlink "$l")" in "$SHAREDIR"/*) rm -f "$l" ;; esac       # links made by older versions
        elif [ -f "$l" ] && [ "$SHAREDIR" != "$SYSTEM_SHARE" ]; then
            rm -f "$l"
        fi
    done
}

uninstall() {
    say "Removing VPNMan"
    INIT_NOW=$INIT; [ "$INIT_NOW" = auto ] && INIT_NOW=$(detect_init)
    case "$INIT_NOW" in
        systemd) systemctl disable --now vpnmand 2>/dev/null || true ;;
        runit) rm -f /var/service/vpnmand /etc/service/vpnmand 2>/dev/null || true ;;
        openrc) rc-service vpnmand stop 2>/dev/null || true; rc-update del vpnmand default 2>/dev/null || true ;;
        sysv) /etc/init.d/vpnmand stop 2>/dev/null || true; update-rc.d -f vpnmand remove 2>/dev/null || true ;;
        openbsd) rcctl disable vpnmand 2>/dev/null || true; rcctl stop vpnmand 2>/dev/null || true ;;
    esac
    # firewall rules, routing rule/table and cgroup created by the daemon (while the program still exists)
    if [ -z "$DESTDIR" ] && [ -x "$BINDIR/vpnman" ]; then "$BINDIR/vpnman" cleanup --force >/dev/null 2>&1 || true; fi
    if [ -f "$D$SHAREDIR/vpnman/xray-installed" ]; then      # Xray is removed only when this installer put it there
        xbin=$(cat "$D$SHAREDIR/vpnman/xray-installed" 2>/dev/null)
        [ -n "$xbin" ] && rm -f "$D$xbin"
    fi
    rm -rf "$D$LIBDIR" "$D$SHAREDIR/vpnman"
    rm -f "$D$BINDIR/vpnman" "$D$BINDIR/vpnmand" "$D$BINDIR/vpnman-gtk"
    rm -f "$D$SHAREDIR/applications/io.github.smiley_mcsmiles.VPNMan.desktop" \
          "$D$SHAREDIR/metainfo/io.github.smiley_mcsmiles.VPNMan.metainfo.xml" \
          "$D$SHAREDIR/icons/hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan.svg" \
          "$D$SHAREDIR/pixmaps/io.github.smiley_mcsmiles.VPNMan.svg" \
          "$D$MANDIR/vpnman.1" "$D$SHAREDIR/bash-completion/completions/vpnman" \
          "$D$SHAREDIR/zsh/site-functions/_vpnman" "$D$SHAREDIR/fish/vendor_completions.d/vpnman.fish"
    rm -f "$D$SHAREDIR"/icons/hicolor/symbolic/apps/io.github.smiley_mcsmiles.VPNMan*.svg \
          "$D$SHAREDIR"/icons/hicolor/*/apps/io.github.smiley_mcsmiles.VPNMan.png
    if [ -z "$DESTDIR" ]; then unlink_system_dirs; refresh_icon_cache; fi
    rm -f "$D/etc/systemd/system/vpnmand.service" "$D/usr/lib/systemd/system/vpnmand.service" \
          "$D/etc/init.d/vpnmand" "$D/etc/rc.d/vpnmand" "$D/usr/local/etc/rc.d/vpnmand"
    rm -rf "$D/etc/sv/vpnmand" "$D/etc/runit/sv/vpnmand"
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$D/etc/vpnman"
        say "Purged /etc/vpnman"
    else
        say "Kept /etc/vpnman (profiles, settings). Use --purge to delete."
    fi
    have systemctl && [ -z "$DESTDIR" ] && systemctl daemon-reload 2>/dev/null || true
    # a stale kill switch must never outlive the software that owns it
    if [ -z "$DESTDIR" ]; then
        have nft && nft delete table inet vpnman 2>/dev/null || true
        have nft && nft delete table inet vpnman_proxy 2>/dev/null || true
        have nft && nft delete table inet vpnman_block 2>/dev/null || true
    fi
    exit 0
}

if [ "$UNINSTALL" -eq 1 ]; then uninstall; fi
if [ "$XRAY_ONLY" -eq 1 ]; then
    install_xray || exit 1
    exit 0
fi
if [ "$CHECK" -eq 1 ]; then
    say "Checking this machine ($OS, init: $(detect_init))"
    preflight
    if [ -z "$WARNINGS" ]; then say "Everything looks good."; else printf '\nTo fix:%s\n' "$WARNINGS"; fi
    exit 0
fi
if [ "$DEPS" -eq 1 ]; then
    install_deps
    if ! have xray && [ -z "$DESTDIR" ]; then install_xray || true; fi
fi

[ -d "$SRC/vpnman" ] && [ -d "$SRC/data" ] || die "run install.sh from the extracted VPNMan directory (vpnman/ and data/ must be next to it)"
if [ -z "$DESTDIR" ]; then preflight; fi        # staging for a package must not depend on the build machine

say "Installing VPNMan to $D$PREFIX"
rm -rf "$D$LIBDIR"
mkdir -p "$D$LIBDIR"
cp -R "$SRC/vpnman" "$D$LIBDIR/vpnman"
find "$D$LIBDIR" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

mkdir -p "$D/etc/vpnman" && chmod 700 "$D/etc/vpnman"
mkdir -p "$D$SHAREDIR/vpnman"
cp -R "$SRC/data/init" "$D$SHAREDIR/vpnman/init"

wrapper "$D$BINDIR/vpnman"
wrapper "$D$BINDIR/vpnmand" daemon
wrapper "$D$BINDIR/vpnman-gtk" gui

mkdir -p "$D$SHAREDIR/applications" "$D$SHAREDIR/metainfo" "$D$MANDIR" \
         "$D$SHAREDIR/icons/hicolor/scalable/apps" "$D$SHAREDIR/icons/hicolor/symbolic/apps"
cp "$SRC/data/io.github.smiley_mcsmiles.VPNMan.desktop" "$D$SHAREDIR/applications/"
cp "$SRC/data/io.github.smiley_mcsmiles.VPNMan.metainfo.xml" "$D$SHAREDIR/metainfo/"
cp "$SRC/data/icons/hicolor/scalable/apps/"*.svg "$D$SHAREDIR/icons/hicolor/scalable/apps/"
cp "$SRC/data/icons/hicolor/symbolic/apps/"*.svg "$D$SHAREDIR/icons/hicolor/symbolic/apps/"
for sz in 48x48 64x64 128x128 256x256; do
    mkdir -p "$D$SHAREDIR/icons/hicolor/$sz/apps"
    cp "$SRC/data/icons/hicolor/$sz/apps/"*.png "$D$SHAREDIR/icons/hicolor/$sz/apps/"
done
# Flat fallback with no cache at all: used by GTK/GNOME Shell/Cinnamon when the themed lookup fails
mkdir -p "$D$SHAREDIR/pixmaps"
cp "$SRC/data/icons/hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan.svg" "$D$SHAREDIR/pixmaps/"
# A private, cache-free copy: GTK trusts a stale icon-theme.cache (it only checks the mtime of hicolor/ itself),
# so the app falls back to this copy - and hands it to the tray host - when the system theme misses the icons.
mkdir -p "$D$SHAREDIR/vpnman/icons"
cp -R "$SRC/data/icons/hicolor" "$D$SHAREDIR/vpnman/icons/"
cp "$SRC/data/vpnman.1" "$D$MANDIR/vpnman.1"
# shell completions (generated from the real argument parser by tools/gen_completions.py)
if [ -d "$SRC/data/completions" ]; then
    mkdir -p "$D$SHAREDIR/bash-completion/completions" "$D$SHAREDIR/zsh/site-functions" "$D$SHAREDIR/fish/vendor_completions.d"
    cp "$SRC/data/completions/vpnman.bash" "$D$SHAREDIR/bash-completion/completions/vpnman"
    cp "$SRC/data/completions/_vpnman" "$D$SHAREDIR/zsh/site-functions/_vpnman"
    cp "$SRC/data/completions/vpnman.fish" "$D$SHAREDIR/fish/vendor_completions.d/vpnman.fish"
    chmod 644 "$D$SHAREDIR/bash-completion/completions/vpnman" "$D$SHAREDIR/zsh/site-functions/_vpnman" \
              "$D$SHAREDIR/fish/vendor_completions.d/vpnman.fish"
fi
# the launcher must find the wrapper even for non-default prefixes
sed -i.bak "s|^Exec=.*|Exec=$BINDIR/vpnman-gtk|" "$D$SHAREDIR/applications/io.github.smiley_mcsmiles.VPNMan.desktop" 2>/dev/null \
    && rm -f "$D$SHAREDIR/applications/io.github.smiley_mcsmiles.VPNMan.desktop.bak"

# `cp` keeps the source file modes: a tarball extracted with a strict umask would otherwise install files
# that normal users (who run the GUI and CLI) cannot read.
chmod -R go+rX "$D$LIBDIR" "$D$SHAREDIR/vpnman"
chmod 644 "$D$SHAREDIR/applications/io.github.smiley_mcsmiles.VPNMan.desktop" \
          "$D$SHAREDIR/metainfo/io.github.smiley_mcsmiles.VPNMan.metainfo.xml" \
          "$D$SHAREDIR/pixmaps/io.github.smiley_mcsmiles.VPNMan.svg" "$D$MANDIR/vpnman.1"
find "$D$SHAREDIR/icons/hicolor" -name 'io.github.smiley_mcsmiles.VPNMan*' -type f -exec chmod 644 {} +
chmod 755 "$D$BINDIR/vpnman" "$D$BINDIR/vpnmand" "$D$BINDIR/vpnman-gtk"
# pre-compile so unprivileged users (who cannot write to /usr) do not recompile on every start
# (checked-hash: validated against the source contents, immune to mtime games)
if [ -z "$DESTDIR" ]; then "$PY" -m compileall -q --invalidation-mode checked-hash "$D$LIBDIR" >/dev/null 2>&1 || "$PY" -m compileall -q "$D$LIBDIR" >/dev/null 2>&1 || true; fi

if [ "$INIT" = auto ]; then INIT=$(detect_init); fi
case "$INIT" in
    all-linux) install_init systemd; install_init sysv ;;
    *) install_init "$INIT" ;;
esac
say "Service definition installed for: $INIT"

enable_service() {
    case "$INIT" in
        systemd) try systemctl daemon-reload; try systemctl enable vpnmand; try systemctl restart vpnmand ;;
        runit)
            sv=/etc/sv
            if [ ! -d /etc/sv ] && [ -d /etc/runit/sv ]; then sv=/etc/runit/sv; fi
            link=""
            for d in /var/service /etc/service /service /etc/runit/runsvdir/default /etc/runit/runsvdir/current; do
                if [ -d "$d" ]; then link=$d; break; fi
            done
            if [ -z "$link" ]; then
                warn "no runit service directory found (/var/service, /etc/service); link $sv/vpnmand into yours"
            else
                try ln -sf "$sv/vpnmand" "$link/vpnmand"      # runsvdir notices new services within ~5 seconds
                # upgrade: a service that is already running keeps running the OLD code until restarted
                if have sv && [ -e "$link/vpnmand/supervise/ok" ]; then try sv restart "$link/vpnmand"; fi
            fi ;;
        openrc) try rc-update add vpnmand default; try rc-service vpnmand restart ;;
        sysv)
            if have update-rc.d; then try update-rc.d vpnmand defaults
            elif have chkconfig; then try chkconfig --add vpnmand
            elif have insserv; then try insserv vpnmand
            else warn "no update-rc.d/chkconfig: vpnmand will not start at boot (it was started now)"
            fi
            try /etc/init.d/vpnmand restart ;;
        openbsd) try rcctl enable vpnmand; try rcctl restart vpnmand ;;
        freebsd) try sysrc vpnmand_enable=YES; try service vpnmand restart ;;
        none) warn "no init system detected - start the daemon yourself with: vpnmand" ;;
    esac
}

# The GUI keeps running in the tray after its window is closed, so an upgrade would otherwise leave the OLD code
# running (and a second launch would just re-open that old instance). Ask running copies to quit; the user simply
# starts the app again.
stop_running_gui() {
    if have pkill; then
        if pkill -f -- '^[^ ]*python[0-9.]* -m vpnman gui' 2>/dev/null || pkill -f -- '^[^ ]*python[0-9.]* -m vpnman.gui.trayhelper' 2>/dev/null; then
            say "Closed the running VPNMan window so the new version starts next time"
        fi
    fi
    return 0
}

wait_for_daemon() {  # exit status of `vpnman status`: 0/3 = daemon answered, anything else = not (yet)
    i=0
    while [ $i -lt 30 ]; do
        rc=0
        "$BINDIR/vpnman" status >/dev/null 2>&1 || rc=$?
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ]; then return 0; fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

diagnose_daemon() {
    warn "the vpnmand service did not answer within 30 seconds"
    printf '\n--- diagnostics ---\n' >&2
    "$BINDIR/vpnman" --version >&2 2>&1 || printf 'the vpnman program itself fails to start (see the error above)\n' >&2
    case "$INIT" in
        systemd) systemctl --no-pager --lines=12 status vpnmand >&2 2>&1 || true ;;
        runit) sv status vpnmand >&2 2>&1 || true
               if ! pgrep -x runsvdir >/dev/null 2>&1; then
                   printf 'runsvdir does not appear to be running - nothing supervises /var/service on this system\n' >&2
               fi
               if [ -f /var/log/vpnmand/current ]; then tail -n 15 /var/log/vpnmand/current >&2; fi ;;
        openrc|sysv) /etc/init.d/vpnmand status >&2 2>&1 || true
                     if [ -f /var/log/vpnmand.out ]; then tail -n 15 /var/log/vpnmand.out >&2; fi ;;
    esac
    printf -- '-------------------\nRun "vpnman doctor" for more, or start it by hand: %s/vpnmand\n\n' "$BINDIR" >&2
}

if [ -z "$DESTDIR" ] && { [ "$DO_POST" -eq 1 ] || [ -n "${VPNMAN_SYSTEM_SHARE:-}" ]; }; then
    link_system_dirs
fi

# SELinux (Fedora, RHEL): files copied out of a home directory can carry a context the shell/launchers may not read
if [ -z "$DESTDIR" ] && [ "$OS" = Linux ] && have restorecon && [ -d /sys/fs/selinux ]; then
    restorecon -R "$LIBDIR" "$SHAREDIR/vpnman" "$SHAREDIR/applications/$APPID.desktop" "$SHAREDIR/icons/hicolor" \
        "$SYSTEM_SHARE/applications/$APPID.desktop" "$SYSTEM_SHARE/icons/hicolor" "$BINDIR/vpnman" "$BINDIR/vpnmand" \
        "$BINDIR/vpnman-gtk" >/dev/null 2>&1 || true
fi
if [ -z "$DESTDIR" ] && have desktop-file-validate; then
    desktop-file-validate "$SHAREDIR/applications/$APPID.desktop" >&2 2>&1 || warn "the launcher failed desktop-file-validate (see above)"
fi

if [ "$DO_POST" -eq 1 ] && [ -z "$DESTDIR" ]; then
    mkdir -p /etc/vpnman && chmod 700 /etc/vpnman
    if ! grep -q "^$GROUP:" /etc/group 2>/dev/null; then
        say "Creating group '$GROUP'"
        if have groupadd; then groupadd -r "$GROUP" 2>/dev/null || groupadd "$GROUP" || warn "could not create group $GROUP"
        elif have addgroup; then addgroup -S "$GROUP" || warn "could not create group $GROUP"
        elif have pw; then pw groupadd "$GROUP" || warn "could not create group $GROUP"
        else warn "no groupadd/addgroup - create the '$GROUP' group yourself (optional on Linux)"
        fi
    fi
    TARGET_USER=${SUDO_USER:-${DOAS_USER:-}}
    if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != root ] && grep -q "^$GROUP:" /etc/group 2>/dev/null; then
        say "Adding $TARGET_USER to group '$GROUP'"
        if [ "$OS" = OpenBSD ]; then
            others=$(id -Gn "$TARGET_USER" | tr ' ' ',')
            try usermod -G "$others,$GROUP" "$TARGET_USER"
        elif have usermod && [ "$OS" = Linux ]; then try usermod -aG "$GROUP" "$TARGET_USER"
        elif have adduser && [ "$OS" = Linux ]; then try adduser "$TARGET_USER" "$GROUP"
        elif have pw; then try pw groupmod "$GROUP" -m "$TARGET_USER"
        fi
    fi
    refresh_icon_cache
    stop_running_gui
    enable_service
    say "Waiting for the VPNMan service to start"
    if wait_for_daemon; then
        say "Service is running"
    else
        diagnose_daemon
    fi
    # Desktop integration: menus and icons are looked up through XDG_DATA_DIRS
    case ":${XDG_DATA_DIRS:-$SHAREDIR:/usr/share}:" in
        *":$SHAREDIR:"*) ;;
        *) warn "$SHAREDIR is not in XDG_DATA_DIRS, so your desktop may not show the VPNMan launcher/icon. Reinstall with --prefix /usr, or add it to XDG_DATA_DIRS" ;;
    esac
fi

if [ "$INSTALL_XRAY" -eq 1 ] && [ -z "$DESTDIR" ]; then install_xray || true; fi

# An interactive install offers Xray when it is missing.  Never for package builds (--no-post), never without a
# terminal to answer on (curl | sh, scripts, CI), never with --no-xray.
if [ "$INSTALL_XRAY" -eq 0 ] && [ "$NO_XRAY" -eq 0 ] && [ "$DO_POST" -eq 1 ] && [ -t 0 ] && [ -t 1 ] \
        && ! have xray && [ ! -x "$D$BINDIR/xray" ]; then
    printf '\nXray is not installed. VPNMan uses it for the proxies (VLESS, VMess, Trojan, Shadowsocks) and for the\n'
    printf 'Network Proxy. Download the official release (checksum verified) and install it as %s/xray? [Y/n] ' "$BINDIR"
    ans=""
    read -r ans || ans=n
    case "$ans" in
        ""|y|Y|yes|Yes|YES) install_xray || true ;;
        *) say "Skipped. Install it later with: sudo sh $0 --xray-only" ;;
    esac
fi

if [ -n "$WARNINGS" ]; then
    printf '\nVPNMan is installed, with warnings:%s\n' "$WARNINGS"
else
    printf '\nVPNMan is installed.\n'
fi
cat <<DONE

  GUI:  vpnman-gtk          CLI:  vpnman   (interactive menu)   Daemon: vpnmand
  Import a profile:  vpnman import my.ovpn      Kill switch:  vpnman lock on
Open VPNMan from your application menu (log out and in if it does not show up yet).
Run "vpnman doctor" to check the service, icons and which protocols have their tools installed.
DONE
