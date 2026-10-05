#!/bin/sh
# VPNMan installer - POSIX sh, runs on Linux (systemd, runit, OpenRC, SysV) and the BSDs.
#
#   sudo ./install.sh                  install to /usr/local, set up the service for this machine
#   sudo ./install.sh --prefix /usr    choose another prefix
#   DESTDIR=/tmp/stage ./install.sh --init systemd --no-post    stage files for a package
#   sudo ./install.sh --uninstall [--purge]
#   sudo ./install.sh --install-deps   install dependencies with the native package manager first
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
CHECK=0
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
  --install-deps      install runtime dependencies first (apt, dnf, pacman, xbps, apk, zypper, pkg_add, pkg)
  --check             only report what is missing on this machine; install nothing
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
        --check) CHECK=1 ;;
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
if [ -z "$DESTDIR" ] && [ "$CHECK" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "run as root (try: sudo sh $0 $*   or: doas sh $0 $*   or: su -c 'sh $0 $*')"
fi

LIBDIR=$PREFIX/lib/vpnman
SHAREDIR=$PREFIX/share
BINDIR=$PREFIX/bin
MANDIR=$SHAREDIR/man/man1
[ "$OS" = OpenBSD ] && MANDIR=$PREFIX/man/man1
D=$DESTDIR

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
        apt-get) echo "apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1" ;;
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
                 REQ="python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 iproute2"
                 OPT="openvpn wireguard-tools nftables openresolv desktop-file-utils libgtk-4-bin stunnel4" ;;
        dnf) REQ="python3 python3-gobject gtk4 libadwaita iproute"
             OPT="openvpn wireguard-tools nftables desktop-file-utils gtk-update-icon-cache stunnel" ;;
        pacman) REQ="python python-gobject gtk4 libadwaita iproute2"
                OPT="openvpn wireguard-tools nftables desktop-file-utils stunnel" ;;
        xbps-install) REQ="python3 python3-gobject gtk4 libadwaita iproute2"
                      OPT="openvpn wireguard-tools nftables polkit desktop-file-utils gtk-update-icon-cache stunnel" ;;
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
    if ! have openvpn && ! have wg && ! have wg-quick; then
        warn "no VPN client found yet - install openvpn and/or wireguard-tools (see: vpnman protocols)"
    fi
    if ! have nft && ! have iptables && ! have pfctl; then
        warn "no firewall tool (nft, iptables or pfctl) - the kill switch will be unavailable until one is installed"
    fi
    if [ -z "$(detect_init | grep -v none)" ]; then
        warn "could not detect your init system; the service will not be set up automatically (use --init to choose one)"
    fi
}

wrapper() {  # wrapper <path> <python args...>
    out=$1; shift
    mkdir -p "$(dirname "$out")"
    cat > "$out" <<WRAP
#!/bin/sh
# generated by VPNMan install.sh
PY=\${VPNMAN_PYTHON:-}
if [ -z "\$PY" ]; then
    for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
        if command -v "\$c" >/dev/null 2>&1; then PY=\$c; break; fi
    done
fi
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

refresh_icon_cache() {
    theme=$SHAREDIR/icons/hicolor
    if [ -d "$theme" ] && [ -z "$(find "$theme" -type f ! -name 'icon-theme.cache' ! -name index.theme 2>/dev/null | head -n 1)" ]; then
        rm -f "$theme/icon-theme.cache"      # nothing left: a stale cache would advertise icons that are gone
    else
        for t in gtk4-update-icon-cache gtk-update-icon-cache; do
            if have "$t"; then "$t" -q -f -t "$theme" 2>/dev/null && break; fi
        done
    fi
    if have update-desktop-database; then update-desktop-database -q "$SHAREDIR/applications" 2>/dev/null; fi
    return 0
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
    rm -rf "$D$LIBDIR" "$D$SHAREDIR/vpnman"
    rm -f "$D$BINDIR/vpnman" "$D$BINDIR/vpnmand" "$D$BINDIR/vpnman-gtk"
    rm -f "$D$SHAREDIR/applications/io.github.smiley_mcsmiles.VPNMan.desktop" \
          "$D$SHAREDIR/metainfo/io.github.smiley_mcsmiles.VPNMan.metainfo.xml" \
          "$D$SHAREDIR/icons/hicolor/scalable/apps/io.github.smiley_mcsmiles.VPNMan.svg" \
          "$D$SHAREDIR/pixmaps/io.github.smiley_mcsmiles.VPNMan.svg" \
          "$D$MANDIR/vpnman.1"
    rm -f "$D$SHAREDIR"/icons/hicolor/symbolic/apps/io.github.smiley_mcsmiles.VPNMan*.svg \
          "$D$SHAREDIR"/icons/hicolor/*/apps/io.github.smiley_mcsmiles.VPNMan.png
    if [ -z "$DESTDIR" ]; then refresh_icon_cache; fi
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
    fi
    exit 0
}

if [ "$UNINSTALL" -eq 1 ]; then uninstall; fi
if [ "$CHECK" -eq 1 ]; then
    say "Checking this machine ($OS, init: $(detect_init))"
    preflight
    if [ -z "$WARNINGS" ]; then say "Everything looks good."; else printf '\nTo fix:%s\n' "$WARNINGS"; fi
    exit 0
fi
if [ "$DEPS" -eq 1 ]; then install_deps; fi

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
if [ -z "$DESTDIR" ]; then "$PY" -m compileall -q "$D$LIBDIR" >/dev/null 2>&1 || true; fi

if [ "$INIT" = auto ]; then INIT=$(detect_init); fi
case "$INIT" in
    all-linux) install_init systemd; install_init sysv ;;
    *) install_init "$INIT" ;;
esac
say "Service definition installed for: $INIT"

enable_service() {
    case "$INIT" in
        systemd) try systemctl daemon-reload; try systemctl enable --now vpnmand ;;
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
            fi ;;
        openrc) try rc-update add vpnmand default; try rc-service vpnmand start ;;
        sysv)
            if have update-rc.d; then try update-rc.d vpnmand defaults
            elif have chkconfig; then try chkconfig --add vpnmand
            elif have insserv; then try insserv vpnmand
            else warn "no update-rc.d/chkconfig: vpnmand will not start at boot (it was started now)"
            fi
            try /etc/init.d/vpnmand start ;;
        openbsd) try rcctl enable vpnmand; try rcctl start vpnmand ;;
        freebsd) try sysrc vpnmand_enable=YES; try service vpnmand start ;;
        none) warn "no init system detected - start the daemon yourself with: vpnmand" ;;
    esac
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
