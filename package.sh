#!/usr/bin/env bash
# Build distributable packages for VPNMan into ./dist
#
#   ./package.sh            build everything that can be built on this machine, and
#                           generate recipes (PKGBUILD, spec, template, APKBUILD, port) for the rest
#   ./package.sh tar deb    build selected targets
#   ./package.sh --container rpm    build inside a Fedora container (podman/docker) - works from any distro
#
# Targets: tar  deb  rpm  arch  void  alpine  openbsd  recipes  clean
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' vpnman/__init__.py)
NAME=vpnman
DIST=$ROOT/dist
BUILD=$ROOT/build
SRCNAME=$NAME-$VERSION
URL=https://github.com/Smiley-McSmiles/VPNMan
DESC="Multi-protocol VPN manager with GTK4/libadwaita UI, interactive CLI and kill switch"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Files that make up the program, shared by every package type.
SRC_ITEMS=(vpnman data packaging install.sh package.sh README.md LICENSE tests)

stage() {  # stage <destdir> <init>
    local dest=$1 init=$2
    rm -rf "$dest"
    mkdir -p "$dest"
    DESTDIR=$dest "$ROOT/install.sh" --prefix /usr --init "$init" --no-post >/dev/null
    find "$dest" -name '*.pyc' -delete
    find "$dest" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
}

build_tar() {
    log "tarball"
    mkdir -p "$DIST" "$BUILD"
    local t=$BUILD/$SRCNAME
    rm -rf "$t"
    mkdir -p "$t"
    for i in "${SRC_ITEMS[@]}"; do [ -e "$i" ] && cp -R "$i" "$t/"; done
    find "$t" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
    # normalise modes so the archive installs correctly whatever the packager's umask was
    chmod -R u+rwX,go+rX,go-w "$t"
    chmod 755 "$t/install.sh" "$t/package.sh"
    tar -C "$BUILD" -czf "$DIST/$SRCNAME.tar.gz" "$SRCNAME"
    log "  -> dist/$SRCNAME.tar.gz"
}

build_deb() {
    have python3 || { warn "python3 not found, skipping deb"; return; }
    log "deb"
    local root=$BUILD/deb/${NAME}_$VERSION
    stage "$root" all-linux
    mkdir -p "$root/DEBIAN" "$root/usr/share/doc/$NAME"
    cp LICENSE "$root/usr/share/doc/$NAME/copyright"
    gzip -9n "$root/usr/share/man/man1/vpnman.1"
    local size
    size=$(du -sk "$root" | cut -f1)
    cat > "$root/DEBIAN/control" <<CTL
Package: $NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Installed-Size: $size
Depends: python3 (>= 3.9), python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1 (>= 1.4), iproute2
Recommends: openvpn, wireguard-tools, nftables | iptables, openresolv | resolvconf
Suggests: stunnel4, gnome-shell-extension-appindicator, openconnect, openfortivpn, sstp-client, pptp-linux, strongswan-swanctl, vpnc, network-manager
Maintainer: VPNMan contributors <noreply@example.invalid>
Homepage: $URL
Description: $DESC
 VPNMan manages OpenVPN, WireGuard, AmneziaWG, OpenConnect, Fortinet, SSTP,
 IKEv2, Tailscale and other tunnels, with a network lock (kill switch) based
 on nftables, iptables or pf. Works with systemd, runit, OpenRC and SysV init.
CTL
    cat > "$root/DEBIAN/postinst" <<'PST'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    find /usr/lib/vpnman -name __pycache__ -type d -exec rm -rf {} + >/dev/null 2>&1 || true
    getent group vpnman >/dev/null || addgroup --system vpnman >/dev/null 2>&1 || groupadd -r vpnman
    mkdir -p /etc/vpnman && chmod 700 /etc/vpnman
# GTK only validates icon-theme.cache against the mtime of hicolor/ itself, so new icons stay invisible until it is rebuilt
    for d in /usr/share/icons/hicolor /usr/local/share/icons/hicolor; do
        [ -d "$d" ] || continue
        for t in gtk4-update-icon-cache gtk-update-icon-cache; do
            if command -v $t >/dev/null 2>&1; then $t -q -f -t "$d" >/dev/null 2>&1 && break; fi
        done
    done
    if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || :; fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl enable vpnmand || true
        systemctl restart vpnmand || true      # restart (not just start): an upgrade must replace the running daemon
    elif [ -x /etc/init.d/vpnmand ]; then
        update-rc.d vpnmand defaults >/dev/null 2>&1 || true
        /etc/init.d/vpnmand restart || true
    fi
    pkill -f -- '^[^ ]*python[0-9.]* -m vpnman gui' >/dev/null 2>&1 || true
fi
exit 0
PST
    cat > "$root/DEBIAN/prerm" <<'PRM'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = upgrade ]; then
    if [ -d /run/systemd/system ]; then systemctl stop vpnmand || true
    elif [ -x /etc/init.d/vpnmand ]; then /etc/init.d/vpnmand stop || true; fi
fi
exit 0
PRM
    cat > "$root/DEBIAN/postrm" <<'PRM'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    command -v nft >/dev/null 2>&1 && nft delete table inet vpnman 2>/dev/null || true
    [ -d /run/systemd/system ] && systemctl daemon-reload || true
fi
if [ "$1" = remove ] || [ "$1" = purge ]; then
# GTK only validates icon-theme.cache against the mtime of hicolor/ itself, so new icons stay invisible until it is rebuilt
for d in /usr/share/icons/hicolor /usr/local/share/icons/hicolor; do
    [ -d "$d" ] || continue
    for t in gtk4-update-icon-cache gtk-update-icon-cache; do
        if command -v $t >/dev/null 2>&1; then $t -q -f -t "$d" >/dev/null 2>&1 && break; fi
    done
done
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || :; fi
fi
if [ "$1" = purge ]; then rm -rf /etc/vpnman; fi
exit 0
PRM
    chmod 755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
    mkdir -p "$DIST"
    # works on any distribution: packaging/mkdeb.py writes the ar/tar structure itself
    python3 "$ROOT/packaging/mkdeb.py" "$root" "$DIST/${NAME}_${VERSION}_all.deb"
    log "  -> dist/${NAME}_${VERSION}_all.deb"
}

recipe_rpm() {
    mkdir -p "$DIST/recipes"
    cat > "$DIST/recipes/$NAME.spec" <<SPEC
# Do not clamp file mtimes to the changelog date: with identical mtimes and same-size edits (1.0.0 -> 1.0.2) Python
# keeps trusting stale __pycache__ files and the upgraded program silently keeps running the old code.
%global clamp_mtime_to_source_date_epoch 0
%global source_date_epoch_from_changelog 0

Name:           $NAME
Version:        $VERSION
Release:        1%{?dist}
Summary:        $DESC
License:        MIT
URL:            $URL
Source0:        $SRCNAME.tar.gz
BuildArch:      noarch
Requires:       python3 >= 3.9, python3-gobject, gtk4, libadwaita >= 1.4, iproute
Recommends:     openvpn, wireguard-tools, nftables
Suggests:       stunnel, gnome-shell-extension-appindicator, openconnect, openfortivpn, strongswan, NetworkManager

%description
VPNMan manages OpenVPN, WireGuard, AmneziaWG, OpenConnect, Fortinet, SSTP, IKEv2,
Tailscale and more, with a kill switch for nftables, iptables and pf.

%prep
%autosetup -n $SRCNAME

%install
DESTDIR=%{buildroot} ./install.sh --prefix /usr --init systemd --no-post
mkdir -p %{buildroot}/etc/vpnman

%post
# stale compiled caches from the previous version must never survive an upgrade
find /usr/lib/vpnman -name __pycache__ -type d -exec rm -rf {} + >/dev/null 2>&1 || :
getent group vpnman >/dev/null || groupadd -r vpnman
mkdir -p /etc/vpnman && chmod 700 /etc/vpnman
# GTK only validates icon-theme.cache against the mtime of hicolor/ itself, so new icons stay invisible until it is rebuilt
for d in /usr/share/icons/hicolor /usr/local/share/icons/hicolor; do
    [ -d "\$d" ] || continue
    for t in gtk4-update-icon-cache gtk-update-icon-cache; do
        if command -v \$t >/dev/null 2>&1; then \$t -q -f -t "\$d" >/dev/null 2>&1 && break; fi
    done
done
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || :; fi
# plain systemctl (no distro macros) so the spec builds on any rpm-based distro;
# the distro preset would leave an unknown service disabled, so enable and start explicitly
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl enable vpnmand.service >/dev/null 2>&1 || :
    systemctl restart vpnmand.service >/dev/null 2>&1 || :
fi
# a GUI left running in the tray would keep executing the old version
pkill -f -- '^[^ ]*python[0-9.]* -m vpnman gui' >/dev/null 2>&1 || :

%preun
if [ "\$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now vpnmand.service >/dev/null 2>&1 || :
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
# GTK only validates icon-theme.cache against the mtime of hicolor/ itself, so new icons stay invisible until it is rebuilt
for d in /usr/share/icons/hicolor /usr/local/share/icons/hicolor; do
    [ -d "\$d" ] || continue
    for t in gtk4-update-icon-cache gtk-update-icon-cache; do
        if command -v \$t >/dev/null 2>&1; then \$t -q -f -t "\$d" >/dev/null 2>&1 && break; fi
    done
done
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || :; fi

if [ "\$1" -eq 0 ] && command -v nft >/dev/null 2>&1; then
    nft delete table inet vpnman >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%dir %attr(0700,root,root) /etc/vpnman
/usr/bin/vpnman
/usr/bin/vpnmand
/usr/bin/vpnman-gtk
/usr/lib/vpnman
/usr/lib/systemd/system/vpnmand.service
/usr/share/vpnman
/usr/share/applications/io.github.smiley_mcsmiles.VPNMan.desktop
/usr/share/metainfo/io.github.smiley_mcsmiles.VPNMan.metainfo.xml
/usr/share/icons/hicolor/*/apps/io.github.smiley_mcsmiles.VPNMan*
/usr/share/pixmaps/io.github.smiley_mcsmiles.VPNMan.svg
/usr/share/man/man1/vpnman.1*

%changelog
* Mon Oct 05 2026 VPNMan contributors <noreply@example.invalid> - $VERSION-1
- Packaged VPNMan $VERSION
SPEC
}

build_rpm() {
    recipe_rpm
    have rpmbuild || { warn "rpmbuild not found; spec written to dist/recipes/$NAME.spec"; return; }
    log "rpm"
    build_tar
    local top=$BUILD/rpm
    rm -rf "$top"
    mkdir -p "$top"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
    cp "$DIST/$SRCNAME.tar.gz" "$top/SOURCES/"
    cp "$DIST/recipes/$NAME.spec" "$top/SPECS/"
    rpmbuild --define "_topdir $top" -bb "$top/SPECS/$NAME.spec" >/dev/null
    cp "$top"/RPMS/*/*.rpm "$DIST/"
    log "  -> $(ls "$DIST"/*.rpm)"
}

recipe_arch() {
    mkdir -p "$DIST/recipes/arch"
    cat > "$DIST/recipes/arch/PKGBUILD" <<PKG
# Maintainer: VPNMan contributors
pkgname=$NAME
pkgver=$VERSION
pkgrel=1
pkgdesc="$DESC"
arch=('any')
url="$URL"
license=('MIT')
depends=('python' 'python-gobject' 'gtk4' 'libadwaita' 'iproute2')
optdepends=('openvpn: OpenVPN' 'wireguard-tools: WireGuard' 'nftables: kill switch (preferred)'
            'iptables: kill switch fallback' 'openconnect: AnyConnect/GlobalProtect' 'openfortivpn: Fortinet'
            'strongswan: IKEv2' 'networkmanager: L2TP and others')
source=("\$pkgname-\$pkgver.tar.gz")
sha256sums=('SKIP')

package() {
  cd "\$srcdir/\$pkgname-\$pkgver"
  DESTDIR="\$pkgdir" ./install.sh --prefix /usr --init systemd --no-post
  install -Dm644 LICENSE "\$pkgdir/usr/share/licenses/\$pkgname/LICENSE"
}
PKG
}

build_arch() {
    recipe_arch
    build_tar
    cp "$DIST/$SRCNAME.tar.gz" "$DIST/recipes/arch/"
    have makepkg || { warn "makepkg not found; PKGBUILD written to dist/recipes/arch"; return; }
    log "arch"
    (cd "$DIST/recipes/arch" && makepkg -f --skipinteg >/dev/null) && cp "$DIST"/recipes/arch/*.pkg.tar.* "$DIST/"
}

recipe_void() {
    mkdir -p "$DIST/recipes/void"
    cat > "$DIST/recipes/void/template" <<TPL
# Template file for 'vpnman' (copy to srcpkgs/vpnman/template in void-packages)
pkgname=$NAME
version=$VERSION
revision=1
depends="python3 python3-gobject gtk4 libadwaita iproute2 nftables openvpn wireguard-tools"
short_desc="$DESC"
maintainer="VPNMan contributors <noreply@example.invalid>"
license="MIT"
homepage="$URL"
distfiles="\${homepage}/archive/refs/tags/v\${version}.tar.gz"
checksum=SKIP
build_style=gnu-makefile
do_build() { :; }
do_install() {
	DESTDIR=\${DESTDIR} ./install.sh --prefix /usr --init runit --no-post
	vlicense LICENSE
}
post_install() {
	# runit: enable with  ln -s /etc/sv/vpnmand /var/service/
	:
}
TPL
}

recipe_alpine() {
    mkdir -p "$DIST/recipes/alpine"
    cat > "$DIST/recipes/alpine/APKBUILD" <<APK
# Maintainer: VPNMan contributors <noreply@example.invalid>
pkgname=$NAME
pkgver=$VERSION
pkgrel=0
pkgdesc="$DESC"
url="$URL"
arch="noarch"
license="MIT"
depends="python3 py3-gobject3 gtk4.0 libadwaita iproute2 nftables openvpn wireguard-tools"
source="\$pkgname-\$pkgver.tar.gz"
builddir="\$srcdir/\$pkgname-\$pkgver"
options="!check"

package() {
	DESTDIR="\$pkgdir" ./install.sh --prefix /usr --init openrc --no-post
	install -Dm644 LICENSE "\$pkgdir"/usr/share/licenses/\$pkgname/LICENSE
}
APK
}

recipe_openbsd() {
    mkdir -p "$DIST/recipes/openbsd/pkg"
    cat > "$DIST/recipes/openbsd/Makefile" <<MK
COMMENT =	$DESC
DISTNAME =	$NAME-$VERSION
CATEGORIES =	net security
HOMEPAGE =	$URL
MAINTAINER =	VPNMan contributors <noreply@example.invalid>
# MIT
PERMIT_PACKAGE =	Yes
MODULES =	lang/python
MODPY_PYBUILD =	No
RUN_DEPENDS =	x11/gnome/libadwaita \\
		x11/py-gobject3 \\
		net/openvpn \\
		net/wireguard-tools
NO_BUILD =	Yes
NO_TEST =	Yes
SUBST_VARS +=	LOCALBASE

do-install:
	cd \${WRKSRC} && DESTDIR=\${DESTDIR} ./install.sh --prefix \${PREFIX} --init openbsd --no-post

.include <bsd.port.mk>
MK
    echo "$DESC" > "$DIST/recipes/openbsd/pkg/DESCR"
}

build_recipes() { recipe_rpm; recipe_arch; recipe_void; recipe_alpine; recipe_openbsd; log "recipes -> dist/recipes/"; }

# --container [IMAGE]: build the rpm inside a Fedora container (podman or docker), so it works from any distro
if [ "${1:-}" = "--container" ]; then
    shift
    engine=$(command -v podman || command -v docker || true)
    [ -n "$engine" ] || { echo "--container needs podman or docker" >&2; exit 1; }
    image=${PKG_IMAGE:-registry.fedoraproject.org/fedora:latest}
    log "building [$*] in $image with $(basename "$engine")"
    "$engine" run --rm -v "$ROOT:/src:Z" -w /src "$image" bash -c \
        "dnf -y -q install rpm-build python3 tar gzip findutils sed systemd-rpm-macros >/dev/null && \
         cp -r /src /tmp/build-src && cd /tmp/build-src && rm -rf dist build && ./package.sh ${*:-rpm} && \
         mkdir -p /src/dist && cp dist/*.rpm dist/*.tar.gz dist/*.deb /src/dist/ 2>/dev/null; true"
    log "done. Output in $DIST"
    exit 0
fi

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(all)
for t in "${targets[@]}"; do
    case "$t" in
        all) build_tar; build_deb; build_rpm; build_arch; build_recipes ;;
        tar) build_tar ;;
        deb) build_deb ;;
        rpm) build_rpm ;;
        arch) build_arch ;;
        void) recipe_void ;;
        alpine) recipe_alpine ;;
        openbsd) recipe_openbsd ;;
        recipes) build_recipes ;;
        clean) rm -rf "$DIST" "$BUILD" ;;
        *) echo "unknown target: $t" >&2; exit 2 ;;
    esac
done
log "done. Output in $DIST"
