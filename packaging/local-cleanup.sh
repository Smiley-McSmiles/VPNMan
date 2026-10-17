# An install.sh copy under /usr/local shadows this package: its programs come first in PATH, its unit in
# /etc/systemd/system overrides ours, and its launcher - same name, earlier in XDG_DATA_DIRS - hides ours (and once its
# program is gone, GNOME hides it too, so the app vanished from the menu).  Remove all of it, launcher and icons included.
rm -rf /usr/local/lib/vpnman /usr/local/share/vpnman
for f in /usr/local/bin/vpnman /usr/local/bin/vpnmand /usr/local/bin/vpnman-gtk \
         /usr/local/sbin/vpnman /usr/local/sbin/vpnmand /usr/local/sbin/vpnman-gtk \
         /usr/local/share/applications/io.github.smiley_mcsmiles.VPNMan.desktop \
         /usr/local/share/metainfo/io.github.smiley_mcsmiles.VPNMan.metainfo.xml \
         /usr/local/share/pixmaps/io.github.smiley_mcsmiles.VPNMan.svg \
         /usr/local/share/man/man1/vpnman.1 /usr/local/share/man/man1/vpnman.1.gz \
         /usr/local/share/bash-completion/completions/vpnman /usr/local/share/zsh/site-functions/_vpnman \
         /usr/local/share/fish/vendor_completions.d/vpnman.fish \
         /usr/local/share/icons/hicolor/*/apps/io.github.smiley_mcsmiles.VPNMan*; do
    if [ -e "$f" ] || [ -L "$f" ]; then rm -f "$f"; fi
done
# a unit install.sh wrote for the /usr/local copy (a unit of the administrator's own stays)
if [ -f /etc/systemd/system/vpnmand.service ] && grep -q "/usr/local/" /etc/systemd/system/vpnmand.service; then
    rm -f /etc/systemd/system/vpnmand.service
fi
