#!/bin/sh
. admin/common.sh

export_source_directory
build_binaries

DEB_REVISION=1

if [ -d deb ]; then
	rm -Rf deb
fi

mkdir -p \
	deb/DEBIAN \
	deb/usr/bin \
	deb/usr/share/doc/uhub \
	deb/etc/uhub \
	|| exit 1

find deb -type d | xargs chmod 755

# Copy binaries...
cp ${PACKAGE}/${BINARY} deb/usr/bin
strip deb/usr/bin/${BINARY}

# Copy configuration files...
cp ${PACKAGE}/doc/uhub.conf deb/etc/uhub
cp ${PACKAGE}/doc/users.conf deb/etc/uhub
echo "Welcome to uHub" > deb/etc/uhub/motd.txt

# Copy debian policy files
cp ${PACKAGE}/README deb/usr/share/doc/uhub
cp ${PACKAGE}/AUTHORS deb/usr/share/doc/uhub
gzip -c --best < ${PACKAGE}/ChangeLog > deb/usr/share/doc/uhub/changelog.gz

cat > deb/usr/share/doc/uhub/copyright <<EOF
uHub - a high performance hub for the ADC peer-to-peer network

Copyright (C) 2007-2009 Jan Vidar Krey <janvidar@extatic.org>

uHub is free and open source software, licensed under the
GNU General Public License version 3.

For details, see /usr/share/common-licenses/GPL-3
EOF

gzip -c --best > deb/usr/share/doc/uhub/changelog.Debian.gz <<EOF
uhub (${VERSION}) stable; urgency=low

  * See changelog.gz for details.

 -- Jan Vidar Krey <janvidar@extatic.org>  `date -R`
EOF

### Write control files
cd deb
echo "/etc/uhub/uhub.conf"   > DEBIAN/conffiles
echo "/etc/uhub/users.conf" >> DEBIAN/conffiles
echo "/etc/uhub/motd.txt"   >> DEBIAN/conffiles

md5sum `find usr -type f` > DEBIAN/md5sums

INSTALL_SIZE=`du -s | cut -f 1`

cat > DEBIAN/control <<EOF
Package: uhub
Version: ${VERSION}-${DEB_REVISION}
Architecture: ${HOST_MACHINE}
Maintainer: Jan Vidar Krey <janvidar@extatic.org>
Installed-Size: ${INSTALL_SIZE}
Depends: libc6 (>= 2.7-1), libevent1 (>= 1.3e-1)
Section: net
Priority: optional
Description: a high performance hub for the ADC peer-to-peer network
 uHub is a high performance peer-to-peer hub for the ADC network.
 Its low memory footprint allows it to handle several thousand users
 on high-end servers, or a small private hub on embedded hardware.
 .
Homepage: http://www.extatic.org/uhub/
EOF
cd ..

### Create deb file
fakeroot dpkg-deb --build deb
mv deb.deb uhub_${VERSION}-${DEB_REVISION}_${HOST_MACHINE}.deb

### Check for errors
lintian uhub_${VERSION}-${DEB_REVISION}_${HOST_MACHINE}.deb

