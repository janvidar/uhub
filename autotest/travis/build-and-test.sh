#!/bin/sh

set -x

export CFLAGS="$(dpkg-buildflags --get CFLAGS) $(dpkg-buildflags --get CPPFLAGS)"
export LDFLAGS="$(dpkg-buildflags --get LDFLAGS) -Wl,--as-needed"

mkdir -p builddir
cd builddir

CMAKEOPTS="..
           -DCMAKE_INSTALL_PREFIX=/usr"

if [ "${CONFIG}" = "full" ]; then
    CMAKEOPTS="${CMAKEOPTS}
               -DRELEASE=OFF
               -DLOWLEVEL_DEBUG=ON
               -DSSL_SUPPORT=ON
               -DUSE_OPENSSL=ON
               -DADC_STRESS=ON"
else
    CMAKEOPTS="${CMAKEOPTS}
               -DRELEASE=ON
               -DLOWLEVEL_DEBUG=OFF
               -DSSL_SUPPORT=OFF
               -DADC_STRESS=OFF"
fi


cmake ${CMAKEOPTS} \
      -DCMAKE_C_FLAGS="${CFLAGS}" \
      -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
make VERBOSE=1


sudo make install
du -shc /etc/uhub/ /usr/bin/uhub* /usr/lib/uhub/

