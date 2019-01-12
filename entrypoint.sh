#!/bin/bash

mkdir -p dist
git submodule update --init

cd thirdparty/sqlite
x86_64-w64-mingw32-gcc -shared -DWIN64 -DNDEBUG -D_WINDOWS -D_USRDLL -DNO_TCL -D_CRT_SECURE_NO_DEPRECATE -DTHREADSAFE=1 -DTEMP_STORE=1 -DSQLITE_MAX_EXPR_DEPTH=0 -I. shell.c sqlite3.c -o sqlite3.dll -Wl,--out-implib,libsqlite3.dll.a
cp sqlite3.h sqlite3ext.h /usr/x86_64-w64-mingw32/include/
cp sqlite3.dll /usr/x86_64-w64-mingw32/lib/
cp sqlite3.dll /app/dist/
cd /app

cd thirdparty/openssl
mkdir dist
./Configure --prefix=/app/thirdparty/openssl/dist shared mingw64 --cross-compile-prefix=x86_64-w64-mingw32-
make depend -j$(nproc)
make -j$(nproc)
make -j$(nproc) install
cp dist/lib/libcrypto.dll.a dist/lib/libssl.dll.a /usr/x86_64-w64-mingw32/lib/
cp -R dist/include/openssl /usr/x86_64-w64-mingw32/include/openssl
cp dist/bin/libeay32.dll dist/bin/ssleay32.dll /app/dist/
cd /app

cmake -DCMAKE_TOOLCHAIN_FILE=toolchain-mingw64.cmake .
make -j$(nproc)
echo 'Welcome to uHub' > dist/motd.txt
cp doc/plugins.conf doc/uhub.conf doc/users.conf doc/rules.txt dist/
cp uhub.exe uhub-passwd.exe mod_*.dll dist/
