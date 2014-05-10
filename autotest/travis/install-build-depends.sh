#!/bin/sh

sudo apt-get update -qq

sudo apt-get install -qq cmake

if [ "${CONFIG}" = "full" ]; then
    sudo apt-get install -qq libsqlite3-dev
fi

if [ "${SSL}" = "openssl" ]; then
    sudo apt-get install -qq libssl-dev
elif [ "${SSL}" = "gnutls" ]; then
    sudo apt-get install -qq libgnutls-dev
fi
