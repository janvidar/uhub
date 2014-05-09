#!/bin/sh

sudo apt-get update -qq

sudo apt-get install -qq cmake

if [ "${CONFIG}" = "full" ]; then
    sudo apt-get install -qq libsqlite3-dev libssl-dev
fi

