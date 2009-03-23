#!/bin/bash

PUB="${HOME}/.ssh/id_rsa.pub"
CFG="${HOME}/.ssh/config"

if [ ! "`grep build-archive ${CFG}`" ]; then
echo "Updating ssh config (${CFG})..."
cat >> ${CFG} <<EOF

Host build-archive
	ForwardX11	no
	HostName	login.domeneshop.no
	User		extatic
EOF
else
echo "ssh config seems OK (${CFG})"
fi

if [ ! -f ${PUB} ]; then
	echo "No id_rsa.pub - run ssh-keygen"
	exit 1
fi

echo "Copying public key (${PUB})..."
cat ${PUB} | ssh build-archive "cat >> .ssh/authorized_keys"

