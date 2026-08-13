#!/bin/sh

OPENSSL=/usr/bin/openssl
NAME=certificate

if [ ! -x ${OPENSSL} ]; then
	echo "Cannot locate the openssl utility: ${OPENSSL}"
	exit 1
fi

${OPENSSL} req -x509 -newkey ed25519 -keyout ${NAME}.key -out ${NAME}.crt -days 3650 -nodes -subj "/CN=uhub" 2>/dev/null
cat ${NAME}.key ${NAME}.crt > ${NAME}.pem && rm -f ${NAME}.key ${NAME}.crt
echo "Created certificate ${NAME}.pem"

