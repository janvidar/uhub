#!/bin/sh

OPENSSL=/usr/bin/openssl
NAME=certificate

if [ ! -x ${OPENSSL} ]; then
	echo "Cannot locate the openssl utility: ${OPENSSL}"
	exit 1
fi

${OPENSSL} genrsa -out ${NAME}.key 1024 &&
${OPENSSL} req -new -x509 -nodes -sha1 -days 365 -key ${NAME}.key > ${NAME}.crt &&
cat ${NAME}.key ${NAME}.crt > ${NAME}.pem && rm -f ${NAME}.key ${NAME}.crt

echo "Created certificate ${NAME}.pem"

