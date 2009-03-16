HOST_SYSTEM=`uname -s | tr [:upper:] [:lower:] | sed s/darwin/macosx/`

if [ "${HOST_SYSTEM}" = "macosx" ]; then
	HOST_MACHINE=`uname -p | tr [:upper:] [:lower:]`
else
	HOST_MACHINE=`uname -m | tr [:upper:] [:lower:] | sed s/i686/i386/ | sed s/x86_64/amd64/ | sed s/ppc64/powerpc/`
fi

if [ "${HOST_SYSTEM}" = "mingw32_nt-5.1" ]; then
	HOST_SYSTEM=win32
fi

VERSION=`grep define\ VERSION version.h | cut -f 3 -d " " | tr -d [=\"=]`
SNAPSHOT=`date '+%Y%m%d'`
PACKAGE=uhub-${VERSION}
PACKAGE_SRC=${PACKAGE}-src
PACKAGE_BIN=${PACKAGE}-${HOST_SYSTEM}-${HOST_MACHINE}

URL_ARCHIVE='build-archive:~/uhub/'
URL_PUBLISH='domeneshop:~/www/downloads/uhub/'
URL_SNAPSHOT='domeneshop:~/www/downloads/uhub/snapshots/'

function export_source_directory() {
	if [ -d ${PACKAGE} ]; then
		rm -Rf ${PACKAGE};
	fi
	git archive --format=tar --prefix=${PACKAGE}/ HEAD | tar x
}

function export_sources()
{
	export_source_directory
	make autotest.c && cp autotest.c ${PACKAGE}/autotest.c
	rm -Rf ${PACKAGE}/admin

	tar cf ${PACKAGE_SRC}.tar ${PACKAGE}
	gzip  -c -9 ${PACKAGE_SRC}.tar > ${PACKAGE_SRC}.tar.gz
	bzip2 -c -9 ${PACKAGE_SRC}.tar > ${PACKAGE_SRC}.tar.bz2

	rm -f ${PACKAGE_SRC}.tar
        rm -Rf ${PACKAGE};

	cp ChangeLog ChangeLog-${VERSION}
}

function export_binaries()
{
	export_source_directory
	rm -Rf ${PACKAGE}/admin
	rm -Rf ${PACKAGE}/autotest
	rm -Rf ${PACKAGE}/src
	rm -f ${PACKAGE}/autotest.c
	rm -f ${PACKAGE}/*akefile
	rm -f ${PACKAGE}/version.h
	rm -f ${PACKAGE}/doc/Doxyfile
	rm -f ${PACKAGE}/doc/uhub.dot

	make

	if [ -x uhub ]; then
		cp uhub ${PACKAGE}
	elif [ -x uhub.exe ]; then
		cp uhub.exe ${PACKAGE}
	else
		echo "No binary found!"
		exit 1
	fi

	tar cf ${PACKAGE_BIN}.tar ${PACKAGE}
	gzip  -c -9 ${PACKAGE_BIN}.tar > ${PACKAGE_BIN}.tar.gz
	bzip2 -c -9 ${PACKAGE_BIN}.tar > ${PACKAGE_BIN}.tar.bz2
	rm -f ${PACKAGE_BIN}.tar
        rm -Rf ${PACKAGE};
}


