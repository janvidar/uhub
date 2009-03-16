HOST_SYSTEM=`uname -s | tr [:upper:] [:lower:] | sed s/darwin/macosx/`

if [ "${HOST_SYSTEM}" = "macosx" ]; then
	HOST_MACHINE=`uname -p | tr [:upper:] [:lower:]`
else
	HOST_MACHINE=`uname -m | tr [:upper:] [:lower:] | sed s/i686/i386/ | sed s/x86_64/amd64/ | sed s/ppc64/powerpc/`
fi

if [ "${HOST_SYSTEM}" = "mingw32_nt-5.1" ]; then
	HOST_SYSTEM=win32
	BINARY=uhub.exe
	WANTZIP=1
else
	WANTZIP=0
	BINARY=uhub
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

	if [ ! -d .git ]; then
		echo "No git repo found in `dirname $0`"
		exit 1
	fi

	git archive --format=tar --prefix=${PACKAGE}/ HEAD | tar x

	if [ ! -d ${PACKAGE} ]; then
		echo "Something went wrong while exporting the repo."
		exit 1
	fi
}

function package_zips()
{
	tar cf $1.tar $2
	gzip -c -9 $1.tar > $1.tar.gz
	bzip2 -c -9 $1.tar > $1.tar.bz2
	rm -f $1.tar
	zip -q -9 -r $1.zip $2
}

function export_sources()
{
	export_source_directory
	make autotest.c && cp autotest.c ${PACKAGE}/autotest.c
	rm -Rf ${PACKAGE}/admin

	package_zips ${PACKAGE_SRC} ${PACKAGE}
        
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

	if [ -x ${BINARY} ]; then
		cp ${BINARY} ${PACKAGE}
	else
		echo "No binary found!"
		exit 1
	fi

	package_zips ${PACKAGE_BIN} ${PACKAGE}

	rm -Rf ${PACKAGE};
}


