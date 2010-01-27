# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $
EAPI="2"

DESCRIPTION="High performance ADC hub"
HOMEPAGE="http://www.uhub.org/"
SRC_URI="http://www.extatic.org/downloads/uhub/${P}-src.tar.bz2"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+ssl"

DEPEND="=dev-lang/perl-5*
ssl? ( >=dev-libs/openssl-0.9.8 )
"
RDEPEND="${DEPEND}"
src_install() {
        mkdir -p ${D}/usr/bin
        mkdir -p ${D}/etc/uhub
        emake DESTDIR="${D}" UHUB_PREFIX="${D}/usr" install || die "install failed"
}

