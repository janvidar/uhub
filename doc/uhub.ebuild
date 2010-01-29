# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $
inherit eutils

if [ "$PV" != "9999" ]; then
        SRC_URI="http://www.extatic.org/downloads/uhub/${P}-src.tar.bz2"
        KEYWORDS="~amd64 ~x86"
else
        inherit git
        SRC_URI=""
        EGIT_REPO_URI="git://github.com/janvidar/uhub.git"
        KEYWORDS=""
fi

EAPI="2"

DESCRIPTION="High performance ADC hub"
HOMEPAGE="http://www.uhub.org/"

LICENSE="GPL-3"
SLOT="0"
IUSE="+ssl"

DEPEND=">=dev-libs/libevent-1.3
=dev-lang/perl-5*
ssl? ( >=dev-libs/openssl-0.9.8 )
"
RDEPEND="${DEPEND}"
src_compile() {
        $opts=""
        use ssl && opts="USE_SSL=YES $opts"
        emake $opts
}
src_install() {
        dodir /usr/bin
        dodir /etc/uhub
        emake DESTDIR="${D}" UHUB_PREFIX="${D}/usr" install || die "install failed"
        newinitd doc/uhub.gentoo.rc uhub || newinitd ${FILESDIR}/uhub.rc uhub
}
pkg_postinst() {
        enewuser uhub
}
