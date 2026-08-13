# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $
inherit eutils

if [ "$PV" != "9999" ]; then
        SRC_URI="https://www.extatic.org/downloads/uhub/${P}-src.tar.bz2"
        KEYWORDS="~amd64 ~x86"
else
        inherit git
        SRC_URI=""
        EGIT_REPO_URI="git://github.com/janvidar/uhub.git"
        KEYWORDS=""
fi

EAPI="2"

DESCRIPTION="High performance ADC hub"
HOMEPAGE="https://www.uhub.org/"

LICENSE="GPL-3"
SLOT="0"
IUSE="+ssl"

DEPEND="=dev-lang/perl-5*
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

        # uhub-seeder is a second daemon (the seed cache) and is not covered by
        # the build system's install target, so install it and its sample
        # configuration here. It does not read uhub.conf.
        dobin uhub-seeder || die "uhub-seeder install failed"
        insinto /etc/uhub
        doins doc/uhub-seeder.conf
        # It holds the bot account password in cleartext, and the seeder that
        # has to read it does not run as root.
        fowners uhub /etc/uhub/uhub-seeder.conf
        fperms 0600 /etc/uhub/uhub-seeder.conf

        # None of the man pages are installed by the build system.
        doman doc/uhub.1 doc/uhub-passwd.1 doc/uhub-seeder.1
        dodoc doc/getstarted.txt doc/seedcache.txt

        # The seed cache directory; the seeder creates it at 0700 if missing.
        keepdir /var/lib/uhub/seed
        fowners uhub /var/lib/uhub/seed
        fperms 0700 /var/lib/uhub/seed

        # There is no OpenRC service file for the seeder in the tree (the hub's
        # comes from the overlay's FILESDIR too), so none is installed here.
        newinitd doc/uhub.gentoo.rc uhub || newinitd ${FILESDIR}/uhub.rc uhub
}
# The user is created before src_install rather than after the merge, because
# the seed cache directory is installed owned by it.
pkg_setup() {
        enewuser uhub
}
pkg_postinst() {
        enewuser uhub
        elog "uhub-seeder is a separate daemon and is not started by uhub."
        elog "It needs a registered bot account on the hub and a reachable"
        elog "listening port of its own. See /etc/uhub/uhub-seeder.conf and"
        elog "uhub-seeder(1) before enabling it."
}
