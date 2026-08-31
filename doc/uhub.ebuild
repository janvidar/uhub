# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

if [[ ${PV} == 9999 ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/janvidar/uhub.git"
else
	# The release tarball, not GitHub's generated "Source code" asset: the
	# latter has the submodules as empty gitlinks and does not build.
	SRC_URI="https://github.com/janvidar/uhub/releases/download/${PV}/${PN}-${PV}-src.tar.gz"
	S="${WORKDIR}/${PN}-${PV}-src"
	KEYWORDS="~amd64 ~x86"
fi

DESCRIPTION="High performance ADC hub"
HOMEPAGE="https://www.uhub.org/"

# GPLv3 with an OpenSSL linking exception; see COPYING and COPYING.OpenSSL.
LICENSE="GPL-3"
SLOT="0"
# TLS is mandatory and is no longer a build option, so there is no ssl USE flag.
# javascript embeds the bundled QuickJS submodule and needs nothing external.
IUSE="fuse javascript systemd test"
RESTRICT="!test? ( test )"

# Perl is no longer needed: the test suite is compiled directly, with no code
# generation step. SQLite and a TLS library are both hard requirements.
DEPEND="
	dev-db/sqlite:3
	dev-libs/openssl:0=
	fuse? (
		sys-fs/fuse:3
		app-arch/bzip2
	)
	systemd? ( sys-apps/systemd )
"
RDEPEND="
	${DEPEND}
	acct-user/uhub
	acct-group/uhub
"
# Appended rather than assigned: the cmake eclass sets its own BDEPEND, and a
# plain assignment here would discard it. CMakeLists.txt requires 3.21.
BDEPEND="${BDEPEND} >=dev-build/cmake-3.21"

src_configure() {
	local mycmakeargs=(
		# Where things are installed. GNUInstallDirs would put sysconfdir and
		# localstatedir under the prefix for any prefix other than a literal
		# /usr, which is what a Gentoo Prefix install has, so name all three
		# rather than relying on that special case.
		-DCMAKE_INSTALL_LIBDIR="$(get_libdir)"
		-DCMAKE_INSTALL_SYSCONFDIR="${EPREFIX}/etc"
		-DCMAKE_INSTALL_LOCALSTATEDIR="${EPREFIX}/var"
		# The hub compiles these in so that it finds its plugins and its
		# configuration without either being named in a config file. They have
		# to agree with the install locations above.
		-DUHUB_PLUGIN_DIR="${EPREFIX}/usr/$(get_libdir)/uhub"
		-DUHUB_CONFIG_DIR="${EPREFIX}/etc/uhub"
		-DUHUB_STATE_DIR="${EPREFIX}/var/lib/uhub"
		-DSYSTEMD_SUPPORT=$(usex systemd ON OFF)
		-DUHUB_SYSTEMD_UNIT_DIR="${EPREFIX}/lib/systemd/system"
		# uhub-fuse mounts a hub as a filesystem; file lists are bzip2'd XML.
		-DFUSE_SUPPORT=$(usex fuse ON OFF)
		-DJAVASCRIPT_SUPPORT=$(usex javascript ON OFF)
		-DUHUB_TESTS=$(usex test ON OFF)
	)
	cmake_src_configure
}

src_install() {
	# Installs the binaries (uhub, uhub-passwd, uhub-seeder), the plugins, the
	# sample configuration, the seeder configuration at 0600, the man pages and
	# the state directory.
	cmake_src_install

	dodoc doc/getstarted.txt doc/architecture.txt doc/linking.txt \
		doc/prometheus.txt doc/bbs.txt doc/seedcache.txt

	if use javascript; then
		dodoc doc/javascript.txt
	fi

	if use fuse; then
		dodoc doc/fuse.txt
		# uhub-fuse.conf, like the seeder's, holds a password in cleartext.
		fowners uhub:uhub /etc/uhub/uhub-fuse.conf
		fperms 0600 /etc/uhub/uhub-fuse.conf
	fi

	# uhub-seeder.conf holds the bot account password in cleartext, and the
	# seeder that has to read it does not run as root.
	fowners uhub:uhub /etc/uhub/uhub-seeder.conf
	fperms 0600 /etc/uhub/uhub-seeder.conf

	# The hub creates its default user database here when no plugins.conf
	# overrides the built-in plugin set, so it must be writable by the hub.
	fowners uhub:uhub /var/lib/uhub
	fperms 0750 /var/lib/uhub

	# The seed cache directory; the seeder creates it at 0700 if missing.
	keepdir /var/lib/uhub/seed
	fowners uhub:uhub /var/lib/uhub/seed
	fperms 0700 /var/lib/uhub/seed

	# cmake_src_install puts the systemd units in place when USE=systemd; the
	# tree carries no OpenRC service, so that one comes from the overlay's
	# FILESDIR when it provides one.
	if [[ -f ${FILESDIR}/uhub.rc ]]; then
		newinitd "${FILESDIR}"/uhub.rc uhub
	fi
	if [[ -f ${FILESDIR}/uhub.confd ]]; then
		newconfd "${FILESDIR}"/uhub.confd uhub
	fi
}

pkg_postinst() {
	elog "uhub runs with no configuration file at all. When none configures"
	elog "plugins it loads a default set (SQLite authentication, logging,"
	elog "topic commands, chat history and user commands), so the hub is"
	elog "usable as installed. 'uhub -C' reports what it would load."
	elog ""
	elog "Credentials come from the authentication plugin, so create an"
	elog "operator account before anything else:"
	elog "    uhub-passwd /var/lib/uhub/users.db add <nick> <password> admin"
	elog ""
	elog "uhub-seeder is a separate daemon and is not started by uhub."
	elog "It needs a registered bot account on the hub and a reachable"
	elog "listening port of its own. See /etc/uhub/uhub-seeder.conf and"
	elog "uhub-seeder(1) before enabling it."
}
