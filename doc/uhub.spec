Summary: High performance ADC p2p hub.
Name: uhub
Version: 0.8.0
Release: 1
License: GPLv3
Group: Networking/File transfer
Source: https://github.com/janvidar/uhub/releases/download/%{version}/uhub-%{version}-src.tar.gz
URL: https://www.uhub.org
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: cmake >= 3.21
BuildRequires: gcc
BuildRequires: make
BuildRequires: sqlite-devel
BuildRequires: openssl-devel

%description
uhub is a high performance peer-to-peer hub for the ADC network.
Its low memory footprint allows it to handle several thousand users on
high-end servers, or a small private hub on embedded hardware.

Key features:
- High performance and low memory usage
- IPv4 and IPv6 support
- TLS support (adcs://), always built in
- Advanced access control support
- Prometheus metrics endpoint
- Easy configuration: the hub runs with no configuration file at all, and
  loads a default set of plugins when none is configured
- Plugin support
 - mod_auth_sqlite    - registered users and persistent bans in a SQLite database
 - mod_logging        - log hub activity to a file or syslog
 - mod_chat_history   - chat history, in memory or persisted to SQLite
 - mod_topic          - !topic and friends
 - mod_ucmd           - right-click context menus in ADC clients
 - mod_users          - operator account management (!useradd and friends)
 - mod_welcome        - MOTD / rules messages
 - and others; see /etc/uhub/plugins.conf

This package also contains uhub-seeder, a separate seed cache daemon. It logs
into a hub as a registered bot account and keeps files that were posted in
chat available after the user who posted them has left. It is not started by
default: it needs a bot account, a password and a listening port of its own
first. See /etc/uhub/uhub-seeder.conf and uhub-seeder(1).

%prep
%setup -q -n %{name}-%{version}-src

%build
# CMake is the build system; there is no hand-written Makefile. CMAKE_INSTALL_LIBDIR
# has to be %%{_lib} so the plugins land in %%{_libdir}/uhub (lib64 on 64-bit), which
# is both what %%files lists below and what the hub compiles in as its default
# plugin directory.
cmake -S . -B build \
	-DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DCMAKE_INSTALL_LIBDIR=%{_lib} \
	-DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir} \
	-DCMAKE_INSTALL_LOCALSTATEDIR=%{_localstatedir} \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -- %{?_smp_mflags}

%check
# autotest-bin is only built when the third_party/exotic submodule is present,
# so a source tree without it has no tests rather than a broken one.
ctest --test-dir build --output-on-failure --no-tests=ignore

%install
rm -rf $RPM_BUILD_ROOT
# Installs the binaries, the plugins, the sample configuration (uhub.conf,
# plugins.conf, messages.conf, users.conf, rules.txt, motd.txt, boards.conf),
# the seeder configuration at 0600, the man pages, and the state directory.
DESTDIR=$RPM_BUILD_ROOT cmake --install build

# Init scripts, sysconfig and logrotate are RedHat-specific and not part of the
# build system's install target.
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/init.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
install doc/init.d.RedHat/etc/init.d/uhub $RPM_BUILD_ROOT%{_sysconfdir}/init.d
install doc/init.d.RedHat/etc/init.d/uhub-seeder $RPM_BUILD_ROOT%{_sysconfdir}/init.d
install -m644 doc/init.d.RedHat/etc/sysconfig/uhub $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/
install -m644 doc/init.d.RedHat/etc/sysconfig/uhub-seeder $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/
install -m644 doc/init.d.RedHat/etc/logrotate.d/uhub $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/
install -m644 doc/init.d.RedHat/etc/logrotate.d/uhub-seeder $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/

# The seed cache directory. The seeder creates it if it is missing, but
# packaging it means it exists with the right owner from the start.
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/uhub/seed

%files
%defattr(-,root,root)
%doc AUTHORS BUGS COPYING COPYING.OpenSSL ChangeLog README.md TODO
%doc doc/Doxyfile doc/architecture.txt doc/bbs.txt doc/compile.txt
%doc doc/getstarted.txt doc/javascript.txt doc/linking.txt doc/prometheus.txt
%doc doc/seedcache.txt doc/uhub.dot
%config(noreplace) %{_sysconfdir}/uhub/uhub.conf
%config(noreplace) %{_sysconfdir}/uhub/plugins.conf
%config(noreplace) %{_sysconfdir}/uhub/messages.conf
%config(noreplace) %{_sysconfdir}/uhub/users.conf
%config(noreplace) %{_sysconfdir}/uhub/motd.txt
%config(noreplace) %{_sysconfdir}/uhub/rules.txt
%config(noreplace) %{_sysconfdir}/uhub/boards.conf
%attr(0600,uhub,root) %config(noreplace) %{_sysconfdir}/uhub/uhub-seeder.conf
%{_sysconfdir}/init.d/uhub
%{_sysconfdir}/init.d/uhub-seeder
%config(noreplace) %{_sysconfdir}/logrotate.d/uhub
%config(noreplace) %{_sysconfdir}/logrotate.d/uhub-seeder
%config(noreplace) %{_sysconfdir}/sysconfig/uhub
%config(noreplace) %{_sysconfdir}/sysconfig/uhub-seeder
# The hub creates its default user database here when no plugins.conf overrides
# the built-in plugin set, so it has to be writable by the user the hub runs as.
%dir %attr(0750,uhub,root) %{_localstatedir}/lib/uhub
%dir %attr(0700,uhub,root) %{_localstatedir}/lib/uhub/seed
# Globbed rather than named .gz: whether man pages are compressed, and with
# what, is the distribution's choice.
%{_mandir}/man1/uhub.1*
%{_mandir}/man1/uhub-passwd.1*
%{_mandir}/man1/uhub-seeder.1*
%{_bindir}/uhub
%{_bindir}/uhub-passwd
%{_bindir}/uhub-seeder
%dir %{_libdir}/uhub
%{_libdir}/uhub/mod_*.so

%clean
rm -rf $RPM_BUILD_ROOT

%pre
# Created before %%files is applied, because the state and seed directories and
# the seeder configuration are packaged owned by this user.
/usr/sbin/useradd -r -M -d %{_localstatedir}/lib/uhub -s /sbin/nologin \
	-c 'The uhub ADC p2p hub Daemon' uhub >/dev/null 2>&1 ||:

%post
/sbin/chkconfig --add uhub
# Registered but deliberately not started: uhub-seeder needs a bot account, a
# password and a reachable port of its own before it can do anything, and the
# shipped uhub-seeder.conf only has placeholders.
/sbin/chkconfig --add uhub-seeder
if [ $1 -gt 1 ] ; then
    /etc/rc.d/init.d/uhub restart >/dev/null || :
fi
if [ $1 -eq 1 ] ; then
    echo "uhub: no operator account exists yet. Create one with:"
    echo "    uhub-passwd %{_localstatedir}/lib/uhub/users.db add <nick> <password> admin"
    echo "See %{_docdir}/%{name}/getstarted.txt"
fi

%preun
if [ $1 -eq 0 ] ; then
    /etc/rc.d/init.d/uhub stop >/dev/null 2>&1 ||:
    /etc/rc.d/init.d/uhub-seeder stop >/dev/null 2>&1 ||:
    /sbin/chkconfig --del uhub ||:
    /sbin/chkconfig --del uhub-seeder ||:
fi

%changelog
* Sun Aug 31 2026 Jan Vidar Krey
- build with CMake; the hand-written Makefile the spec called is long gone
- install through "cmake --install" rather than copying each file by hand
- install the plugins into %%{_libdir}/uhub, not a hardcoded /usr/lib/uhub,
  which put them in the wrong place on 64-bit and did not match %%files
- package messages.conf and boards.conf; drop users.db, which does not exist
  in the source tree and made the build fail
- package /var/lib/uhub: the hub creates its default user database there
- create the uhub user in %%pre, since files are packaged owned by it, and
  stop/deregister the services on uninstall
- run the test suite in %%check
* Tue Aug 11 2026 Jan Vidar Krey
- add uhub-seeder daemon, its config, init script and man page
- install the uhub-passwd and uhub-seeder man pages (only uhub.1 was shipped)
- package the uhub-passwd binary, which was installed but not listed
* Fri Dec 30 2011 E_zombie
- add users.db 
- add new doc
* Tue Jun 26 2010 E_zombie
- add plugins.conf
* Tue Jan 31 2010 E_zombie
- change GROUP
- chmod for files
- add postinstall scripts
- fix "License"
* Tue Jan 26 2010 E_zombie
- first .spec release
