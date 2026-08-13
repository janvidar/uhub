Summary: High performance ADC p2p hub.
Name: uhub
Version: 0.4.0
Release: 2
License: GPLv3
Group: Networking/File transfer
Source: uhub-%{version}.tar.gz
URL: https://www.uhub.org
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: sqlite-devel
BuildRequires: openssl-devel

%description
uhub is a high performance peer-to-peer hub for the ADC network.
Its low memory footprint allows it to handle several thousand users on
high-end servers, or a small private hub on embedded hardware.

Key features:
- High performance and low memory usage
- IPv4 and IPv6 support
- Experimental SSL support (optional)
- Advanced access control support
- Easy configuration
- plugin support
 - mod_welcome  - MOTD\RULES messages
 - mod_auth_sipmle - auth with sqlite DB
 - mod_logging - log hub activity

This package also contains uhub-seeder, a separate seed cache daemon. It logs
into a hub as a registered bot account and keeps files that were posted in
chat available after the user who posted them has left. It is not started by
default: it needs a bot account, a password and a listening port of its own
first. See /etc/uhub/uhub-seeder.conf and uhub-seeder(1).

%prep
%setup -q -n %{name}-%{version}

%build
echo RPM_BUILD_ROOT = $RPM_BUILD_ROOT
make

%install
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/etc/uhub
mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man1
mkdir -p $RPM_BUILD_ROOT/usr/lib/uhub

install uhub $RPM_BUILD_ROOT/usr/bin/
install uhub-passwd $RPM_BUILD_ROOT/usr/bin/
install uhub-seeder $RPM_BUILD_ROOT/usr/bin/
> doc/motd.txt
install -m644 doc/uhub.conf doc/users.conf doc/rules.txt doc/motd.txt doc/plugins.conf doc/users.db $RPM_BUILD_ROOT/etc/uhub
# The seeder is a separate daemon with its own configuration file; it does not
# read uhub.conf. Mode 0600: it holds the bot account password in cleartext.
install -m600 doc/uhub-seeder.conf $RPM_BUILD_ROOT/etc/uhub
install doc/init.d.RedHat/etc/init.d/uhub $RPM_BUILD_ROOT/etc/init.d
install doc/init.d.RedHat/etc/init.d/uhub-seeder $RPM_BUILD_ROOT/etc/init.d
install -m644 doc/init.d.RedHat/etc/sysconfig/uhub  $RPM_BUILD_ROOT/etc/sysconfig/
install -m644 doc/init.d.RedHat/etc/sysconfig/uhub-seeder $RPM_BUILD_ROOT/etc/sysconfig/
install -m644 doc/init.d.RedHat/etc/logrotate.d/uhub $RPM_BUILD_ROOT/etc/logrotate.d/
install -m644 doc/init.d.RedHat/etc/logrotate.d/uhub-seeder $RPM_BUILD_ROOT/etc/logrotate.d/
for manpage in uhub uhub-passwd uhub-seeder ; do \
	/bin/gzip -9c doc/$manpage.1 > doc/$manpage.1.gz || exit 1 ; \
	install -m644 doc/$manpage.1.gz $RPM_BUILD_ROOT/usr/share/man/man1 || exit 1 ; \
done
# The seed cache directory. The seeder creates it if it is missing, but
# packaging it means it exists with the right owner from the start.
mkdir -p $RPM_BUILD_ROOT/var/lib/uhub/seed
install -m644 mod_*.so $RPM_BUILD_ROOT/usr/lib/uhub


%files
%defattr(-,root,root)
%doc AUTHORS BUGS COPYING ChangeLog README.md TODO doc/Doxyfile doc/architecture.txt doc/compile.txt doc/getstarted.txt doc/linking.txt doc/seedcache.txt doc/uhub.dot
%config(noreplace) /etc/uhub/uhub.conf
#%{_sysconfdir}/uhub/uhub.conf
%config(noreplace) %{_sysconfdir}/uhub/users.conf
%config(noreplace) %{_sysconfdir}/uhub/motd.txt
%config(noreplace) %{_sysconfdir}/uhub/rules.txt
%config(noreplace) %{_sysconfdir}/uhub/plugins.conf
%config(noreplace) %{_sysconfdir}/uhub/users.db
%attr(0600,uhub,root) %config(noreplace) %{_sysconfdir}/uhub/uhub-seeder.conf
%{_sysconfdir}/init.d/uhub
%{_sysconfdir}/init.d/uhub-seeder
%config(noreplace) %{_sysconfdir}/logrotate.d/uhub
%config(noreplace) %{_sysconfdir}/logrotate.d/uhub-seeder
%config(noreplace) %{_sysconfdir}/sysconfig/uhub
%config(noreplace) %{_sysconfdir}/sysconfig/uhub-seeder
%dir %attr(0700,uhub,root) /var/lib/uhub/seed
/usr/share/man/man1/uhub.1.gz
/usr/share/man/man1/uhub-passwd.1.gz
/usr/share/man/man1/uhub-seeder.1.gz
%{_bindir}/uhub
%{_bindir}/uhub-passwd
%{_bindir}/uhub-seeder
%{_libdir}/uhub/mod_*.so

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add uhub
# Registered but deliberately not started: uhub-seeder needs a bot account, a
# password and a reachable port of its own before it can do anything, and the
# shipped uhub-seeder.conf only has placeholders.
/sbin/chkconfig --add uhub-seeder
if [ $1 -gt 1 ] ; then
    /etc/rc.d/init.d/uhub restart >/dev/null || :
fi
# need more information about add services and users in system
/usr/sbin/adduser -M -d /tmp -G nobody -s /sbin/nologin -c 'The uhub ADC p2p hub Daemon' uhub >/dev/null 2>&1 ||:
# The seed cache directory and the seeder configuration are packaged before the
# uhub user exists, so fix their owner here. The seeder runs unprivileged and
# has to be able to read its own config, which holds the bot account password.
chown uhub /var/lib/uhub/seed /etc/uhub/uhub-seeder.conf >/dev/null 2>&1 ||:
# write SSL create
echo "PLS see /usr/share/doc/uhub/"

%changelog
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


