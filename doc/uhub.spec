Summary: High performance ADC p2p hub.
Name: uhub
Version: 0.3.1
Release: 3
License: GPLv3
Group: Networking/File transfer
Source: uhub-%{version}.tar.gz
URL: http://www.uhub.org
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root


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

install uhub $RPM_BUILD_ROOT/usr/bin/
> doc/motd.txt
install -m644 doc/uhub.conf doc/users.conf doc/rules.txt doc/motd.txt $RPM_BUILD_ROOT/etc/uhub
install doc/init.d.RedHat/etc/init.d/uhub $RPM_BUILD_ROOT/etc/init.d
install -m644 doc/init.d.RedHat/etc/sysconfig/uhub  $RPM_BUILD_ROOT/etc/sysconfig/
install -m644 doc/init.d.RedHat/etc/logrotate.d/uhub $RPM_BUILD_ROOT/etc/logrotate.d/
/bin/gzip -9c doc/uhub.1 > doc/uhub.1.gz &&
install -m644 doc/uhub.1.gz $RPM_BUILD_ROOT/usr/share/man/man1


%files
%defattr(-,root,root)
%doc AUTHORS BUGS COPYING ChangeLog README TODO doc/Doxyfile doc/architecture.txt doc/compile.txt doc/extensions.txt doc/getstarted.txt doc/uhub.dot
%config(noreplace) /etc/uhub/uhub.conf
#%{_sysconfdir}/uhub/uhub.conf
%config(noreplace) %{_sysconfdir}/uhub/users.conf
%config(noreplace) %{_sysconfdir}/uhub/motd.txt
%config(noreplace) %{_sysconfdir}/uhub/rules.txt
%{_sysconfdir}/init.d/uhub
%config(noreplace) %{_sysconfdir}/logrotate.d/uhub
%config(noreplace) %{_sysconfdir}/sysconfig/uhub
/usr/share/man/man1/uhub.1.gz
%{_bindir}/uhub


%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/chkconfig --add uhub
if [ $1 -gt 1 ] ; then
    /etc/rc.d/init.d/uhub restart >/dev/null || :
fi
# need more informations about add services and users in system
/usr/sbin/adduser -M -d /tmp -G nobody -s /sbin/nologin -c 'The Uhub ADC p2p hub Daemon' uhub >/dev/null 2>&1 ||:

%changelog
* Tue Jan 31 2010 E_zombie
- change GROUP
- chmod for files
- add postinstall scripts
- fix "License"
* Tue Jan 26 2010 E_zombie
- first .spec release


