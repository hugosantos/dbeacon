Name:		dbeacon
Summary:	Multicast Beacon
Version:	0.3.8
Release:	1
URL:		http://fivebits.net/proj/dbeacon/
License:	GPL
Source0:	http://fivebits.net/files/dbeacon/dbeacon-%{version}.tar.gz
Group:		Networking
Packager:	Nick Lamb <njl195@zepler.org.uk>
BuildRoot:	%{_builddir}/%{name}-root

%description
dbeacon is a Multicast Beacon written in C++. The main purpose of a beacon
is to monitor other beacon's reachability and collect statistics such as
loss, delay and jitter between beacons. dbeacon supports both IPv4 and IPv6
multicast, collecting information via ASM and SSM.

%prep
%setup -q -n dbeacon-%{version}

%build
%__make

%install
[ %{buildroot} != "/" ] && rm -rf %{buildroot}
%makeinstall PREFIX=%{buildroot}/usr/

%clean
[ %{buildroot} != "/" ] && rm -rf %{buildroot}

%files
%defattr(-, root, root)
%doc README docs/FAQ docs/PROTOCOL
%{_bindir}/*

%changelog
* Mon Sep 19 2005 Nick Lamb <njl195@zepler.org.uk> 0.3.8
- rebuild

* Fri Apr 8  2005 Nick Lamb <njl195@zepler.org.uk> 0.3.2
- First attempt to package for wider audience

