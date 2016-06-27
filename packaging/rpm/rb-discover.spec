%global __rbdir /usr/lib/redborder

Name: rb-discover
Version: %{__version}
Release: %{__release}%{?dist}
Summary: Package for rb-discover project

License: AGPL 3.0
URL: https://github.com/redBorder/rb-discover
Source0: %{name}-%{version}.tar.gz

Requires: bash rvm redborder-common

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}/%{__rbdir}/bin
mkdir -p %{buildroot}/%{__rbdir}/lib
install -D -m 0755 rb_discover_server.rb %{buildroot}/%{__rbdir}/bin
install -D -m 0755 rb_discover_client.rb %{buildroot}/%{__rbdir}/bin
install -D -m 0644 udp_ping.rb %{buildroot}/%{__rbdir}/lib
install -D -m 0755 rb_discover_server.sh %{buildroot}/%{__rbdir}/bin
install -D -m 0755 rb_discover_client.sh %{buildroot}/%{__rbdir}/bin
install -D -m 0755 rb_discover_start.sh %{buildroot}/%{__rbdir}/bin
install -D -m 0644 rb-discover.service %{buildroot}/usr/lib/systemd/system/rb-discover.service

%files
%defattr(0755,root,root)
%{__rbdir}/bin
%defattr(0644,root,root)
%{__rbdir}/lib
/usr/lib/systemd/system/rb-discover.service
%doc

%changelog
* Thu Jun 23 2016 Juan J. Prieto <jjprieto@redborder.com> - 1.0.0-1
- first spec version
