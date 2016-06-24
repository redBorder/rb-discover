%global __rbdir /usr/lib/redborder

Name: rb-discover
Version: %{__version}
Release: %{__release}%{?dist}
Summary: Package for rb-discover project

License: AGPL 3.0
URL: https://github.com/redBorder/rb-discover
Source0: %{name}-%{version}.tar.gz

Requires: bash rvm

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/%{__rbdir}/bin
mkdir -p %{buildroot}/%{__rbdir}/lib
install -D -m 0755 rb_discover_server.rb %{buildroot}/%{__rbdir}/bin
install -D -m 0755 rb_discover_client.rb %{buildroot}/%{__rbdir}/bin
install -D -m 0644 udp_ping.rb %{buildroot}/%{__rbdir}/lib
install -D -m 0644 rb_discover_server.sh %{buildroot}/%{_bindir} 
install -D -m 0644 rb_discover_client.sh %{buildroot}/%{_bindir} 

%files
%defattr(0755,root,root)
%{__rbdir}/bin
%{_bindir}
%defattr(0644,root,root)
%{__rbdir}/lib
%doc

%changelog
* Thu Jun 23 2016 Juan J. Prieto <jjprieto@redborder.com> - 1.0.0-1
- first spec version
