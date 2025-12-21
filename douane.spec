Name:           douane-firewall
Version:        2.0.10
Release:        1%{?dist}
Summary:        Application Firewall for Linux
License:        GPLv3
URL:            https://github.com/shipdocs/Douane
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3
Requires:       python3-gobject
Requires:       libappindicator-gtk3
Requires:       iptables
Requires:       libnetfilter_queue
Requires:       polkit
Requires:       python3-psutil
Requires:       python3-scapy

%description
Douane is a production-ready application firewall that gives Linux users the same outbound connection control they had on Windows. It intercepts every outbound connection attempt and lets you decide which applications can access the network.

%prep
%setup -q

%build
# No compilation needed for Python

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
mkdir -p $RPM_BUILD_ROOT/usr/lib/python3/site-packages/douane
mkdir -p $RPM_BUILD_ROOT/etc/douane
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/douane-firewall
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system

# Install executables
install -m 755 douane-firewall $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-daemon $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-gui-client $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-control-panel $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-setup-firewall $RPM_BUILD_ROOT/usr/local/bin/

# Install Python modules
cp -r douane/* $RPM_BUILD_ROOT/usr/lib/python3/site-packages/douane/

# Install config
install -m 644 config.json $RPM_BUILD_ROOT/etc/douane/config.json

# Install Systemd service
install -m 644 douane-firewall.service $RPM_BUILD_ROOT/lib/systemd/system/

# Install Desktop files
install -m 644 douane-firewall.desktop $RPM_BUILD_ROOT/usr/share/applications/
install -m 644 douane-control-panel.desktop $RPM_BUILD_ROOT/usr/share/applications/

%files
/usr/local/bin/douane-firewall
/usr/local/bin/douane-daemon
/usr/local/bin/douane-gui-client
/usr/local/bin/douane-control-panel
/usr/local/bin/douane-setup-firewall
/usr/lib/python3/site-packages/douane/
/etc/douane/config.json
/lib/systemd/system/douane-firewall.service
/usr/share/applications/douane-firewall.desktop
/usr/share/applications/douane-control-panel.desktop

%changelog
* Sat Dec 20 2024 Martin <shipdocs@users.noreply.github.com> - 2.0.9-1
- Initial RPM release
