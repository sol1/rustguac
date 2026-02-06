# RPM spec for rustguac — lightweight Rust replacement for Apache Guacamole.
#
# This spec expects pre-built binaries (build-rpm.sh does compilation before
# rpmbuild runs). The _builddir macro is pointed at the repo checkout so
# install phase can find everything in place.
#
# Target: Rocky Linux 9 / RHEL 9 / AlmaLinux 9
# Requires EPEL for: ffmpeg-libs, libtelnet, libwebsockets, chromium

%global _prefix /opt/rustguac

Name:           rustguac
Version:        %{_version}
Release:        1%{?dist}
Summary:        Lightweight Rust replacement for Apache Guacamole client
License:        Apache-2.0
URL:            https://github.com/sol1/rustguac

BuildRequires:  systemd-rpm-macros

Requires:       cairo
Requires:       libjpeg-turbo
Requires:       libpng
Requires:       libwebp
Requires:       libssh2
Requires:       openssl-libs
Requires:       libvncserver
Requires:       pango
Requires:       pulseaudio-libs
Requires:       ffmpeg-libs
Requires:       libtelnet
Requires:       libwebsockets
Requires:       freerdp-libs
Requires:       ca-certificates

Recommends:     tigervnc-server
Recommends:     chromium
Recommends:     xorg-x11-utils
Recommends:     cryptsetup

%description
rustguac is a lightweight Rust replacement for the Apache Guacamole Java
webapp. It proxies the Guacamole protocol over WebSockets between web
browsers and guacd (the C daemon from guacamole-server). Supports SSH,
VNC, RDP, and web browser sessions (headless Chromium on Xvnc).

# Nothing to unpack or compile — build-rpm.sh handles everything.
%prep

%build

%install
rm -rf %{buildroot}

# Directory structure
install -d %{buildroot}%{_prefix}/bin
install -d %{buildroot}%{_prefix}/sbin
install -d %{buildroot}%{_prefix}/lib
install -d %{buildroot}%{_prefix}/static
install -d %{buildroot}%{_prefix}/static/guac
install -d %{buildroot}%{_prefix}/data
install -d %{buildroot}%{_prefix}/recordings
install -d %{buildroot}%{_prefix}/tls
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/ld.so.conf.d

# rustguac binary
install -m 755 target/release/rustguac %{buildroot}%{_prefix}/bin/rustguac

# Drive setup helper script
install -m 755 scripts/drive-setup.sh %{buildroot}%{_prefix}/bin/drive-setup.sh

# guacd binary and libraries from staging
install -m 755 rpm/staging%{_prefix}/sbin/guacd %{buildroot}%{_prefix}/sbin/guacd
cp -a rpm/staging%{_prefix}/lib/*.so* %{buildroot}%{_prefix}/lib/

# FreeRDP plugin for RDPDR/RDPSND channels (drive redirection, audio, printing)
install -d %{buildroot}%{_libdir}/freerdp3
cp -a rpm/staging%{_libdir}/freerdp3/*.so* %{buildroot}%{_libdir}/freerdp3/ 2>/dev/null || true

# Static web assets
cp -r static/* %{buildroot}%{_prefix}/static/

# Default config — reuse the debian default (no duplication)
install -m 644 debian/config.toml.default %{buildroot}%{_prefix}/config.toml

# Systemd units — reuse the debian service files (no duplication)
install -m 644 debian/rustguac.service %{buildroot}%{_unitdir}/rustguac.service
install -m 644 debian/rustguac-guacd.service %{buildroot}%{_unitdir}/rustguac-guacd.service

# ldconfig drop-in so guacd can find its libs
echo "%{_prefix}/lib" > %{buildroot}%{_sysconfdir}/ld.so.conf.d/rustguac.conf

%pre
# Create rustguac system user with a real home directory (Chromium needs it)
if ! getent passwd rustguac >/dev/null 2>&1; then
    useradd -r -m -d /home/rustguac -s /sbin/nologin -c "rustguac service account" rustguac
fi

%post
chown -R rustguac:rustguac %{_prefix}/data %{_prefix}/recordings
# Generate self-signed TLS certificate if none exists
if [ ! -f %{_prefix}/tls/cert.pem ] || [ ! -f %{_prefix}/tls/key.pem ]; then
    CERT_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    echo "Generating self-signed TLS certificate for ${CERT_HOSTNAME}..."
    %{_prefix}/bin/rustguac generate-cert \
        --hostname "$CERT_HOSTNAME" \
        --out-dir %{_prefix}/tls
    chmod 600 %{_prefix}/tls/key.pem
    chmod 644 %{_prefix}/tls/cert.pem
fi
chown -R rustguac:rustguac %{_prefix}/tls
/sbin/ldconfig
%systemd_post rustguac.service rustguac-guacd.service
echo ""
echo "  To set up encrypted file transfer (LUKS drive), run:"
echo "    sudo %{_prefix}/bin/drive-setup.sh"
echo ""

%preun
%systemd_preun rustguac.service rustguac-guacd.service

%postun
/sbin/ldconfig
if [ $1 -eq 0 ]; then
    # Full uninstall — clean up
    rm -rf %{_prefix}
    userdel -r rustguac 2>/dev/null || true
fi
%systemd_postun_with_restart rustguac.service rustguac-guacd.service

%files
%license debian/copyright
%dir %{_prefix}
%{_prefix}/bin/rustguac
%{_prefix}/bin/drive-setup.sh
%{_prefix}/sbin/guacd
%{_prefix}/lib/*.so*
%{_libdir}/freerdp3/
%{_prefix}/static/
%config(noreplace) %{_prefix}/config.toml
%dir %attr(0750,rustguac,rustguac) %{_prefix}/data
%dir %attr(0750,rustguac,rustguac) %{_prefix}/recordings
%dir %attr(0750,rustguac,rustguac) %{_prefix}/tls
%{_unitdir}/rustguac.service
%{_unitdir}/rustguac-guacd.service
%{_sysconfdir}/ld.so.conf.d/rustguac.conf
