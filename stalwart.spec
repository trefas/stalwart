Name:    stalwart
Version: 0.13.0
Release: alt1

Summary: Secure, scalable mail & collaboration server (IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV)
Summary(ru_RU.UTF-8): Защищённый, масштабируемый почтовый и коллаборационный сервер с поддержкой IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV.
License: AGPL-3.0-only AND SEL
Group:   Development/Tools
URL:     https://stalw.art

Source0: %name-%version.tar

BuildRequires:  rust-cargo /proc
BuildRequires:  rust >= 1.70
BuildRequires:  libclang
BuildRequires:  zlib-devel
Requires(pre):  shadow-utils
Requires(post): systemd
Requires:       ca-certificates

%description
Stalwart - secure, scalable mail & collaboration server (IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV)

%description -l ru_RU.UTF-8
Stalwart — защищённый, масштабируемый почтовый и коллаборационный сервер с поддержкой IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV.

%prep
%setup -q

%build
cargo build --release --no-default-features --features "sqlite postgres mysql rocks elastic s3 redis azure nats"
cargo build --release -p stalwart-cli

%install
# Создание директорий
install -d %{buildroot}/opt/stalwart/bin
install -d %{buildroot}/opt/stalwart/etc
install -d %{buildroot}/opt/stalwart/logs
install -d %{buildroot}/opt/stalwart/data

# Бинарники
install -m 755 target/release/stalwart %{buildroot}/opt/stalwart/bin/stalwart
install -m 755 target/release/stalwart-cli %{buildroot}/opt/stalwart/bin/stalwart-cli

# Пример конфигурации
install -m 700 resources/config/config.toml %{buildroot}/opt/stalwart/etc/config.toml

# systemd unit
install -D -m 644 resources/systemd/stalwart-mail.service %{buildroot}/lib/systemd/system/stalwart-mail.service

%pre
getent group stalwart >/dev/null || groupadd -r stalwart
getent passwd stalwart >/dev/null || useradd -r -g stalwart -d /opt/stalwart -s /sbin/nologin -c "Stalwart mail server" stalwart

%post
%systemd_post stalwart-mail.service

%preun
%systemd_preun stalwart-mail.service

%postun
%systemd_postun_with_restart stalwart-mail.service

%files
%defattr(-,stalwart,stalwart,-)
/opt/stalwart/bin/stalwart
/opt/stalwart/bin/stalwart-cli
/opt/stalwart/etc/config.toml
%dir /opt/stalwart
%dir /opt/stalwart/bin
%dir /opt/stalwart/etc
%dir /opt/stalwart/logs
%dir /opt/stalwart/data
/lib/systemd/system/stalwart-mail.service

%changelog
* Thu Jul 17 2025 Andrey Semenow <trefas@altlinux.org> %version-%release
- First release for ALT Linux
