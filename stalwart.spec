Name:    stalwart
Version: 0.13.0
Release: alt1

Summary: Secure, scalable mail & collaboration server (IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV)
Summary(ru_RU.UTF-8): Защищённый, масштабируемый почтовый и коллаборационный сервер с поддержкой IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV.
License: AGPL-3.0-only
Group:   Development/Tools
URL:     https://stalw.art

Source0: %name-%version.tar

BuildRequires:  rust-cargo /proc
BuildRequires:  rust >= 1.70
BuildRequires:  pkgconfig
BuildRequires:  clang-devel
BuildRequires:  libclang19
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
export CC=clang
export CXX=clang++
export LIBCLANG_PATH=/usr/lib/llvm-19.1/lib64
cargo build --release --no-default-features --features "sqlite postgres mysql elastic s3 redis azure nats"
cargo build --release -p stalwart-cli

%install
# Создание директорий
mkdir -p %buildroot%_bindir
mkdir -p %buildroot%_unitdir
mkdir -p %buildroot%_datadir/%name
mkdir -p %buildroot%_sysconfdir/%name

# Бинарники
install -pm755 target/release/stalwart %buildroot%_bindir/
install -pm755 target/release/stalwart-cli %buildroot%_bindir/

# Пример конфигурации
install -pm700 resources/config/config.toml %buildroot%_sysconfdir/%name/

# systemd unit
install -pm644 resources/systemd/stalwart-mail.service %buildroot%_unitdir/

%pre
getent group stalwart >/dev/null || groupadd -r stalwart
getent passwd stalwart >/dev/null || useradd -r -g stalwart -s /sbin/nologin -c "Stalwart mail server" stalwart

%post
%systemd_post stalwart-mail.service

%preun
%systemd_preun stalwart-mail.service

%postun
%systemd_postun_with_restart stalwart-mail.service

%files
%doc README.md
%_bindir/%name
%_bindir/stalwart-cli
%dir %_datadir/%name
%_sysconfdir/%name/config.toml

%changelog
* Thu Jul 17 2025 Andrey Semenow <trefas@altlinux.org> %version-%release
- First release for ALT Linux
