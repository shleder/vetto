Name:           vetto
Version:        0.2.5
Release:        1%{?dist}
Summary:        Daemon-less sandbox and audit layer for AI coding agents
License:        Apache-2.0
URL:            https://github.com/shleder/vetto
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  cargo >= 1.75

%description
vetto wraps local coding agents in an operating-system sandbox and produces
terminal-native visibility and post-session reports.

%prep
%autosetup

%build
cargo build --locked --release

%check
cargo test --locked

%install
install -Dm0755 target/release/vetto %{buildroot}%{_bindir}/vetto
install -Dm0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dm0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
mkdir -p %{buildroot}%{_datadir}/vetto/profiles
cp -a profiles/. %{buildroot}%{_datadir}/vetto/profiles/

%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/vetto
%{_datadir}/vetto/profiles

%changelog
* Fri Aug 28 2026 vetto contributors - 0.2.5-1
- Sync the source-only recipe with the published 0.2.5 release.

* Fri Aug 28 2026 vetto contributors - 0.2.3-1
- Sync the source-only recipe with the published 0.2.3 release.

* Sun Aug 23 2026 vetto contributors - 0.2.0-0.alpha.2
- Universal read-only rescue alpha metadata.

* Sun Aug 23 2026 vetto contributors - 0.1.0-0.1
- Source-only packaging recipe; no release performed.
