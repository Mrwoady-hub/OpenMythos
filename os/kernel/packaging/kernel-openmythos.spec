%global kernel_release 6.18.48-1.openmythos.fc44.x86_64
%global _buildhost openmythos-builder.invalid
%global clamp_mtime_to_source_date_epoch 1
%global use_source_date_epoch_as_buildtime 1
%global _source_payload w19.zstdio
%global _binary_payload w19.zstdio
%global debug_package %{nil}
%global __strip /bin/true

Name:           kernel-openmythos
Version:        6.18.48
Release:        1.openmythos%{?dist}
Summary:        OpenMythos-owned Linux kernel
License:        GPL-2.0-only
URL:            https://www.kernel.org/
Source0:        linux-%{version}.tar.xz
Source1:        6.18.48-x86_64.config
Source2:        module-signing.pem
BuildRequires:  bc, binutils, bison, elfutils-libelf-devel, flex, gcc, make
BuildRequires:  kmod, openssl, openssl-devel, perl-interpreter, python3, rsync
Requires:       kernel-openmythos-core-uname-r = %{kernel_release}
Requires:       kernel-openmythos-modules-uname-r = %{kernel_release}
Provides:       installonlypkg(kernel)
Provides:       kernel = %{version}-%{release}

%description
The install-only OpenMythos kernel package for the Stone image.

%package core
Summary: OpenMythos kernel image and built-in metadata
Provides: kernel-openmythos-core-uname-r = %{kernel_release}
Provides: kernel-core-uname-r = %{kernel_release}

%description core
The bootable OpenMythos kernel and built-in module metadata.

%package modules
Summary: Signed loadable modules for the OpenMythos kernel
Provides: kernel-openmythos-modules-uname-r = %{kernel_release}
Provides: kernel-modules-uname-r = %{kernel_release}
Requires: kernel-openmythos-core-uname-r = %{kernel_release}

%description modules
Loadable modules signed by the externally supplied Gate 01 identity.

%prep
%setup -q -n linux-%{version}
if [[ -z ${OPENMYTHOS_MODULE_SIGNING_KEY:-} || \
      ! -f $OPENMYTHOS_MODULE_SIGNING_KEY || \
      ! -r $OPENMYTHOS_MODULE_SIGNING_KEY ]]; then
  echo "OPENMYTHOS_MODULE_SIGNING_KEY must name a readable regular file" >&2
  exit 1
fi
cp -p -- %{SOURCE1} .config
cp -p -- %{SOURCE2} certs/openmythos-module.pem

%build
if [[ ! ${OPENMYTHOS_CONFIG_SHA256:-} =~ ^[0-9a-f]{64}$ ]]; then
  echo "OPENMYTHOS_CONFIG_SHA256 must be 64 lowercase hexadecimal characters" >&2
  exit 1
fi
printf '%s  .config\n' "$OPENMYTHOS_CONFIG_SHA256" | sha256sum --check --status
make olddefconfig
printf '%s  .config\n' "$OPENMYTHOS_CONFIG_SHA256" | sha256sum --check --status
test "$(make -s LOCALVERSION=-1.openmythos.fc44.x86_64 kernelrelease)" = \
  "%{kernel_release}"
make %{?_smp_mflags} \
  LOCALVERSION=-1.openmythos.fc44.x86_64 \
  KBUILD_BUILD_VERSION=1 \
  KBUILD_BUILD_USER=openmythos \
  KBUILD_BUILD_HOST=openmythos-builder \
  KBUILD_BUILD_TIMESTAMP=@1787899659 \
  KCFLAGS='-fdebug-prefix-map=%{_builddir}=. -fmacro-prefix-map=%{_builddir}=.' \
  KAFLAGS='-fdebug-prefix-map=%{_builddir}=. -fmacro-prefix-map=%{_builddir}=.' \
  all

%install
rm -rf -- %{buildroot}
make \
  LOCALVERSION=-1.openmythos.fc44.x86_64 \
  INSTALL_MOD_PATH=%{buildroot}/usr \
  DEPMOD=true \
  modules_install

module_root=%{buildroot}/usr/lib/modules/%{kernel_release}
test -d "$module_root/kernel"
if find "$module_root" -type f -name '*.ko.*' -print -quit | grep -q .; then
  echo "compressed modules are forbidden in Gate 01" >&2
  exit 1
fi
while IFS= read -r -d '' module; do
  scripts/sign-file sha256 "$OPENMYTHOS_MODULE_SIGNING_KEY" \
    certs/openmythos-module.pem "$module"
done < <(find "$module_root/kernel" -type f -name '*.ko' -print0 | LC_ALL=C sort -z)

rm -f -- "$module_root/build" "$module_root/source"
install -m 0644 arch/x86/boot/bzImage "$module_root/vmlinuz"
install -m 0644 .config "$module_root/config"
install -m 0644 System.map "$module_root/System.map"
depmod -b %{buildroot}/usr %{kernel_release}

%posttrans core
if [[ ${OPENMYTHOS_IMAGE_BUILD:-0} != 1 ]]; then
  /usr/bin/kernel-install add "%{kernel_release}" \
    "/usr/lib/modules/%{kernel_release}/vmlinuz"
fi

%preun core
if [[ $1 -eq 0 && ${OPENMYTHOS_IMAGE_BUILD:-0} != 1 ]]; then
  /usr/bin/kernel-install remove "%{kernel_release}"
fi

%files

%files core
/usr/lib/modules/%{kernel_release}/vmlinuz
/usr/lib/modules/%{kernel_release}/config
/usr/lib/modules/%{kernel_release}/System.map
/usr/lib/modules/%{kernel_release}/modules.builtin
/usr/lib/modules/%{kernel_release}/modules.builtin.modinfo
/usr/lib/modules/%{kernel_release}/modules.builtin.alias.bin
/usr/lib/modules/%{kernel_release}/modules.builtin.bin

%files modules
/usr/lib/modules/%{kernel_release}/kernel/
/usr/lib/modules/%{kernel_release}/modules.alias
/usr/lib/modules/%{kernel_release}/modules.alias.bin
/usr/lib/modules/%{kernel_release}/modules.dep
/usr/lib/modules/%{kernel_release}/modules.dep.bin
/usr/lib/modules/%{kernel_release}/modules.devname
/usr/lib/modules/%{kernel_release}/modules.order
/usr/lib/modules/%{kernel_release}/modules.softdep
/usr/lib/modules/%{kernel_release}/modules.symbols
/usr/lib/modules/%{kernel_release}/modules.symbols.bin
/usr/lib/modules/%{kernel_release}/modules.weakdep

%changelog
* Fri Aug 28 2026 OpenMythos Release Engineering <release@openmythos.dev> - 6.18.48-1.openmythos
- Package the Gate 01 owned kernel and deterministically signed modules.
