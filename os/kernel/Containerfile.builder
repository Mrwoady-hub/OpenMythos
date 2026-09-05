FROM quay.io/fedora/fedora-bootc@sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756

RUN dnf -y install \
      bash bc binutils bison cpio diffutils dwarves \
      elfutils-libelf-devel findutils flex gcc gcc-c++ glibc-static \
      gpg2 hostname kmod libfaketime make openssl openssl-devel patch \
      perl-interpreter python3 python3-jsonschema rpm-build rpmdevtools rsync tar xz zstd \
    && dnf clean all \
    && rm -rf /var/cache/dnf

RUN test "$(rpm --eval '%{?dist}')" = ".fc44" \
    && test "$(uname -m)" = "x86_64"

LABEL org.opencontainers.image.title="OpenMythos Linux 6.18 Gate 01 builder" \
      org.opencontainers.image.source="https://github.com/The-Swarm-Corporation/OpenMythos" \
      org.opencontainers.image.base.digest="sha256:d6481b291e960abb02a346294dcac2818df8dfe2b1bc51d1ae8fa53a15718756"
