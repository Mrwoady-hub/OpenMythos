#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 builder-a|builder-b|canonical" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
case "$1" in
  builder-a)
    builder_id=builder-a
    ambient_hostname=ambient-a
    ambient_tz=UTC
    ambient_umask=0022
    ;;
  builder-b)
    builder_id=builder-b
    ambient_hostname=ambient-b
    ambient_tz=Pacific/Honolulu
    ambient_umask=0077
    ;;
  canonical)
    builder_id=canonical
    ambient_hostname=ambient-canonical
    ambient_tz=UTC
    ambient_umask=0022
    ;;
  *) usage ;;
esac

if [[ $(id -u) -eq 0 ]]; then
  echo "run the kernel build rootless" >&2
  exit 2
fi
umask "$ambient_umask"
export TZ=$ambient_tz

script_path=$(realpath -- "${BASH_SOURCE[0]}")
repo_root=$(git -C "$(dirname "$script_path")" rev-parse --show-toplevel)
repo_root=$(realpath -- "$repo_root")
if [[ $script_path != "$repo_root/scripts/gate01/build-kernel.sh" ]]; then
  echo "kernel builder must run from its owning repository" >&2
  exit 2
fi

gate_root=$(realpath -m -- "$repo_root/build/gate01")
builder_root=$(realpath -m -- "$gate_root/$builder_id")
output=$(realpath -m -- "$builder_root/kernel")
if [[ $builder_root != "$gate_root/$builder_id" || \
      $output != "$gate_root/$builder_id/kernel" ]]; then
  echo "refusing kernel output outside the selected Gate 01 builder" >&2
  exit 2
fi

remove_builder_tree() {
  case "$1" in
    "$output"|"$output/podman") podman unshare rm -rf -- "$1" ;;
    *) echo "refusing unsafe builder cleanup: $1" >&2; return 1 ;;
  esac
}

mkdir -p -- "$builder_root"
exec 9>"$builder_root/kernel-build.lock"
if ! flock -n 9; then
  echo "kernel build is already active for $builder_id" >&2
  exit 1
fi

source_lock="$repo_root/os/kernel/source.lock.json"
toolchain_lock="$repo_root/os/build/toolchain.lock.json"
source_archive="$gate_root/cache/sources/linux-6.18.48.tar.xz"
toolchain_archive="$gate_root/cache/kernel-builder.oci.tar"
config_dir="$repo_root/os/kernel/config"
config="$config_dir/6.18.48-x86_64.config"
config_checksum="$config.sha256"
public_certificate="$gate_root/secrets/module-signing.pem"
public_manifest="$gate_root/secrets/module-key.json"
private_key="$gate_root/secrets/module-signing.key"
spec="$repo_root/os/kernel/packaging/kernel-openmythos.spec"

required_inputs=(
  "$source_lock" "$toolchain_lock" "$source_archive" "$toolchain_archive"
  "$config" "$config_checksum" "$public_certificate" "$public_manifest"
  "$private_key" "$spec"
)
for path in "${required_inputs[@]}"; do
  if [[ ! -f $path || -L $path ]]; then
    echo "required regular file is missing or a symlink: $path" >&2
    exit 1
  fi
done
if [[ $(stat -c '%a' -- "$private_key") != 600 ]]; then
  echo "private key mode must be 0600" >&2
  exit 1
fi

PYTHONPATH="$repo_root" python3 -c '
import sys
from pathlib import Path
from tools.gate01.inputs import load_source_lock, validate_source_lock
lock = load_source_lock(Path(sys.argv[1]))
validate_source_lock(lock)
' "$source_lock"
PYTHONPATH="$repo_root" python3 -m tools.gate01.toolchain verify \
  "$toolchain_lock" --archive "$toolchain_archive"
source_sha=$(jq -er '.archive_sha256' "$source_lock")
printf '%s  %s\n' "$source_sha" "$source_archive" | sha256sum --check --status
(cd "$config_dir" && sha256sum --check --status "$(basename "$config_checksum")")
PYTHONPATH="$repo_root" python3 -m tools.gate01.kernel_config audit \
  --config "$config" --requirements "$config_dir/requirements.json"
config_sha=$(awk 'NF == 2 {print $1}' "$config_checksum")
if [[ ! $config_sha =~ ^[0-9a-f]{64}$ ]]; then
  echo "committed config checksum is malformed" >&2
  exit 1
fi

certificate_check=""
podman_root=""
output_scan_complete=0

scan_output_tree() {
  local scan_output scan_status
  scan_output=$(mktemp -- "$gate_root/.kernel-scan.XXXXXXXX")
  PYTHONPATH="$repo_root" python3 -m tools.gate01.module_key scan \
    --private-key "$private_key" --root "$output" >"$scan_output"
  scan_status=$?
  rm -f -- "$scan_output"
  return "$scan_status"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [[ -n $certificate_check ]]; then
    rm -f -- "$certificate_check"
  fi
  if [[ -n $podman_root && $podman_root == "$output/podman" ]]; then
    remove_builder_tree "$podman_root"
  fi
  if [[ $output_scan_complete -eq 0 && -d $output ]]; then
    if ! scan_output_tree; then
      chmod -R 0700 -- "$output"
      echo "private key leakage detected in $output" >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

certificate_check=$(mktemp -- "$gate_root/.module-key-check.XXXXXXXX")
PYTHONPATH="$repo_root" python3 -m tools.gate01.module_key describe \
  --certificate "$public_certificate" --output "$certificate_check"
cmp -s -- "$certificate_check" "$public_manifest" || {
  echo "public module certificate does not match its manifest" >&2
  exit 1
}
rm -f -- "$certificate_check"

toolchain_manifest=$(jq -er '.manifest_digest' "$toolchain_lock")
observed_toolchain_manifest="sha256:$(
  skopeo inspect --raw "oci-archive:$toolchain_archive" | sha256sum | awk '{print $1}'
)"
if [[ $observed_toolchain_manifest != "$toolchain_manifest" ]]; then
  echo "toolchain child manifest digest mismatch" >&2
  exit 1
fi
toolchain_image_id=$(
  skopeo inspect --raw "oci-archive:$toolchain_archive" | jq -er '.config.digest'
)
if [[ ! $toolchain_image_id =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "toolchain archive has an invalid image ID" >&2
  exit 1
fi

remove_builder_tree "$output"
mkdir -p -- "$output/rpmbuild"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
chmod 0755 -- "$output" "$output/rpmbuild" "$output/rpmbuild"/*
install -m 0644 -- "$source_archive" \
  "$output/rpmbuild/SOURCES/linux-6.18.48.tar.xz"
install -m 0644 -- "$config" \
  "$output/rpmbuild/SOURCES/6.18.48-x86_64.config"
install -m 0644 -- "$public_certificate" \
  "$output/rpmbuild/SOURCES/module-signing.pem"
install -m 0644 -- "$spec" \
  "$output/rpmbuild/SPECS/kernel-openmythos.spec"
find "$output/rpmbuild/SOURCES" "$output/rpmbuild/SPECS" -type f \
  -exec chmod 0644 -- {} + \
  -exec touch --date=@1787899659 -- {} +

podman_root="$output/podman"
mkdir -p -- "$podman_root"/{root,runroot,tmp}
chmod 0700 -- "$podman_root" "$podman_root"/*
podman_cmd=(
  podman --root "$podman_root/root" --runroot "$podman_root/runroot"
  --tmpdir "$podman_root/tmp" --storage-driver vfs
)
"${podman_cmd[@]}" load --quiet --input "$toolchain_archive" >/dev/null
"${podman_cmd[@]}" image exists "$toolchain_image_id"

container_common=(
  run --rm --network=none --read-only --security-opt label=disable
  --tmpfs "/tmp:rw,noexec,nosuid,nodev"
  --hostname "$ambient_hostname"
  --volume "$repo_root:/repo:ro"
  --volume "$(dirname "$source_archive"):/source-cache:ro"
  --volume "$config_dir:/config:ro"
  --volume "$private_key:/run/secrets/module-signing.key:ro"
  --volume "$output:/work:rw"
  --env SOURCE_DATE_EPOCH=1787899659
  --env TZ=UTC
  --env LC_ALL=C.UTF-8
  --env LANG=C.UTF-8
  --env OPENMYTHOS_MODULE_SIGNING_KEY=/run/secrets/module-signing.key
  --env "OPENMYTHOS_CONFIG_SHA256=$config_sha"
  --env PYTHONDONTWRITEBYTECODE=1
  --env PYTHONPATH=/repo
  --entrypoint /bin/bash
  "$toolchain_image_id"
)

"${podman_cmd[@]}" "${container_common[@]}" -c \
  'gcc --version | head -n 1' >"$output/compiler-version.txt"
chmod 0644 -- "$output/compiler-version.txt"

build_log="$output/build.log"
start_seconds=$SECONDS
peak_output_bytes=$(du -sb -- "$output" 2>/dev/null | awk '{print $1}')
set +e
# The single-quoted program below runs inside the container.
# shellcheck disable=SC2016
"${podman_cmd[@]}" "${container_common[@]}" -Eeuo pipefail -c '
cd /work
rpmbuild -ba \
  --define "_topdir /work/rpmbuild" \
  --define "dist .fc44" \
  --define "_smp_mflags -j4" \
  /work/rpmbuild/SPECS/kernel-openmythos.spec
' >"$build_log" 2>&1 &
build_pid=$!
while kill -0 "$build_pid" 2>/dev/null; do
  current_output_bytes=$(du -sb -- "$output" 2>/dev/null | awk '{print $1}')
  if ((current_output_bytes > peak_output_bytes)); then
    peak_output_bytes=$current_output_bytes
  fi
  sleep 2
done
wait "$build_pid"
build_status=$?
set -e
elapsed_seconds=$((SECONDS - start_seconds))
current_output_bytes=$(du -sb -- "$output" 2>/dev/null | awk '{print $1}')
if ((current_output_bytes > peak_output_bytes)); then
  peak_output_bytes=$current_output_bytes
fi
chmod 0644 -- "$build_log"
if [[ $build_status -ne 0 ]]; then
  echo "kernel RPM build failed; see $build_log" >&2
  exit "$build_status"
fi

expected_srpm="kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm"
expected_binary_rpms=(
  "kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64.rpm"
  "kernel-openmythos-core-6.18.48-1.openmythos.fc44.x86_64.rpm"
  "kernel-openmythos-modules-6.18.48-1.openmythos.fc44.x86_64.rpm"
)
mapfile -t observed_srpms < <(
  find "$output/rpmbuild/SRPMS" -maxdepth 1 -type f -name '*.rpm' -printf '%f\n' |
    LC_ALL=C sort
)
if [[ ${#observed_srpms[@]} -ne 1 || ${observed_srpms[0]} != "$expected_srpm" ]]; then
  echo "kernel build did not produce the exact expected source RPM" >&2
  exit 1
fi
mapfile -t observed_binary_rpms < <(
  find "$output/rpmbuild/RPMS" -type f -name '*.rpm' -printf '%f\n' |
    LC_ALL=C sort
)
if [[ ${#observed_binary_rpms[@]} -ne 3 ]]; then
  echo "kernel build did not produce exactly three binary RPMs" >&2
  exit 1
fi
for index in "${!expected_binary_rpms[@]}"; do
  if [[ ${observed_binary_rpms[$index]} != "${expected_binary_rpms[$index]}" ]]; then
    echo "kernel build binary RPM set is not exact" >&2
    exit 1
  fi
done

"${podman_cmd[@]}" "${container_common[@]}" -Eeuo pipefail -c '
python3 -m tools.gate01.rpm_artifacts inspect \
  --rpm-dir /work/rpmbuild/RPMS/x86_64 \
  --srpm-dir /work/rpmbuild/SRPMS \
  --output /work/rpm-artifacts.json \
  --extract-root /work/extracted
'
PYTHONPATH="$repo_root" python3 -m tools.gate01.rpm_artifacts validate \
  "$output/rpm-artifacts.json"

compiler_version=$(<"$output/compiler-version.txt")
jq -n \
  --arg builder_id "$builder_id" \
  --arg ambient_hostname "$ambient_hostname" \
  --arg ambient_tz "$ambient_tz" \
  --arg ambient_umask "$ambient_umask" \
  --arg compiler_version "$compiler_version" \
  --arg toolchain_manifest "$toolchain_manifest" \
  --argjson elapsed_seconds "$elapsed_seconds" \
  --argjson peak_output_bytes "$peak_output_bytes" \
  '{
    schema_version: 1,
    builder_id: $builder_id,
    ambient_environment: {
      hostname: $ambient_hostname,
      tz: $ambient_tz,
      umask: $ambient_umask
    },
    declared_environment: {
      source_date_epoch: 1787899659,
      tz: "UTC",
      locale: "C.UTF-8",
      build_host: "openmythos-builder",
      build_user: "openmythos",
      rpm_buildhost: "openmythos-builder.invalid",
      parallelism: 4
    },
    compiler_version: $compiler_version,
    toolchain_manifest_digest: $toolchain_manifest,
    elapsed_seconds: $elapsed_seconds,
    peak_output_bytes: $peak_output_bytes,
    network_used: false
  }' >"$output/build-report.json"
chmod 0644 -- "$output/build-report.json" "$output/rpm-artifacts.json" \
  "$output/installed-files.json"

remove_builder_tree "$podman_root"
podman_root=""
set +e
scan_output_tree
scan_status=$?
set -e
output_scan_complete=1
if [[ $scan_status -ne 0 ]]; then
  chmod -R 0700 -- "$output"
  echo "private key leakage detected in $output" >&2
  exit 1
fi
find "$output" -type d -exec chmod 0755 -- {} +
find "$output" -type f -exec chmod 0644 -- {} +

printf 'built %s kernel RPM set in %s seconds at %s\n' \
  "$builder_id" "$elapsed_seconds" "$output"
