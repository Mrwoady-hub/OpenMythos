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

# Bash can read a running script incrementally. Re-execute a verified private copy
# before doing any build work so edits to the worktree cannot alter this process.
if [[ ${OPENMYTHOS_STABLE_KERNEL_DRIVER:-0} != 1 ]]; then
  original_script=$(realpath -- "${BASH_SOURCE[0]}")
  original_repo=$(git -C "$(dirname "$original_script")" rev-parse --show-toplevel)
  original_repo=$(realpath -- "$original_repo")
  if [[ $original_script != "$original_repo/scripts/gate01/build-kernel.sh" ]]; then
    echo "kernel builder must run from its owning repository" >&2
    exit 2
  fi
  bootstrap_gate=$(realpath -m -- "$original_repo/build/gate01")
  bootstrap_builder=$(realpath -m -- "$bootstrap_gate/$builder_id")
  if [[ $bootstrap_builder != "$bootstrap_gate/$builder_id" ]]; then
    echo "refusing kernel bootstrap outside the selected Gate 01 builder" >&2
    exit 2
  fi
  mkdir -p -- "$bootstrap_builder"
  stable_driver_root=$(mktemp -d -- "$bootstrap_builder/.kernel-driver.XXXXXXXX")
  stable_driver="$stable_driver_root/build-kernel.sh"
  before_identity=$(stat -c '%d:%i:%s:%Y:%Z' -- "$original_script")
  install -m 0555 -- "$original_script" "$stable_driver"
  after_identity=$(stat -c '%d:%i:%s:%Y:%Z' -- "$original_script")
  if [[ $before_identity != "$after_identity" ]] || ! cmp -s -- "$original_script" "$stable_driver"; then
    rm -f -- "$stable_driver"
    rmdir -- "$stable_driver_root"
    echo "kernel build driver changed while being snapshotted" >&2
    exit 1
  fi
  stable_driver_sha=$(sha256sum -- "$stable_driver" | awk '{print $1}')
  chmod 0500 -- "$stable_driver_root"
  export OPENMYTHOS_STABLE_KERNEL_DRIVER=1
  export OPENMYTHOS_ORIGINAL_REPO=$original_repo
  export OPENMYTHOS_ORIGINAL_KERNEL_DRIVER=$original_script
  export OPENMYTHOS_STABLE_KERNEL_DRIVER_ROOT=$stable_driver_root
  export OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256=$stable_driver_sha
  exec /bin/bash "$stable_driver" "$builder_id"
  status=$?
  chmod 0700 -- "$stable_driver_root"
  rm -f -- "$stable_driver"
  rmdir -- "$stable_driver_root"
  exit "$status"
fi

umask "$ambient_umask"
export TZ=$ambient_tz

script_path=$(realpath -- "${BASH_SOURCE[0]}")
repo_root=$(realpath -- "${OPENMYTHOS_ORIGINAL_REPO:?}")
original_script=$(realpath -- "${OPENMYTHOS_ORIGINAL_KERNEL_DRIVER:?}")
stable_driver_root=$(realpath -- "${OPENMYTHOS_STABLE_KERNEL_DRIVER_ROOT:?}")
if [[ $original_script != "$repo_root/scripts/gate01/build-kernel.sh" || \
      $script_path != "$stable_driver_root/build-kernel.sh" || \
      $(sha256sum -- "$script_path" | awk '{print $1}') != \
        "${OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256:?}" ]]; then
  echo "stable kernel build driver identity is invalid" >&2
  exit 2
fi

gate_root=$(realpath -m -- "$repo_root/build/gate01")
builder_root=$(realpath -m -- "$gate_root/$builder_id")
output=$(realpath -m -- "$builder_root/kernel")
runtime_root=$(realpath -m -- "$builder_root/kernel-runtime")
inspection_work=$(realpath -m -- "$builder_root/kernel-inspection")
build_podman_root=$(realpath -m -- "$builder_root/kernel-podman-build")
inspect_podman_root=$(realpath -m -- "$builder_root/kernel-podman-inspect")
if [[ $builder_root != "$gate_root/$builder_id" || \
      $output != "$builder_root/kernel" || \
      $runtime_root != "$builder_root/kernel-runtime" || \
      $inspection_work != "$builder_root/kernel-inspection" || \
      $build_podman_root != "$builder_root/kernel-podman-build" || \
      $inspect_podman_root != "$builder_root/kernel-podman-inspect" || \
      $stable_driver_root != "$builder_root"/.kernel-driver.* ]]; then
  echo "refusing kernel paths outside the selected Gate 01 builder" >&2
  exit 2
fi

remove_builder_tree() {
  case "$1" in
    "$output"|"$runtime_root"|"$inspection_work"|\
    "$build_podman_root"|"$inspect_podman_root")
      if [[ -e $1 ]]; then
        podman unshare rm -rf -- "$1"
      fi
      ;;
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
config_requirements="$config_dir/requirements.json"
public_certificate="$gate_root/secrets/module-signing.pem"
public_manifest="$gate_root/secrets/module-key.json"
private_key="$gate_root/secrets/module-signing.key"
spec="$repo_root/os/kernel/packaging/kernel-openmythos.spec"
verifier="$repo_root/tools/gate01/rpm_artifacts.py"

required_inputs=(
  "$source_lock" "$toolchain_lock" "$source_archive" "$toolchain_archive"
  "$config" "$config_checksum" "$config_requirements" "$public_certificate"
  "$public_manifest" "$private_key" "$spec" "$verifier" "$original_script"
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

output_scan_complete=0
source_freeze_verified=0

scan_output_tree() {
  local scan_output scan_status
  scan_output=$(mktemp -- "$gate_root/.kernel-scan.XXXXXXXX")
  set +e
  PYTHONPATH="$repo_root" python3 -m tools.gate01.module_key scan \
    --private-key "$private_key" --root "$output" >"$scan_output"
  scan_status=$?
  set -e
  rm -f -- "$scan_output"
  return "$scan_status"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  remove_builder_tree "$build_podman_root"
  remove_builder_tree "$inspect_podman_root"
  remove_builder_tree "$inspection_work"
  remove_builder_tree "$runtime_root"
  if [[ $output_scan_complete -eq 0 && -d $output ]]; then
    if ! scan_output_tree; then
      chmod -R 0700 -- "$output"
      echo "private key leakage detected in $output" >&2
      status=1
    fi
  fi
  if [[ $source_freeze_verified -eq 0 && $status -eq 0 ]]; then
    echo "source freeze was not verified" >&2
    status=1
  fi
  chmod 0700 -- "$stable_driver_root" 2>/dev/null
  rm -f -- "$stable_driver_root/build-kernel.sh"
  rmdir -- "$stable_driver_root" 2>/dev/null
  exit "$status"
}
trap cleanup EXIT

remove_builder_tree "$output"
remove_builder_tree "$runtime_root"
remove_builder_tree "$inspection_work"
remove_builder_tree "$build_podman_root"
remove_builder_tree "$inspect_podman_root"
mkdir -p -- "$output" "$runtime_root/source-snapshot" \
  "$runtime_root/verifier/tools/gate01" "$inspection_work"
chmod 0700 -- "$runtime_root" "$runtime_root/source-snapshot" \
  "$runtime_root/verifier" "$runtime_root/verifier/tools" \
  "$runtime_root/verifier/tools/gate01" "$inspection_work"

snapshot_regular() {
  local input=$1 output_path=$2 mode=$3 before after
  before=$(stat -c '%d:%i:%s:%Y:%Z' -- "$input")
  install -m "$mode" -- "$input" "$output_path"
  after=$(stat -c '%d:%i:%s:%Y:%Z' -- "$input")
  if [[ $before != "$after" ]] || ! cmp -s -- "$input" "$output_path"; then
    echo "input changed while being snapshotted: $input" >&2
    exit 1
  fi
}

snapshot_source_lock="$runtime_root/source-snapshot/source.lock.json"
snapshot_toolchain_lock="$runtime_root/source-snapshot/toolchain.lock.json"
snapshot_source_archive="$runtime_root/source-snapshot/linux-6.18.48.tar.xz"
snapshot_toolchain_archive="$runtime_root/source-snapshot/kernel-builder.oci.tar"
snapshot_config="$runtime_root/source-snapshot/6.18.48-x86_64.config"
snapshot_config_checksum="$runtime_root/source-snapshot/6.18.48-x86_64.config.sha256"
snapshot_config_requirements="$runtime_root/source-snapshot/requirements.json"
snapshot_public_certificate="$runtime_root/source-snapshot/module-signing.pem"
snapshot_public_manifest="$runtime_root/source-snapshot/module-key.json"
snapshot_spec="$runtime_root/source-snapshot/kernel-openmythos.spec"
snapshot_verifier="$runtime_root/verifier/tools/gate01/rpm_artifacts.py"

snapshot_regular "$source_lock" "$snapshot_source_lock" 0444
snapshot_regular "$toolchain_lock" "$snapshot_toolchain_lock" 0444
snapshot_regular "$source_archive" "$snapshot_source_archive" 0444
snapshot_regular "$toolchain_archive" "$snapshot_toolchain_archive" 0444
snapshot_regular "$config" "$snapshot_config" 0444
snapshot_regular "$config_checksum" "$snapshot_config_checksum" 0444
snapshot_regular "$config_requirements" "$snapshot_config_requirements" 0444
snapshot_regular "$public_certificate" "$snapshot_public_certificate" 0444
snapshot_regular "$public_manifest" "$snapshot_public_manifest" 0444
snapshot_regular "$spec" "$snapshot_spec" 0444
snapshot_regular "$verifier" "$snapshot_verifier" 0444
chmod 0555 -- "$runtime_root/source-snapshot" "$runtime_root/verifier" \
  "$runtime_root/verifier/tools" "$runtime_root/verifier/tools/gate01"
if ! cmp -s -- "$spec" "$snapshot_spec" || \
   ! cmp -s -- "$verifier" "$snapshot_verifier" || \
   [[ $(sha256sum -- "$original_script" | awk '{print $1}') != \
      "${OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256}" ]]; then
  echo "Task 6 source changed while snapshots were being frozen" >&2
  exit 1
fi

task6_source_manifest="$runtime_root/task6-source.sha256"
(
  cd "$repo_root"
  sha256sum \
    scripts/gate01/build-kernel.sh \
    os/kernel/packaging/kernel-openmythos.spec \
    tools/gate01/rpm_artifacts.py
) >"$task6_source_manifest"
chmod 0444 -- "$task6_source_manifest"
snapshot_manifest="$runtime_root/snapshot.sha256"
(
  cd "$runtime_root"
  sha256sum \
    source-snapshot/source.lock.json \
    source-snapshot/toolchain.lock.json \
    source-snapshot/linux-6.18.48.tar.xz \
    source-snapshot/kernel-builder.oci.tar \
    source-snapshot/6.18.48-x86_64.config \
    source-snapshot/6.18.48-x86_64.config.sha256 \
    source-snapshot/requirements.json \
    source-snapshot/module-signing.pem \
    source-snapshot/module-key.json \
    source-snapshot/kernel-openmythos.spec \
    verifier/tools/gate01/rpm_artifacts.py
) >"$snapshot_manifest"
chmod 0444 -- "$snapshot_manifest"

PYTHONPATH="$repo_root" python3 -c '
import sys
from pathlib import Path
from tools.gate01.inputs import load_source_lock, validate_source_lock
lock = load_source_lock(Path(sys.argv[1]))
validate_source_lock(lock)
' "$snapshot_source_lock"
PYTHONPATH="$repo_root" python3 -m tools.gate01.toolchain verify \
  "$snapshot_toolchain_lock" --archive "$snapshot_toolchain_archive"
source_sha=$(jq -er '.archive_sha256' "$snapshot_source_lock")
printf '%s  %s\n' "$source_sha" "$snapshot_source_archive" | \
  sha256sum --check --status
(
  cd "$runtime_root/source-snapshot"
  sha256sum --check --status "$(basename "$snapshot_config_checksum")"
)
PYTHONPATH="$repo_root" python3 -m tools.gate01.kernel_config audit \
  --config "$snapshot_config" --requirements "$snapshot_config_requirements"
config_sha=$(awk 'NF == 2 {print $1}' "$snapshot_config_checksum")
if [[ ! $config_sha =~ ^[0-9a-f]{64}$ ]]; then
  echo "committed config checksum is malformed" >&2
  exit 1
fi

certificate_check=$(mktemp -- "$runtime_root/.module-key-check.XXXXXXXX")
PYTHONPATH="$repo_root" python3 -m tools.gate01.module_key describe \
  --certificate "$snapshot_public_certificate" --output "$certificate_check"
cmp -s -- "$certificate_check" "$snapshot_public_manifest" || {
  echo "public module certificate does not match its manifest" >&2
  exit 1
}
rm -f -- "$certificate_check"

toolchain_manifest=$(jq -er '.manifest_digest' "$snapshot_toolchain_lock")
observed_toolchain_manifest="sha256:$(
  skopeo inspect --raw "oci-archive:$snapshot_toolchain_archive" | \
    sha256sum | awk '{print $1}'
)"
if [[ $observed_toolchain_manifest != "$toolchain_manifest" ]]; then
  echo "toolchain child manifest digest mismatch" >&2
  exit 1
fi
toolchain_image_id=$(
  skopeo inspect --raw "oci-archive:$snapshot_toolchain_archive" | \
    jq -er '.config.digest'
)
if [[ ! $toolchain_image_id =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "toolchain archive has an invalid image ID" >&2
  exit 1
fi

isolation_plan="$runtime_root/container-isolation.json"
jq -n \
  --arg repository_root "$repo_root" \
  --arg output "$output" \
  --arg build_store "$build_podman_root" \
  --arg inspection_store "$inspect_podman_root" \
  --arg private_key "$private_key" \
  --arg verifier_snapshot "$runtime_root/verifier" \
  --arg public_certificate "$snapshot_public_certificate" \
  --arg rpms "$output/rpmbuild/RPMS/x86_64" \
  --arg srpms "$output/rpmbuild/SRPMS" \
  --arg inspection_work "$inspection_work" \
  '{
    repository_root: $repository_root,
    output: $output,
    build_store: $build_store,
    inspection_store: $inspection_store,
    signing_environment: {probe: false, build: true, inspection: false},
    probe_mounts: [],
    build_mounts: [
      {source: $output, target: "/work", read_only: false},
      {
        source: $private_key,
        target: "/run/secrets/module-signing.key",
        read_only: true
      }
    ],
    inspection_mounts: [
      {source: $verifier_snapshot, target: "/verifier", read_only: true},
      {
        source: $public_certificate,
        target: "/public/module-signing.pem",
        read_only: true
      },
      {source: $rpms, target: "/rpms", read_only: true},
      {source: $srpms, target: "/srpms", read_only: true},
      {source: $inspection_work, target: "/inspect", read_only: false}
    ]
  }' >"$isolation_plan"
chmod 0444 -- "$isolation_plan"
(
  cd "$runtime_root/verifier"
  PYTHONDONTWRITEBYTECODE=1 python3 -m tools.gate01.rpm_artifacts \
    audit-isolation --plan "$isolation_plan"
)

mkdir -p -- "$output/rpmbuild"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
chmod 0755 -- "$output" "$output/rpmbuild" "$output/rpmbuild"/*
install -m 0644 -- "$snapshot_source_archive" \
  "$output/rpmbuild/SOURCES/linux-6.18.48.tar.xz"
install -m 0644 -- "$snapshot_config" \
  "$output/rpmbuild/SOURCES/6.18.48-x86_64.config"
install -m 0644 -- "$snapshot_public_certificate" \
  "$output/rpmbuild/SOURCES/module-signing.pem"
install -m 0644 -- "$snapshot_spec" \
  "$output/rpmbuild/SPECS/kernel-openmythos.spec"
find "$output/rpmbuild/SOURCES" "$output/rpmbuild/SPECS" -type f \
  -exec chmod 0644 -- {} + \
  -exec touch --date=@1787899659 -- {} +

initialize_podman_store() {
  local store_root=$1 array_name=$2 observed_config_id observed_manifest_digest
  local -n command_ref=$array_name
  mkdir -p -- "$store_root"/{root,runroot,tmp}
  chmod 0700 -- "$store_root" "$store_root"/*
  command_ref=(
    podman --root "$store_root/root" --runroot "$store_root/runroot"
    --tmpdir "$store_root/tmp" --storage-driver vfs
  )
  "${command_ref[@]}" load --quiet --input "$snapshot_toolchain_archive" >/dev/null
  "${command_ref[@]}" image exists "$toolchain_image_id"
  observed_config_id=$(
    "${command_ref[@]}" image inspect --format '{{.Id}}' "$toolchain_image_id"
  )
  observed_manifest_digest=$(
    "${command_ref[@]}" image inspect --format '{{.Digest}}' "$toolchain_image_id"
  )
  (
    cd "$runtime_root/verifier"
    PYTHONDONTWRITEBYTECODE=1 python3 -m tools.gate01.rpm_artifacts audit-image \
      --observed-config-id "$observed_config_id" \
      --observed-manifest-digest "$observed_manifest_digest" \
      --expected-config-id "$toolchain_image_id" \
      --expected-manifest-digest "$toolchain_manifest"
  )
}

declare -a build_podman_cmd=()
initialize_podman_store "$build_podman_root" build_podman_cmd

container_security=(
  run --rm --network=none --read-only --security-opt label=disable
  --tmpfs "/tmp:rw,noexec,nosuid,nodev"
  --hostname "$ambient_hostname"
  --env SOURCE_DATE_EPOCH=1787899659
  --env TZ=UTC
  --env LC_ALL=C.UTF-8
  --env LANG=C.UTF-8
  --env PYTHONDONTWRITEBYTECODE=1
)

# The compiler probe intentionally has no host mounts and no signing environment.
"${build_podman_cmd[@]}" "${container_security[@]}" \
  --entrypoint /bin/bash "$toolchain_image_id" -c \
  'gcc --version | head -n 1' >"$output/compiler-version.txt"
chmod 0644 -- "$output/compiler-version.txt"

build_log="$output/build.log"
start_seconds=$SECONDS
peak_output_bytes=$(du -sb -- "$output" 2>/dev/null | awk '{print $1}')
set +e
# Only this rpmbuild container receives the private key and signing variable.
# shellcheck disable=SC2016
"${build_podman_cmd[@]}" "${container_security[@]}" \
  --volume "$output:/work:rw" \
  --volume "$private_key:/run/secrets/module-signing.key:ro" \
  --env OPENMYTHOS_MODULE_SIGNING_KEY=/run/secrets/module-signing.key \
  --env "OPENMYTHOS_CONFIG_SHA256=$config_sha" \
  --entrypoint /bin/bash "$toolchain_image_id" -Eeuo pipefail -c '
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

# Tear down the signing-capable store, then independently import the locked image
# into a fresh secret-free store for inspection.
remove_builder_tree "$build_podman_root"
declare -a inspect_podman_cmd=()
initialize_podman_store "$inspect_podman_root" inspect_podman_cmd
mkdir -p -- "$inspection_work/evidence"
chmod 0755 -- "$inspection_work" "$inspection_work/evidence"
"${inspect_podman_cmd[@]}" "${container_security[@]}" \
  --volume "$runtime_root/verifier:/verifier:ro" \
  --volume "$snapshot_public_certificate:/public/module-signing.pem:ro" \
  --volume "$output/rpmbuild/RPMS/x86_64:/rpms:ro" \
  --volume "$output/rpmbuild/SRPMS:/srpms:ro" \
  --volume "$inspection_work:/inspect:rw" \
  --env PYTHONPATH=/verifier \
  --entrypoint /bin/bash "$toolchain_image_id" -Eeuo pipefail -c '
python3 -m tools.gate01.rpm_artifacts inspect \
  --rpm-dir /rpms \
  --srpm-dir /srpms \
  --output /inspect/evidence/rpm-artifacts.json \
  --extract-root /inspect/extracted \
  --public-certificate /public/module-signing.pem
'
(
  cd "$runtime_root/verifier"
  PYTHONDONTWRITEBYTECODE=1 python3 -m tools.gate01.rpm_artifacts validate \
    "$inspection_work/evidence/rpm-artifacts.json"
)
remove_builder_tree "$inspect_podman_root"

mv -- "$inspection_work/evidence/rpm-artifacts.json" "$output/rpm-artifacts.json"
mv -- "$inspection_work/evidence/installed-files.json" "$output/installed-files.json"
mv -- "$inspection_work/extracted" "$output/extracted"

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
    isolation: {
      stable_driver_snapshot: true,
      frozen_spec_and_verifier: true,
      build_and_inspection_stores_distinct: true,
      stores_visible_inside_containers: false,
      probe_private_key_mounted: false,
      inspector_private_key_mounted: false,
      inspector_public_certificate_only: true,
      recursive_repository_mount: false
    },
    compiler_version: $compiler_version,
    toolchain_manifest_digest: $toolchain_manifest,
    elapsed_seconds: $elapsed_seconds,
    peak_output_bytes: $peak_output_bytes,
    network_used: false
  }' >"$output/build-report.json"
install -m 0644 -- "$snapshot_manifest" "$output/source-snapshot.sha256"

(
  cd "$repo_root"
  sha256sum --check --status "$task6_source_manifest"
)
(
  cd "$runtime_root"
  sha256sum --check --status "$snapshot_manifest"
)
if [[ $(sha256sum -- "$original_script" | awk '{print $1}') != \
      "${OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256}" ]]; then
  echo "kernel build driver changed during proof" >&2
  exit 1
fi
source_freeze_verified=1

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
