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
  stable_driver_root=
  stable_driver=
  bootstrap_cleanup() {
    local status=$? cleanup_failed=0 root_parent root_basename
    trap - EXIT
    set +e
    if [[ -n $stable_driver_root ]]; then
      root_parent=$(dirname -- "$stable_driver_root")
      root_basename=$(basename -- "$stable_driver_root")
      if [[ $root_parent == "$bootstrap_builder" && \
            $root_basename =~ ^\.kernel-driver\.[A-Za-z0-9]{8}$ && \
            $stable_driver == "$stable_driver_root/build-kernel.sh" ]]; then
        if [[ -e $stable_driver_root || -L $stable_driver_root ]]; then
          chmod 0700 -- "$stable_driver_root" || cleanup_failed=1
        fi
        if [[ -e $stable_driver || -L $stable_driver ]]; then
          rm -f -- "$stable_driver" || cleanup_failed=1
        fi
        if [[ -e $stable_driver_root || -L $stable_driver_root ]]; then
          rmdir -- "$stable_driver_root" || cleanup_failed=1
        fi
      else
        echo "refusing unsafe bootstrap driver cleanup" >&2
        cleanup_failed=1
      fi
    fi
    if [[ $status -eq 0 && $cleanup_failed -ne 0 ]]; then
      status=1
    fi
    exit "$status"
  }
  trap bootstrap_cleanup EXIT
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
fi

stable_cleanup_repo=${OPENMYTHOS_ORIGINAL_REPO:-}
stable_cleanup_root=${OPENMYTHOS_STABLE_KERNEL_DRIVER_ROOT:-}
stable_cleanup_script=$(realpath -m -- "${BASH_SOURCE[0]}")
remove_stable_driver_copy() {
  local expected_parent root_parent root_basename cleanup_failed=0
  expected_parent="$stable_cleanup_repo/build/gate01/$builder_id"
  root_parent=$(dirname -- "$stable_cleanup_root")
  root_basename=$(basename -- "$stable_cleanup_root")
  if [[ $stable_cleanup_repo != /* || \
        $root_parent != "$expected_parent" || \
        ! $root_basename =~ ^\.kernel-driver\.[A-Za-z0-9]{8}$ || \
        $stable_cleanup_script != "$stable_cleanup_root/build-kernel.sh" ]]; then
    echo "refusing unsafe stable driver cleanup" >&2
    return 1
  fi
  if [[ ! -e $stable_cleanup_root && ! -L $stable_cleanup_root ]]; then
    return 0
  fi
  chmod 0700 -- "$stable_cleanup_root" || cleanup_failed=1
  if [[ -e $stable_cleanup_root/build-kernel.sh || \
        -L $stable_cleanup_root/build-kernel.sh ]]; then
    rm -f -- "$stable_cleanup_root/build-kernel.sh" || cleanup_failed=1
  fi
  if [[ -e $stable_cleanup_root || -L $stable_cleanup_root ]]; then
    rmdir -- "$stable_cleanup_root" || cleanup_failed=1
  fi
  return "$cleanup_failed"
}
early_cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT
  set +e
  remove_stable_driver_copy || cleanup_failed=1
  if [[ $status -eq 0 && $cleanup_failed -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap early_cleanup EXIT

umask "$ambient_umask"
export TZ=$ambient_tz

script_path=$(realpath -- "${BASH_SOURCE[0]}")
repo_root=$(realpath -- "${OPENMYTHOS_ORIGINAL_REPO:?}")
original_script=$(realpath -- "${OPENMYTHOS_ORIGINAL_KERNEL_DRIVER:?}")
stable_driver_root=$(realpath -- "${OPENMYTHOS_STABLE_KERNEL_DRIVER_ROOT:?}")
stable_driver_parent=$(dirname -- "$stable_driver_root")
stable_driver_basename=$(basename -- "$stable_driver_root")
if [[ $original_script != "$repo_root/scripts/gate01/build-kernel.sh" || \
      $script_path != "$stable_driver_root/build-kernel.sh" || \
      $stable_driver_parent != "$repo_root/build/gate01/$builder_id" || \
      ! $stable_driver_basename =~ ^\.kernel-driver\.[A-Za-z0-9]{8}$ || \
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
      $stable_driver_parent != "$builder_root" ]]; then
  echo "refusing kernel paths outside the selected Gate 01 builder" >&2
  exit 2
fi

remove_builder_tree() {
  case "$1" in
    "$output"|"$runtime_root"|"$inspection_work"|\
    "$build_podman_root"|"$inspect_podman_root")
      if [[ -e $1 || -L $1 ]]; then
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
frozen_python_root="$runtime_root/frozen-python"
proof_helper_relative_paths=(
  tools/__init__.py
  tools/gate01/__init__.py
  tools/gate01/inputs.py
  tools/gate01/kernel_config.py
  tools/gate01/module_key.py
  tools/gate01/rpm_artifacts.py
  tools/gate01/toolchain.py
)
proof_source_relative_paths=(
  scripts/gate01/build-kernel.sh
  os/kernel/packaging/kernel-openmythos.spec
  "${proof_helper_relative_paths[@]}"
)

required_inputs=(
  "$source_lock" "$toolchain_lock" "$source_archive" "$toolchain_archive"
  "$config" "$config_checksum" "$config_requirements" "$public_certificate"
  "$public_manifest" "$private_key" "$spec" "$original_script"
)
for relative_path in "${proof_helper_relative_paths[@]}"; do
  required_inputs+=("$repo_root/$relative_path")
done
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
retained_rpm_binding_verified=0
frozen_helpers_ready=0

run_frozen_python() (
  cd "$runtime_root"
  python3 -I -S -B \
    "$frozen_python_root/tools/gate01/rpm_artifacts.py" \
    bootstrap --root "$frozen_python_root" -- "$@"
)

scan_output_tree() {
  local scan_output scan_status
  if [[ $frozen_helpers_ready -ne 1 ]]; then
    return 2
  fi
  scan_output=$(mktemp -- "$gate_root/.kernel-scan.XXXXXXXX")
  set +e
  run_frozen_python -m tools.gate01.module_key scan \
    --private-key "$private_key" --root "$output" >"$scan_output"
  scan_status=$?
  set -e
  rm -f -- "$scan_output"
  return "$scan_status"
}

cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT
  set +e
  remove_builder_tree "$build_podman_root" || cleanup_failed=1
  remove_builder_tree "$inspect_podman_root" || cleanup_failed=1
  remove_builder_tree "$inspection_work" || cleanup_failed=1
  if [[ $output_scan_complete -eq 0 && -d $output ]]; then
    if [[ $frozen_helpers_ready -ne 1 ]]; then
      chmod -R 0700 -- "$output" || cleanup_failed=1
      echo "frozen output scanner unavailable for $output" >&2
      cleanup_failed=1
    elif ! scan_output_tree; then
      chmod -R 0700 -- "$output" || cleanup_failed=1
      echo "private key leakage detected in $output" >&2
      cleanup_failed=1
    fi
  fi
  remove_builder_tree "$runtime_root" || cleanup_failed=1
  if [[ $source_freeze_verified -eq 0 && $status -eq 0 ]]; then
    echo "source freeze was not verified" >&2
    cleanup_failed=1
  fi
  if [[ $retained_rpm_binding_verified -eq 0 && $status -eq 0 ]]; then
    echo "retained RPM binding was not verified" >&2
    cleanup_failed=1
  fi
  remove_stable_driver_copy || cleanup_failed=1
  if [[ $status -eq 0 && $cleanup_failed -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

remove_builder_tree "$output"
remove_builder_tree "$runtime_root"
remove_builder_tree "$inspection_work"
remove_builder_tree "$build_podman_root"
remove_builder_tree "$inspect_podman_root"
mkdir -p -- "$output" "$runtime_root/source-snapshot" \
  "$frozen_python_root/tools/gate01" "$inspection_work"
chmod 0700 -- "$runtime_root" "$runtime_root/source-snapshot" \
  "$frozen_python_root" "$frozen_python_root/tools" \
  "$frozen_python_root/tools/gate01" "$inspection_work"

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
for relative_path in "${proof_helper_relative_paths[@]}"; do
  snapshot_regular \
    "$repo_root/$relative_path" "$frozen_python_root/$relative_path" 0444
done
chmod 0555 -- "$runtime_root/source-snapshot" "$frozen_python_root" \
  "$frozen_python_root/tools" "$frozen_python_root/tools/gate01"
frozen_helpers_ready=1

python_runtime_evidence="$runtime_root/python-runtime.json"
run_frozen_python -m tools.gate01.rpm_artifacts audit-runtime \
  --expected-root "$frozen_python_root" --output "$python_runtime_evidence"

proof_source_before="$runtime_root/proof-source-before.sha256"
(
  cd "$repo_root"
  sha256sum "${proof_source_relative_paths[@]}"
) >"$proof_source_before"
chmod 0444 -- "$proof_source_before"

run_frozen_python -m tools.gate01.rpm_artifacts audit-freeze \
  --source-root "$repo_root" --snapshot-root "$frozen_python_root"
if ! cmp -s -- "$spec" "$snapshot_spec" || \
   [[ $(sha256sum -- "$original_script" | awk '{print $1}') != \
      "${OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256}" ]]; then
  echo "Task 6 source changed while snapshots were being frozen" >&2
  exit 1
fi

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
    source-snapshot/kernel-openmythos.spec
  for relative_path in "${proof_helper_relative_paths[@]}"; do
    sha256sum "frozen-python/$relative_path"
  done
) >"$snapshot_manifest"
chmod 0444 -- "$snapshot_manifest"

run_frozen_python -m tools.gate01.rpm_artifacts \
  audit-source-lock "$snapshot_source_lock"
run_frozen_python -m tools.gate01.toolchain verify \
  "$snapshot_toolchain_lock" --archive "$snapshot_toolchain_archive"
source_sha=$(jq -er '.archive_sha256' "$snapshot_source_lock")
printf '%s  %s\n' "$source_sha" "$snapshot_source_archive" | \
  sha256sum --check --status
(
  cd "$runtime_root/source-snapshot"
  sha256sum --check --status "$(basename "$snapshot_config_checksum")"
)
run_frozen_python -m tools.gate01.kernel_config audit \
  --config "$snapshot_config" --requirements "$snapshot_config_requirements"
config_sha=$(awk 'NF == 2 {print $1}' "$snapshot_config_checksum")
if [[ ! $config_sha =~ ^[0-9a-f]{64}$ ]]; then
  echo "committed config checksum is malformed" >&2
  exit 1
fi

certificate_check=$(mktemp -- "$runtime_root/.module-key-check.XXXXXXXX")
run_frozen_python -m tools.gate01.module_key describe \
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

build_work_target=/work
private_key_target=/run/secrets/module-signing.key
frozen_python_target=/verifier
public_certificate_target=/public/module-signing.pem
binary_rpms_target=/rpm-root
source_rpms_target=/srpms
inspection_work_target=/inspect

declare -ar build_volume_specs=(
  "$output:$build_work_target:rw"
  "$private_key:$private_key_target:ro"
)
declare -ar inspection_volume_specs=(
  "$frozen_python_root:$frozen_python_target:ro"
  "$snapshot_public_certificate:$public_certificate_target:ro"
  "$output/rpmbuild/RPMS:$binary_rpms_target:ro"
  "$output/rpmbuild/SRPMS:$source_rpms_target:ro"
  "$inspection_work:$inspection_work_target:rw"
)
declare -a build_mount_args=()
declare -a inspection_mount_args=()
for volume_spec in "${build_volume_specs[@]}"; do
  build_mount_args+=(--volume "$volume_spec")
done
for volume_spec in "${inspection_volume_specs[@]}"; do
  inspection_mount_args+=(--volume "$volume_spec")
done
readonly -a build_mount_args inspection_mount_args

isolation_plan="$runtime_root/container-isolation.json"
jq -n \
  --arg repository_root "$repo_root" \
  --arg output "$output" \
  --arg build_store "$build_podman_root" \
  --arg inspection_store "$inspect_podman_root" \
  --arg private_key "$private_key" \
  --arg verifier_snapshot "$frozen_python_root" \
  --arg public_certificate "$snapshot_public_certificate" \
  --arg rpms "$output/rpmbuild/RPMS" \
  --arg srpms "$output/rpmbuild/SRPMS" \
  --arg inspection_work "$inspection_work" \
  --arg build_work_target "$build_work_target" \
  --arg private_key_target "$private_key_target" \
  --arg frozen_python_target "$frozen_python_target" \
  --arg public_certificate_target "$public_certificate_target" \
  --arg binary_rpms_target "$binary_rpms_target" \
  --arg source_rpms_target "$source_rpms_target" \
  --arg inspection_work_target "$inspection_work_target" \
  '{
    repository_root: $repository_root,
    output: $output,
    build_store: $build_store,
    inspection_store: $inspection_store,
    private_key_source: $private_key,
    public_certificate_source: $public_certificate,
    signing_environment: {probe: false, build: true, inspection: false},
    probe_mounts: [],
    build_mounts: [
      {source: $output, target: $build_work_target, read_only: false},
      {
        source: $private_key,
        target: $private_key_target,
        read_only: true
      }
    ],
    inspection_mounts: [
      {
        source: $verifier_snapshot,
        target: $frozen_python_target,
        read_only: true
      },
      {
        source: $public_certificate,
        target: $public_certificate_target,
        read_only: true
      },
      {source: $rpms, target: $binary_rpms_target, read_only: true},
      {source: $srpms, target: $source_rpms_target, read_only: true},
      {
        source: $inspection_work,
        target: $inspection_work_target,
        read_only: false
      }
    ]
  }' >"$isolation_plan"
chmod 0444 -- "$isolation_plan"
declare -a isolation_audit_args=()
for volume_spec in "${build_volume_specs[@]}"; do
  isolation_audit_args+=(--build-volume "$volume_spec")
done
for volume_spec in "${inspection_volume_specs[@]}"; do
  isolation_audit_args+=(--inspection-volume "$volume_spec")
done
run_frozen_python -m tools.gate01.rpm_artifacts audit-isolation \
  --plan "$isolation_plan" "${isolation_audit_args[@]}"
# The plan has been consumed exactly once.  Podman receives the already-audited
# readonly arrays above; no later file parse can substitute unaudited mounts.
chmod 0000 -- "$isolation_plan"

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
  run_frozen_python -m tools.gate01.rpm_artifacts audit-image \
    --observed-config-id "$observed_config_id" \
    --observed-manifest-digest "$observed_manifest_digest" \
    --expected-config-id "$toolchain_image_id" \
    --expected-manifest-digest "$toolchain_manifest"
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
  "${build_mount_args[@]}" \
  --env "OPENMYTHOS_MODULE_SIGNING_KEY=$private_key_target" \
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
mapfile -t observed_rpm_root_entries < <(
  find "$output/rpmbuild/RPMS" -mindepth 1 -maxdepth 1 \
    -printf '%f:%y\n' | LC_ALL=C sort
)
if [[ ${#observed_rpm_root_entries[@]} -ne 1 || \
      ${observed_rpm_root_entries[0]} != "x86_64:d" ]]; then
  echo "kernel build RPM root must contain only the x86_64 directory" >&2
  exit 1
fi
mapfile -t observed_srpms < <(
  find "$output/rpmbuild/SRPMS" -maxdepth 1 -type f -name '*.rpm' -printf '%f\n' |
    LC_ALL=C sort
)
if [[ ${#observed_srpms[@]} -ne 1 || ${observed_srpms[0]} != "$expected_srpm" ]]; then
  echo "kernel build did not produce the exact expected source RPM" >&2
  exit 1
fi
mapfile -t observed_binary_rpms < <(
  find "$output/rpmbuild/RPMS/x86_64" -maxdepth 1 -type f -name '*.rpm' \
    -printf '%f\n' |
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
inspected_rpm_manifest_sha256=$(
  "${inspect_podman_cmd[@]}" "${container_security[@]}" \
    "${inspection_mount_args[@]}" \
    --workdir /tmp --entrypoint python3 "$toolchain_image_id" \
    -I -S -B /verifier/tools/gate01/rpm_artifacts.py \
    bootstrap --root /verifier -- -m tools.gate01.rpm_artifacts inspect \
    --rpm-dir /rpm-root/x86_64 \
    --srpm-dir /srpms \
    --output /inspect/evidence/rpm-artifacts.json \
    --extract-root /inspect/extracted \
    --public-certificate /public/module-signing.pem \
    --print-manifest-sha256
)
if [[ ! $inspected_rpm_manifest_sha256 =~ ^[0-9a-f]{64}$ ]]; then
  echo "inspected RPM manifest SHA-256 is malformed" >&2
  exit 1
fi
readonly inspected_rpm_manifest_sha256
run_frozen_python -m tools.gate01.rpm_artifacts validate \
  "$inspection_work/evidence/rpm-artifacts.json"
run_frozen_python -m tools.gate01.rpm_artifacts rebind \
  --rpm-dir "$output/rpmbuild/RPMS/x86_64" \
  --srpm-dir "$output/rpmbuild/SRPMS" \
  --manifest "$inspection_work/evidence/rpm-artifacts.json"
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
      frozen_spec_and_python_closure: true,
      build_and_inspection_stores_distinct: true,
      stores_visible_inside_containers: false,
      probe_private_key_mounted: false,
      inspector_private_key_mounted: false,
      inspector_public_certificate_only: true,
      recursive_repository_mount: false,
      retained_rpm_binding: true,
      joint_source_and_rpm_final_boundary: true,
      isolated_python_flags: ["-I", "-S", "-B"]
    },
    compiler_version: $compiler_version,
    toolchain_manifest_digest: $toolchain_manifest,
    elapsed_seconds: $elapsed_seconds,
    peak_output_bytes: $peak_output_bytes,
    network_used: false
  }' >"$output/build-report.json"

proof_source_after="$runtime_root/proof-source-after.sha256"
(
  cd "$repo_root"
  sha256sum "${proof_source_relative_paths[@]}"
) >"$proof_source_after"
chmod 0444 -- "$proof_source_after"
if ! cmp -s -- "$proof_source_before" "$proof_source_after"; then
  echo "proof-relevant repository sources changed during build" >&2
  exit 1
fi
run_frozen_python -m tools.gate01.rpm_artifacts audit-freeze \
  --source-root "$repo_root" --snapshot-root "$frozen_python_root"
(
  cd "$runtime_root"
  sha256sum --check --status "$snapshot_manifest"
)
if [[ $(sha256sum -- "$original_script" | awk '{print $1}') != \
      "${OPENMYTHOS_STABLE_KERNEL_DRIVER_SHA256}" ]]; then
  echo "kernel build driver changed during proof" >&2
  exit 1
fi

proof_source_final="$runtime_root/proof-source-final.sha256"
(
  cd "$repo_root"
  sha256sum "${proof_source_relative_paths[@]}"
) >"$proof_source_final"
chmod 0444 -- "$proof_source_final"
if ! cmp -s -- "$proof_source_before" "$proof_source_final" || \
   ! cmp -s -- "$proof_source_after" "$proof_source_final"; then
  echo "proof-relevant repository sources changed before final binding" >&2
  exit 1
fi
install -m 0644 -- "$proof_source_before" "$output/proof-source-before.sha256"
install -m 0644 -- "$proof_source_after" "$output/proof-source-after.sha256"
install -m 0644 -- "$proof_source_final" "$output/proof-source-final.sha256"
install -m 0644 -- "$snapshot_manifest" "$output/source-snapshot.sha256"
install -m 0644 -- "$python_runtime_evidence" "$output/python-runtime.json"

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

# This sole final proof call holds every source, frozen copy, manifest, and RPM
# descriptor together across two hashes and one global path/topology sweep.
run_frozen_python -m tools.gate01.rpm_artifacts bind-final \
  --rpm-dir "$output/rpmbuild/RPMS/x86_64" \
  --srpm-dir "$output/rpmbuild/SRPMS" \
  --rpm-manifest "$output/rpm-artifacts.json" \
  --expected-rpm-manifest-sha256 "$inspected_rpm_manifest_sha256" \
  --source-root "$repo_root" \
  --snapshot-root "$frozen_python_root" \
  --spec-snapshot "$snapshot_spec" \
  --driver-snapshot "$script_path" \
  --expected-source-manifest "$proof_source_before" \
  --final-source-manifest "$output/proof-source-final.sha256"
source_freeze_verified=1
retained_rpm_binding_verified=1

printf 'built %s kernel RPM set in %s seconds at %s\n' \
  "$builder_id" "$elapsed_seconds" "$output"
