#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

if [[ $# -ne 1 ]]; then
  echo "usage: $0 --refresh-baseline|--write|--check" >&2
  exit 2
fi
case "$1" in
  --refresh-baseline|--write|--check) mode=$1 ;;
  *) echo "usage: $0 --refresh-baseline|--write|--check" >&2; exit 2 ;;
esac
if [[ $(id -u) -eq 0 ]]; then
  echo "run the config generator rootless" >&2
  exit 2
fi

script_path=$(realpath -- "${BASH_SOURCE[0]}")
repo_root=$(git -C "$(dirname "$script_path")" rev-parse --show-toplevel)
repo_root=$(realpath -- "$repo_root")
if [[ $script_path != "$repo_root/scripts/gate01/generate-config.sh" ]]; then
  echo "generator must run from its owning repository" >&2
  exit 2
fi

config_dir="$repo_root/os/kernel/config"
source_lock="$repo_root/os/kernel/source.lock.json"
input_lock="$repo_root/os/build/inputs.lock.json"
toolchain_lock="$repo_root/os/build/toolchain.lock.json"
source_archive="$repo_root/build/gate01/cache/sources/linux-6.18.48.tar.xz"
toolchain_archive="$repo_root/build/gate01/cache/kernel-builder.oci.tar"
fedora_archive="$repo_root/build/gate01/cache/images/fedora-bootc.oci.tar"
baseline="$config_dir/fedora-44-x86_64.config"
baseline_checksum="$baseline.sha256"
fragment="$config_dir/gate01-x86_64.fragment"
requirements="$config_dir/requirements.json"
final_config="$config_dir/6.18.48-x86_64.config"
final_checksum="$final_config.sha256"
config_work="$repo_root/build/gate01/config-work"
store="$config_work/store"
work=""

cleanup() {
  local resolved_store resolved_work
  resolved_store=$(realpath -m -- "$store")
  if [[ $resolved_store != "$config_work/store" ]]; then
    echo "refusing unsafe container-store cleanup: $resolved_store" >&2
    return 1
  fi
  if [[ -n $work ]]; then
    resolved_work=$(realpath -m -- "$work")
    case "$resolved_work" in
      "$config_work"/work.*) ;;
      *) echo "refusing unsafe work cleanup: $resolved_work" >&2; return 1 ;;
    esac
    podman unshare rm -rf -- "$resolved_store" "$resolved_work"
  else
    podman unshare rm -rf -- "$resolved_store"
  fi
}

mkdir -p -- "$config_work"
if ! mkdir -- "$store" 2>/dev/null; then
  echo "disposable container store already exists: $store" >&2
  exit 1
fi
trap cleanup EXIT
mkdir -p -- "$store/root" "$store/runroot"
work=$(mktemp -d -- "$config_work/work.XXXXXXXX")

for path in "$source_lock" "$input_lock" "$toolchain_lock" \
  "$source_archive" "$toolchain_archive" "$fragment" "$requirements"; do
  if [[ ! -f $path || -L $path ]]; then
    echo "required regular file is missing or a symlink: $path" >&2
    exit 1
  fi
done

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

podman_cmd=(
  podman --root "$store/root" --runroot "$store/runroot"
  --storage-driver overlay
)
"${podman_cmd[@]}" load --quiet --input "$toolchain_archive" >/dev/null
"${podman_cmd[@]}" image exists "$toolchain_image_id"

if [[ $mode == --refresh-baseline ]]; then
  if [[ ! -f $fedora_archive || -L $fedora_archive ]]; then
    echo "cached Fedora OCI archive is missing or a symlink: $fedora_archive" >&2
    exit 1
  fi
  PYTHONPATH="$repo_root" python3 -c '
import sys
from pathlib import Path
from tools.gate01.inputs import load_external_inputs, validate_external_inputs
lock = load_external_inputs(Path(sys.argv[1]))
validate_external_inputs(lock)
' "$input_lock"
  fedora_manifest=$(jq -er '.fedora_bootc.manifest_digest' "$input_lock")
  observed_fedora_manifest="sha256:$(
    skopeo inspect --raw "oci-archive:$fedora_archive" | sha256sum | awk '{print $1}'
  )"
  if [[ $observed_fedora_manifest != "$fedora_manifest" ]]; then
    echo "Fedora bootc child manifest digest mismatch" >&2
    exit 1
  fi
  fedora_image_id=$(
    skopeo inspect --raw "oci-archive:$fedora_archive" | jq -er '.config.digest'
  )
  if [[ ! $fedora_image_id =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Fedora archive has an invalid image ID" >&2
    exit 1
  fi
  "${podman_cmd[@]}" load --quiet --input "$fedora_archive" >/dev/null
  "${podman_cmd[@]}" image exists "$fedora_image_id"

  baseline_tmp="$baseline.tmp"
  rm -f -- "$baseline_tmp"
  # shellcheck disable=SC2016
  "${podman_cmd[@]}" run --rm --network=none --read-only \
    --security-opt label=disable --entrypoint /bin/bash "$fedora_image_id" \
    -Eeuo pipefail -c '
mapfile -t configs < <(find /usr/lib/modules -mindepth 2 -maxdepth 2 -type f -name config -print)
if [[ ${#configs[@]} -ne 1 ]]; then
  printf "expected exactly one stock kernel config, found %s\n" "${#configs[@]}" >&2
  exit 1
fi
cat -- "${configs[0]}"
' > "$baseline_tmp"
  PYTHONPATH="$repo_root" python3 -c '
import sys
from pathlib import Path
from tools.gate01.kernel_config import parse_config
parse_config(Path(sys.argv[1]))
' "$baseline_tmp"
  mv -- "$baseline_tmp" "$baseline"
  PYTHONPATH="$repo_root" python3 -m tools.gate01.kernel_config checksum \
    --config "$baseline" --output "$baseline_checksum"
  printf 'wrote Fedora baseline from %s at %s\n' \
    "$fedora_manifest" "$baseline"
  exit 0
fi

for path in "$baseline" "$baseline_checksum"; do
  if [[ ! -f $path || -L $path ]]; then
    echo "committed Fedora baseline input is missing or a symlink: $path" >&2
    exit 1
  fi
done

# shellcheck disable=SC2016
"${podman_cmd[@]}" run --rm --network=none --read-only \
  --security-opt label=disable --tmpfs /tmp:rw,nosuid,nodev \
  --volume "$repo_root:/repo:ro" \
  --volume "$config_dir:/config:ro" \
  --volume "$(dirname "$source_archive"):/sources:ro" \
  --volume "$work:/work:rw" \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/repo \
  --entrypoint /bin/bash "$toolchain_image_id" \
  -Eeuo pipefail -c '
cd /config
sha256sum --check --status fedora-44-x86_64.config.sha256
cd /work
tar --no-same-owner --no-same-permissions -C /work -xf /sources/linux-6.18.48.tar.xz
source_dir=/work/linux-6.18.48
test -d "$source_dir"
KCONFIG_CONFIG=/work/merged.config \
  "$source_dir/scripts/kconfig/merge_config.sh" -m \
  /config/fedora-44-x86_64.config /config/gate01-x86_64.fragment
make -s -C "$source_dir" O=/work/out KCONFIG_CONFIG=/work/merged.config olddefconfig
make -s -C "$source_dir" O=/work/out KCONFIG_CONFIG=/work/merged.config listnewconfig \
  > /work/listnewconfig
if [[ -s /work/listnewconfig ]]; then
  echo "new kernel config symbols remain unresolved:" >&2
  cat /work/listnewconfig >&2
  exit 1
fi
python3 -m tools.gate01.kernel_config audit \
  --config /work/merged.config --requirements /config/requirements.json
python3 -c '\''from pathlib import Path; p=Path("/work/merged.config"); p.write_bytes(p.read_bytes().rstrip(b"\n") + b"\n")'\''
'

generated="$work/6.18.48-x86_64.config"
mv -- "$work/merged.config" "$generated"
generated_checksum="$work/6.18.48-x86_64.config.sha256"
PYTHONPATH="$repo_root" python3 -m tools.gate01.kernel_config checksum \
  --config "$generated" --output "$generated_checksum"

if [[ $mode == --write ]]; then
  final_tmp="$final_config.tmp"
  checksum_tmp="$final_checksum.tmp"
  cp -- "$generated" "$final_tmp"
  mv -- "$final_tmp" "$final_config"
  cp -- "$generated_checksum" "$checksum_tmp"
  mv -- "$checksum_tmp" "$final_checksum"
  printf 'wrote Gate 01 kernel config at %s\n' "$final_config"
  exit 0
fi

if ! cmp -s -- "$generated" "$final_config" || \
   ! cmp -s -- "$generated_checksum" "$final_checksum"; then
  echo "Gate 01 kernel config differs; compare:" >&2
  echo "  $generated $final_config" >&2
  echo "  $generated_checksum $final_checksum" >&2
  exit 1
fi
printf 'Gate 01 kernel config is current\n'
