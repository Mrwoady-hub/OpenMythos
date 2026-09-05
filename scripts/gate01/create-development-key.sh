#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  echo "usage: $0 [--output-dir DIR]" >&2
  exit 2
}

explicit_output=0
case $# in
  0) ;;
  2)
    [[ $1 == --output-dir ]] || usage
    explicit_output=1
    requested_output=$2
    ;;
  *) usage ;;
esac

script_path=$(realpath -- "${BASH_SOURCE[0]}")
repo_root=$(git -C "$(dirname "$script_path")" rev-parse --show-toplevel)
repo_root=$(realpath -- "$repo_root")
if [[ $script_path != "$repo_root/scripts/gate01/create-development-key.sh" ]]; then
  echo "key creator must run from its owning repository" >&2
  exit 2
fi

gate_root=$(realpath -m -- "$repo_root/build/gate01")
if [[ $explicit_output -eq 0 ]]; then
  requested_output="$gate_root/secrets"
fi
output_dir=$(realpath -m -- "$requested_output")

case "$output_dir" in
  "$gate_root"/*) ;;
  *)
    if [[ $explicit_output -ne 1 ]]; then
      echo "default output escaped the Gate 01 build directory" >&2
      exit 2
    fi
    process_tmp=$(realpath -m -- "${TMPDIR:-/tmp}")
    case "$output_dir" in
      "$process_tmp"/*) ;;
      *)
        echo "output must be beneath build/gate01 or the process TMPDIR" >&2
        exit 2
        ;;
    esac
    ;;
esac

mkdir -p -- "$output_dir"
chmod 0700 -- "$output_dir"
if [[ ! -d $output_dir || -L $output_dir || \
  $(realpath -- "$output_dir") != "$output_dir" ]]; then
  echo "output is not a resolved directory: $output_dir" >&2
  exit 1
fi

private_key="$output_dir/module-signing.key"
certificate="$output_dir/module-signing.pem"
certificate_der="$output_dir/module-signing.x509"
manifest="$output_dir/module-key.json"
private_key_part="$private_key.part"
certificate_part="$certificate.part"
certificate_der_part="$certificate_der.part"
manifest_part="$manifest.part"

cleanup() {
  rm -f -- "$private_key_part" "$certificate_part" \
    "$certificate_der_part" "$manifest_part"
}
trap cleanup EXIT

certificate_spki_sha256() {
  openssl x509 -in "$1" -pubkey -noout |
    openssl pkey -pubin -pubout -outform DER |
    sha256sum | awk '{print $1}'
}

private_spki_sha256() {
  openssl pkey -in "$1" -pubout -outform DER |
    sha256sum | awk '{print $1}'
}

verify_pair() {
  local private_hash certificate_hash
  private_hash=$(private_spki_sha256 "$1")
  certificate_hash=$(certificate_spki_sha256 "$2")
  if [[ $private_hash != "$certificate_hash" ]]; then
    echo "private key and certificate public keys do not match" >&2
    return 1
  fi
}

outputs=("$private_key" "$certificate" "$certificate_der" "$manifest")
existing=0
for path in "${outputs[@]}"; do
  if [[ -e $path || -L $path ]]; then
    ((existing += 1))
  fi
done

if [[ $existing -ne 0 && $existing -ne ${#outputs[@]} ]]; then
  echo "refusing partial module-signing key set in $output_dir" >&2
  exit 1
fi

if [[ $existing -eq ${#outputs[@]} ]]; then
  for path in "${outputs[@]}"; do
    if [[ ! -f $path || -L $path ]]; then
      echo "key-set member is not a regular non-symlink file: $path" >&2
      exit 1
    fi
  done
  [[ $(stat -c '%a' -- "$private_key") == 600 ]] || {
    echo "private key mode is not 0600" >&2
    exit 1
  }
  [[ $(stat -c '%a' -- "$certificate") == 644 ]] || {
    echo "PEM certificate mode is not 0644" >&2
    exit 1
  }
  [[ $(stat -c '%a' -- "$certificate_der") == 644 ]] || {
    echo "DER certificate mode is not 0644" >&2
    exit 1
  }
  [[ $(stat -c '%a' -- "$manifest") == 600 ]] || {
    echo "certificate manifest mode is not 0600" >&2
    exit 1
  }
  verify_pair "$private_key" "$certificate"
  cmp -s -- <(openssl x509 -in "$certificate" -outform DER) "$certificate_der" || {
    echo "PEM and DER certificates do not match" >&2
    exit 1
  }
  PYTHONPATH="$repo_root" python3 -m tools.gate01.module_key describe \
    --certificate "$certificate" --output "$manifest_part"
  cmp -s -- "$manifest_part" "$manifest" || {
    echo "certificate manifest does not match the certificate" >&2
    exit 1
  }
else
  cleanup
  openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj '/CN=OpenMythos Gate 01 Development Module Key/O=OpenMythos Development/' \
    -keyout "$private_key_part" \
    -out "$certificate_part"
  openssl x509 -in "$certificate_part" -outform DER \
    -out "$certificate_der_part"
  verify_pair "$private_key_part" "$certificate_part"
  chmod 0600 -- "$private_key_part"
  chmod 0644 -- "$certificate_part" "$certificate_der_part"
  mv -- "$private_key_part" "$private_key"
  mv -- "$certificate_part" "$certificate"
  mv -- "$certificate_der_part" "$certificate_der"
  PYTHONPATH="$repo_root" python3 -m tools.gate01.module_key describe \
    --certificate "$certificate" --output "$manifest"
fi

spki_sha256=$(certificate_spki_sha256 "$certificate")
printf 'SPKI SHA-256: %s; development key only; Gate 02 replaces this identity\n' \
  "$spki_sha256"
