#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

repo_root=$(git rev-parse --show-toplevel)
lock="$repo_root/os/kernel/source.lock.json"
skip_images=0
if [[ $# -ne 0 ]]; then
  [[ $# -eq 3 ]] || exit 2
  [[ $1 == --source-lock && $3 == --skip-images ]] || exit 2
  lock=$(realpath -- "$2")
  [[ $lock == "$repo_root/build/gate01/"* ]] || exit 2
  skip_images=1
fi
cache="$repo_root/build/gate01/cache/sources"
image_cache="$repo_root/build/gate01/cache/images"
key="$repo_root/os/kernel/keys/gregkh-kernel-releases.asc"
image_lock="$repo_root/os/build/inputs.lock.json"
mkdir -p "$cache" "$image_cache"

(cd "$repo_root/os/kernel/keys" && \
  sha256sum --check gregkh-kernel-releases.asc.sha256)
PYTHONPATH="$repo_root" python3 -c \
  'import sys; from pathlib import Path; from tools.gate01.inputs import load_source_lock, validate_source_lock; value = load_source_lock(Path(sys.argv[1])); validate_source_lock(value)' \
  "$lock"
if [[ $skip_images -eq 0 ]]; then
  PYTHONPATH="$repo_root" python3 -c \
    'import sys; from pathlib import Path; from tools.gate01.inputs import load_external_inputs, validate_external_inputs; value = load_external_inputs(Path(sys.argv[1])); validate_external_inputs(value)' \
    "$image_lock"
fi

keyring_dir=""
archive=""
signature=""
cleanup() {
  if [[ -n "$archive" ]]; then rm -f -- "$archive.part"; fi
  if [[ -n "$signature" ]]; then rm -f -- "$signature.part"; fi
  rm -f -- "$image_cache/fedora-bootc.oci.tar.part"
  rm -f -- "$image_cache/image-builder.oci.tar.part"
  if [[ -n "$keyring_dir" ]]; then
    rm -rf -- "$keyring_dir"
  fi
}
trap cleanup EXIT

version=$(jq -er '.version' "$lock")
archive="$cache/linux-$version.tar.xz"
signature="$cache/linux-$version.tar.sign"
archive_url=$(jq -er '.archive_url' "$lock")
signature_url=$(jq -er '.signature_url' "$lock")
archive_sha=$(jq -er '.archive_sha256' "$lock")
signature_sha=$(jq -er '.signature_sha256' "$lock")
expected_fpr=$(jq -er '.signer_fingerprint' "$lock")

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$archive.part" "$archive_url"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$signature.part" "$signature_url"
printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum --check --status
printf '%s  %s\n' "$signature_sha" "$signature.part" | sha256sum --check --status
mv "$archive.part" "$archive"
mv "$signature.part" "$signature"

keyring_dir=$(mktemp -d -p "$cache")
chmod 700 "$keyring_dir"
GNUPGHOME="$keyring_dir" gpg --batch --import "$key" >/dev/null 2>&1
actual_fpr=$(GNUPGHOME="$keyring_dir" gpg --batch --with-colons \
  --fingerprint | awk -F: '$1 == "fpr" {print $10; exit}')
test "$actual_fpr" = "$expected_fpr"
signature_status="$cache/signature-status.txt"
xz -cd "$archive" | GNUPGHOME="$keyring_dir" gpgv --status-fd=1 \
  --keyring "$keyring_dir/pubring.kbx" "$signature" - > "$signature_status"
grep -q '^\[GNUPG:\] VALIDSIG ' "$signature_status"

if [[ $skip_images -eq 0 ]]; then
  for image_name in fedora_bootc image_builder; do
    reference=$(jq -er --arg name "$image_name" '.[$name].reference' "$image_lock")
    manifest=$(jq -er --arg name "$image_name" '.[$name].manifest_digest' "$image_lock")
    case "$image_name" in
      fedora_bootc) output="$image_cache/fedora-bootc.oci.tar" ;;
      image_builder) output="$image_cache/image-builder.oci.tar" ;;
      *) exit 2 ;;
    esac
    skopeo copy --override-os linux --override-arch amd64 \
      "docker://$reference@$manifest" "oci-archive:$output.part:$image_name"
    actual="sha256:$(skopeo inspect --raw "oci-archive:$output.part" | sha256sum | awk '{print $1}')"
    test "$actual" = "$manifest"
    mv "$output.part" "$output"
  done
  python3 -m tools.gate01.inputs record-fetch \
    --source-lock "$lock" --external-lock "$image_lock" \
    --archive "$archive" --signature "$signature" \
    --signature-status "$signature_status" \
    --fedora-archive "$image_cache/fedora-bootc.oci.tar" \
    --image-builder-archive "$image_cache/image-builder.oci.tar" \
    --output "$repo_root/build/gate01/cache/input-verification.json"
  printf 'cached Fedora bootc and image-builder at their locked x86_64 manifests\n'
fi
printf 'verified linux-%s source and signature from %s\n' "$version" "$expected_fpr"
