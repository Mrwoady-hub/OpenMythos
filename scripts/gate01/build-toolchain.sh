#!/usr/bin/env bash
set -Eeuo pipefail
umask 022
test "$(id -u)" -ne 0 || { echo "run the toolchain build rootless" >&2; exit 2; }

repo_root=$(git rev-parse --show-toplevel)
inputs="$repo_root/os/build/inputs.lock.json"
output="$repo_root/build/gate01/cache/kernel-builder.oci.tar"
tag="localhost/openmythos/kernel-builder:fedora44"
base_ref=$(jq -er '.fedora_bootc.reference' "$inputs")
base_digest=$(jq -er '.fedora_bootc.manifest_digest' "$inputs")
mkdir -p "$(dirname "$output")"

podman pull "$base_ref@$base_digest"
podman build --pull=never --no-cache --format=oci \
  --timestamp=1787899659 --tag "$tag" \
  --file "$repo_root/os/kernel/Containerfile.builder" "$repo_root/os/kernel"
skopeo copy "containers-storage:$tag" "oci-archive:$output"

archive_sha=$(sha256sum "$output" | awk '{print $1}')
manifest_digest="sha256:$(skopeo inspect --raw "oci-archive:$output" | sha256sum | awk '{print $1}')"
report="$repo_root/build/gate01/cache/toolchain-report.json"
podman run --rm --network=none "$tag" python3 -c '
import json, subprocess
commands = {
    "gcc": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
    "ld": subprocess.check_output(["ld", "--version"], text=True).splitlines()[0],
    "make": subprocess.check_output(["make", "--version"], text=True).splitlines()[0],
    "rpmbuild": subprocess.check_output(["rpmbuild", "--version"], text=True).strip(),
    "rpm": subprocess.check_output(["rpm", "--version"], text=True).strip(),
    "python3": subprocess.check_output(["python3", "--version"], text=True).strip(),
}
rpms = subprocess.check_output(
    ["rpm", "-qa", "--qf", "%{NEVRA}\\n"], text=True
).splitlines()
print(json.dumps({"commands": commands, "installed_rpms": sorted(set(rpms))}))
' > "$report"

python3 -m tools.gate01.toolchain write \
  --path "$repo_root/os/build/toolchain.lock.json" \
  --image-reference "$tag@$manifest_digest" \
  --manifest-digest "$manifest_digest" \
  --archive-sha256 "$archive_sha" \
  --report "$report"
python3 -m tools.gate01.toolchain verify "$repo_root/os/build/toolchain.lock.json"
