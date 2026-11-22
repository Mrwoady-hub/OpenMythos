# Kernel signing boundary

The committed kernel configuration names the public module-signing certificate,
but Git contains no private key material. Gate 01 creates one development
identity locally and supplies that same identity to both clean builders so that
their RSA module signatures are comparable.

The supervisor copies the private key byte-for-byte into a fully sealed memfd,
without hashing it. Only signing work and the secret scanners receive FD25;
input audit, live attestation, RPM inspection and meta verification never do.
No private-key pathname is mounted into a container. It never enters an SRPM,
RPM, OCI layer, QCOW2 image, log, or evidence bundle. The public certificate is
included in the kernel trust set and in Gate 01 evidence.

`CONFIG_MODULE_SIG_ALL=n` disables automatic Kbuild signing. Packaging signs
every installed uncompressed module explicitly with `sign-file sha256`, then
inspection verifies strict detached CMS signatures against the exact public
certificate. `CONFIG_MODULE_SIG_FORCE=y` remains mandatory.

All production commands use the sealed bootstrap launcher:

```sh
scripts/gate01/build-kernel.sh build builder-a
scripts/gate01/build-kernel.sh build builder-b
scripts/gate01/build-kernel.sh compare
scripts/gate01/build-kernel.sh meta-requirements builder-a
scripts/gate01/build-kernel.sh lifecycle-check
```

The lifecycle/build commands require explicit controller authorization during
Task 6 review. The keyless lifecycle check does not run a kernel build. A
durable detached receipt is the acceptance marker; consumers rebind all 13
public files under explicit nonzero expected UID/GID, validate their semantics,
and reject xattrs. Material cleanup precedes receipt durability; subsequent
local close/unlock/output failures are fixed warnings and do not revoke it.

The keyless lifecycle report includes its executed bootstrap/capsule identities,
all 13 reviewed source records, the full locked OCI summary, config fixture and
sealed runtime-policy hashes, and an index-independent public scoped manifest
against `cfc94e5437dac3f80deed3bad70c3d56ae4840a1`. The scope never walks kernel
keys or build secrets. Original public source descriptors remain held through
container/store/temporary cleanup and a final full coherence check; only then
does the report record cleanup complete and verdict `pass`.

Prebaseline VFS normalization uses exact `schema_version: 3` and
`linux-inotify-fanotify-vfs-normalization-v3`. Its canonical compressed
`initial_raw_ledger`, declared `repair_groups`, and ordered aggregate raw
transitions reconstruct the complete final ledger and bind its hash/root anchor
to the accepted audit. The locked count remains 138,620 non-root paths plus `/`.
The level-9 zlib/base64 codec checks exact count/size/hash, canonical reencoding,
bounded EOF with no trailing stream, and complete duplicate-free path coverage;
its caps are 250,000 entries, 256 MiB raw, and 16 MiB encoded. Aggregate hardlink
and runtime-target transitions do not replace live per-syscall event proof.

That proof combines exact inotify names/cookies/inode events with at most two
operation-local fanotify groups bound to held opaque FIDs. Each raw mutation
runs in a fresh minimal child. The worker requires one native thread and ignored
SIGPIPE; a blocked-child authorization pipe authenticates the pidfd before any
pidfd-only termination. Numeric PIDs never authorize events or signals. Baseline
and terminal drains, held endpoint/listing checks, and the full final audit are
mandatory; unsupported profiles, watch loss/overflow, ambiguous/coalesced events,
or helper failure reject normalization. Metadata watch custody is operation-local
with indexed listings and a tested linear operation bound at 4,097 directories.

Every resource has a local cleanup owner before fallible inspection/registration.
Factory-based contexts acquire only after entry establishes that owner; an
already-open object must not wait in another call's arguments for adoption.
Terminal cleanup drains ownership incrementally without new action collections
or allocating exception snapshots; numeric fields detach before one close
attempt. All independently authorized cleanup is attempted; an existing
primary exception remains the same object with fixed redacted cleanup notes.
Cleanup-only failure is fatal before receipt durability. Store creation uses
held-parent exact create/delete event provenance; ambiguity never authorizes
replacement deletion or pathname reacquisition after scope release. Public
evidence readback must equal the supplied bytes before identity/publication.
These checks never compute a private-key digest. The post-durable warning rule
above is the only cleanup-success exception.

Create/start attempts retain exact invocation cleanup ownership even when
policy release fails after the subprocess takes effect. Store cleanup may
remove bounded recreated bookkeeping only with a separately retained successful
subprocess outcome; an unproven or nonzero command outcome never grants
authority over replacement children.

Gate 01 does not PE-sign the kernel and makes no claim that firmware or shim
will accept it under Secure Boot. Gate 02 replaces this development identity
with controlled kernel and module signing and records MOK enrollment evidence.
