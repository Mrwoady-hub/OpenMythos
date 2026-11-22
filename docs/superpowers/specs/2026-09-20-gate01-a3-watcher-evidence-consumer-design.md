# Gate-01 A3 Watcher Evidence Consumer Design

Date: 2026-09-20
Status: Approved
Scope: Task 6, Round 10, Finding A consumer validation only

## Summary

A2 already produces descriptor-backed start and stop evidence for the reserved
`conmon.pid` lifecycle. A3 makes that evidence an exact, fail-closed input to
the Gate-01 accepted-builder validator. It coordinates the producer identity
and consumer schema, validates the recorded lifecycle as one cross-bound
chain, and proves semantic rejection through fully rehashed detached builder
receipts.

A3 does not implement Round-10 Finding B container-ID/path binding. It also
does not move receipt custody, publication, or canonical JSON authority out of
their existing owners.

## Decisions

The watcher contract has separate wire-format and behavioral identities:

```text
schema = openmythos-runtime-input-binding-v2
policy = inotify-reserved-lifecycle-fail-closed-v1
```

Both values are mandatory and exact. The prior watcher shape and
`inotify-target-fail-closed-v1` policy are rejected. There is no legacy
fallback, implicit upgrade, normalization, or compatibility mode.

Validation remains dependency-free and in the existing files:

- `tools/gate01/container_runtime.py` produces the exact identity and evidence.
- `tools/gate01/proof_io.py` continues to own held-descriptor custody,
  canonical receipt commitments, and detached-tree acceptance, unchanged.
- `tools/gate01/kernel_build.py` owns watcher evidence semantics.
- `tests/gate01/test_kernel_build.py` owns producer, consumer, mutation, and
  full-receipt coverage.

No schema module or runtime JSON-Schema dependency is added. A separate module
would enlarge the sealed source closure without improving this bounded trust
boundary, while descriptive JSON Schema cannot prove event ordering,
cross-record equality, descriptor custody, or detached-tree coherence.

## Scope

### Included

- Publish the explicit watcher `schema` and new `policy` identities.
- Consume the complete A2 start and stop projections for build, inspection,
  and probe roles.
- Enforce exact recursive shapes and strict scalar types.
- Cross-bind recorded PID presence, metadata, listings, parent metadata,
  ordered events, event multisets, limits, and the pre-start store snapshot.
- Preserve the existing config-parent endpoint and survivor proof.
- Reject semantic mutations after all file, tree, and receipt hashes have been
  recomputed correctly.
- Preserve existing receipt, OCI, lifecycle, store, scratch, role, and
  publication checks.

### Excluded

- New or stronger container-ID/path binding from Round-10 Finding B.
- A new detached receipt protocol or changes to its serialization.
- Historical receipt migration or acceptance of the old watcher schema.
- PID content-digest evidence, raw inotify buffer replay, or an emitted
  watch-number-to-parent-inode map.
- Receipt signing or claims that a coherently rewritten unsigned receipt is
  cryptographically authentic.
- A real Podman lifecycle, kernel build, RPM build, network fetch, or private
  key access during A3 verification.
- Unrelated refactoring or a generalized evidence-validation framework.

## Data Flow and Trust Boundaries

The accepted path remains:

```text
container_runtime producer
  -> canonical public evidence in the 13-file builder tree
  -> detached tree receipt and held-descriptor custody
  -> BoundAcceptedTree.open
  -> _validate_bound_builder
  -> _validate_runtime_evidence
  -> strict watcher semantic validation
```

`BoundAcceptedTree` proves that the consumer holds the complete committed tree
and that its bytes, metadata, allowlist, and receipt commitments are coherent.
The watcher validator proves that those held bytes make the required semantic
claims. Neither layer substitutes for the other.

Each build, inspection, or probe role is validated against its own store and
runtime records. Build and inspection watcher records need not be byte-equal,
because their real inode and watch identities can differ. Swapping a watcher
record between roles must fail its role-local metadata bindings.

## Exact Wire Shape

The `runtime_input_binding` object has exactly these keys:

```text
basenames
coalesced_parent_watch_count
parent_fields_excluding_time
persistent_parent_listing
policy
schema
stop_projection
```

Its fixed values are:

```text
basenames = {config: config.json, containerenv: .containerenv}
coalesced_parent_watch_count = 2
parent_fields_excluding_time =
  [dev, ino, type, mode, uid, gid, nlink, size]
persistent_parent_listing = exact
schema = openmythos-runtime-input-binding-v2
policy = inotify-reserved-lifecycle-fail-closed-v1
```

`stop_projection` retains the established config-parent fields and adds the
mandatory `reserved_lifecycle` field. Its exact keys are:

```text
allowed_removed_names
endpoint_metadata
event_multiset
observed_events
post_listing
post_parent_metadata
pre_listing
pre_parent_metadata
reserved_lifecycle
state
survivor_metadata
```

`reserved_lifecycle` has exactly `initial`, `start`, and `stop`. The start
projection has exactly:

```text
current_present
event_multiset
initial_present
limits
observed_events
post_listing
post_parent_metadata
pre_listing
pre_parent_metadata
state
target_after
target_before
```

The reserved stop projection has exactly:

```text
current_present
event_multiset
limits
observed_events
post_listing
post_parent_metadata
pre_listing
pre_parent_metadata
state
target_after
target_before
```

A runtime stat record has exactly `dev`, `gid`, `ino`, `mode`, `mtime_ns`,
`ctime_ns`, `nlink`, `size`, `type`, and `uid`. An ordered event has exactly
`cookie`, `mask`, `name`, and `watch`; a multiset row adds exact integer
`count`. A limits object is exactly:

```text
max_event_bytes = 65536
max_events = 1024
max_middle_events = 16
```

All objects reject missing and extra keys. Integer validation requires exact
Python/JSON integer values; booleans do not satisfy integer fields. Lists have
their specified order, uniqueness, and element types. Equality comparisons
use canonical evidence equality where Python's Boolean/integer aliasing could
otherwise weaken the check.

Stat fields are nonnegative; inode numbers are positive; permission modes are
in `0..0o7777`; and parent and linked-target link counts are positive. The
only permitted zero link count is `reserved_lifecycle.stop.target_after`.
Event watches and multiset counts are positive integers. A multiset contains
one row per distinct `(watch, mask, cookie, name)` tuple, sorted by that tuple,
and the sum of its counts equals the ordered-event length.

## PID Lifecycle Semantics

### Common chain

The recorded held PID inode is one exact chain:

```text
reserved_lifecycle.initial
  == start.target_after
  == stop.target_before
```

All three records must describe a regular, singly linked pre-stop inode owned
by the expected build UID/GID. Device, inode, type, mode, ownership, link
count, size, mtime, and ctime are equal across this chain.

The pre-start `store_bindings.reported_paths.ConmonPidFile.target` controls
the initial branch:

- If `start.initial_present` is false, the store target and
  `start.target_before` are both null.
- If `start.initial_present` is true, the store target is present and its
  available device, inode, type, mode, ownership, and link-count fields match
  `start.target_before`; that record also equals the common chain above.

`start.state` is exactly `post-start`, `start.current_present` is exactly
true, `stop.state` is exactly `post-stop`, and `stop.current_present` is
exactly false.

The field named `reserved_lifecycle.initial` means the first held PID inode.
For an initially absent PID it is the inode bound after creation; it does not
claim the inode existed before start.

### Initially present start

An initially present start requires:

- non-null and equal `target_before` and `target_after`;
- identical pre/post runtime/PID-parent listings containing `.containerenv` and
  `conmon.pid`;
- no ordered start events and an empty start multiset;
- stable runtime/PID-parent identity, type, mode, ownership, and link count.

### Initially absent start

An initially absent start requires:

- null `target_before` and a regular, singly linked `target_after`;
- a sorted, unique, safe-basename listing for the immediate runtime/PID parent
  under runroot, containing `.containerenv` and not `conmon.pid`;
- a post-listing formed by adding only `conmon.pid`;
- this exact event grammar for `conmon.pid` on one positive integer watch with
  zero cookies:

```text
CREATE, zero to sixteen MODIFY or ATTRIB events, CLOSE_WRITE
```

There is exactly one CREATE and one CLOSE_WRITE. Moves, deletes, duplicate
boundary events, directory flags, extra mask bits, other names, other watches,
and nonzero cookies are rejected.

### Stop

The reserved stop pre-listing equals the start post-listing. Its post-listing
removes only `conmon.pid` and continues to contain `.containerenv`.

The outer stop sequence contains exactly six events. It enforces these
per-name sequences while allowing arbitrary interleaving between names:

```text
attach:    DELETE
ctl:       CLOSE_WRITE, DELETE
winsz:     CLOSE_WRITE, DELETE
conmon.pid DELETE
```

All config events share one positive integer watch. The PID deletion uses one
different positive integer watch. For an initially absent start, its creation
watch equals the stop PID watch. An initially present start has no start event
from which to derive that equality. Every config and PID stop event has a zero
cookie.

The nested reserved stop event is exactly the PID projection of the outer
sequence. Each recorded multiset is recomputed canonically from its ordered
sequence, including repeated middle-event counts, and must match exactly.

After unlink, `stop.target_after` retains the pre-stop device, inode, type,
mode, UID, GID, size, and mtime. Its link count is exactly zero. Only link
count and ctime may differ from `stop.target_before`.

## Parent and Listing Continuity

Listings for the immediate runtime/PID parent under runroot are sorted, unique
lists of safe basenames. A3 does not invent a universal list of other
legitimate siblings. Instead, it proves exact deltas:

- initially present start: no listing change;
- initially absent start: add only `conmon.pid`;
- the stable interval: stop pre-listing equals start post-listing;
- stop: remove only `conmon.pid`.

Each parent record describes a directory owned by the expected build UID/GID.
Device, inode, type, mode, ownership, and link count remain stable through
start and stop. Directory allocation size may change during either admitted
transition. Between start-post and stop-pre, size also remains stable. Parent
mtime and ctime may change and are not used as equality fields.

This immediate parent is
`runroot/vfs-containers/<container-id>/userdata`; it is not the store's
`store-runroot` directory. A3 does not compare those two directory inodes.

## Existing Config-Parent Proof

The existing exact config-parent proof remains mandatory:

- pre-listing is the seven expected config bundle entries;
- post-listing retains only `artifacts`, `config.json`, `secrets`, and `shm`;
- endpoint types, modes, owners, link counts, and sizes remain exact;
- survivor before/after metadata remains equal;
- `config.json` remains bound to the reported OCI config target;
- config-parent metadata permits only the already authorized transition
  fields;
- the outer ordered events and multiset include both the five config events
  and the one reserved PID event without weakening either grammar.

A3 leaves all existing OCI, store, scratch, lifecycle, role, and container
checks in place. It adds no StaticDir, cgroup, containerenv-path, graphroot,
runroot, or container-ID relationship; those improvements remain Finding B.

## Honest Proof Boundary

The receipt can validate only emitted assertions. The live watcher remains
the authority for several facts that A2 does not serialize:

- PID bytes remain unchanged: the live code hashes the held descriptor, but
  the digest is not emitted.
- Reads are 4,096-byte bounded acquisitions, raw inotify padding is valid,
  the queue is empty at guarded boundaries, and no late event was omitted:
  decoded events and declared limits are emitted, raw buffers and drain
  attempts are not.
- A numeric watch belongs to a particular held parent descriptor: parent
  metadata and watch numbers are emitted separately, without a direct map.
- Failure latching and retry prohibition occurred: these are live state-machine
  guarantees, not successful-receipt fields.

A3 validates the decoded event grammar, limit identities, watch consistency,
metadata continuity, and every available cross-record binding. It does not
claim receipt-level replay of unavailable facts and does not weaken the live
checks that establish them.

## Error Handling

Watcher validation is read-only and fail-closed. Any wrong identity, shape,
type, limit, state, metadata relationship, listing delta, event grammar,
multiset, or role-local binding raises `ReceiptError` before the builder is
accepted. The validator never repairs evidence, coerces values, selects a
fallback schema, or partially publishes success.

Receipt custody remains active while semantic validation runs. A coherent
receipt around evidence that violates these semantic invariants is still
rejected by the semantic layer. Existing cleanup, durability, receipt-last
publication, and post-durability warning behavior are unchanged.

## Verification Strategy

### Producer and focused consumer tests

- Assert the producer's exact top-level keys and both new identities.
- Accept exact initially present and initially absent records.
- Reject the legacy policy/shape and all missing or extra fields.
- Reject Boolean aliases and malformed stat, event, limit, and listing types.
- Table-drive mutations of presence, target metadata, parent metadata,
  listings, event names, watches, cookies, masks, ordering, multiplicity,
  multiset counts, limits, and state.
- Change the PID stop cookie consistently in the outer sequence, nested
  sequence, and both recomputed multisets, and still reject it.
- Prove boundary counts: zero and sixteen start middle events pass; seventeen
  fails.
- Accept legal cross-name stop interleavings, repeated legal middle events
  whose multiset count exceeds one, and permitted parent size/ctime changes.
- Exercise both successful and rejected watcher records through the existing
  probe-role validation route.
- Preserve unrelated current runtime and config-projection regressions.

### Authentic detached-tree tests

Critical semantic mutations are applied to synthetic builder-role fixtures
published as actual detached trees and receipts. Tests then recompute the
changed file hash, complete tree, tree hash, and detached receipt so
byte-integrity checks pass. The mutated tree must be opened through
`BoundAcceptedTree.open` and rejected by `_validate_bound_builder` for
semantic reasons.

This matrix covers at least schema/policy, presence, listing delta, parent
identity, PID inode, event order, event multiplicity, and build/inspection
watcher-record swaps. Valid controls for both initial-presence branches must
continue to pass.

### Completion checks

- Run the new focused tests under `PYTHONHASHSEED=0` and `1`.
- Run the complete `tests.gate01.test_kernel_build` module under both seeds.
- Compile the changed Python files without writing bytecode into the worktree.
- Run `git diff --check` and verify the authorized worktree status.
- Obtain two independent code reviews against this spec.
- Do not run Podman, build RPMs or a kernel, use the network, or inspect a
  private key as part of A3.

## GitHub Publication

After A3 implementation, verification, review, and user approval, commit the
completed `stone-boot-proof` branch and push it only to:

```text
https://github.com/Mrwoady-hub/OpenMythos.git
```

Do not push to `kyegomez/OpenMythos` and do not open an upstream pull request.
The configured GitHub credential is currently expired, so authentication must
be renewed immediately before publication.
