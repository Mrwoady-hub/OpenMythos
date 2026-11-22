# Gate-01 A3 Watcher Evidence Consumer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the approved A2 `conmon.pid` watcher start/stop evidence an exact, fail-closed input to every Gate-01 runtime evidence consumer.

**Architecture:** Keep production evidence in `container_runtime.py`, held-tree custody in the unchanged `proof_io.py`, and semantic acceptance in a private `kernel_build.py` watcher validator. Build independent synthetic fixtures in the existing test module, complete focused TDD before activating the consumer, then prove semantic rejection through fully rehashed 13-file detached trees.

**Tech Stack:** Python 3 standard library, `unittest`, Linux inotify fixtures, canonical JSON, held file descriptors, detached Gate-01 receipts, Git.

**Spec:** `docs/superpowers/specs/2026-09-20-gate01-a3-watcher-evidence-consumer-design.md`

## Global Constraints

- Exact schema identity: `openmythos-runtime-input-binding-v2`.
- Exact policy identity: `inotify-reserved-lifecycle-fail-closed-v1`.
- Reject the legacy shape and `inotify-target-fail-closed-v1`; do not add fallback, normalization, or migration logic.
- Implementation edits are limited to `tools/gate01/container_runtime.py`, `tools/gate01/kernel_build.py`, and `tests/gate01/test_kernel_build.py`.
- Do not modify `proof_io.py`, add a schema module, add a dependency, or change a source-closure list.
- Do not implement new Round-10 Finding B container-ID/path bindings. Preserve current checks unchanged.
- Do not emit PID content hashes, raw inotify buffers, or a watch-to-parent map.
- Do not run Podman, a container lifecycle, an RPM/kernel build, a network fetch, or inspect a private key.
- Use only mock/synthetic lifecycle paths and existing real-inotify unit fixtures.
- The original checkout's existing `open_mythos/main.py` modification is user-owned and must remain untouched.
- The approved spec requires implementation, verification, two reviews, and user approval before the completed branch is committed. Therefore tasks use immutable byte snapshots and review gates instead of intermediate Git commits.
- Final publication is an explicit non-force push to remote `woady`, never `origin`, and no upstream pull request.

## Frozen Pre-A3 Baseline

The implementation files are currently untracked relative to `HEAD`, so
`git diff HEAD` cannot isolate A3. Before editing, require these exact bytes:

```text
644 255562 99ecf37e797ab522a6ecb8ea27fab3461269d266c24d4f0d633bbda7ea337e4b tools/gate01/container_runtime.py
644 206120 bcc63ed6226258bf1d5e28ea61ff9b8c729914b8c4f3d576ca1e767672ea876b tools/gate01/kernel_build.py
664 1608467 bde7a76e81abf6d648e47880cf67386d12133ef94bffc734189bc9bafbc4250c tests/gate01/test_kernel_build.py
```

`HEAD` is the approved design commit `c782681`. Preserve the other eleven
tracked modifications and eight untracked Task-6 files exactly until the
final whole-branch staging review.

## File Map

- Modify `tools/gate01/container_runtime.py`: publish the exact A3 schema and policy identities; do not change A2 lifecycle behavior or evidence fields.
- Modify `tools/gate01/kernel_build.py`: add private exact-shape/stat/listing/event helpers, validate the reserved PID lifecycle, retain the config-parent proof, and route all roles through it.
- Modify `tests/gate01/test_kernel_build.py`: add independent A3 fixtures, focused producer/consumer tests, probe coverage, and authentic detached-tree mutation tests.
- Keep `tools/gate01/proof_io.py` unchanged: it remains the receipt/custody authority.

---

### Task 1: Freeze the baseline and version producer evidence

**Files:**
- Modify: `tools/gate01/container_runtime.py:97-102,508-535`
- Test: `tests/gate01/test_kernel_build.py:7581-7650,7887-7950`

**Interfaces:**
- Consumes: `WatchedRuntimeBindings.evidence -> dict[str, Any]` and the completed A2 start/stop projections.
- Produces: exact top-level `schema` and `policy` strings used later by the consumer.

- [ ] **Step 1: Verify and copy the immutable pre-A3 implementation bytes**

Run:

```bash
sha256sum tools/gate01/container_runtime.py tools/gate01/kernel_build.py tests/gate01/test_kernel_build.py
stat -c '%a %s %n' tools/gate01/container_runtime.py tools/gate01/kernel_build.py tests/gate01/test_kernel_build.py
test ! -e /tmp/openmythos-a3-c782681-baseline
mkdir -m 700 /tmp/openmythos-a3-c782681-baseline
cp --preserve=mode tools/gate01/container_runtime.py /tmp/openmythos-a3-c782681-baseline/
cp --preserve=mode tools/gate01/kernel_build.py /tmp/openmythos-a3-c782681-baseline/
cp --preserve=mode tests/gate01/test_kernel_build.py /tmp/openmythos-a3-c782681-baseline/
```

Expected: hashes, modes, and sizes equal the frozen table above. Stop if any
value differs or the snapshot directory already exists.

- [ ] **Step 2: Add failing exact-identity assertions to both real A2 lifecycle positives**

Immediately after `complete_stop_transition`, assign
`evidence = inputs.evidence` in each test, then add:

```python
self.assertEqual(
    set(evidence),
    {
        "basenames",
        "coalesced_parent_watch_count",
        "parent_fields_excluding_time",
        "persistent_parent_listing",
        "policy",
        "schema",
        "stop_projection",
    },
)
self.assertEqual(evidence["schema"], "openmythos-runtime-input-binding-v2")
self.assertEqual(
    evidence["policy"],
    "inotify-reserved-lifecycle-fail-closed-v1",
)
```

Apply the assertions to:

```text
BoundInputTests.test_reserved_pid_initially_absent_real_inotify_start_stop_lifecycle
BoundInputTests.test_a2r1r1_actual_initially_present_start_stop_is_preserved
```

- [ ] **Step 3: Run the producer tests to verify RED**

Run:

```bash
PYTHONHASHSEED=0 python3 -B -m unittest \
  tests.gate01.test_kernel_build.BoundInputTests.test_reserved_pid_initially_absent_real_inotify_start_stop_lifecycle \
  tests.gate01.test_kernel_build.BoundInputTests.test_a2r1r1_actual_initially_present_start_stop_is_preserved -v
```

Expected: both fail because `schema` is missing and the policy is still v1.

- [ ] **Step 4: Add producer-owned constants and publish them**

Near the existing runtime event limits, add:

```python
_RUNTIME_INPUT_SCHEMA = "openmythos-runtime-input-binding-v2"
_RUNTIME_INPUT_POLICY = "inotify-reserved-lifecycle-fail-closed-v1"
```

In `WatchedRuntimeBindings.evidence`, replace the policy literal and add the
schema without changing any other field:

```python
"policy": _RUNTIME_INPUT_POLICY,
"schema": _RUNTIME_INPUT_SCHEMA,
```

- [ ] **Step 5: Run the producer tests to verify GREEN under both seeds**

Run the Step 3 command with `PYTHONHASHSEED=0`, then repeat with
`PYTHONHASHSEED=1`.

Expected: PASS under both seeds. Do not commit. Record the two changed-file
hashes for the task review.

---

### Task 2: Add independent fixtures and strict metadata validation

**Files:**
- Modify: `tools/gate01/kernel_build.py:2357-2384`
- Test: `tests/gate01/test_kernel_build.py:344-420,28970-29370`

**Interfaces:**
- Consumes: watcher evidence plus already validated OCI-config and Conmon target projections.
- Produces:

```text
_validate_runtime_stat_evidence(
    value: Any,
    *,
    expected_uid: int,
    expected_gid: int,
    kind: int,
    mode: int | None = None,
    nlink: int | None = None,
) -> dict[str, Any]

_validate_runtime_listing(value: Any) -> list[str]

_validate_runtime_event_evidence(
    events: Any,
    multiset: Any,
) -> list[dict[str, Any]]

_validate_runtime_input_binding(
    value: Any,
    *,
    config_target: Mapping[str, Any],
    conmon_target: Mapping[str, Any] | None,
    expected_uid: int,
    expected_gid: int,
) -> None
```

The last helper remains private and unwired until Task 4.

- [ ] **Step 1: Add a test-only canonical multiset helper**

Reuse the test module's existing `Counter` import and add:

```python
def _fixture_event_multiset(events: list[dict[str, object]]) -> list[dict[str, object]]:
    counts = Counter(
        (event["watch"], event["mask"], event["cookie"], event["name"])
        for event in events
    )
    return [
        {
            "watch": watch,
            "mask": mask,
            "cookie": cookie,
            "name": name,
            "count": count,
        }
        for (watch, mask, cookie, name), count in sorted(counts.items())
    ]
```

This helper is test-owned and must not call production validation.

- [ ] **Step 2: Add an independent A3 watcher fixture constructor**

Add a helper beside `_runtime_evidence` with this interface:

```python
def _a3_runtime_input_binding(
    *,
    dev: int,
    uid: int,
    gid: int,
    sequence: int,
    config_stop: dict[str, object],
    initially_present: bool,
    middle_masks: tuple[int, ...] = (),
) -> tuple[dict[str, object], dict[str, object] | None]:
```

Start the helper with this local stat constructor so it does not depend on
production validation or the local function inside `_runtime_evidence`:

```python
def runtime_stat(
    ino: int,
    kind: int,
    mode: int,
    *,
    size: int = 0,
    mtime_ns: int = 100,
    ctime_ns: int = 100,
    nlink: int = 1,
) -> dict[str, int]:
    return {
        "dev": dev,
        "gid": gid,
        "ino": ino,
        "mode": mode,
        "mtime_ns": mtime_ns,
        "ctime_ns": ctime_ns,
        "nlink": nlink,
        "size": size,
        "type": kind,
        "uid": uid,
    }
```

Construct fresh dictionaries with these exact fixture identities:

```python
limits = {
    "max_event_bytes": 65536,
    "max_events": 1024,
    "max_middle_events": 16,
}
pid = runtime_stat(
    sequence + 31, stat.S_IFREG, 0o644, size=4, mtime_ns=100, ctime_ns=100
)
parent_before = runtime_stat(
    sequence + 32, stat.S_IFDIR, 0o700, size=4096, mtime_ns=100, ctime_ns=100
)
parent_after_start = {**parent_before, "size": 8192, "ctime_ns": 101}
parent_before_stop = {**parent_after_start, "ctime_ns": 102}
parent_after_stop = {**parent_before_stop, "size": 4096, "ctime_ns": 103}
pre_listing = [".containerenv", "conmon.pid"] if initially_present else [".containerenv"]
post_listing = [".containerenv", "conmon.pid"]
start_events = [] if initially_present else [
    {"cookie": 0, "mask": 256, "name": "conmon.pid", "watch": 2},
    *(
        {"cookie": 0, "mask": mask, "name": "conmon.pid", "watch": 2}
        for mask in middle_masks
    ),
    {"cookie": 0, "mask": 8, "name": "conmon.pid", "watch": 2},
]
pid_delete = {"cookie": 0, "mask": 512, "name": "conmon.pid", "watch": 2}
```

Use config watch `1` and PID watch `2`. Build the outer stop projection without
sharing mutable dictionaries:

```python
stop = copy.deepcopy(config_stop)
outer_events = copy.deepcopy(stop["observed_events"])
outer_events.insert(1, copy.deepcopy(pid_delete))
stop["observed_events"] = outer_events
stop["event_multiset"] = _fixture_event_multiset(outer_events)
```

Then add:

```python
stop["reserved_lifecycle"] = {
    "initial": copy.deepcopy(pid),
    "start": {
        "initial_present": initially_present,
        "current_present": True,
        "limits": copy.deepcopy(limits),
        "target_before": copy.deepcopy(pid) if initially_present else None,
        "target_after": copy.deepcopy(pid),
        "pre_listing": pre_listing,
        "post_listing": post_listing,
        "pre_parent_metadata": copy.deepcopy(parent_before),
        "post_parent_metadata": parent_after_start,
        "observed_events": start_events,
        "event_multiset": _fixture_event_multiset(start_events),
        "state": "post-start",
    },
    "stop": {
        "current_present": False,
        "limits": copy.deepcopy(limits),
        "target_before": copy.deepcopy(pid),
        "target_after": {**pid, "nlink": 0, "ctime_ns": pid["ctime_ns"] + 1},
        "pre_listing": post_listing,
        "post_listing": [".containerenv"],
        "pre_parent_metadata": parent_before_stop,
        "post_parent_metadata": parent_after_stop,
        "observed_events": [copy.deepcopy(pid_delete)],
        "event_multiset": _fixture_event_multiset([pid_delete]),
        "state": "post-stop",
    },
}
```

Return the exact v2 watcher object and initial Conmon target:

```python
watcher = {
    "basenames": {"config": "config.json", "containerenv": ".containerenv"},
    "coalesced_parent_watch_count": 2,
    "parent_fields_excluding_time": [
        "dev", "ino", "type", "mode", "uid", "gid", "nlink", "size"
    ],
    "persistent_parent_listing": "exact",
    "policy": "inotify-reserved-lifecycle-fail-closed-v1",
    "schema": "openmythos-runtime-input-binding-v2",
    "stop_projection": stop,
}
conmon_target = None
if initially_present:
    conmon_target = {
        **{
            key: pid[key]
            for key in ("dev", "gid", "ino", "mode", "nlink", "type", "uid")
        },
        "present": True,
    }
return watcher, conmon_target
```

- [ ] **Step 3: Add RED tests for exact shapes and metadata relationships**

Add these methods to `ComparisonAndMetaProofTests`:

```text
test_a3_watcher_metadata_contract_accepts_exact_presence_branches
test_a3_watcher_metadata_contract_rejects_shape_chain_and_parent_mutations
```

The positive test calls `_validate_runtime_input_binding` for both Boolean
branches. Add one positive absent-start fixture with a safe sibling such as
`libpod` inserted, in sorted order, into all four runtime/PID-parent listings;
it must pass because A3 proves exact deltas rather than a universal sibling
list. The negative test deep-copies a fresh fixture for every case and covers
this exact table:

```python
mutations = {
    "legacy-schema": lambda w, _c: w.pop("schema"),
    "wrong-schema": lambda w, _c: w.update(
        {"schema": "openmythos-runtime-input-binding-v1"}
    ),
    "legacy-policy": lambda w, _c: w.update(
        {"policy": "inotify-target-fail-closed-v1"}
    ),
    "extra-key": lambda w, _c: w.update({"extra": None}),
    "boolean-inode": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["initial"].update({"ino": True}),
    "presence-before": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["start"].update({"target_before": None}),
    "chain-inode": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["stop"]["target_before"].update({"ino": 1}),
    "linked-zero": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["initial"].update({"nlink": 0}),
    "unlinked-one": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["stop"]["target_after"].update({"nlink": 1}),
    "unsorted-listing": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["start"].update({"post_listing": ["conmon.pid", ".containerenv"]}),
    "unsafe-basename": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["start"]["post_listing"].append("../escape"),
    "parent-identity": lambda w, _c: w["stop_projection"]["reserved_lifecycle"]
        ["stop"]["pre_parent_metadata"].update({"ino": 1}),
}
```

Use the initially present fixture for `presence-before`, linked-target, and
pre-start Conmon-target cases; use a fresh absent fixture for the absent
listing-delta cases. Also mutate the pre-start Conmon target independently to
prove the present branch binds its available metadata fields. Expect
`ReceiptError` for every case.

- [ ] **Step 4: Run the metadata tests to verify RED**

Run:

```bash
PYTHONHASHSEED=0 python3 -B -m unittest \
  tests.gate01.test_kernel_build.ComparisonAndMetaProofTests.test_a3_watcher_metadata_contract_accepts_exact_presence_branches \
  tests.gate01.test_kernel_build.ComparisonAndMetaProofTests.test_a3_watcher_metadata_contract_rejects_shape_chain_and_parent_mutations -v
```

Expected: FAIL because `_validate_runtime_input_binding` does not exist.

- [ ] **Step 5: Implement strict stat, listing, and event-row primitives**

Add `from collections import Counter` to `kernel_build.py` and implement the
interfaces above with these rules:

```python
_RUNTIME_STAT_FIELDS = {
    "dev", "gid", "ino", "mode", "mtime_ns", "ctime_ns",
    "nlink", "size", "type", "uid",
}
_RUNTIME_EVENT_FIELDS = {"cookie", "mask", "name", "watch"}
_RUNTIME_MULTISET_FIELDS = {*_RUNTIME_EVENT_FIELDS, "count"}
_RUNTIME_LIMITS = {
    "max_event_bytes": 65536,
    "max_events": 1024,
    "max_middle_events": 16,
}
```

- `_validate_runtime_stat_evidence` rejects extra/missing fields, booleans,
  negative values, zero inode, mode above `0o7777`, wrong owner/type/mode, and
  all zero link counts unless `nlink=0` was explicitly requested.
- `_validate_runtime_listing` requires a sorted, unique list of nonempty
  strings with no `/`, NUL, control character, `.` entry, or `..` entry.
- `_validate_runtime_event_evidence` validates rows before indexing, requires
  positive watches and multiset counts, nonnegative masks/cookies, one row per
  distinct tuple, exact `(watch, mask, cookie, name)` ordering, and equality to
  a `Counter` recomputation. It returns the validated ordered events.

- [ ] **Step 6: Implement exact watcher shape, target chain, and parent/listing continuity**

Implement `_validate_runtime_input_binding` with exact top-level, stop,
reserved, start, and reserved-stop field sets copied from the spec. Retain the
existing config endpoint/survivor checks, including the OCI config target
binding. Add the PID rules:

```python
watcher = _evidence_exact(value, {
    "basenames", "coalesced_parent_watch_count",
    "parent_fields_excluding_time", "persistent_parent_listing",
    "policy", "schema", "stop_projection",
})
stop = _evidence_exact(watcher["stop_projection"], {
    "allowed_removed_names", "endpoint_metadata", "event_multiset",
    "observed_events", "post_listing", "post_parent_metadata",
    "pre_listing", "pre_parent_metadata", "reserved_lifecycle",
    "state", "survivor_metadata",
})
reserved = _evidence_exact(stop["reserved_lifecycle"], {
    "initial", "start", "stop",
})
start = _evidence_exact(reserved["start"], {
    "current_present", "event_multiset", "initial_present", "limits",
    "observed_events", "post_listing", "post_parent_metadata",
    "pre_listing", "pre_parent_metadata", "state",
    "target_after", "target_before",
})
reserved_stop = _evidence_exact(reserved["stop"], {
    "current_present", "event_multiset", "limits", "observed_events",
    "post_listing", "post_parent_metadata", "pre_listing",
    "pre_parent_metadata", "state", "target_after", "target_before",
})
```

Require the fixed basenames, watch count, parent-field list, persistent-listing
marker, schema, and policy values verbatim. Require
`type(start["initial_present"]) is bool`, `start.current_present is True`,
`start.state == "post-start"`, `reserved_stop.current_present is False`, and
`reserved_stop.state == "post-stop"`. Bind a null pre-start Conmon target to
the absent branch and the seven available target fields to the present branch.

Add the PID metadata equality rules:

```python
if not _evidence_same(initial, start["target_after"]):
    raise ReceiptError("runtime PID initial/start metadata differs")
if not _evidence_same(initial, reserved_stop["target_before"]):
    raise ReceiptError("runtime PID start/stop metadata differs")
```

For the unlinked target, compare every field except `nlink` and `ctime_ns`,
require `nlink == 0`, and keep `mtime_ns` equal. Validate exact listing deltas
for each presence branch. Compare parent fields `dev`, `ino`, `type`, `mode`,
`uid`, `gid`, and `nlink` across transitions; compare `size` additionally from
start-post to stop-pre; ignore only parent `mtime_ns` and `ctime_ns`.

Do not compare the runtime/PID-parent inode with the store's `store-runroot`
inode. Do not wire this helper into `_validate_runtime_evidence` yet.

- [ ] **Step 7: Run the metadata tests to verify GREEN**

Repeat Step 4 under seeds `0` and `1`.

Expected: PASS. Run `git diff --check`, compare the two changed implementation
files with `/tmp/openmythos-a3-c782681-baseline`, and record hashes for review.
Do not commit.

---

### Task 3: Enforce event grammars, limits, and canonical projections

**Files:**
- Modify: `tools/gate01/kernel_build.py` private watcher helpers from Task 2
- Test: `tests/gate01/test_kernel_build.py` A3 fixture and focused watcher tests

**Interfaces:**
- Consumes: `_validate_runtime_event_evidence(events, multiset)` and the exact Task-2 lifecycle records.
- Produces: complete but still unwired watcher semantics ready for activation.

- [ ] **Step 1: Add positive grammar and boundary tests**

Add:

```text
ComparisonAndMetaProofTests.test_a3_watcher_event_contract_accepts_exact_grammars_and_boundaries
```

Require all of these to pass:

```python
for middle_masks in ((), (2,), (4,), (2, 4) * 8):
    # 0, 1, 2, and 16 legal middle operations
    validate(initially_present=False, middle_masks=middle_masks)
validate(initially_present=True, middle_masks=())
```

Add a legal stop interleaving that places the PID delete between config
events, and a repeated `(watch=2, mask=2, cookie=0, name="conmon.pid")` start
event whose canonical multiset row has `count == 2`.

- [ ] **Step 2: Add focused RED mutations for grammar and projection failures**

Add:

```text
ComparisonAndMetaProofTests.test_a3_watcher_event_contract_rejects_order_watch_cookie_and_multiset_mutations
```

Use fresh evidence for every case and cover:

```text
17 middle events
initially-present start event
wrong first or last start mask
duplicate CREATE or CLOSE_WRITE
start DELETE, move, or directory-flag mask
nonzero start cookie
second start watch
wrong start name
missing or duplicate PID stop DELETE
wrong config per-name order
same config and PID watch
nonzero stop cookie
nested stop event differs from the outer PID projection
wrong multiset tuple, order, count, duplicate row, Boolean count
wrong max_event_bytes, max_events, or max_middle_events
```

For the nonzero PID stop cookie, change the cookie in both outer and nested
ordered events and recompute both multisets before validation. This ensures
the test reaches the zero-cookie rule instead of failing on inconsistency.

- [ ] **Step 3: Run the event tests to verify RED**

Run both new event methods under seed `0`.

Expected: positive fixtures pass structural validation, while at least the
semantic event mutations are incorrectly accepted.

- [ ] **Step 4: Implement exact start and stop grammars**

In `_validate_runtime_input_binding` or a private
`_validate_reserved_lifecycle` helper, enforce:

```python
if start["limits"] != _RUNTIME_LIMITS or reserved_stop["limits"] != _RUNTIME_LIMITS:
    raise ReceiptError("runtime PID lifecycle limits differ")

if start["initial_present"]:
    if start_events:
        raise ReceiptError("runtime PID present-start events differ")
else:
    masks = [event["mask"] for event in start_events]
    middle = masks[1:-1]
    if (
        len(masks) < 2
        or masks[0] != 256
        or masks[-1] != 8
        or masks.count(256) != 1
        or masks.count(8) != 1
        or len(middle) > 16
        or any(mask not in {2, 4} for mask in middle)
    ):
        raise ReceiptError("runtime PID start event grammar differs")
```

Every PID start event uses exact name `conmon.pid`, one positive watch, zero
cookie, and one of the exact masks above. For outer stop events, require six
events total, zero cookies, config sequences:

```python
{"attach": [512], "ctl": [8, 512], "winsz": [8, 512]}
```

and one `conmon.pid: [512]`. Config events share one watch; the PID watch is
different. An absent-start watch equals the stop PID watch. The nested PID
stop sequence and multiset equal the exact outer PID projection.

- [ ] **Step 5: Run all focused watcher tests to verify GREEN**

Run the four Task-2/Task-3 A3 methods under seeds `0` and `1`.

Expected: PASS. Run the existing direct numeric-alias test as a regression:

```bash
python3 -B -m unittest \
  tests.gate01.test_kernel_build.ComparisonAndMetaProofTests.test_semantic_postfix_rejects_numeric_aliases_ownership_and_reversed_ranges -v
```

Do not commit. Record the snapshot diff and new hashes for review.

---

### Task 4: Activate the consumer for build, inspection, and probe roles

**Files:**
- Modify: `tools/gate01/kernel_build.py:2384-2524`
- Modify: `tests/gate01/test_kernel_build.py:344-420,6253-6460,29278-29335`

**Interfaces:**
- Consumes: completed private validator from Tasks 2-3 and producer identity from Task 1.
- Produces: `_validate_runtime_evidence` acceptance of only the complete v2 watcher contract in all roles.

- [ ] **Step 1: Upgrade the shared runtime fixture without using production validation**

Change the fixture signature to:

```python
def _runtime_evidence(
    repository: Path,
    builder: str,
    capsule: dict[str, object],
    *,
    probe_root: Path | None = None,
    normalization_audit=None,
    initially_present_by_role: Mapping[str, bool] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
```

Default `initially_present_by_role` to false for both build and inspection.
After constructing the existing config stop fixture, call the test-only A3
constructor with each role's distinct `sequence`. Store its watcher object in
`runtime_input_binding` and its returned Conmon target in the existing
`reported_paths.ConmonPidFile.target`. Do not call a production validator to
make the fixture valid.

- [ ] **Step 2: Add runtime-level and probe RED tests**

Add:

```text
ComparisonAndMetaProofTests.test_a3_runtime_validator_accepts_build_inspection_and_probe_roles
NoBuildEvidenceTests.test_a3_probe_accepts_both_pid_presence_branches
```

The runtime test validates an absent/absent contract and a mixed
present/absent contract. It then wraps the build role as a probe with the
existing `probe_root` calling convention. Construct that fixture with:

```python
rootfs, contract = _runtime_evidence(
    repository,
    "probe",
    capsule,
    probe_root=probe_root,
    initially_present_by_role={"build": branch, "inspection": False},
)
```

Then use:

```python
probe_root = Path("/synthetic-probe")
probe_rootfs = {
    "schema_version": 1,
    "expected": rootfs["expected"],
    "probe": rootfs["build"],
}
probe_contract = {
    "schema_version": 1,
    "key_scope": {"probe": False},
    "stores_distinct": True,
    "repository_mounted": False,
    "probe": contract["build"],
}
kernel_build._validate_runtime_evidence(
    probe_rootfs,
    probe_contract,
    capsule,
    repository=repository,
    builder="probe",
    expected_uid=os.getuid(),
    expected_gid=os.getgid(),
    probe_root=probe_root,
)
```

Change `NoBuildEvidenceTests._probe` to accept
`initially_present: bool = False` and pass:

```python
initially_present_by_role={
    "build": initially_present,
    "inspection": False,
}
```

to `_runtime_evidence`. The no-build test drives both branches through
`_probe` and `run_no_build_lifecycle`.

Extend
`NoBuildEvidenceTests.test_probe_evidence_rejects_runtime_policy_and_phase_corruptions`
with exact schema, legacy policy, PID chain, listing, and event-cookie
corruptions.

- [ ] **Step 3: Run the integration tests to verify RED**

Run the two new methods and the existing probe corruption method.

Expected: FAIL because the old consumer rejects the v2 top-level and reserved
fields before the new helper is reached.

- [ ] **Step 4: Replace the legacy watcher block with the complete helper call**

After current reported-path and image checks establish `reported`, call:

```python
_validate_runtime_input_binding(
    backend["runtime_input_binding"],
    config_target=reported["OCIConfigPath"]["target"],
    conmon_target=reported["ConmonPidFile"]["target"],
    expected_uid=expected_uid,
    expected_gid=expected_gid,
)
```

Delete the legacy inline exact shape, v1 policy, five-event stop logic, and its
duplicated config projection checks only after they exist in the new helper.
Remove the now-unused nested `runtime_stat` function only after all of its
watcher call sites have moved. Do not move or weaken any reported-path,
container-ID, OCI, store, scratch,
normalization, lifecycle, or live-attestation checks.

- [ ] **Step 5: Run integration and surrounding regressions to verify GREEN**

Run under seeds `0` and `1`:

```text
all six new A3 focused/integration methods
NoBuildEvidenceTests.test_probe_evidence_rejects_runtime_policy_and_phase_corruptions
ComparisonAndMetaProofTests.test_runtime_semantics_reject_cross_field_and_rehashed_corruptions
ComparisonAndMetaProofTests.test_semantic_postfix_rejects_numeric_aliases_ownership_and_reversed_ranges
BoundInputTests.test_a2r2_real_composed_start_stop_both_pid_initial_states
```

Expected: PASS. Do not commit. Compare all three implementation files against
the frozen `/tmp` baseline and submit the bounded diff for review.

---

### Task 5: Prove semantic rejection through authentic detached trees

**Files:**
- Modify: `tests/gate01/test_kernel_build.py:29112-29335`

**Interfaces:**
- Consumes: `_runtime_evidence`, `ComparisonAndMetaProofTests._publish_builder`, `BoundAcceptedTree.open`, and `_validate_bound_builder`.
- Produces: complete receipt-level positive controls and semantic mutation coverage.

- [ ] **Step 1: Extend the synthetic builder publisher narrowly**

Change the existing typing import to `from typing import Callable, Mapping`,
then add these keyword parameters:

```python
initially_present_by_role: Mapping[str, bool] | None = None,
runtime_contract_mutator: Callable[[dict[str, object]], None] | None = None,
```

Pass the branch map to `_runtime_evidence`. Immediately after receiving
`rootfs, contract`, apply the optional mutator to `contract`, then serialize
the two public files as before. Do not hand-edit receipt hashes: the existing
`create_detached_receipt` and `publish_candidate` calls must commit the
mutated canonical bytes and complete 13-file tree.

- [ ] **Step 2: Add valid detached-tree controls for both branches**

Add:

```text
ComparisonAndMetaProofTests.test_a3_detached_tree_accepts_both_pid_presence_controls
```

Publish and validate:

```python
{"build": False, "inspection": False}
{"build": True, "inspection": False}
```

Open each tree with `BoundAcceptedTree.open`, call `_validate_bound_builder`,
and require success. Record `/proc/self/fd` before and after each case.

- [ ] **Step 3: Add the fully rehashed semantic mutation matrix**

Add:

```text
ComparisonAndMetaProofTests.test_a3_detached_tree_rejects_rehashed_watcher_semantic_mutations
```

Use these concrete cases so both roles and both presence branches participate:

```text
build/absent: wrong schema
inspection/present: legacy policy
build/absent: initial presence contradicts null store target
inspection/present: invalid start listing delta
build/absent: stop-pre parent inode differs
inspection/present: PID stop-before inode differs
build/absent: start event order differs
inspection/absent: duplicate PID stop event with recomputed multisets
build/present: nonzero PID stop cookie in outer+nested events with both multisets recomputed
```

For every case:

```python
final, receipt = self._publish_builder(
    repository,
    "builder-a",
    initially_present_by_role=branches,
    runtime_contract_mutator=mutate,
)
with proof_io.BoundAcceptedTree.open(
    final,
    receipt,
    allowed_files=kernel_build.PUBLIC_OUTPUT_FILES,
    expected_uid=os.geteuid(),
    expected_gid=os.getegid(),
) as tree:
    with self.assertRaises(ReceiptError):
        kernel_build._validate_bound_builder(repository, "builder-a", tree)
```

The `BoundAcceptedTree.open` call stays outside `assertRaises`; otherwise the
test would not prove that receipt integrity passed before semantic rejection.

- [ ] **Step 4: Add a cross-role watcher-swap receipt test**

Add:

```text
ComparisonAndMetaProofTests.test_a3_detached_tree_rejects_cross_role_watcher_swap
```

Deep-copy and exchange only the two `runtime_input_binding` objects. Leave
store paths and role-local target metadata in place. Publish a new detached
tree and require `_validate_bound_builder` to reject the role-local metadata
mismatch after `BoundAcceptedTree.open` succeeds.

- [ ] **Step 5: Run authentic-tree tests under both seeds**

Run the three new detached-tree methods under seeds `0` and `1`.

Expected: all valid controls PASS; every fully rehashed semantic mutation
raises `ReceiptError`; FD counts return to baseline. Run the existing all-13
malformed-role test as a regression. Do not commit.

---

### Task 6: Complete verification and independent review

**Files:**
- Verify: `tools/gate01/container_runtime.py`
- Verify: `tools/gate01/kernel_build.py`
- Verify: `tests/gate01/test_kernel_build.py`
- Verify: `docs/superpowers/specs/2026-09-20-gate01-a3-watcher-evidence-consumer-design.md`

**Interfaces:**
- Consumes: completed Tasks 1-5.
- Produces: a reviewed A3 change set and exact final staging manifest; no Git commit yet.

- [ ] **Step 1: Run all new focused A3 tests under two seeds**

Run one `unittest` command containing every new A3 method plus the two modified
real producer positives, first with seed `0`, then seed `1`.

Expected: PASS with identical test counts under both seeds.

- [ ] **Step 2: Run the complete kernel test module under two seeds**

Run:

```bash
PYTHONHASHSEED=0 python3 -B -m unittest tests.gate01.test_kernel_build -v
PYTHONHASHSEED=1 python3 -B -m unittest tests.gate01.test_kernel_build -v
```

Expected: PASS under both seeds. The recurring sandbox warning
`Failed to create stream fd: Operation not permitted` is non-fatal only when
the command exits zero and no test reports an error or failure.

- [ ] **Step 3: Compile changed Python files outside the worktree**

Create a fresh bytecode prefix with `mktemp -d`, set `PYTHONPYCACHEPREFIX` to
that exact directory, and run:

```bash
python3 -B -m py_compile \
  tools/gate01/container_runtime.py \
  tools/gate01/kernel_build.py \
  tests/gate01/test_kernel_build.py
```

Expected: exit zero and no worktree bytecode.

- [ ] **Step 4: Prove the exact A3 diff against the frozen bytes**

Run `diff -u` from each frozen `/tmp` file to its worktree counterpart. Review
every hunk against the spec. Then run:

```bash
git diff --check
git status --short --branch
sha256sum tools/gate01/container_runtime.py tools/gate01/kernel_build.py tests/gate01/test_kernel_build.py
stat -c '%a %s %n' tools/gate01/container_runtime.py tools/gate01/kernel_build.py tests/gate01/test_kernel_build.py
```

Expected: only the approved three implementation files differ from the
snapshot; modes remain `644`, `644`, and `664`; no unrelated worktree path was
changed during A3.

- [ ] **Step 5: Obtain two independent reviews**

Give each reviewer the approved spec, this plan, the frozen baseline hashes,
the three snapshot diffs, focused/full test transcripts, and final identities.
One reviewer checks spec/semantic completeness; the other checks tests,
receipt authenticity, regression scope, and prohibited actions.

Expected: two approvals. Resolve every blocking finding, rerun all affected
focused tests under both seeds, rerun the full module under both seeds, and
refresh hashes before continuing.

- [ ] **Step 6: Prepare the whole-branch staging manifest and stop for user approval**

List every tracked modification and untracked Task-6 file that the final
commit will include. Confirm that the design commit remains `c782681`, the new
plan is present, the original checkout still has only its pre-existing user
change, and no file under `build/` is inspected or staged.

Expected: report verification results, review approvals, final hashes, and the
exact proposed staging list to the user. Do not stage, commit, authenticate, or
push until the user explicitly approves publication of that reviewed set.

---

### Task 7: Commit and publish the approved branch

**Files:**
- Stage: only the exact user-approved whole-branch manifest from Task 6
- Publish: branch `stone-boot-proof` to remote `woady`

**Interfaces:**
- Consumes: explicit post-review user approval and valid GitHub authentication.
- Produces: one final implementation commit and a non-force branch on `Mrwoady-hub/OpenMythos`.

- [ ] **Step 1: Recheck repository and remote identity**

Run:

```bash
git branch --show-current
git remote -v
git status --short --branch
```

Expected: current branch `stone-boot-proof`; `woady` points to
`https://github.com/Mrwoady-hub/OpenMythos.git`; `origin` remains upstream and
must not receive a push.

- [ ] **Step 2: Stage exactly the approved manifest**

Use explicit paths, never `git add .` or `git add -A`. Then run:

```bash
git diff --cached --name-status
git diff --cached --check
git diff --cached --stat
```

Expected: the cached path list exactly equals the Task-6 approved manifest and
contains no `build/` output, credential, private key, or original-checkout
path.

- [ ] **Step 3: Create the final implementation commit**

Run:

```bash
git commit -m "feat: build Gate 01 stone boot proof"
```

Expected: commit succeeds; `git status --short` is empty in the isolated
worktree. Record the commit ID.

- [ ] **Step 4: Renew authentication without storing credentials in the repository**

Run `gh auth status`. If it still reports the expired `Mrwoady-hub` token,
pause for the user to complete `gh auth login -h github.com`. Re-run
`gh auth status` and require an authenticated `Mrwoady-hub` account before any
push.

- [ ] **Step 5: Inspect remote branch state and push without force**

Run:

```bash
git ls-remote --heads woady stone-boot-proof
git push woady stone-boot-proof:stone-boot-proof
```

If the remote branch already exists and diverges, stop and inspect/fetch it;
do not force-push. Never push to `origin`.

Expected: the exact local commit is published at
`Mrwoady-hub/OpenMythos/tree/stone-boot-proof`. Do not open an upstream pull
request.
