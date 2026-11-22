"""No-hook Podman lifecycle, OCI/rootfs audit, and live attestation for Gate 01."""

from __future__ import annotations

import argparse
import copy
from collections import Counter
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
from enum import Enum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import time
from types import TracebackType
from typing import Any, Iterable, Mapping

from tools.gate01.proof_io import (
    _add_cleanup_note,
    ARTIFACT_FD_ROLES,
    BUILD_KEY_FD,
    BUILD_RESULT_FD,
    EVIDENCE_FD_ROLES,
    INPUT_AUDIT_FD_ROLES,
    OCI_ARCHIVE_FD,
    PUBLIC_CERTIFICATE_FD,
    RUNTIME_CONTAINERENV_FD,
    VERIFIER_FD,
    FixedDescriptors,
    _hash_descriptor,
    _json_safe,
    _object_sha256,
    _open_parent_directory,
    _read_descriptor,
    _release_all,
    _close_descriptors,
    _close_descriptor_sequence,
    _close_resource_mapping,
    _close_resource_preserving_primary,
    _release_preserving_primary,
    _require_sealed_regular_descriptor,
    _stat_identity,
    _stat_version,
    _write_public_file,
    seal_public_bytes,
)

_IN_MODIFY = 0x00000002
_IN_ATTRIB = 0x00000004
_IN_CLOSE_WRITE = 0x00000008
_IN_MOVED_FROM = 0x00000040
_IN_MOVED_TO = 0x00000080
_IN_CREATE = 0x00000100
_IN_DELETE = 0x00000200
_IN_DELETE_SELF = 0x00000400
_IN_MOVE_SELF = 0x00000800
_IN_UNMOUNT = 0x00002000
_IN_Q_OVERFLOW = 0x00004000
_IN_IGNORED = 0x00008000
_IN_ONLYDIR = 0x01000000
_IN_ISDIR = 0x40000000
_RUNTIME_WATCH_MASK = (
    _IN_MODIFY
    | _IN_ATTRIB
    | _IN_CLOSE_WRITE
    | _IN_MOVED_FROM
    | _IN_MOVED_TO
    | _IN_CREATE
    | _IN_DELETE
    | _IN_DELETE_SELF
    | _IN_MOVE_SELF
    | _IN_UNMOUNT
    | _IN_Q_OVERFLOW
    | _IN_IGNORED
)
_INOTIFY_HEADER = struct.Struct("=iIII")
_STOP_CONFIG_ENTRY_SCHEMA = {
    "artifacts": (stat.S_IFDIR, 0o755),
    "attach": (stat.S_IFSOCK, 0o700),
    "config.json": (stat.S_IFREG, 0o644),
    "ctl": (stat.S_IFIFO, 0o640),
    "secrets": (stat.S_IFDIR, 0o755),
    "shm": (stat.S_IFDIR, 0o700),
    "winsz": (stat.S_IFIFO, 0o640),
}
_STOP_ENDPOINT_NAMES = ("attach", "ctl", "winsz")
# A lifecycle proof is deliberately small: it admits the kernel events made
# by one direct write(2), not an unbounded backlog that could hide churn.
_RUNTIME_MAX_EVENT_BYTES = 64 * 1024
_RUNTIME_MAX_EVENTS = 1024
_RUNTIME_INPUT_SCHEMA = "openmythos-runtime-input-binding-v2"
_RUNTIME_INPUT_POLICY = "inotify-reserved-lifecycle-fail-closed-v1"
_RESERVED_PID_MAX_MIDDLE_EVENTS = 16
_SYS_OPENAT2 = 437  # linux/amd64, the only accepted builder platform
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_IN_ROOT = 0x10


class _OpenHow(ctypes.Structure):
    _fields_ = (
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    )


def _runtime_parent_metadata(value: os.stat_result) -> tuple[int, ...]:
    """Parent fields that remain stable across Podman's exec bookkeeping.

    Podman creates and removes new bundle entries for each exec, which
    necessarily advances directory mtime/ctime.  Identity, ownership, mode,
    link count, allocation size, final listing, and all baseline-name events
    remain acceptance-critical.
    """
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
    )


def _runtime_parent_transition_metadata(value: os.stat_result) -> tuple[int, ...]:
    # Removing the exact three stop endpoints may change directory allocation
    # size in addition to mtime/ctime; all other parent metadata stays fixed.
    return _runtime_parent_metadata(value)[:-1]


def _runtime_stat_evidence(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev,
        "gid": value.st_gid,
        "ino": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
        "nlink": value.st_nlink,
        "size": value.st_size,
        "type": stat.S_IFMT(value.st_mode),
        "uid": value.st_uid,
    }


def _runtime_event_evidence(events: Iterable[_RuntimeWatchEvent]) -> list[dict[str, Any]]:
    return [
        {"cookie": event.cookie, "mask": event.mask, "name": os.fsdecode(event.name), "watch": event.watch}
        for event in events
    ]


def _runtime_event_multiset(events: Iterable[_RuntimeWatchEvent]) -> list[dict[str, Any]]:
    return [
        {"cookie": cookie, "count": count, "mask": mask, "name": os.fsdecode(name), "watch": watch}
        for (watch, mask, cookie, name), count in sorted(
            Counter((event.watch, event.mask, event.cookie, event.name) for event in events).items()
        )
    ]


def _open_inotify() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


def _add_inotify_directory_watch(descriptor: int, parent_descriptor: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    path = os.fsencode(f"/proc/self/fd/{parent_descriptor}")
    watch = libc.inotify_add_watch(
        descriptor,
        ctypes.c_char_p(path),
        ctypes.c_uint32(
            # /proc/self/fd/N is intentionally dereferenced to the already
            # held directory inode; IN_ONLYDIR then rejects any non-directory
            # referent.
            _RUNTIME_WATCH_MASK | _IN_ONLYDIR
        ),
    )
    if watch < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(watch)


def _read_inotify_chunks(descriptor: int) -> Iterable[bytes]:
    """Yield one bounded kernel read at a time; never stage an unbounded queue."""
    while True:
        try:
            value = os.read(descriptor, 4096)
        except BlockingIOError:
            return
        if not value:
            raise RuntimeError("runtime input watch was lost")
        yield value


def _read_creation_events(descriptor: int) -> tuple[tuple[int, int, int, bytes], ...]:
    """Bounded exact parent-name grammar for mkdir's pre-inode interval."""
    result = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, 65536)
        except BlockingIOError:
            return tuple(result)
        if not chunk:
            raise RuntimeError("store creation watch ended")
        total += len(chunk)
        if total > 1048576:
            raise RuntimeError("store creation watch exceeds bound")
        offset = 0
        while offset < len(chunk):
            if len(chunk) - offset < _INOTIFY_HEADER.size:
                raise RuntimeError("store creation watch header is truncated")
            watch, mask, cookie, length = _INOTIFY_HEADER.unpack_from(chunk, offset)
            offset += _INOTIFY_HEADER.size
            if length > 256 or length % 16 or offset + length > len(chunk):
                raise RuntimeError("store creation watch name is malformed")
            raw = chunk[offset:offset + length]
            name = raw.split(b"\0", 1)[0]
            if length and (not name or b"/" in name or raw != name + bytes(length - len(name)) or len(name) == length):
                raise RuntimeError("store creation watch name is not canonical")
            result.append((watch, mask, cookie, name))
            if len(result) > 2:
                raise RuntimeError("store creation watch event count differs")
            offset += length


@dataclass
class _WatchedRuntimeParent:
    path: Path
    descriptor: int
    initial_status: os.stat_result
    initial_names: tuple[str, ...]
    watch_number: int
    labels_by_name: dict[bytes, str]


@dataclass(frozen=True)
class _RuntimeWatchEvent:
    watch: int
    mask: int
    cookie: int
    name: bytes


@dataclass
class _WatchedRuntimeFile:
    label: str
    path: Path
    name: str
    parent: _WatchedRuntimeParent
    descriptor: int
    initial_status: os.stat_result
    initial_sha256: str


class WatchedRuntimeBindings:
    """Hold Podman runtime inputs while watching their exact basenames.

    Podman exec legitimately churns new names in its OCI bundle.  This
    dedicated binding therefore permits only transient events for basenames
    absent at binding, while baseline-name events, watch loss/overflow,
    persistent siblings, target byte/metadata changes, and parent/path
    replacement all fail closed.
    """

    def __init__(
        self,
        *,
        watch_descriptor: int,
        parents_by_watch: dict[int, _WatchedRuntimeParent],
        records: dict[str, _WatchedRuntimeFile],
        reserved_lifecycle: tuple[str, str] | None = None,
    ) -> None:
        self._watch_descriptor = watch_descriptor
        self._parents_by_watch = parents_by_watch
        self._records = records
        self._closed = False
        self._terminal_proof_failed = False
        self._stop_projection_label: str | None = None
        self._stop_endpoint_initial: dict[str, os.stat_result] = {}
        self._stop_transition_before: dict[str, os.stat_result] | None = None
        self._stop_transition_parent_before: os.stat_result | None = None
        self._stop_transition_evidence: dict[str, Any] | None = None
        self._reserved_lifecycle: dict[str, Any] | None = None
        self._start_transition_before: tuple[tuple[str, ...], os.stat_result] | None = None
        self._start_transition_evidence: dict[str, Any] | None = None
        if reserved_lifecycle is not None:
            self._initialize_reserved_lifecycle(*reserved_lifecycle)

    @classmethod
    def open(
        cls,
        paths: Mapping[str, Path],
        *,
        stop_projection_label: str | None = None,
        reserved_lifecycle: tuple[str, str] | None = None,
    ) -> "WatchedRuntimeBindings":
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("runtime input labels must be a non-empty unique set")
        if stop_projection_label is not None and stop_projection_label not in paths:
            raise ValueError("stop projection label must name a runtime input")
        if reserved_lifecycle is not None:
            reserved_label, reserved_name = reserved_lifecycle
            if (
                reserved_label not in paths
                or not isinstance(reserved_name, str)
                or reserved_name in {"", ".", ".."}
                or "/" in reserved_name
            ):
                raise ValueError("reserved lifecycle name is invalid")
        normalized = {
            label: Path(os.path.abspath(os.fspath(path)))
            for label, path in paths.items()
        }
        grouped: dict[Path, list[tuple[str, Path]]] = {}
        for label, path in sorted(normalized.items()):
            grouped.setdefault(path.parent, []).append((label, path))

        watch_descriptor = -1
        parents_by_watch: dict[int, _WatchedRuntimeParent] = {}
        records: dict[str, _WatchedRuntimeFile] = {}
        result: WatchedRuntimeBindings | None = None
        try:
            watch_descriptor = _open_inotify()
            for parent_path, children in sorted(
                grouped.items(), key=lambda item: os.fspath(item[0])
            ):
                parent_descriptor, _opened_parent = _open_parent_directory(
                    children[0][1]
                )
                try:
                    watch_number = _add_inotify_directory_watch(
                        watch_descriptor, parent_descriptor
                    )
                    parent = _WatchedRuntimeParent(
                        path=parent_path,
                        descriptor=parent_descriptor,
                        initial_status=os.fstat(parent_descriptor),
                        initial_names=tuple(sorted(os.listdir(parent_descriptor))),
                        watch_number=watch_number,
                        labels_by_name={
                            os.fsencode(path.name): label for label, path in children
                        },
                    )
                    if len(parent.labels_by_name) != len(children):
                        raise ValueError(
                            "runtime inputs in one parent must have unique basenames"
                        )
                    parents_by_watch[watch_number] = parent
                    parent_descriptor = -1
                finally:
                    if parent_descriptor >= 0:
                        _release_primary = sys.exception()
                        try:
                            os.close(parent_descriptor)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

                for label, path in children:
                    parent = parents_by_watch[watch_number]
                    named = os.stat(
                        path.name,
                        dir_fd=parent.descriptor,
                        follow_symlinks=False,
                    )
                    if not stat.S_ISREG(named.st_mode):
                        raise ValueError(
                            f"runtime input must be a regular file: {label}"
                        )
                    descriptor = os.open(
                        path.name,
                        os.O_RDONLY
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW
                        | os.O_NONBLOCK,
                        dir_fd=parent.descriptor,
                    )
                    try:
                        opened = os.fstat(descriptor)
                        if _stat_identity(named) != _stat_identity(opened):
                            raise RuntimeError(
                                f"runtime input path identity changed: {label}"
                            )
                        digest = _hash_descriptor(descriptor)
                        if _stat_version(opened) != _stat_version(
                            os.fstat(descriptor)
                        ):
                            raise RuntimeError(
                                f"runtime input changed while opening: {label}"
                            )
                        records[label] = _WatchedRuntimeFile(
                            label=label,
                            path=path,
                            name=path.name,
                            parent=parent,
                            descriptor=descriptor,
                            initial_status=opened,
                            initial_sha256=digest,
                        )
                        descriptor = -1
                    finally:
                        if descriptor >= 0:
                            _release_primary = sys.exception()
                            try:
                                os.close(descriptor)
                            except BaseException:
                                if _release_primary is None:
                                    raise
                                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            result = cls(
                watch_descriptor=watch_descriptor,
                parents_by_watch=parents_by_watch,
                records=records,
                reserved_lifecycle=reserved_lifecycle,
            )
            if stop_projection_label is not None:
                result._initialize_stop_projection(stop_projection_label)
            result.verify_coherent()
            watch_descriptor = -1
            return result
        except BaseException as primary:
            if result is not None:
                reserved = getattr(result, "_reserved_lifecycle", None)
                if reserved is not None and isinstance(reserved.get("descriptor"), int):
                    descriptor = reserved["descriptor"]
                    reserved["descriptor"] = None
                    try:
                        os.close(descriptor)
                    except BaseException:
                        _add_cleanup_note(primary, "additional reserved lifecycle descriptor cleanup failed")
            try:
                try:
                    _close_resource_mapping(records, primary, descriptor_attribute="descriptor")
                except BaseException as _map_primary:
                    # The map remains installed until this literal numeric fallback drains it.
                    _raw_records = records
                    while _raw_records:
                        try:
                            _raw_owner = _raw_records.popitem()[1]
                        except BaseException:
                            _raw_owner = dict.popitem(_raw_records)[1]
                        _raw_fd = _raw_owner.descriptor
                        _raw_owner.descriptor = -1
                        if _raw_fd is not None and _raw_fd >= 0:
                            try:
                                os.close(_raw_fd)
                            except BaseException:
                                _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                    _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            finally:
                try:
                    try:
                        _close_resource_mapping(parents_by_watch, primary, descriptor_attribute="descriptor")
                    except BaseException as _map_primary:
                        # The map remains installed until this literal numeric fallback drains it.
                        _raw_records = parents_by_watch
                        while _raw_records:
                            try:
                                _raw_owner = _raw_records.popitem()[1]
                            except BaseException:
                                _raw_owner = dict.popitem(_raw_records)[1]
                            _raw_fd = _raw_owner.descriptor
                            _raw_owner.descriptor = -1
                            if _raw_fd is not None and _raw_fd >= 0:
                                try:
                                    os.close(_raw_fd)
                                except BaseException:
                                    _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
                finally:
                    closing, watch_descriptor = watch_descriptor, -1
                    _close_descriptors(closing, primary=primary)
            raise

    def descriptor(self, label: str) -> int:
        return self._records[label].descriptor

    def read(self, label: str) -> bytes:
        return _read_descriptor(self.descriptor(label))

    @property
    def hashes(self) -> dict[str, str]:
        return {
            label: record.initial_sha256
            for label, record in sorted(self._records.items())
        }

    @property
    def evidence(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "basenames": {
                label: record.name for label, record in sorted(self._records.items())
            },
            "coalesced_parent_watch_count": len(self._parents_by_watch),
            "parent_fields_excluding_time": [
                "dev", "ino", "type", "mode", "uid", "gid", "nlink", "size"
            ],
            "policy": _RUNTIME_INPUT_POLICY,
            "schema": _RUNTIME_INPUT_SCHEMA,
            "persistent_parent_listing": "exact",
        }
        if self._stop_projection_label is not None:
            record = self._records[self._stop_projection_label]
            result["stop_projection"] = (
                self._stop_transition_evidence
                if self._stop_transition_evidence is not None
                else {
                    "allowed_removed_names": list(_STOP_ENDPOINT_NAMES),
                    "endpoint_metadata": {
                        name: _runtime_stat_evidence(value)
                        for name, value in sorted(self._stop_endpoint_initial.items())
                    },
                    "pre_listing": list(record.parent.initial_names),
                    "state": "pre-stop",
                }
            )
        return result

    def _initialize_stop_projection(self, label: str) -> None:
        record = self._records[label]
        if record.name != "config.json":
            raise RuntimeError("stop endpoint baseline target is not config.json")
        parent = record.parent
        if set(parent.initial_names) != set(_STOP_CONFIG_ENTRY_SCHEMA):
            raise RuntimeError("stop endpoint baseline listing is not exact")
        statuses: dict[str, os.stat_result] = {}
        for name, (expected_type, expected_mode) in _STOP_CONFIG_ENTRY_SCHEMA.items():
            value = os.stat(
                name, dir_fd=parent.descriptor, follow_symlinks=False
            )
            if (
                stat.S_IFMT(value.st_mode) != expected_type
                or stat.S_IMODE(value.st_mode) != expected_mode
                or value.st_uid != os.geteuid()
                or value.st_gid != os.getegid()
            ):
                raise RuntimeError(
                    f"stop endpoint baseline metadata is not exact: {name}"
                )
            if name in _STOP_ENDPOINT_NAMES and (
                value.st_nlink != 1 or value.st_size != 0
            ):
                raise RuntimeError(
                    f"stop endpoint baseline metadata is not exact: {name}"
                )
            statuses[name] = value
        if _stat_identity(statuses["config.json"]) != _stat_identity(
            record.initial_status
        ):
            raise RuntimeError("stop endpoint baseline config identity differs")
        self._stop_projection_label = label
        self._stop_endpoint_initial = {
            name: statuses[name] for name in _STOP_ENDPOINT_NAMES
        }

    def _initialize_reserved_lifecycle(self, label: str, name: str) -> None:
        """Bind the one Podman lifecycle basename sharing containerenv's parent."""
        record = self._records[label]
        parent = record.parent
        encoded = os.fsencode(name)
        if encoded in parent.labels_by_name:
            raise RuntimeError("reserved lifecycle name aliases a runtime input")
        descriptor = -1
        try:
            try:
                named = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                named = None
            if named is None:
                self._reserved_lifecycle = {
                    "label": label, "name": name, "parent": parent,
                    "initial_present": False, "current_present": False,
                    "status": None, "descriptor": None, "sha256": None,
                    "start_state": "pending", "stop_state": "pending",
                    "failed": False,
                }
                return
            if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
                raise RuntimeError("reserved lifecycle target is not an exact regular file")
            descriptor = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent.descriptor,
            )
            opened = os.fstat(descriptor)
            if _stat_identity(named) != _stat_identity(opened):
                raise RuntimeError("reserved lifecycle target changed while binding")
            self._reserved_lifecycle = {
                "label": label, "name": name, "parent": parent,
                "initial_present": True, "current_present": True,
                "status": opened, "descriptor": descriptor,
                "sha256": _hash_descriptor(descriptor),
                "start_state": "pending", "stop_state": "pending",
                "failed": False,
            }
            descriptor = -1
        finally:
            if descriptor >= 0:
                _release_primary = sys.exception()
                try:
                    os.close(descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

    def _latch_reserved_failure(self, phase: str) -> None:
        """Make a rejected lifecycle proof cleanup-only, never retryable."""
        reserved = self._reserved_lifecycle
        if reserved is None:
            return
        reserved["failed"] = True
        if phase == "start":
            reserved["start_state"] = "failed"
            if reserved.get("stop_state") == "active":
                reserved["stop_state"] = "failed"
        elif phase == "stop":
            reserved["stop_state"] = "failed"
            if reserved.get("start_state") == "active":
                reserved["start_state"] = "failed"
        else:
            raise ValueError("reserved lifecycle failure phase is invalid")

    def _latch_primary(self, phase: str | None, primary: BaseException) -> None:
        # This independent marker is the only required recovery publication;
        # phase selection and dictionary bookkeeping are best effort only.
        self._terminal_proof_failed = True
        try:
            if phase is None:
                reserved = self._reserved_lifecycle
                phase = "stop" if reserved is not None and reserved.get("start_state") == "complete" else "start"
            self._latch_reserved_failure(phase)
        except BaseException:
            _add_cleanup_note(primary, "additional reserved lifecycle terminal latch failed")

    def begin_start_transition(self) -> None:
        try:
            if self._terminal_proof_failed:
                raise RuntimeError("reserved lifecycle proof is terminally failed")
            return self._begin_start_transition()
        except BaseException as primary:
            self._latch_primary("start", primary)
            raise

    def _begin_start_transition(self) -> None:
        reserved = getattr(self, "_reserved_lifecycle", None)
        if reserved is None:
            return
        if self._terminal_proof_failed or reserved["failed"]:
            raise RuntimeError("reserved lifecycle proof is terminally failed")
        if (
            reserved["start_state"] != "pending"
            or self._start_transition_before is not None
            or self._start_transition_evidence is not None
        ):
            raise RuntimeError("reserved lifecycle start transition is not available")
        self.verify_coherent()
        parent = reserved["parent"]
        if self._collect_events():
            raise RuntimeError("reserved lifecycle start did not begin from a clean watch")
        self._start_transition_before = (tuple(parent.initial_names), os.fstat(parent.descriptor))
        reserved["start_state"] = "active"

    def complete_start_transition(self) -> dict[str, Any]:
        try:
            if self._terminal_proof_failed:
                raise RuntimeError("reserved lifecycle proof is terminally failed")
            return self._complete_start_transition()
        except BaseException as primary:
            self._latch_primary("start", primary)
            raise

    def _complete_start_transition(self) -> dict[str, Any]:
        reserved = self._reserved_lifecycle
        if reserved is None:
            return {"state": "not-configured"}
        if self._terminal_proof_failed or reserved["failed"]:
            raise RuntimeError("reserved lifecycle proof is terminally failed")
        if self._start_transition_before is None or reserved["start_state"] != "active":
            raise RuntimeError("reserved lifecycle start transition was not started")
        parent = reserved["parent"]
        name = reserved["name"]
        before_names, before_parent = self._start_transition_before
        events = self._collect_events()
        try:
            initially_present = reserved["initial_present"]
            if initially_present:
                if events:
                    raise RuntimeError("reserved lifecycle start events are not exact")
                self._verify_reserved_lifecycle(require_present=True)
                expected_names = before_names
            else:
                if not events or any(
                    event.watch != parent.watch_number or event.name != os.fsencode(name)
                    or event.cookie != 0 or event.mask & _IN_ISDIR
                    or event.mask not in {_IN_CREATE, _IN_MODIFY, _IN_ATTRIB, _IN_CLOSE_WRITE}
                    for event in events
                ):
                    raise RuntimeError("reserved lifecycle start events are not exact")
                masks = [event.mask for event in events]
                middle = masks[1:-1]
                if (
                    masks[0] != _IN_CREATE or masks[-1] != _IN_CLOSE_WRITE
                    or masks.count(_IN_CREATE) != 1 or masks.count(_IN_CLOSE_WRITE) != 1
                    or len(middle) > _RESERVED_PID_MAX_MIDDLE_EVENTS
                    or any(mask not in {_IN_MODIFY, _IN_ATTRIB} for mask in middle)
                ):
                    raise RuntimeError("reserved lifecycle start events are not exact")
                descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.descriptor)
                try:
                    status = os.fstat(descriptor)
                    named = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
                    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or _stat_identity(status) != _stat_identity(named):
                        raise RuntimeError("reserved lifecycle created target is unsafe")
                    digest = _hash_descriptor(descriptor)
                    try:
                        # A1: the native map and local custody sentinel change
                        # as one guarded transfer, with matching rollback.
                        reserved["descriptor"] = descriptor
                        reserved["status"] = status
                        reserved["sha256"] = digest
                        descriptor = -1
                    except BaseException:
                        if reserved.get("descriptor") == descriptor:
                            dict.__setitem__(reserved, "descriptor", None)
                        raise
                finally:
                    if descriptor >= 0:
                        _release_primary = sys.exception()
                        try:
                            os.close(descriptor)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional reserved lifecycle descriptor cleanup failed")
                reserved["current_present"] = True
                expected_names = tuple(sorted((*before_names, name)))
            self._verify_snapshot(
                expected_parent_names={parent.watch_number: expected_names},
                parent_size_transition=frozenset({parent.watch_number}),
            )
            if self._collect_events():
                raise RuntimeError("reserved lifecycle start had late filesystem events")
            after_parent = os.fstat(parent.descriptor)
            parent.initial_names, parent.initial_status = expected_names, after_parent
            evidence = {
                "initial_present": initially_present,
                "current_present": True,
                "limits": {"max_event_bytes": _RUNTIME_MAX_EVENT_BYTES, "max_events": _RUNTIME_MAX_EVENTS, "max_middle_events": _RESERVED_PID_MAX_MIDDLE_EVENTS},
                "target_before": _runtime_stat_evidence(reserved["status"]) if initially_present else None,
                "target_after": _runtime_stat_evidence(reserved["status"]),
                "pre_listing": list(before_names), "post_listing": list(expected_names),
                "pre_parent_metadata": _runtime_stat_evidence(before_parent),
                "post_parent_metadata": _runtime_stat_evidence(after_parent),
                "event_multiset": _runtime_event_multiset(events),
                "observed_events": _runtime_event_evidence(events),
                "state": "post-start",
            }
            self._start_transition_before = None
            self._start_transition_evidence = evidence
            reserved["start_state"] = "complete"
            return evidence
        finally:
            pass

    def _collect_events(self) -> list[_RuntimeWatchEvent]:
        events: list[_RuntimeWatchEvent] = []
        total_bytes = 0
        for chunk in _read_inotify_chunks(self._watch_descriptor):
            total_bytes += len(chunk)
            if total_bytes > _RUNTIME_MAX_EVENT_BYTES:
                raise RuntimeError("runtime input watch event byte limit exceeded")
            offset = 0
            while offset < len(chunk):
                if len(chunk) - offset < _INOTIFY_HEADER.size:
                    raise RuntimeError("malformed runtime input watch event")
                watch, mask, cookie, name_length = _INOTIFY_HEADER.unpack_from(
                    chunk, offset
                )
                offset += _INOTIFY_HEADER.size
                if name_length > len(chunk) - offset:
                    raise RuntimeError("malformed runtime input watch event")
                encoded = chunk[offset : offset + name_length]
                offset += name_length
                if name_length:
                    if b"\0" not in encoded:
                        raise RuntimeError("malformed runtime input watch event")
                    name, padding = encoded.split(b"\0", 1)
                    if padding.strip(b"\0"):
                        raise RuntimeError("malformed runtime input watch event")
                else:
                    name = b""
                if mask & _IN_Q_OVERFLOW:
                    raise RuntimeError("runtime input watch overflow")
                parent = self._parents_by_watch.get(watch)
                if parent is None:
                    raise RuntimeError("runtime input watch was lost")
                if mask & (_IN_IGNORED | _IN_DELETE_SELF | _IN_MOVE_SELF | _IN_UNMOUNT):
                    raise RuntimeError("runtime input watch was lost")
                if mask & ~(_RUNTIME_WATCH_MASK | _IN_ISDIR):
                    raise RuntimeError("malformed runtime input watch event")
                if not (mask & _RUNTIME_WATCH_MASK):
                    raise RuntimeError("malformed runtime input watch event")
                events.append(_RuntimeWatchEvent(watch, mask, cookie, name))
                if len(events) > _RUNTIME_MAX_EVENTS:
                    raise RuntimeError("runtime input watch event count limit exceeded")
        return events

    def _drain_events(self) -> bool:
        events = self._collect_events()
        for event in events:
            parent = self._parents_by_watch[event.watch]
            reserved = self._reserved_lifecycle
            if (
                reserved is not None
                and parent is reserved["parent"]
                and event.name == os.fsencode(reserved["name"])
                and (reserved["start_state"] != "active" and reserved["stop_state"] != "active")
            ):
                self._latch_reserved_failure(
                    "start" if reserved["start_state"] != "complete" else "stop"
                )
                raise RuntimeError("reserved lifecycle event occurred outside a transition window")
            label = parent.labels_by_name.get(event.name)
            if label is not None and event.mask & _RUNTIME_WATCH_MASK:
                raise RuntimeError(f"runtime input name changed: {label}")
            if (
                self._stop_projection_label is not None
                and self._stop_transition_before is None
                and event.name in {os.fsencode(name) for name in _STOP_ENDPOINT_NAMES}
                and parent is self._records[self._stop_projection_label].parent
            ):
                raise RuntimeError(
                    "runtime stop endpoint changed before stop: "
                    f"{os.fsdecode(event.name)}"
                )
            if os.fsdecode(event.name) in parent.initial_names:
                raise RuntimeError("runtime input baseline name changed")
            if not event.name:
                raise RuntimeError("runtime input parent metadata changed")
        return bool(events)

    def _verify_reserved_lifecycle(self, *, require_present: bool | None = None) -> None:
        """Verify the PID inode independently of the mutable directory name."""
        reserved = self._reserved_lifecycle
        if reserved is None:
            return
        parent = reserved["parent"]
        descriptor = reserved["descriptor"]
        status = reserved["status"]
        present = (
            reserved["current_present"] and reserved["stop_state"] != "active"
            if require_present is None else require_present
        )
        try:
            named = os.stat(reserved["name"], dir_fd=parent.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            named = None
        if not present:
            if descriptor is None and named is None:
                return
            if not isinstance(descriptor, int) or not isinstance(status, os.stat_result):
                raise RuntimeError("reserved lifecycle target custody is invalid")
            opened = os.fstat(descriptor)
            # unlink changes nlink and ctime; the inode's identity, mode,
            # ownership, size, mtime, and bytes remain authoritative.
            stable = lambda value: _stat_version(value)[:6] + _stat_version(value)[7:9]
            if named is not None or opened.st_nlink != 0 or stable(opened) != stable(status) or _hash_descriptor(descriptor) != reserved["sha256"]:
                raise RuntimeError("reserved lifecycle held target changed during unlink")
            return
        if not isinstance(descriptor, int) or not isinstance(status, os.stat_result):
            raise RuntimeError("reserved lifecycle target custody is invalid")
        if named is None:
            raise RuntimeError("reserved lifecycle target is absent")
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_version(opened) != _stat_version(status)
            or _stat_version(named) != _stat_version(status)
            or _stat_identity(named) != _stat_identity(opened)
            or _hash_descriptor(descriptor) != reserved["sha256"]
        ):
            raise RuntimeError("reserved lifecycle target changed")

    def _verify_snapshot(
        self,
        *,
        expected_parent_names: Mapping[int, tuple[str, ...]] | None = None,
        parent_size_transition: frozenset[int] = frozenset(),
    ) -> dict[str, str]:
        first = {
            label: _hash_descriptor(record.descriptor)
            for label, record in sorted(self._records.items())
        }
        second = {
            label: _hash_descriptor(record.descriptor)
            for label, record in sorted(self._records.items())
        }
        for label, record in sorted(self._records.items()):
            current = os.fstat(record.descriptor)
            try:
                named = os.stat(
                    record.name,
                    dir_fd=record.parent.descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise RuntimeError(
                    f"runtime input path identity changed: {label}"
                ) from error
            if _stat_identity(named) != _stat_identity(record.initial_status):
                raise RuntimeError(f"runtime input path identity changed: {label}")
            if (
                first[label] != second[label]
                or second[label] != record.initial_sha256
                or _stat_version(current) != _stat_version(record.initial_status)
                or _stat_version(named) != _stat_version(record.initial_status)
            ):
                raise RuntimeError(f"runtime input changed after binding: {label}")
        for parent in self._parents_by_watch.values():
            current = os.fstat(parent.descriptor)
            parent_metadata = (
                _runtime_parent_transition_metadata
                if parent.watch_number in parent_size_transition
                else _runtime_parent_metadata
            )
            if parent_metadata(current) != parent_metadata(parent.initial_status):
                raise RuntimeError("runtime input parent metadata changed")
            expected_names = (
                expected_parent_names.get(parent.watch_number, parent.initial_names)
                if expected_parent_names is not None
                else parent.initial_names
            )
            if tuple(sorted(os.listdir(parent.descriptor))) != expected_names:
                raise RuntimeError("runtime input parent listing changed")
            reopened, reopened_status = _open_parent_directory(
                next(
                    record.path
                    for record in self._records.values()
                    if record.parent is parent
                )
            )
            try:
                if _stat_identity(reopened_status) != _stat_identity(
                    parent.initial_status
                ):
                    raise RuntimeError("runtime input parent path identity changed")
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(reopened)
                except BaseException:
                    if _release_primary is None:
                        raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        self._verify_reserved_lifecycle()
        return second

    def begin_stop_transition(self, label: str) -> None:
        try:
            if self._terminal_proof_failed:
                raise RuntimeError("reserved lifecycle proof is terminally failed")
            return self._begin_stop_transition(label)
        except BaseException as primary:
            self._latch_primary("stop", primary)
            raise

    def _begin_stop_transition(self, label: str) -> None:
        reserved = self._reserved_lifecycle
        if label != self._stop_projection_label:
            raise RuntimeError("stop transition label is not configured")
        if self._stop_transition_before is not None:
            raise RuntimeError("stop transition was already started")
        if self._stop_transition_evidence is not None:
            raise RuntimeError("stop transition was already completed")
        if reserved is not None and (
            reserved["failed"] or reserved["start_state"] != "complete" or reserved["stop_state"] != "pending"
        ):
            raise RuntimeError("reserved lifecycle stop requires a completed start")
        self.verify_coherent()
        record = self._records[label]
        parent = record.parent
        before: dict[str, os.stat_result] = {}
        for name in parent.initial_names:
            before[name] = os.stat(
                name, dir_fd=parent.descriptor, follow_symlinks=False
            )
        for name, initial in self._stop_endpoint_initial.items():
            if _stat_version(before[name]) != _stat_version(initial):
                raise RuntimeError(
                    f"stop endpoint changed before stop: {name}"
                )
        if self._collect_events():
            raise RuntimeError("stop transition did not begin from a clean watch")
        self._stop_transition_before = before
        self._stop_transition_parent_before = os.fstat(parent.descriptor)
        if reserved is not None:
            self._verify_reserved_lifecycle(require_present=True)
            reserved["stop_before"] = os.fstat(reserved["descriptor"])
            reserved["stop_parent_before"] = os.fstat(reserved["parent"].descriptor)
            reserved["stop_state"] = "active"

    def complete_stop_transition(self, label: str) -> dict[str, Any]:
        try:
            if self._terminal_proof_failed:
                raise RuntimeError("reserved lifecycle proof is terminally failed")
            return self._complete_stop_transition(label)
        except BaseException as primary:
            self._latch_primary("stop", primary)
            raise

    def _complete_stop_transition(self, label: str) -> dict[str, Any]:
        reserved = self._reserved_lifecycle
        if self._terminal_proof_failed or reserved is not None and reserved["failed"]:
            raise RuntimeError("reserved lifecycle proof is terminally failed")
        if label != self._stop_projection_label:
            raise RuntimeError("stop transition label is not configured")
        if self._stop_transition_before is None:
            raise RuntimeError("stop transition was not started")
        record = self._records[label]
        parent = record.parent
        events = self._collect_events()
        by_name: dict[bytes, list[int]] = {
            os.fsencode(name): [] for name in _STOP_ENDPOINT_NAMES
        }
        if reserved is not None and (
            reserved["failed"] or reserved["start_state"] != "complete" or reserved["stop_state"] != "active"
        ):
            raise RuntimeError("reserved lifecycle stop requires a completed start")
        reserved_events: list[_RuntimeWatchEvent] = []
        invalid_event = False
        for event in events:
            if (
                reserved is not None
                and event.watch == reserved["parent"].watch_number
                and event.name == os.fsencode(reserved["name"])
            ):
                reserved_events.append(event)
                continue
            if (
                event.watch != parent.watch_number
                or event.cookie != 0
                or event.mask & _IN_ISDIR
                or event.name not in by_name
            ):
                invalid_event = True
                continue
            by_name[event.name].append(event.mask)
        expected_by_name = {
            b"attach": [_IN_DELETE],
            b"ctl": [_IN_CLOSE_WRITE, _IN_DELETE],
            b"winsz": [_IN_CLOSE_WRITE, _IN_DELETE],
        }
        expected_reserved = [] if reserved is None else [_IN_DELETE]
        if (
            invalid_event
            or by_name != expected_by_name
            or [event.mask for event in reserved_events] != expected_reserved
            or any(event.cookie != 0 or event.mask != _IN_DELETE for event in reserved_events)
        ):
            for event in events:
                target_label = self._parents_by_watch[event.watch].labels_by_name.get(
                    event.name
                ) if event.watch in self._parents_by_watch else None
                if target_label is not None:
                    raise RuntimeError(
                        f"runtime input name changed: {target_label}"
                    )
            raise RuntimeError("stop endpoint deletion events are not exact")

        pre_listing = tuple(parent.initial_names)
        post_listing = tuple(
            name for name in pre_listing if name not in _STOP_ENDPOINT_NAMES
        )
        expected_names = {parent.watch_number: post_listing}
        transition_watches = {parent.watch_number}
        reserved_before: os.stat_result | None = None
        reserved_post_listing: tuple[str, ...] | None = None
        if reserved is not None:
            reserved_parent = reserved["parent"]
            if not reserved["current_present"] or reserved["descriptor"] is None or reserved["status"] is None:
                raise RuntimeError("reserved lifecycle target was absent before stop")
            reserved_before = reserved.get("stop_before")
            if not isinstance(reserved_before, os.stat_result):
                raise RuntimeError("reserved lifecycle stop baseline is absent")
            self._verify_reserved_lifecycle(require_present=False)
            reserved_post_listing = tuple(
                name for name in reserved_parent.initial_names if name != reserved["name"]
            )
            expected_names[reserved_parent.watch_number] = reserved_post_listing
            transition_watches.add(reserved_parent.watch_number)
        self._verify_snapshot(
            expected_parent_names=expected_names,
            parent_size_transition=frozenset(transition_watches),
        )
        before = self._stop_transition_before
        parent_before = self._stop_transition_parent_before
        if parent_before is None:
            raise RuntimeError("stop transition parent baseline is absent")
        survivor_before: dict[str, os.stat_result] = {
            name: value
            for name, value in before.items()
            if name not in _STOP_ENDPOINT_NAMES
        }
        survivor_after: dict[str, os.stat_result] = {}
        for name, initial in survivor_before.items():
            value = os.stat(
                name, dir_fd=parent.descriptor, follow_symlinks=False
            )
            if _stat_version(value) != _stat_version(initial):
                raise RuntimeError(
                    f"stop transition survivor metadata changed: {name}"
                )
            survivor_after[name] = value
        if self._collect_events():
            raise RuntimeError("stop transition had late filesystem events")

        post_parent_status = os.fstat(parent.descriptor)
        evidence = {
            "allowed_removed_names": list(_STOP_ENDPOINT_NAMES),
            "endpoint_metadata": {
                name: _runtime_stat_evidence(value)
                for name, value in sorted(self._stop_endpoint_initial.items())
            },
            "event_multiset": [
                {
                    "cookie": cookie,
                    "count": count,
                    "mask": mask,
                    "name": os.fsdecode(name),
                    "watch": watch,
                }
                for (watch, mask, cookie, name), count in sorted(
                    Counter(
                        (event.watch, event.mask, event.cookie, event.name)
                        for event in events
                    ).items()
                )
            ],
            "observed_events": [
                {
                    "cookie": event.cookie,
                    "mask": event.mask,
                    "name": os.fsdecode(event.name),
                    "watch": event.watch,
                }
                for event in events
            ],
            "post_listing": list(post_listing),
            "post_parent_metadata": _runtime_stat_evidence(post_parent_status),
            "pre_listing": list(pre_listing),
            "pre_parent_metadata": _runtime_stat_evidence(parent_before),
            "state": "post-stop",
            "survivor_metadata": {
                name: {
                    "after": _runtime_stat_evidence(survivor_after[name]),
                    "before": _runtime_stat_evidence(value),
                }
                for name, value in sorted(survivor_before.items())
            },
        }
        if reserved is not None:
            reserved_parent = reserved["parent"]
            assert reserved_before is not None and reserved_post_listing is not None
            reserved_after = os.fstat(reserved["descriptor"])
            if (
                _stat_version(reserved_after)[:6] + _stat_version(reserved_after)[7:8]
                != _stat_version(reserved_before)[:6] + _stat_version(reserved_before)[7:8]
                or reserved_after.st_nlink != 0
            ):
                raise RuntimeError("reserved lifecycle held target changed during unlink")
            evidence["reserved_lifecycle"] = {
                "initial": _runtime_stat_evidence(reserved["status"]),
                "start": self._start_transition_evidence,
                "stop": {
                    "current_present": False,
                    "limits": {"max_event_bytes": _RUNTIME_MAX_EVENT_BYTES, "max_events": _RUNTIME_MAX_EVENTS, "max_middle_events": _RESERVED_PID_MAX_MIDDLE_EVENTS},
                    "target_before": _runtime_stat_evidence(reserved_before),
                    "target_after": _runtime_stat_evidence(reserved_after),
                    "event_multiset": _runtime_event_multiset(reserved_events),
                    "observed_events": _runtime_event_evidence(reserved_events),
                    "pre_listing": list(reserved_parent.initial_names),
                    "post_listing": list(reserved_post_listing),
                    "pre_parent_metadata": _runtime_stat_evidence(reserved["stop_parent_before"]),
                    "post_parent_metadata": _runtime_stat_evidence(os.fstat(reserved_parent.descriptor)),
                    "state": "post-stop",
                },
            }
            reserved_parent.initial_names = reserved_post_listing
            reserved_parent.initial_status = os.fstat(reserved_parent.descriptor)
            reserved["current_present"] = False
            reserved["stop_state"] = "complete"
        parent.initial_names = post_listing
        parent.initial_status = post_parent_status
        self._stop_transition_before = None
        self._stop_transition_parent_before = None
        self._stop_transition_evidence = evidence
        return evidence

    def verify_coherent(self) -> dict[str, str]:
        try:
            if self._terminal_proof_failed:
                raise RuntimeError("reserved lifecycle proof is terminally failed")
            return self._verify_coherent()
        except BaseException as primary:
            self._latch_primary(None, primary)
            raise

    def _verify_coherent(self) -> dict[str, str]:
        if self._closed:
            raise RuntimeError("runtime inputs are closed")
        reserved = self._reserved_lifecycle
        if reserved is not None:
            if reserved["failed"]:
                raise RuntimeError("reserved lifecycle proof is terminally failed")
            if reserved["start_state"] == "active":
                self._latch_reserved_failure("start")
                raise RuntimeError("reserved lifecycle start transition is active")
            if reserved["stop_state"] == "active":
                self._latch_reserved_failure("stop")
                raise RuntimeError("reserved lifecycle stop transition is active")
        # Re-run the complete snapshot if unrelated runtime events raced it.
        # A clean final nonblocking drain is the observation boundary.
        for _attempt in range(8):
            self._drain_events()
            result = self._verify_snapshot()
            if not self._drain_events():
                return result
        raise RuntimeError("runtime input parent did not quiesce")

    def close(self) -> None:
        if self._closed:
            return
        reserved = getattr(self, "_reserved_lifecycle", None)
        failure = None
        if reserved is not None and isinstance(reserved.get("descriptor"), int):
            descriptor = reserved["descriptor"]
            reserved["descriptor"] = None
            try:
                os.close(descriptor)
            except BaseException as error:
                failure = error
        records = self._records
        parents = self._parents_by_watch
        watch = self._watch_descriptor
        self._watch_descriptor = -1
        try:
            try:
                _close_resource_mapping(records, descriptor_attribute="descriptor")
            except BaseException as _map_primary:
                # The map remains installed until this literal numeric fallback drains it.
                _raw_records = records
                while _raw_records:
                    try:
                        _raw_owner = _raw_records.popitem()[1]
                    except BaseException:
                        _raw_owner = dict.popitem(_raw_records)[1]
                    _raw_fd = _raw_owner.descriptor
                    _raw_owner.descriptor = -1
                    if _raw_fd is not None and _raw_fd >= 0:
                        try:
                            os.close(_raw_fd)
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                raise
        except BaseException as error:
            if failure is None:
                failure = error
        finally:
            try:
                try:
                    _close_resource_mapping(parents, descriptor_attribute="descriptor")
                except BaseException as _map_primary:
                    # The map remains installed until this literal numeric fallback drains it.
                    _raw_records = parents
                    while _raw_records:
                        try:
                            _raw_owner = _raw_records.popitem()[1]
                        except BaseException:
                            _raw_owner = dict.popitem(_raw_records)[1]
                        _raw_fd = _raw_owner.descriptor
                        _raw_owner.descriptor = -1
                        if _raw_fd is not None and _raw_fd >= 0:
                            try:
                                os.close(_raw_fd)
                            except BaseException:
                                _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException as error:
                if failure is None:
                    failure = error
            finally:
                try:
                    _numeric_failure = None
                    _numeric_fd = watch
                    if _numeric_fd >= 0:
                        try:
                            os.close(_numeric_fd)
                        except BaseException as _numeric_error:
                            if _numeric_failure is None:
                                _numeric_failure = _numeric_error
                    if _numeric_failure is not None:
                        raise RuntimeError("bound descriptor release failed") from _numeric_failure
                except BaseException as error:
                    if failure is None:
                        failure = error
                self._closed = not records and not parents
        if failure is not None:
            raise failure

    def __enter__(self) -> "WatchedRuntimeBindings":
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        _release_primary = exception
        try:
            self.close()
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

EXPECTED_MASKED_PATHS = (
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/sys/devices/virtual/powercap",
    "/sys/firmware",
    "/sys/fs/selinux",
    "/proc/interrupts",
    "/sys/devices/virtual/powercap",
)
EXPECTED_READONLY_PATHS = (
    "/proc/asound",
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
)

def controlled_environment(
    ambient: Mapping[str, str],
    *,
    home: Path,
    xdg_runtime: Path,
    temporary: Path,
) -> dict[str, str]:
    # `ambient` is intentionally not copied.  Its argument makes the discard
    # explicit at the call site and supports hostile-environment regressions.
    del ambient
    return {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": os.fspath(temporary),
        "TZ": "UTC",
        "XDG_RUNTIME_DIR": os.fspath(xdg_runtime),
    }


_PODMAN_CONTAINERS_CONF = (
    "[containers]\n"
    "default_capabilities=[]\n"
    "default_sysctls=[]\n"
    "env=[]\n"
    "volumes=[]\n"
    "[engine]\n"
    "conmon_path=[\"/usr/bin/conmon\"]\n"
    "events_logger=\"file\"\n"
    "helper_binaries_dir=[\"/usr/lib/podman\"]\n"
    "hooks_dir=[]\n"
    "runtime=\"/usr/bin/crun\"\n"
).encode("ascii")
_PODMAN_STORAGE_CONF = b"[storage]\ndriver=\"vfs\"\n"
_FULL_SEALS = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)


class SealedPodmanPolicy:
    """The sole immutable Podman containers/storage configuration authority."""

    def __init__(self, containers: Any, storage: Any) -> None:
        self._containers = containers
        self._storage = storage
        self._closed = False
        self.verify()

    @classmethod
    def create(cls) -> "SealedPodmanPolicy":
        containers = seal_public_bytes(
            _PODMAN_CONTAINERS_CONF, "podman-containers-conf"
        )
        resources = None
        try:
            resources = [containers]
            storage = seal_public_bytes(
                _PODMAN_STORAGE_CONF, "podman-storage-conf"
            )
            try:
                resources.append(storage)
            except BaseException as primary:
                _release_primary = primary
                closing, storage.fd = storage.fd, -1
                try:
                    if closing >= 0:
                        os.close(closing)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            return cls(containers, storage)
        except BaseException as primary:
            if resources is None:
                closing, containers.fd = containers.fd, -1
                try:
                    if closing >= 0:
                        os.close(closing)
                except BaseException:
                    _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            else:
                while resources:
                    resource = resources[-1]
                    closing, resource.fd = resource.fd, -1
                    try:
                        if closing >= 0:
                            os.close(closing)
                    except BaseException:
                        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
                    try:
                        resources.pop()
                    except BaseException:
                        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
                        list.pop(resources)
            raise

    @property
    def descriptors(self) -> tuple[int, int]:
        return self._containers.fd, self._storage.fd

    @property
    def hashes(self) -> dict[str, str]:
        return {
            "containers_conf_sha256": self._containers.sha256,
            "storage_conf_sha256": self._storage.sha256,
        }

    def containers_bytes(self) -> bytes:
        return _read_descriptor(self._containers.fd)

    def verify(self) -> None:
        if self._closed:
            raise RuntimeError("sealed Podman policy is closed")
        for description, capsule, expected in (
            ("containers", self._containers, _PODMAN_CONTAINERS_CONF),
            ("storage", self._storage, _PODMAN_STORAGE_CONF),
        ):
            status = os.fstat(capsule.fd)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_nlink != 0
                or fcntl.fcntl(capsule.fd, fcntl.F_GET_SEALS) & _FULL_SEALS
                != _FULL_SEALS
                or _read_descriptor(capsule.fd) != expected
                or _hash_descriptor(capsule.fd) != capsule.sha256
            ):
                raise RuntimeError(f"sealed Podman {description} policy changed")

    @contextmanager
    def child_configuration(
        self,
        environment: Mapping[str, str],
        pass_fds: Iterable[int],
    ) -> Iterable[tuple[dict[str, str], tuple[int, ...]]]:
        self.verify()
        forbidden = {
            "CONTAINERS_CONF",
            "CONTAINERS_CONF_OVERRIDE",
            "CONTAINERS_STORAGE_CONF",
            "XDG_CONFIG_HOME",
        }
        if forbidden & set(environment):
            raise RuntimeError("ambient Podman configuration input is forbidden")
        duplicates: list[int] = []
        try:
            for descriptor in self.descriptors:
                duplicate = os.dup(descriptor)
                try:
                    duplicates.append(duplicate)
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(duplicate)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
            child_environment = dict(environment)
            child_environment["CONTAINERS_CONF"] = (
                f"/proc/self/fd/{duplicates[0]}"
            )
            child_environment["CONTAINERS_STORAGE_CONF"] = (
                f"/proc/self/fd/{duplicates[1]}"
            )
            inherited = tuple(sorted({*pass_fds, *duplicates}))
            yield child_environment, inherited
        finally:
            primary = sys.exception()
            failure = None
            try:
                _close_descriptor_sequence(duplicates)
            except BaseException as error:
                failure = error
            finally:
                try:
                    self.verify()
                except BaseException as error:
                    if failure is None:
                        failure = error
            if failure is not None:
                if primary is None:
                    raise RuntimeError("Podman child policy cleanup failed") from failure
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")

    def close(self) -> None:
        if self._closed:
            return
        containers = self._containers
        storage = self._storage
        self._containers = self._storage = None
        self._closed = True
        failure = None
        closing, containers.fd = containers.fd, -1
        try:
            if closing >= 0:
                os.close(closing)
        except BaseException as error:
            failure = error
        finally:
            closing, storage.fd = storage.fd, -1
            try:
                if closing >= 0:
                    os.close(closing)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise RuntimeError("Podman policy cleanup failed") from failure


def _inherited_podman_policy_descriptors(
    environment: Mapping[str, str] | None = None,
) -> tuple[int, int]:
    """Validate sealed policy descriptors named by a nested Podman worker."""
    source = os.environ if environment is None else environment
    values: list[int] = []
    for name, expected in (
        ("CONTAINERS_CONF", _PODMAN_CONTAINERS_CONF),
        ("CONTAINERS_STORAGE_CONF", _PODMAN_STORAGE_CONF),
    ):
        match = re.fullmatch(r"/proc/self/fd/([0-9]+)", source.get(name, ""))
        if match is None:
            raise RuntimeError("nested Podman policy descriptor is absent")
        descriptor = int(match.group(1))
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 0
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & _FULL_SEALS
            != _FULL_SEALS
            or _read_descriptor(descriptor) != expected
        ):
            raise RuntimeError("nested Podman policy descriptor is not exact")
        values.append(descriptor)
    if values[0] == values[1]:
        raise RuntimeError("nested Podman policy descriptor roles collide")
    return values[0], values[1]
def podman_create_arguments(
    *,
    image: str,
    container: str,
    scratch: Path,
) -> tuple[str, ...]:
    """Return the exact closed create contract; no input/key descriptor is global."""
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("container image ID must be digest-qualified")
    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", container) is None:
        raise ValueError("container name is unsafe")
    scratch_path = Path(os.path.abspath(scratch))
    if not scratch_path.is_absolute():
        raise ValueError("container paths must be absolute")
    return (
        "create", "--name", container,
        "--network", "none",
        "--read-only", "--read-only-tmpfs=false",
        "--http-proxy=false", "--image-volume", "ignore",
        "--unsetenv-all", "--no-hostname", "--no-hosts",
        "--cap-drop", "all",
        "--security-opt", "no-new-privileges",
        "--security-opt", "label=disable",
        "--ipc", "private", "--pid", "private", "--uts", "private",
        "--pids-limit", "8192",
        "--env", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
        "--env", "TZ=UTC", "--env", "SOURCE_DATE_EPOCH=1787899659",
        "--env", "HOME=/tmp", "--env", "HOSTNAME=openmythos-builder",
        "--tmpfs", "/tmp:rw,nosuid,nodev,exec,mode=1777",
        "--volume", f"{scratch_path}:/tmp/work:rw,rbind,nosuid,nodev,rprivate",
        "--entrypoint", "/usr/bin/sleep",
        image, "infinity",
    )
class ContainerLifecycleError(RuntimeError):
    pass


class LifecycleState(str, Enum):
    NEW = "NEW"
    CREATED = "CREATED"
    CREATED_INIT = "CREATED_INIT"
    CONFIG_AUDITED = "CONFIG_AUDITED"
    CREATED_INIT_AUDITED = "CREATED_INIT_AUDITED"
    STARTED_UNATTESTED = "STARTED_UNATTESTED"
    LIVE_ATTESTED = "LIVE_ATTESTED"
    AUTHORIZED_ROOTFS_AUDITED = "AUTHORIZED_ROOTFS_AUDITED"
    WORK_AUTHORIZED = "WORK_AUTHORIZED"
    STOPPED = "STOPPED"
    REMOVED = "REMOVED"


@dataclass(frozen=True)
class RootfsPhaseEvidence:
    phase: str
    record: Mapping[str, Any]


@dataclass(frozen=True)
class ContainerLifecycleEvidence:
    before: RootfsPhaseEvidence
    authorized: RootfsPhaseEvidence
    after: RootfsPhaseEvidence
    transitions: tuple[str, ...]
    semantic_equal: bool
    raw_equal: bool

    def __iter__(self):
        # Compatibility for the existing orchestration while its evidence
        # writer migrates to the typed three-phase result.
        yield dict(self.before.record)
        yield dict(self.after.record)
def create_rootfs_audit_record(
    expected: Any,
    actual: Any,
    *,
    locked_non_root_entry_count: int | None = None,
    runtime_projection_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """Commit to one exact independently-derived/observed rootfs audit."""
    from tools.gate01.oci_rootfs import assert_semantic_equal

    assert_semantic_equal(expected, actual)
    if actual.before_anchor != actual.after_anchor:
        raise ContainerLifecycleError("rootfs anchor changed inside complete audit")
    if "/" not in actual.entries:
        raise ContainerLifecycleError("rootfs semantic manifest omits the root entry")
    projected_paths = tuple(sorted(runtime_projection_paths))
    locked_count = (
        len(actual.entries) - 1
        if locked_non_root_entry_count is None
        else locked_non_root_entry_count
    )
    if (
        len(projected_paths) != len(set(projected_paths))
        or any(path not in actual.entries for path in projected_paths)
        or len(actual.entries) - 1 != locked_count + len(projected_paths)
    ):
        raise ContainerLifecycleError("rootfs runtime projection count is not exact")
    executable_files: dict[str, dict[str, Any]] = {}
    for path, entry in sorted(expected.entries.items()):
        if entry.kind != "file" or not (entry.mode & 0o111):
            continue
        raw = actual.raw_entries[path]
        executable_files[path] = {
            "content_sha256": entry.content_sha256,
            "dev": raw.dev,
            "gid": entry.gid,
            "ino": raw.ino,
            "mode": entry.mode,
            "size": entry.size,
            "uid": entry.uid,
        }
    return {
        "executable_files": executable_files,
        "executable_files_sha256": _object_sha256(executable_files),
        "materialized_non_root_entry_count": len(actual.entries) - 1,
        "non_root_entry_count": locked_count,
        "raw_sha256": _object_sha256(actual.raw_entries),
        "root_anchor": _json_safe(actual.after_anchor),
        "root_entry": _json_safe(actual.entries["/"]),
        "runtime_projections": {
            path: _json_safe(actual.entries[path]) for path in projected_paths
        },
        "semantic_sha256": _object_sha256(actual.entries),
    }
def assert_rootfs_audit_records_equal(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> None:
    """Require the complete pre/post semantic and raw rootfs commitments."""
    required = {
        "semantic_sha256",
        "raw_sha256",
        "non_root_entry_count",
        "root_entry",
    }
    if not required <= set(before) or not required <= set(after):
        raise ContainerLifecycleError("rootfs audit record is incomplete")
    if dict(before) != dict(after):
        raise ContainerLifecycleError("rootfs audit changed across container execution")
def run_container_lifecycle(
    backend: Any,
    *,
    executions: Iterable[tuple[str, Mapping[int, int]]],
    allow_key_role: str | None,
) -> ContainerLifecycleEvidence:
    """Apply the audited create/start/exec/stop lifecycle to one backend.

    The backend is deliberately structural rather than subclass based so tests
    can inject a complete fake runtime and assert the exact event sequence.
    Cleanup is attempted even when a proof or execution step fails.
    """
    execution_plan = tuple((role, dict(descriptors)) for role, descriptors in executions)
    for role, descriptors in execution_plan:
        if BUILD_KEY_FD in descriptors and role != allow_key_role:
            raise ContainerLifecycleError(
                f"private key descriptor is forbidden for {role} execution"
            )
    created = False
    started = False
    primary_error: BaseException | None = None
    before: dict[str, Any] | None = None
    authorized: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    try:
        # remove() is state-aware and harmless before material exists. Take
        # cleanup ownership before create can partially succeed then raise.
        created = True
        backend.create()
        # Podman materializes the exact OCI runtime config only at `init`.
        # PID1 has not executed at this point, so the effective spec and entire
        # rootfs can still be audited before any image byte executes.
        backend.initialize()
        backend.audit_effective_spec()
        before = dict(backend.audit_rootfs("before"))
        backend.start()
        started = True
        backend.attest_live()
        authorized = dict(backend.audit_rootfs("authorized"))
        assert_rootfs_audit_records_equal(before, authorized)
        backend.authorize_work()
        for role, descriptors in execution_plan:
            backend.execute(role, descriptors)
        backend.stop_and_wait()
        started = False
        after = dict(backend.audit_rootfs("after"))
        assert_rootfs_audit_records_equal(before, after)
    except BaseException as error:
        primary_error = error
    cleanup_error: BaseException | None = None
    if started:
        try:
            backend.stop_and_wait()
        except BaseException as error:
            cleanup_error = error
            if primary_error is not None:
                _add_cleanup_note(primary_error, "additional container stop cleanup failed")
    if created:
        try:
            backend.remove()
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
            if primary_error is not None:
                _add_cleanup_note(primary_error, "additional container removal cleanup failed")
    if primary_error is not None:
        raise primary_error
    if cleanup_error is not None:
        raise ContainerLifecycleError("container lifecycle cleanup failed") from cleanup_error
    assert before is not None and authorized is not None and after is not None
    return ContainerLifecycleEvidence(
        before=RootfsPhaseEvidence("before", _json_safe(before)),
        authorized=RootfsPhaseEvidence("authorized", _json_safe(authorized)),
        after=RootfsPhaseEvidence("after", _json_safe(after)),
        transitions=(
            LifecycleState.CREATED.value,
            LifecycleState.CREATED_INIT.value,
            LifecycleState.CONFIG_AUDITED.value,
            LifecycleState.CREATED_INIT_AUDITED.value,
            LifecycleState.STARTED_UNATTESTED.value,
            LifecycleState.LIVE_ATTESTED.value,
            LifecycleState.AUTHORIZED_ROOTFS_AUDITED.value,
            LifecycleState.WORK_AUTHORIZED.value,
            LifecycleState.STOPPED.value,
            LifecycleState.REMOVED.value,
        ),
        semantic_equal=(
            before.get("semantic_sha256")
            == authorized.get("semantic_sha256")
            == after.get("semantic_sha256")
        ),
        raw_equal=(
            before.get("raw_sha256")
            == authorized.get("raw_sha256")
            == after.get("raw_sha256")
        ),
    )
def validate_live_process_record(record: Mapping[str, Any], *, expected_uid: int | None = None, expected_gid: int | None = None) -> None:
    """Validate the normalized, host-observed inert PID1 contract."""
    required = {
        "anonymous_executable_maps", "capabilities", "children", "cgroup",
        "cmdline", "cwd", "environment", "exe", "fds", "gid",
        "mapped_files", "mount_contract", "mount_graph", "mount_sha256",
        "namespaces", "network", "no_new_privileges", "nspid",
        "pid_identity", "scratch_empty", "seccomp", "threads", "top", "uid",
        "ownership_projection",
    }
    if not isinstance(record, Mapping) or set(record) != required:
        raise RuntimeError("live process record schema is not exact")
    def valid_ranges(values: Any) -> bool:
        if not isinstance(values, list) or not values:
            return False
        ranges: list[tuple[int, int]] = []
        for value in values:
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", value) is None:
                return False
            start, end = (int(item, 16) for item in value.split("-"))
            if start >= end or end > 2**64:
                return False
            ranges.append((start, end))
        return all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:]))
    expected_environment = sorted(
        (
            "HOME=/tmp", "HOSTNAME=openmythos-builder", "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "SOURCE_DATE_EPOCH=1787899659", "TZ=UTC",
        )
    )
    if record["cmdline"] != ["/usr/bin/sleep", "infinity"]:
        raise RuntimeError("live process command is not exact")
    if record["environment"] != expected_environment:
        raise RuntimeError("live process environment is not exact")
    exe = record["exe"]
    expected_executable_keys = {
        "dev", "gid", "ino", "mode", "path", "sha256", "size", "uid"
    }
    if (
        not isinstance(exe, Mapping)
        or set(exe) != expected_executable_keys
        or exe.get("path") != "/usr/bin/sleep"
        or re.fullmatch(r"[0-9a-f]{64}", str(exe.get("sha256"))) is None
        or any(
            type(exe.get(key)) is not int or int(exe[key]) < 0
            for key in ("dev", "gid", "ino", "mode", "size", "uid")
        )
        or exe.get("ino") == 0
        or exe.get("size") == 0
        or not (int(exe.get("mode", 0)) & 0o111)
        or record["cwd"] != "/"
    ):
        raise RuntimeError("live process executable/cwd is not exact")
    mapped = record["mapped_files"]
    if (
        not isinstance(mapped, Mapping)
        or "/usr/bin/sleep" not in mapped
        or any(
            not isinstance(item, str)
            or not item.startswith("/")
            or not isinstance(value, Mapping)
            or set(value) != expected_executable_keys | {"ranges"}
            or value.get("path") != item
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256"))) is None
            or not valid_ranges(value.get("ranges"))
            or any(
                type(value.get(key)) is not int or int(value[key]) < 0
                for key in ("dev", "gid", "ino", "mode", "size", "uid")
            )
            or value.get("ino") == 0
            or value.get("size") == 0
            or not (int(value.get("mode", 0)) & 0o111)
            for item, value in mapped.items()
        )
        or any(exe[key] != mapped["/usr/bin/sleep"][key] for key in exe)
    ):
        raise RuntimeError("live process mapped files are not from audited rootfs")
    anonymous = record["anonymous_executable_maps"]
    if (
        not isinstance(anonymous, list)
        or any(
            not isinstance(value, Mapping)
            or set(value) != {"name", "permissions", "range"}
            or value.get("name") not in {"[vdso]", "[vsyscall]"}
            or value.get("permissions") not in {"r-xp", "--xp"}
            or not valid_ranges([value.get("range")])
            for value in anonymous
        )
        or len({_object_sha256(value) for value in anonymous}) != len(anonymous)
    ):
        raise RuntimeError("live process anonymous executable maps are not exact")
    pid_identity = record["pid_identity"]
    if (
        not isinstance(pid_identity, Mapping)
        or set(pid_identity)
        != {"host_pid", "pidfd_bound", "proc_dev", "proc_ino", "starttime_ticks"}
        or pid_identity.get("pidfd_bound") is not True
        or any(
            type(pid_identity.get(key)) is not int
            or int(pid_identity[key]) <= 0
            for key in ("host_pid", "proc_dev", "proc_ino", "starttime_ticks")
        )
    ):
        raise RuntimeError("live process pid identity is not exact")
    if record["children"] != [] or type(record["threads"]) is not int or record["threads"] != 1:
        raise RuntimeError("live process set has unexpected descendants or threads")
    top = record["top"]
    nspid = record["nspid"]
    if (
        not isinstance(nspid, list)
        or len(nspid) < 2
        or any(type(pid) is not int or pid <= 0 for pid in nspid)
        or nspid[-1] != 1
        or _object_sha256(top) != _object_sha256([{"host_pid": nspid[0], "pid": 1, "comm": "sleep"}])
        or pid_identity["host_pid"] != nspid[0]
    ):
        raise RuntimeError("live process set is not exactly inert PID1")
    owner_uid = os.getuid() if expected_uid is None else expected_uid
    owner_gid = os.getgid() if expected_gid is None else expected_gid
    expected_ids = [owner_uid] * 4, [owner_gid] * 4
    if record["uid"] != expected_ids[0] or record["gid"] != expected_ids[1]:
        raise RuntimeError("live process credentials are not exact")
    projection = _projection_from_record(record["ownership_projection"])
    if projection.uid(owner_uid) != 0 or projection.gid(owner_gid) != 0:
        raise RuntimeError("live process rootless credentials do not map to container root")
    for executable in (exe, *mapped.values()):
        for kind in ("uid", "gid"):
            if not any(row.inside <= executable[kind] < row.inside + row.length for row in getattr(projection, kind + "_ranges")):
                raise RuntimeError("live process executable semantic ID is unmapped")
    capabilities = record["capabilities"]
    if (
        not isinstance(capabilities, Mapping)
        or set(capabilities)
        != {"ambient", "bounding", "effective", "inheritable", "permitted"}
        or any(type(value) is not int or value != 0 for value in capabilities.values())
        or type(record["no_new_privileges"]) is not int
        or type(record["seccomp"]) is not int
        or record["no_new_privileges"] != 1
        or record["seccomp"] != 2
    ):
        raise RuntimeError("live process privilege contract is not exact")
    namespaces = record["namespaces"]
    expected_namespaces = {"cgroup", "ipc", "mnt", "net", "pid", "uts"}
    if (
        not isinstance(namespaces, Mapping)
        or set(namespaces) != expected_namespaces
        or any(
            re.fullmatch(rf"{name}:\[[0-9]+\]", str(namespaces[name])) is None
            for name in expected_namespaces
        )
    ):
        raise RuntimeError("live process namespace contract is not exact")
    if record["fds"] != {"0": "/dev/null", "1": "pipe", "2": "pipe"}:
        raise RuntimeError("live process fd contract is not exact")
    if record["mount_contract"] != "verified":
        raise RuntimeError("live process mount contract is not exact")
    if re.fullmatch(r"[0-9a-f]{64}", str(record["mount_sha256"])) is None:
        raise RuntimeError("live process mount contract digest is not exact")
    mount_graph = record["mount_graph"]
    if (
        not isinstance(mount_graph, Mapping)
        or set(mount_graph)
        != {"record_count", "records", "root_device", "semantic_sha256"}
        or mount_graph.get("record_count") != 33
        or not isinstance(mount_graph.get("records"), list)
        or len(mount_graph["records"]) != 33
        or re.fullmatch(
            r"[0-9a-f]{64}", str(mount_graph.get("semantic_sha256"))
        ) is None
        or re.fullmatch(
            r"[0-9a-f]+:[0-9a-f]+", str(mount_graph.get("root_device"))
        ) is None
        or _object_sha256(mount_graph["records"])
        != mount_graph["semantic_sha256"]
    ):
        raise RuntimeError("live process mount graph evidence is not exact")
    validate_live_mount_graph(mount_graph, expected_uid=owner_uid, expected_gid=owner_gid, ownership_projection=projection)
    network = record["network"]
    if network != {"interfaces": ["lo"], "listeners": [], "routes": []}:
        raise RuntimeError("live process network contract is not exact")
    if record["scratch_empty"] is not True:
        raise RuntimeError("live process scratch is not empty")
    if re.fullmatch(r"0::/[^\n]*", str(record["cgroup"])) is None:
        raise RuntimeError("live process cgroup is not exact")


@contextmanager
def _mounted_rootfs(
    podman: list[str], container: str, policy_descriptors: tuple[int, ...]
) -> Iterable[str]:
    # Prepare the final command before mount can acquire material ownership.
    unmount_arguments = podman + ["unmount", container]
    try:
        mounted_result = subprocess.run(
            [*podman, "mount", container],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=policy_descriptors,
        )
        mounted = mounted_result.stdout.strip()
        yield mounted
    finally:
        primary = sys.exception()
        try:
            subprocess.run(
                unmount_arguments,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                pass_fds=policy_descriptors,
            )
        except BaseException:
            if primary is None:
                raise
            _add_cleanup_note(primary, "additional rootfs unmount cleanup failed")


def _rootfs_audit_worker(arguments: argparse.Namespace) -> int:
    from tools.gate01.oci_rootfs import (
        audit_rootfs,
        canonicalize_oci_archive,
        normalize_vfs_materialization,
        project_runtime_bind_file,
    )

    podman = [
        "/usr/bin/podman",
        "--root", arguments.store_root,
        "--runroot", arguments.runroot,
        "--tmpdir", arguments.tmpdir,
        "--storage-driver", "vfs",
    ]
    policy_descriptors = _inherited_podman_policy_descriptors()
    with _mounted_rootfs(podman, arguments.container, policy_descriptors) as mounted:
        if not mounted.startswith("/") or "\n" in mounted:
            raise RuntimeError("Podman returned an unsafe rootfs mount path")
        expected_rootfs = Path(arguments.rootfs_path)
        if not expected_rootfs.is_absolute() or mounted != os.fspath(expected_rootfs):
            raise RuntimeError("Podman mounted a rootfs other than the audited OCI root")
        expected_status = expected_rootfs.lstat()
        mounted_status = Path(mounted).lstat()
        if (
            expected_rootfs.is_symlink()
            or not stat.S_ISDIR(expected_status.st_mode)
            or _stat_version(expected_status) != _stat_version(mounted_status)
        ):
            raise RuntimeError("mounted rootfs identity differs from the audited OCI root")
        locked_expected = canonicalize_oci_archive(
            OCI_ARCHIVE_FD,
            expected_archive_sha256=arguments.archive_sha256,
            expected_manifest_digest=arguments.manifest_digest,
        )
        expected = project_runtime_bind_file(
            locked_expected,
            RUNTIME_CONTAINERENV_FD,
            target="/run/.containerenv",
        )
        normalization: Mapping[str, Any] | None = None
        if arguments.phase == "before":
            actual, normalization = normalize_vfs_materialization(
                mounted,
                expected,
                runtime_bind_targets=("/run/.containerenv",),
            )
        else:
            actual = audit_rootfs(mounted)
        record = create_rootfs_audit_record(
            expected,
            actual,
            locked_non_root_entry_count=len(locked_expected.entries) - 1,
            runtime_projection_paths=("/run/.containerenv",),
        )
        record["oci_authority"] = {
            "archive_sha256": locked_expected.archive_sha256,
            "config_digest": locked_expected.config_digest,
            "diff_ids": list(locked_expected.diff_ids),
            "manifest_digest": locked_expected.manifest_digest,
            "semantic_sha256": _object_sha256(locked_expected.entries),
        }
        if normalization is not None:
            record["normalization"] = _json_safe(normalization)
        print(json.dumps(record, sort_keys=True), flush=True)
    return 0
def _attest_live_container(arguments: argparse.Namespace) -> int:
    if re.fullmatch(r"[0-9a-f]{64}", arguments.nonce) is None:
        raise RuntimeError("live attestation nonce is invalid")
    _require_sealed_regular_descriptor(VERIFIER_FD, "verifier capsule")
    scratch = Path("/tmp/work")
    status = scratch.lstat()
    if scratch.is_symlink() or not stat.S_ISDIR(status.st_mode):
        raise RuntimeError("started scratch mount is not a real directory")
    if (status.st_dev, status.st_ino) != (arguments.scratch_dev, arguments.scratch_ino):
        raise RuntimeError("started scratch mount referent differs")
    records: dict[str, tuple[set[str], str, str]] = {}
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            raise RuntimeError("malformed mountinfo")
        fields_left = left.split()
        fields_right = right.split()
        if len(fields_left) < 6 or len(fields_right) < 3:
            raise RuntimeError("malformed mountinfo fields")
        mountpoint = fields_left[4].replace("\\040", " ")
        records[mountpoint] = (
            set(fields_left[5].split(",")), fields_right[0], fields_right[1]
        )
    if "/" not in records or "ro" not in records["/"][0]:
        raise RuntimeError("started container rootfs is not read-only")
    if "/tmp/work" not in records:
        raise RuntimeError("started scratch mount is absent")
    scratch_options = records["/tmp/work"][0]
    if "rw" not in scratch_options or "nosuid" not in scratch_options or "nodev" not in scratch_options:
        raise RuntimeError("started scratch mount options are unsafe")
    try:
        os.fstat(BUILD_KEY_FD)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise RuntimeError("private key leaked into mount attestation exec")
    for descriptor in (
        PUBLIC_CERTIFICATE_FD,
        BUILD_RESULT_FD,
        *ARTIFACT_FD_ROLES.values(),
        *EVIDENCE_FD_ROLES.values(),
        *INPUT_AUDIT_FD_ROLES.values(),
    ):
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError(
                f"undeclared descriptor leaked into live attestation: {descriptor}"
            )
    if tuple(scratch.iterdir()) != ():
        raise RuntimeError("live attestation scratch is not empty")
    if Path("/proc/1/cmdline").read_bytes() != b"/usr/bin/sleep\0infinity\0":
        raise RuntimeError("container PID1 command is not exact")
    namespace_pids = sorted(
        int(item.name) for item in Path("/proc").iterdir() if item.name.isdigit()
    )
    if namespace_pids != [1, os.getpid()]:
        raise RuntimeError("live attestation process set is not exact")
    print(
        json.dumps(
            {
                "root_read_only": True,
                "nonce": arguments.nonce,
                "process_set": namespace_pids,
                "scratch_device": status.st_dev,
                "scratch_inode": status.st_ino,
                "scratch_options": sorted(scratch_options),
                "verdict": "pass",
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0
def _load_json_bytes(value: bytes, description: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-finite JSON value: {constant}")

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(f"invalid {description} JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{description} JSON must be an object")
    return parsed
class PodmanStore:
    """One secret-scoped, builder-specific rootless VFS store."""

    def __init__(
        self,
        root: Path,
        *,
        environment: Mapping[str, str],
        policy: SealedPodmanPolicy,
    ) -> None:
        self.base = Path(os.path.abspath(root))
        self.graphroot = self.base / "root"
        self.runroot = self.base / "runroot"
        self.tmpdir = self.base / "tmp"
        self.environment = dict(environment)
        self.policy = policy
        self._directory_bindings: dict[str, BoundScratch] = {}
        self._reported_paths: dict[str, BoundStorePath] = {}
        self._scope_closed = False
        self._initialization_started = False
        self._cleanup_completion: list[subprocess.CompletedProcess[bytes] | None] = [None]
        self._cleanup_arguments: tuple[str, ...] | None = None
        self._cleanup_pass_fds: tuple[int, ...] | None = None
        self.image_identity: dict[str, Any] | None = None

    def initialize(self) -> None:
        if self._scope_closed:
            raise RuntimeError("Podman store scope has been permanently released")
        self._initialization_started = True
        self._create_directory("store-base", self.base)
        self._prepare_cleanup_command()
        for label, path in (("store-graphroot", self.graphroot), ("store-runroot", self.runroot), ("store-tmpdir", self.tmpdir)):
            self._create_directory(label, path)
        self.verify_scope()

    def _prepare_cleanup_command(self) -> None:
        """Prepare fallible argv state while a newly created base is empty."""
        descriptor = self._directory_bindings["store-base"].descriptor
        arguments = (
            "unshare", "/usr/bin/rm", "-rf", "--",
            f"/proc/self/fd/{descriptor}/root",
            f"/proc/self/fd/{descriptor}/runroot",
            f"/proc/self/fd/{descriptor}/tmp",
        )
        inherited = (descriptor,)
        self._cleanup_arguments = arguments
        self._cleanup_pass_fds = inherited

    def _create_directory(self, label: str, path: Path) -> None:
        """Retain creation custody before the independent full binding check.

        The initial held inode/name remains the cleanup authority if the later
        binding check fails. An initialization attempt never falls back to
        stale-store pathname acquisition.
        """
        parent, parent_status = _open_parent_directory(path)
        descriptor = watch_descriptor = -1
        initial = None
        created = accepted_create = False
        try:
            parent_names = tuple(sorted(os.listdir(parent)))
            if path.name in parent_names:
                raise RuntimeError("store creation basename already exists")
            watch_descriptor = _open_inotify()
            watch = _add_inotify_directory_watch(watch_descriptor, parent)
            if _stat_version(os.fstat(parent)) != _stat_version(parent_status) or tuple(sorted(os.listdir(parent))) != parent_names or _read_creation_events(watch_descriptor):
                raise RuntimeError("store creation parent baseline changed")
            os.mkdir(path.name, 0o700, dir_fd=parent)
            created = True
            descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            opened = os.fstat(descriptor)
            initial = opened
            if _read_creation_events(watch_descriptor) != ((watch, _IN_CREATE | _IN_ISDIR, 0, os.fsencode(path.name)),):
                raise RuntimeError("store creation event provenance differs")
            accepted_create = True
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if _stat_version(opened) != _stat_version(named) or stat.S_IMODE(opened.st_mode) != 0o700 or (opened.st_uid, opened.st_gid) != (os.geteuid(), os.getegid()) or os.listdir(descriptor) or tuple(sorted(os.listdir(parent))) != tuple(sorted((*parent_names, path.name))) or _read_creation_events(watch_descriptor):
                raise RuntimeError("created store directory identity changed")
            original = BoundScratch(path, label, parent, parent_status, descriptor, opened)
            self._directory_bindings[label] = original
            parent = descriptor = -1
            closing, watch_descriptor = watch_descriptor, -1
            os.close(closing)
            validation = BoundScratch.open(path, label=label)
            try:
                if _stat_identity(validation.initial_status) != _stat_identity(original.initial_status):
                    raise RuntimeError("created store directory binding changed")
                original.verify()
            finally:
                _release_primary = sys.exception()
                try:
                    try:
                        _close_resource_preserving_primary(validation, None, drain=_drain_bound_scratch)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_bound_scratch(validation)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        except BaseException as primary:
            if parent >= 0 and created:
                _release_primary = primary
                try:
                    events = _read_creation_events(watch_descriptor)
                    expected = () if accepted_create else ((watch, _IN_CREATE | _IN_ISDIR, 0, os.fsencode(path.name)),)
                    if events != expected or tuple(sorted(os.listdir(parent))) != tuple(sorted((*parent_names, path.name))):
                        raise RuntimeError("created store directory rollback provenance is ambiguous")
                    current_parent = os.fstat(parent)
                    if (current_parent.st_dev, current_parent.st_ino, current_parent.st_mode, current_parent.st_uid, current_parent.st_gid, current_parent.st_nlink) != (parent_status.st_dev, parent_status.st_ino, parent_status.st_mode, parent_status.st_uid, parent_status.st_gid, parent_status.st_nlink + 1):
                        raise RuntimeError("created store directory rollback parent changed")
                    libc = ctypes.CDLL(None, use_errno=True)
                    rollback_fd = libc.openat(ctypes.c_int(parent), ctypes.c_char_p(os.fsencode(path.name)), ctypes.c_int(os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW))
                    if rollback_fd < 0:
                        raise RuntimeError("created store directory rollback open failed")
                    try:
                        current = os.fstat(rollback_fd)
                        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                        if _stat_version(current) != _stat_version(named) or (initial is not None and _stat_identity(current) != _stat_identity(initial)) or stat.S_IMODE(current.st_mode) != 0o700 or (current.st_uid, current.st_gid) != (os.geteuid(), os.getegid()) or os.listdir(rollback_fd) or _read_creation_events(watch_descriptor):
                            raise RuntimeError("created store directory rollback identity changed")
                        if libc.unlinkat(ctypes.c_int(parent), ctypes.c_char_p(os.fsencode(path.name)), ctypes.c_int(0x200)) != 0:
                            raise RuntimeError("created store directory rollback removal failed")
                        if _read_creation_events(watch_descriptor) != ((watch, _IN_DELETE | _IN_ISDIR, 0, os.fsencode(path.name)),) or tuple(sorted(os.listdir(parent))) != parent_names or os.fstat(parent).st_nlink != parent_status.st_nlink:
                            raise RuntimeError("created store directory rollback endpoint differs")
                    finally:
                        _release_primary = sys.exception()
                        try:
                            os.close(rollback_fd)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        finally:
            _release_fd_0 = descriptor
            _release_fd_1 = parent
            _release_fd_2 = watch_descriptor
            descriptor = parent = watch_descriptor = -1
            _close_descriptors(_release_fd_0, _release_fd_1, _release_fd_2, primary=sys.exception())

    def verify_scope(
        self, *, presence_overrides: Mapping[str, bool] | None = None
    ) -> dict[str, Any]:
        if set(self._directory_bindings) != {
            "store-base", "store-graphroot", "store-runroot", "store-tmpdir"
        }:
            raise RuntimeError("fresh Podman store directory binding is incomplete")
        directories = {
            label: binding.verify()
            for label, binding in sorted(self._directory_bindings.items())
        }
        overrides = dict(presence_overrides or {})
        if not set(overrides) <= set(self._reported_paths):
            raise RuntimeError("Podman reported-path presence override is unknown")
        reported = {
            label: binding.verify(
                require_present=overrides.get(
                    label, binding.target_descriptor is not None
                )
            )
            for label, binding in sorted(self._reported_paths.items())
        }
        return {"directories": directories, "reported_paths": reported}

    def bind_reported_path(
        self,
        *,
        label: str,
        path: Path,
        root: str,
        expected_kind: str,
        allow_missing: bool = False,
    ) -> BoundStorePath:
        if label in self._reported_paths:
            raise RuntimeError(f"Podman reported path was already bound: {label}")
        root_label = {
            "graphroot": "store-graphroot",
            "runroot": "store-runroot",
            "tmpdir": "store-tmpdir",
        }.get(root)
        if root_label is None:
            raise ValueError("Podman reported path root role is invalid")
        binding = BoundStorePath.open(
            label=label,
            path=path,
            root=self._directory_bindings[root_label],
            expected_kind=expected_kind,
            allow_missing=allow_missing,
        )
        try:
            self._reported_paths[label] = binding
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(binding, None, drain=_drain_bound_store_path)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_store_path(binding)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        return binding

    def verify_cleanup_scope(self) -> None:
        """Authorize only cleanup of our created container in its held store.

        Reported runtime endpoints may already be gone or have failed proof
        validation. They cannot broaden or replace the four original store
        roots, which remain mandatory authority before stop/force-removal.
        """
        if self._scope_closed or set(self._directory_bindings) != {"store-base", "store-graphroot", "store-runroot", "store-tmpdir"}:
            raise RuntimeError("container cleanup store custody is incomplete")
        _release_all(binding.verify for binding in self._directory_bindings.values())

    def close_scope(self) -> None:
        reported = self._reported_paths
        directories = self._directory_bindings
        failure = None
        try:
            try:
                _close_resource_mapping(reported, descriptor_attribute="target_descriptor", descriptor_sequence_attribute="owned_directories", closed_attribute="closed", descriptor_sentinel=None)
            except BaseException as _map_primary:
                # The map remains installed until this literal numeric fallback drains it.
                _raw_records = reported
                while _raw_records:
                    try:
                        _raw_owner = _raw_records.popitem()[1]
                    except BaseException:
                        _raw_owner = dict.popitem(_raw_records)[1]
                    _raw_fd = _raw_owner.target_descriptor
                    _raw_owner.target_descriptor = None
                    if _raw_fd is not None and _raw_fd >= 0:
                        try:
                            os.close(_raw_fd)
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                    while _raw_owner.owned_directories:
                        try:
                            _raw_fd = _raw_owner.owned_directories.pop()
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                            _raw_fd = list.pop(_raw_owner.owned_directories)
                        try:
                            os.close(_raw_fd)
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                    _raw_owner.closed = True
                raise
        except BaseException as error:
            failure = error
        finally:
            try:
                try:
                    _close_resource_mapping(directories, descriptor_attribute="descriptor", parent_descriptor_attribute="parent_descriptor", closed_attribute="closed")
                except BaseException as _map_primary:
                    # The map remains installed until this literal numeric fallback drains it.
                    _raw_records = directories
                    while _raw_records:
                        try:
                            _raw_owner = _raw_records.popitem()[1]
                        except BaseException:
                            _raw_owner = dict.popitem(_raw_records)[1]
                        _raw_fd = _raw_owner.descriptor
                        _raw_owner.descriptor = -1
                        if _raw_fd is not None and _raw_fd >= 0:
                            try:
                                os.close(_raw_fd)
                            except BaseException:
                                _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                        _raw_fd = _raw_owner.parent_descriptor
                        _raw_owner.parent_descriptor = -1
                        if _raw_fd >= 0:
                            try:
                                os.close(_raw_fd)
                            except BaseException:
                                _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                        _raw_owner.closed = True
                    raise
            except BaseException as error:
                if failure is None:
                    failure = error
            self._scope_closed = not reported and not directories
        if failure is not None:
            raise failure

    @property
    def command(self) -> tuple[str, ...]:
        return (
            "/usr/bin/podman",
            "--root", os.fspath(self.graphroot),
            "--runroot", os.fspath(self.runroot),
            "--tmpdir", os.fspath(self.tmpdir),
            "--storage-driver", "vfs",
        )

    def run(
        self,
        arguments: Iterable[str],
        *,
        pass_fds: Iterable[int] = (),
        check: bool = True,
        stdout: int | Any = subprocess.PIPE,
        stderr: int | Any = subprocess.PIPE,
        stdin: int | Any = subprocess.DEVNULL,
        completed: list[subprocess.CompletedProcess[bytes] | None] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        if completed is not None and (len(completed) != 1 or completed[0] is not None):
            raise RuntimeError("command completion custody must begin empty")
        with self.policy.child_configuration(
            self.environment, tuple(pass_fds)
        ) as (environment, inherited):
            result = subprocess.run(
                [*self.command, *arguments],
                env=environment,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                pass_fds=inherited,
                check=check,
            )
            if completed is not None:
                completed[0] = result
            return result

    def import_image(
        self,
        archive_descriptor: int,
        *,
        expected_config_digest: str,
        expected_manifest_digest: str,
        expected_oci_identity: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.verify_scope()
        result = self.run(
            ("load", "--quiet", "--input", f"/proc/self/fd/{archive_descriptor}"),
            pass_fds=(archive_descriptor,),
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Podman image import failed: {detail}")
        inspect = self.run(
            ("image", "inspect", expected_config_digest), check=True
        )
        records = _load_json_bytes(
            b'{"records":' + inspect.stdout + b'}', "Podman image inspection"
        )["records"]
        if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
            raise RuntimeError("Podman imported image identity is ambiguous")
        record = records[0]
        observed_id = str(record.get("Id", ""))
        if observed_id.removeprefix("sha256:") != expected_config_digest.removeprefix(
            "sha256:"
        ):
            raise RuntimeError("Podman imported config digest differs")
        observed_digest = record.get("Digest")
        if "Digest" not in record or observed_digest not in (None, expected_manifest_digest):
            raise RuntimeError("Podman imported manifest digest differs")
        expected = dict(expected_oci_identity or {})
        fields = ("archive_sha256", "config_digest", "diff_ids", "manifest_digest", "semantic_sha256")
        authority = {key: expected.get(key) for key in fields}
        if (
            authority["archive_sha256"] != _hash_descriptor(archive_descriptor)
            or authority["config_digest"] != expected_config_digest
            or authority["manifest_digest"] != expected_manifest_digest
            or not isinstance(authority["semantic_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", authority["semantic_sha256"]) is None
            or not isinstance(authority["diff_ids"], list)
            or any(not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in authority["diff_ids"])
        ):
            raise RuntimeError("Podman import lacks held OCI archive authority")
        if record.get("RootFS") != {"Type": "layers", "Layers": authority["diff_ids"]}:
            raise RuntimeError("Podman imported rootfs diff IDs differ")
        self.verify_scope()
        self.image_identity = {
            "basis": "held-archive-and-materialized-root" if observed_digest is None else "podman-manifest-and-held-archive",
            "podman_digest": observed_digest,
            "oci_authority": authority,
            "materialized_root_verified": False,
        }
        return dict(self.image_identity)

    def confirm_materialized_identity(self, authority: Mapping[str, Any]) -> None:
        if self.image_identity is None or dict(authority) != self.image_identity["oci_authority"]:
            raise RuntimeError("materialized root lacks the imported OCI authority")
        self.image_identity["materialized_root_verified"] = True


class BoundScratch:
    """Hold the original scratch directory and its parent/name until cleanup."""

    def __init__(
        self,
        path: Path,
        label: str,
        parent_descriptor: int,
        parent_status: os.stat_result,
        descriptor: int,
        initial_status: os.stat_result,
    ) -> None:
        self.path = path
        self.label = label
        self.name = path.name
        self.parent_descriptor = parent_descriptor
        self.parent_status = parent_status
        self.descriptor = descriptor
        self.initial_status = initial_status
        self.closed = False

    @classmethod
    def open(
        cls, path: Path, *, label: str = "container scratch"
    ) -> "BoundScratch":
        absolute = Path(os.path.abspath(path))
        if absolute.name in {"", ".", ".."}:
            raise RuntimeError(f"{label} path is unsafe")
        parent, parent_status = _open_parent_directory(absolute)
        descriptor = -1
        try:
            descriptor = os.open(
                absolute.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            initial = os.fstat(descriptor)
            named = os.stat(absolute.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(initial.st_mode)
                or _stat_identity(initial) != _stat_identity(named)
                or initial.st_uid != os.getuid()
                or initial.st_gid != os.getgid()
                or stat.S_IMODE(initial.st_mode) != 0o700
            ):
                raise RuntimeError(f"{label} metadata is unsafe")
            result = cls(
                absolute, label, parent, parent_status, descriptor, initial
            )
            result.verify()
            parent = descriptor = -1
            return result
        finally:
            _release_fd_0 = descriptor
            _release_fd_1 = parent
            descriptor = parent = -1
            _close_descriptors(_release_fd_0, _release_fd_1, primary=sys.exception())

    @staticmethod
    def _stable_directory_metadata(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            stat.S_IFMT(value.st_mode),
            stat.S_IMODE(value.st_mode),
            value.st_uid,
            value.st_gid,
        )

    def verify(self) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError(f"{self.label} binding is closed")
        current_parent, current_status = _open_parent_directory(self.path)
        try:
            if self._stable_directory_metadata(current_status) != (
                self._stable_directory_metadata(self.parent_status)
            ):
                raise RuntimeError(f"{self.label} parent path was replaced")
        finally:
            _release_primary = sys.exception()
            try:
                os.close(current_parent)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        if self._stable_directory_metadata(os.fstat(self.parent_descriptor)) != (
            self._stable_directory_metadata(self.parent_status)
        ):
            raise RuntimeError(f"{self.label} parent was replaced")
        opened = os.fstat(self.descriptor)
        try:
            named = os.stat(
                self.name,
                dir_fd=self.parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise RuntimeError(f"{self.label} path disappeared") from error
        expected = self._stable_directory_metadata(self.initial_status)
        if (
            self._stable_directory_metadata(opened) != expected
            or self._stable_directory_metadata(named) != expected
        ):
            raise RuntimeError(f"{self.label} path was replaced")
        return {
            "dev": opened.st_dev,
            "gid": opened.st_gid,
            "ino": opened.st_ino,
            "mode": stat.S_IMODE(opened.st_mode),
            "parent_dev": self.parent_status.st_dev,
            "parent_ino": self.parent_status.st_ino,
            "uid": opened.st_uid,
        }

    def close(self) -> None:
        if self.closed:
            return
        _release_fd_0 = self.descriptor
        _release_fd_1 = self.parent_descriptor
        self.closed = True
        self.descriptor = self.parent_descriptor = -1
        _numeric_failure = None
        _numeric_fd = _release_fd_0
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = _release_fd_1
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bound descriptor release failed") from _numeric_failure


class BoundStorePath:
    """Bind one Podman-reported path to a held fresh-store ancestry."""

    def __init__(
        self,
        *,
        label: str,
        path: Path,
        root: BoundScratch,
        relative: Path,
        edges: list[tuple[int, str, int, os.stat_result]],
        owned_directories: list[int],
        expected_kind: str,
        target_descriptor: int | None,
        target_status: os.stat_result | None,
    ) -> None:
        self.label = label
        self.path = path
        self.root = root
        self.relative = relative
        self.edges = edges
        self.owned_directories = owned_directories
        self.expected_kind = expected_kind
        self.target_descriptor = target_descriptor
        self.target_status = target_status
        self.closed = False

    @classmethod
    def open(
        cls,
        *,
        label: str,
        path: Path,
        root: BoundScratch,
        expected_kind: str,
        allow_missing: bool = False,
    ) -> "BoundStorePath":
        if expected_kind not in {"directory", "regular"}:
            raise ValueError("store path expected kind is invalid")
        absolute = Path(os.path.abspath(path))
        try:
            relative = absolute.relative_to(root.path)
        except ValueError as error:
            raise RuntimeError(f"{label} escapes its exact fresh store root") from error
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise RuntimeError(f"{label} is not a strict store descendant")
        root.verify()
        current = root.descriptor
        edges: list[tuple[int, str, int, os.stat_result]] = []
        owned: list[int] = []
        target_descriptor: int | None = None
        try:
            for component in relative.parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                try:
                    owned.append(child)
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(child)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                status = os.fstat(child)
                named = os.stat(component, dir_fd=current, follow_symlinks=False)
                if _stat_identity(status) != _stat_identity(named):
                    raise RuntimeError(f"{label} ancestry changed while binding")
                edges.append((current, component, child, status))
                current = child
            try:
                target_descriptor = os.open(
                    relative.name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                    | (os.O_DIRECTORY if expected_kind == "directory" else os.O_NONBLOCK),
                    dir_fd=current,
                )
            except FileNotFoundError:
                if not allow_missing:
                    raise RuntimeError(f"{label} is absent")
                target_descriptor = None
            target_status = (
                None if target_descriptor is None else os.fstat(target_descriptor)
            )
            result = cls(
                label=label,
                path=absolute,
                root=root,
                relative=relative,
                edges=edges,
                owned_directories=owned,
                expected_kind=expected_kind,
                target_descriptor=target_descriptor,
                target_status=target_status,
            )
            result.verify(require_present=target_descriptor is not None)
            target_descriptor = None
            owned = []
            return result
        finally:
            primary = sys.exception()
            failure = None
            try:
                if target_descriptor is not None:
                    closing, target_descriptor = target_descriptor, None
                    os.close(closing)
            except BaseException as error:
                failure = error
            finally:
                try:
                    _close_descriptor_sequence(owned, reverse=True)
                except BaseException as error:
                    if failure is None:
                        failure = error
            if failure is not None:
                if primary is None:
                    raise RuntimeError("store path cleanup failed") from failure
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")

    @property
    def parent_descriptor(self) -> int:
        return self.edges[-1][2] if self.edges else self.root.descriptor

    @staticmethod
    def _metadata(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            stat.S_IFMT(value.st_mode),
            stat.S_IMODE(value.st_mode),
            value.st_uid,
            value.st_gid,
        )

    def _verify_ancestry(self) -> None:
        self.root.verify()
        for parent, name, child, initial in self.edges:
            opened = os.fstat(child)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or self._metadata(opened) != self._metadata(initial)
                or self._metadata(named) != self._metadata(initial)
            ):
                raise RuntimeError(f"{self.label} store ancestry was replaced")

    def bind_present_target(self) -> None:
        if self.closed:
            raise RuntimeError(f"{self.label} binding is closed")
        self._verify_ancestry()
        if self.target_descriptor is not None:
            self.verify(require_present=True)
            return
        descriptor = os.open(
            self.relative.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self.parent_descriptor,
        )
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                raise RuntimeError(f"{self.label} is not a regular file")
            self.target_status = status
            self.target_descriptor = descriptor
            descriptor = -1
            self.verify(require_present=True)
        finally:
            if descriptor >= 0:
                _release_primary = sys.exception()
                try:
                    os.close(descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

    def verify(self, *, require_present: bool | None = True) -> dict[str, Any]:
        if self.closed:
            raise RuntimeError(f"{self.label} binding is closed")
        self._verify_ancestry()
        try:
            named = os.stat(
                self.relative.name,
                dir_fd=self.parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            named = None
        if require_present is False and named is not None:
            raise RuntimeError(f"{self.label} target remains present")
        if self.target_descriptor is None:
            if require_present is not False or named is not None:
                raise RuntimeError(f"{self.label} target presence changed")
            target: dict[str, Any] | None = None
        else:
            assert self.target_status is not None
            opened = os.fstat(self.target_descriptor)
            expected_type = (
                stat.S_IFDIR if self.expected_kind == "directory" else stat.S_IFREG
            )
            if stat.S_IFMT(opened.st_mode) != expected_type:
                raise RuntimeError(f"{self.label} type changed")
            if named is None:
                if require_present is not False or opened.st_nlink != 0:
                    raise RuntimeError(f"{self.label} target disappeared")
            elif self._metadata(named) != self._metadata(self.target_status):
                raise RuntimeError(f"{self.label} target was replaced")
            if self._metadata(opened) != self._metadata(self.target_status):
                raise RuntimeError(f"{self.label} held target changed")
            target = {
                "dev": opened.st_dev,
                "gid": opened.st_gid,
                "ino": opened.st_ino,
                "mode": stat.S_IMODE(opened.st_mode),
                "nlink": opened.st_nlink,
                "present": named is not None,
                "type": stat.S_IFMT(opened.st_mode),
                "uid": opened.st_uid,
            }
        return {
            "label": self.label,
            "path": os.fspath(self.path),
            "relative": self.relative.as_posix(),
            "root": os.fspath(self.root.path),
            "target": target,
        }

    def close(self) -> None:
        if self.closed:
            return
        target = self.target_descriptor
        directories = self.owned_directories
        self.target_descriptor = None
        failure = None
        try:
            if target is not None:
                os.close(target)
        except BaseException as error:
            failure = error
        finally:
            try:
                _numeric_failure = None
                _numeric_values = directories
                if isinstance(_numeric_values, list):
                    while _numeric_values:
                        try:
                            _numeric_fd = _numeric_values.pop()
                        except BaseException as _numeric_error:
                            if _numeric_failure is None:
                                _numeric_failure = _numeric_error
                            _numeric_fd = list.pop(_numeric_values)
                        if _numeric_fd >= 0:
                            try:
                                os.close(_numeric_fd)
                            except BaseException as _numeric_error:
                                if _numeric_failure is None:
                                    _numeric_failure = _numeric_error
                else:
                    _numeric_index = len(_numeric_values)
                    while _numeric_index:
                        _numeric_index -= 1
                        _numeric_fd = _numeric_values[_numeric_index]
                        if _numeric_fd >= 0:
                            try:
                                os.close(_numeric_fd)
                            except BaseException as _numeric_error:
                                if _numeric_failure is None:
                                    _numeric_failure = _numeric_error
                if _numeric_failure is not None:
                    raise RuntimeError("bound descriptor release failed") from _numeric_failure
            except BaseException as error:
                if failure is None:
                    failure = error
                else:
                    _add_cleanup_note(failure, "additional bound descriptor cleanup failed")
            try:
                directories.clear()
            except BaseException as error:
                if failure is None:
                    failure = error
                else:
                    _add_cleanup_note(failure, "additional bound descriptor cleanup failed")
                list.clear(directories)
            self.closed = not directories
        if failure is not None:
            raise failure


def _retain_cleanup_failure(
    primary: BaseException | None,
    secondary: BaseException,
    note: str,
) -> BaseException:
    """Keep the first cleanup failure and sanitize every later failure."""
    if primary is None:
        return secondary
    _add_cleanup_note(primary, note)
    return primary


def _backend_instance_fields(backend: Any) -> dict[str, Any]:
    """Return the concrete instance dictionary without descriptor dispatch."""
    if not isinstance(backend, PodmanContainerBackend):
        raise RuntimeError("container backend state owner is invalid")
    backend_type_fields = type.__getattribute__(
        PodmanContainerBackend, "__dict__"
    )
    instance_dictionary = backend_type_fields["__dict__"]
    fields = instance_dictionary.__get__(backend, PodmanContainerBackend)
    if type(fields) is not dict:
        raise RuntimeError("container backend state owner is invalid")
    return fields


def _base_exception_context(error: BaseException) -> BaseException | None:
    """Read the concrete BaseException context slot without subclass lookup."""
    if not isinstance(error, BaseException):
        raise TypeError("exception context owner must be an exception")
    descriptor = type.__getattribute__(BaseException, "__dict__")[
        "__context__"
    ]
    return type(descriptor).__get__(descriptor, error, BaseException)


def _base_exception_traceback(error: BaseException) -> TracebackType | None:
    """Read the concrete BaseException traceback slot without subclass lookup."""
    if not isinstance(error, BaseException):
        raise TypeError("exception traceback owner must be an exception")
    descriptor = type.__getattribute__(BaseException, "__dict__")[
        "__traceback__"
    ]
    return type(descriptor).__get__(descriptor, error, BaseException)


def _base_exception_fields(error: BaseException) -> dict[str, Any]:
    """Return concrete BaseException instance storage without subclass lookup."""
    if not isinstance(error, BaseException):
        raise TypeError("exception state owner must be an exception")
    descriptor = type.__getattribute__(BaseException, "__dict__")["__dict__"]
    fields = type(descriptor).__get__(descriptor, error, BaseException)
    if type(fields) is not dict:
        raise RuntimeError("exception state owner is invalid")
    return fields


def _base_exception_with_traceback(
    error: BaseException,
    traceback: TracebackType | None,
) -> BaseException:
    """Replay through the concrete BaseException method descriptor."""
    if not isinstance(error, BaseException):
        raise TypeError("exception traceback owner must be an exception")
    method = type.__getattribute__(BaseException, "__dict__")[
        "with_traceback"
    ]
    result = method(error, traceback)
    if result is not error:
        raise RuntimeError("exception traceback replay changed identity")
    return result


def _add_stop_publication_note_once(
    primary: BaseException,
    note: str,
) -> None:
    """Install one fixed recovery note without attacker-controlled dispatch."""
    try:
        if type(note) is not str:
            raise TypeError("stop publication note must be an exact string")
        fields = _base_exception_fields(primary)
        notes = None
        found_notes = False
        all_exact_string_keys = True
        for key, value in dict.items(fields):
            if type(key) is not str:
                all_exact_string_keys = False
            elif str.__eq__(key, "__notes__") is True:
                notes = value
                found_notes = True
        if not found_notes:
            # Dictionary insertion can compare a colliding stored key.  Omit
            # the diagnostic unless every existing key is an exact string.
            if all_exact_string_keys:
                dict.__setitem__(fields, "__notes__", [note])
            return
        if not issubclass(type(notes), list):
            # Replacing hostile storage can release its final reference and
            # invoke attacker-controlled finalization.  Preserve it untouched;
            # a diagnostic note is never allowed to endanger the primary.
            return
        for index in range(list.__len__(notes)):
            value = list.__getitem__(notes, index)
            if type(value) is str and str.__eq__(value, note) is True:
                return
        list.append(notes, note)
    except BaseException:
        # Diagnostics must never supersede the publication primary.
        pass


def _read_stop_failure_latch(fields: dict[str, Any]) -> bool:
    """Read the authoritative stop latch without invoking a data descriptor."""
    if type(fields) is not dict:
        raise RuntimeError("container backend state owner is invalid")
    try:
        value = dict.__getitem__(fields, "_stop_proof_failed")
    except KeyError as error:
        raise RuntimeError("container stop proof latch is unavailable") from error
    if type(value) is not bool:
        raise RuntimeError("container stop proof latch is invalid")
    return value


def _write_stop_failure_latch(fields: dict[str, Any], value: bool) -> None:
    """Write the authoritative stop latch without invoking a data descriptor."""
    if type(fields) is not dict:
        raise RuntimeError("container backend state owner is invalid")
    if type(value) is not bool:
        raise TypeError("container stop proof latch value must be boolean")
    dict.__setitem__(fields, "_stop_proof_failed", value)


class PodmanContainerBackend:
    """Concrete backend for the audited inert-PID1/exec lifecycle."""

    def __init__(
        self,
        *,
        store: PodmanStore,
        image: str,
        container: str,
        scratch: Path,
        capsule_descriptor: int,
        archive_descriptor: int,
        archive_sha256: str,
        manifest_digest: str,
        execution_arguments: Mapping[str, tuple[str, ...]],
        execution_stdout: Mapping[str, int] | None = None,
        scratch_binding: BoundScratch | None = None,
    ) -> None:
        self.store = store
        self.image = image
        self.container = container
        self.scratch = Path(os.path.abspath(scratch))
        self._owns_scratch_binding = scratch_binding is None
        owned_binding = None
        try:
            owned_binding = BoundScratch.open(self.scratch) if self._owns_scratch_binding else scratch_binding
            self._scratch_binding = owned_binding
            if self._scratch_binding.path != self.scratch:
                raise RuntimeError("container scratch authority differs from execution path")
            self._scratch_binding.verify()
            self.capsule_descriptor = capsule_descriptor
            self.archive_descriptor = archive_descriptor
            self.archive_sha256 = archive_sha256
            self.manifest_digest = manifest_digest
            self.execution_arguments = dict(execution_arguments)
            self.execution_stdout = dict(execution_stdout or {})
            self.execution_results: dict[str, subprocess.CompletedProcess[bytes]] = {}
            self.contract_record: dict[str, Any] | None = None
            self.live_record: dict[str, Any] | None = None
            self.normalization_record: dict[str, Any] | None = None
            self._before_rootfs: dict[str, Any] | None = None
            self._authorized_rootfs: dict[str, Any] | None = None
            self._live_process: Any | None = None
            self._config_inputs: WatchedRuntimeBindings | None = None
            self._specification: dict[str, Any] | None = None
            self._rootfs_path: Path | None = None
            self._created = False
            self._started = False
            _write_stop_failure_latch(_backend_instance_fields(self), False)
            self._state = LifecycleState.NEW
            self._conmon_binding: BoundStorePath | None = None
            self._conmon_present = False
            self.container_id: str | None = None
            self._nonce = hashlib.sha256(
                f"{os.getpid()}:{container}:{time.monotonic_ns()}".encode("ascii")
            ).hexdigest()
        except BaseException as primary:
            if self._owns_scratch_binding and owned_binding is not None:
                _release_primary = primary
                try:
                    try:
                        _close_resource_preserving_primary(owned_binding, None, drain=_drain_bound_scratch)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_bound_scratch(owned_binding)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise

    def create(self) -> None:
        if self._created:
            raise RuntimeError("container backend was already created")
        self._scratch_binding.verify()
        arguments = podman_create_arguments(
            image=self.image,
            container=self.container,
            scratch=self.scratch,
        )
        # The subprocess can create material before its policy finalizer raises.
        # Retain exact-name cleanup authority across that ambiguous boundary.
        self._created = True
        try:
            result = self.store.run(arguments)
            observed = result.stdout.decode("ascii", errors="strict").strip()
            self._scratch_binding.verify()
            if re.fullmatch(r"[0-9a-f]{64}", observed) is None:
                raise RuntimeError("Podman create did not return one canonical container ID")
            self.container_id = observed
        except BaseException as primary:
            cleanup_error: BaseException | None = None
            try:
                self.store.verify_scope()
                self.store.run(("rm", "--force", self.container))
                self._created = False
                self.container_id = None
            except BaseException as cleanup:
                cleanup_error = cleanup
                _add_cleanup_note(primary, "additional container create rollback failed")
            if not self._created:
                self._state = LifecycleState.REMOVED
            if cleanup_error is not None:
                raise
            raise primary
        self._state = LifecycleState.CREATED

    def initialize(self) -> None:
        if self._state != LifecycleState.CREATED or not self._created or self._started:
            raise RuntimeError("container must be newly created before init")
        if self.container_id is None:
            raise RuntimeError("container init lacks a retained container ID")
        self._scratch_binding.verify()
        result = self.store.run(("init", self.container_id))
        observed = result.stdout.decode("ascii", errors="strict").strip()
        if observed not in {"", self.container, self.container_id}:
            raise RuntimeError("Podman init returned an unexpected identity")
        self._scratch_binding.verify()
        self._state = LifecycleState.CREATED_INIT

    def audit_effective_spec(self) -> None:
        if self._state != LifecycleState.CREATED_INIT:
            raise RuntimeError("effective spec audit is out of lifecycle order")
        container_id = getattr(self, "container_id", None)
        scratch_evidence = self._scratch_binding.verify()
        record = _podman_inspect_record(self.store, container_id or self.container)
        if container_id is not None and record.get("Id") != container_id:
            raise RuntimeError("Podman inspect container ID differs")
        if record.get("Name") not in (self.container, f"/{self.container}"):
            raise RuntimeError("Podman inspect container name differs")
        config_path = _exact_oci_config_path(record)
        static_value = record.get("StaticDir")
        if not isinstance(static_value, str) or not static_value.startswith("/"):
            raise RuntimeError("Podman did not expose an absolute static directory")
        conmon_pid_value = record.get("ConmonPidFile")
        if not isinstance(conmon_pid_value, str) or not conmon_pid_value.startswith("/"):
            raise RuntimeError("Podman did not expose an absolute conmon PID path")
        static_directory = Path(static_value)
        runtime_directory = Path(conmon_pid_value).parent
        if container_id is not None:
            expected_static = self.store.graphroot / "vfs-containers" / container_id / "userdata"
            expected_config = expected_static / "config.json"
            expected_pid = self.store.runroot / "vfs-containers" / container_id / "userdata" / "conmon.pid"
            if static_value != os.fspath(expected_static) or config_path != expected_config or conmon_pid_value != os.fspath(expected_pid):
                raise RuntimeError("Podman reported paths do not bind the retained container ID")
        self.store.verify_scope()
        config_binding = self.store.bind_reported_path(
            label="OCIConfigPath", path=config_path, root="graphroot",
            expected_kind="regular",
        )
        static_binding = self.store.bind_reported_path(
            label="StaticDir", path=static_directory, root="graphroot",
            expected_kind="directory",
        )
        self._conmon_binding = self.store.bind_reported_path(
            label="ConmonPidFile", path=Path(conmon_pid_value), root="runroot",
            expected_kind="regular", allow_missing=True,
        )
        self._conmon_present = self._conmon_binding.target_descriptor is not None
        config_inputs = WatchedRuntimeBindings.open(
            {
                "config": config_path,
                "containerenv": runtime_directory / ".containerenv",
            },
            stop_projection_label="config",
            reserved_lifecycle=("containerenv", "conmon.pid"),
        )
        try:
            self._config_inputs = config_inputs
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(config_inputs, None, drain=_drain_watched_runtime_bindings)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_watched_runtime_bindings(config_inputs)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        specification = _load_json_bytes(
            self._config_inputs.read("config"), "effective OCI config"
        )
        root_record = specification.get("root")
        if not isinstance(root_record, Mapping) or not isinstance(
            root_record.get("path"), str
        ):
            raise RuntimeError("effective OCI root path is absent")
        rootfs_path = Path(root_record["path"])
        self.store.bind_reported_path(
            label="rootfs", path=rootfs_path, root="graphroot",
            expected_kind="directory",
        )
        assert config_binding.target_descriptor is not None
        assert static_binding.target_descriptor is not None
        if _stat_version(os.fstat(config_binding.target_descriptor)) != _stat_version(
            os.fstat(self._config_inputs.descriptor("config"))
        ):
            raise RuntimeError("OCI config differs from its held store binding")
        if _stat_identity(os.fstat(config_binding.parent_descriptor)) != _stat_identity(os.fstat(static_binding.target_descriptor)):
            raise RuntimeError("OCI config parent differs from held StaticDir")
        assert self._conmon_binding is not None
        if _stat_identity(os.fstat(self._conmon_binding.parent_descriptor)) != _stat_identity(os.fstat(self._config_inputs._records["containerenv"].parent.descriptor)):
            raise RuntimeError("ConmonPidFile parent differs from held runtime watch")
        self._specification = specification
        self._rootfs_path = rootfs_path
        self.contract_record = validate_effective_oci_spec(
            specification,
            scratch=self.scratch,
            scratch_identity=(scratch_evidence["dev"], scratch_evidence["ino"]),
            rootfs_path=rootfs_path,
            static_directory=static_directory,
            runtime_directory=runtime_directory,
        )
        self.contract_record["container_id"] = container_id
        self.contract_record["config_sha256"] = self._config_inputs.hashes["config"]
        self.contract_record["scratch_binding"] = self._scratch_binding.verify()
        self.contract_record["runtime_input_binding"] = self._config_inputs.evidence
        self.contract_record["store_bindings"] = self.store.verify_scope()
        self.contract_record["sealed_policy_sha256"] = self.store.policy.hashes
        self._state = LifecycleState.CONFIG_AUDITED

    def audit_rootfs(self, phase: str) -> dict[str, Any]:
        if phase not in {"before", "authorized", "after"}:
            raise ValueError("rootfs audit phase is invalid")
        required_state = {
            "before": LifecycleState.CONFIG_AUDITED,
            "authorized": LifecycleState.LIVE_ATTESTED,
            "after": LifecycleState.STOPPED,
        }[phase]
        if self._state != required_state or (
            phase == "after"
            and _read_stop_failure_latch(_backend_instance_fields(self))
        ):
            raise RuntimeError(f"rootfs {phase} audit is out of lifecycle order")
        if self._rootfs_path is None:
            raise RuntimeError("rootfs audit lacks the bound effective root path")
        assert self._config_inputs is not None
        self._scratch_binding.verify()
        self.store.verify_scope(
            presence_overrides={"ConmonPidFile": self._conmon_present}
        )
        with FixedDescriptors(
            {
                OCI_ARCHIVE_FD: self.archive_descriptor,
                RUNTIME_CONTAINERENV_FD: self._config_inputs.descriptor("containerenv"),
                VERIFIER_FD: self.capsule_descriptor,
            }
        ):
            result = self.store.run(
                (
                    "unshare", "/usr/bin/python3", "-I", "-S", "-B",
                    f"/proc/self/fd/{VERIFIER_FD}",
                    "tools.gate01.container_runtime", "rootfs-audit-worker",
                    "--store-root", os.fspath(self.store.graphroot),
                    "--runroot", os.fspath(self.store.runroot),
                    "--tmpdir", os.fspath(self.store.tmpdir),
                    "--container", self.container,
                    "--phase", phase,
                    "--rootfs-path", os.fspath(self._rootfs_path),
                    "--archive-sha256", self.archive_sha256,
                    "--manifest-digest", self.manifest_digest,
                ),
                pass_fds=(OCI_ARCHIVE_FD, RUNTIME_CONTAINERENV_FD, VERIFIER_FD),
                check=False,
            )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"{phase} rootfs audit worker failed ({result.returncode}): {detail}"
            )
        self._scratch_binding.verify()
        record = _load_json_bytes(result.stdout, f"{phase} rootfs audit")
        self.store.confirm_materialized_identity(record.get("oci_authority", {}))
        assert self.contract_record is not None
        self.contract_record["image_identity"] = dict(self.store.image_identity)
        self.store.verify_scope(
            presence_overrides={"ConmonPidFile": self._conmon_present}
        )
        if phase == "before":
            normalization = record.pop("normalization", None)
            if not isinstance(normalization, dict):
                raise RuntimeError("pre-work VFS normalization evidence is absent")
            self.normalization_record = normalization
            assert self.contract_record is not None
            self.contract_record["vfs_normalization"] = normalization
            self._before_rootfs = record
            self._state = LifecycleState.CREATED_INIT_AUDITED
        elif phase == "authorized":
            if self._before_rootfs is None:
                raise RuntimeError("authorized rootfs audit lacks its before baseline")
            assert_rootfs_audit_records_equal(self._before_rootfs, record)
            self._authorized_rootfs = record
            self._state = LifecycleState.AUTHORIZED_ROOTFS_AUDITED
        return record

    def start(self) -> None:
        if self._state != LifecycleState.CREATED_INIT_AUDITED or self._started:
            raise RuntimeError("container start is out of lifecycle order")
        prior_state = self._state
        self._scratch_binding.verify()
        self.store.verify_scope()
        assert self._conmon_binding is not None
        assert self._config_inputs is not None
        self._config_inputs.begin_start_transition()
        # Once the external start may have happened, cleanup retains stop/rm
        # authority even if the guarded proof rejects its effects.
        self._started = True
        self.store.run(("start", getattr(self, "container_id", None) or self.container))
        try:
            self._conmon_binding.bind_present_target()
            self._config_inputs.complete_start_transition()
            self._verify_conmon_descriptor_pair(require_present=True)
            self._conmon_binding.verify(require_present=True)
            self.store.verify_scope()
            self._scratch_binding.verify()
            # This is the terminal external integrity observation.  Only
            # held-descriptor comparison and success publication follow it.
            self._config_inputs.verify_coherent()
            self._verify_conmon_descriptor_pair(require_present=True)
        except BaseException as primary:
            try:
                self._publish_start_presence()
            except BaseException:
                _add_cleanup_note(
                    primary, "additional start presence publication failed"
                )
            raise
        else:
            self._publish_start_presence()
        try:
            self._state = LifecycleState.STARTED_UNATTESTED
        except BaseException:
            object.__setattr__(self, "_state", prior_state)
            raise

    def _publish_start_presence(self) -> None:
        """Publish actual held PID custody without losing a publication primary."""
        assert self._conmon_binding is not None
        present = self._conmon_binding.target_descriptor is not None
        try:
            self._conmon_present = present
        except BaseException:
            object.__setattr__(self, "_conmon_present", present)
            raise

    def _verify_conmon_descriptor_pair(self, *, require_present: bool) -> None:
        """Cross-bind the runroot store PID handle to watcher-held custody."""
        if not isinstance(self._config_inputs, WatchedRuntimeBindings):
            raise RuntimeError("ConmonPidFile watcher owner is invalid")
        if not isinstance(self._conmon_binding, BoundStorePath):
            raise RuntimeError("ConmonPidFile store binding owner is invalid")
        reserved = self._config_inputs._reserved_lifecycle
        if not isinstance(reserved, Mapping):
            raise RuntimeError("ConmonPidFile watcher lifecycle is unavailable")
        watcher_descriptor = reserved.get("descriptor")
        store_descriptor = getattr(self._conmon_binding, "target_descriptor", None)
        if type(watcher_descriptor) is not int:
            raise RuntimeError("ConmonPidFile watcher descriptor is invalid")
        if type(store_descriptor) is not int:
            raise RuntimeError("ConmonPidFile store descriptor is invalid")
        try:
            watcher_status = os.fstat(watcher_descriptor)
        except OSError as error:
            raise RuntimeError("ConmonPidFile watcher descriptor is not open") from error
        try:
            store_status = os.fstat(store_descriptor)
        except OSError as error:
            raise RuntimeError("ConmonPidFile store descriptor is not open") from error
        accepted_status = reserved.get("status")
        accepted_sha256 = reserved.get("sha256")
        if (
            not isinstance(accepted_status, os.stat_result)
            or type(accepted_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", accepted_sha256) is None
        ):
            raise RuntimeError("ConmonPidFile watcher lifecycle is unavailable")
        if require_present:
            if watcher_status.st_nlink != 1 or store_status.st_nlink != 1:
                raise RuntimeError(
                    "ConmonPidFile descriptor pair is not in the linked phase"
                )
        elif watcher_status.st_nlink != 0 or store_status.st_nlink != 0:
            raise RuntimeError(
                "ConmonPidFile descriptor pair is not in the held-unlinked phase"
            )
        accepted_version = _stat_version(accepted_status)
        watcher_version = _stat_version(watcher_status)
        if require_present:
            accepted_status_matches = watcher_version == accepted_version
        else:
            # A proved unlink changes only link count/ctime.  Every other
            # accepted watcher field remains authoritative while held.
            accepted_status_matches = (
                watcher_version[:6] + watcher_version[7:9]
                == accepted_version[:6] + accepted_version[7:9]
            )
        if (
            not stat.S_ISREG(watcher_status.st_mode)
            or not stat.S_ISREG(store_status.st_mode)
            or _stat_identity(watcher_status) != _stat_identity(store_status)
            or _stat_version(watcher_status) != _stat_version(store_status)
            or not accepted_status_matches
        ):
            raise RuntimeError("ConmonPidFile watcher/store descriptor pair differs")
        watcher_bytes = _read_descriptor(watcher_descriptor)
        store_bytes = _read_descriptor(store_descriptor)
        # Digest the exact captured byte objects.  A second descriptor read
        # would create another race interval unrelated to this comparison.
        watcher_sha256 = hashlib.sha256(watcher_bytes).hexdigest()
        store_sha256 = hashlib.sha256(store_bytes).hexdigest()
        try:
            watcher_after = os.fstat(watcher_descriptor)
            store_after = os.fstat(store_descriptor)
        except OSError as error:
            raise RuntimeError(
                "ConmonPidFile descriptor pair changed during comparison"
            ) from error
        if (
            _stat_version(watcher_status) != _stat_version(watcher_after)
            or _stat_version(store_status) != _stat_version(store_after)
        ):
            raise RuntimeError(
                "ConmonPidFile descriptor pair changed during comparison"
            )
        if (
            watcher_bytes != store_bytes
            or watcher_sha256 != store_sha256
            or watcher_sha256 != accepted_sha256
        ):
            raise RuntimeError("ConmonPidFile watcher/store descriptor pair differs")

    def _exec(
        self, arguments: tuple[str, ...], descriptors: Mapping[int, int], *, stdout: Any
    ) -> subprocess.CompletedProcess[bytes]:
        preserve = ",".join(str(value) for value in sorted(descriptors))
        command = ["exec"]
        if preserve:
            command.append(f"--preserve-fd={preserve}")
        command.extend((getattr(self, "container_id", None) or self.container, *arguments))
        with FixedDescriptors(descriptors) if descriptors else _null_context():
            return self.store.run(
                command,
                pass_fds=tuple(sorted(descriptors)),
                stdout=stdout,
                stderr=subprocess.STDOUT if stdout != subprocess.PIPE else subprocess.PIPE,
                check=False,
            )

    def attest_live(self) -> None:
        if self._state != LifecycleState.STARTED_UNATTESTED:
            raise RuntimeError("live attestation is out of lifecycle order")
        self._scratch_binding.verify()
        self.store.verify_scope()
        assert self._specification is not None
        assert self._config_inputs is not None
        if self._before_rootfs is None:
            raise RuntimeError("live attestation lacks its audited rootfs baseline")
        expected_executables = self._before_rootfs.get("executable_files")
        expected_executables_sha256 = self._before_rootfs.get(
            "executable_files_sha256"
        )
        expected_root_anchor = self._before_rootfs.get("root_anchor")
        if not isinstance(expected_executables, Mapping) or not isinstance(
            expected_root_anchor, Mapping
        ) or expected_executables_sha256 != _object_sha256(expected_executables):
            raise RuntimeError("audited rootfs executable/anchor evidence is incomplete")
        live_process = BoundLiveProcess.open(
            self.store,
            getattr(self, "container_id", None) or self.container,
            self.scratch,
            self._specification,
            expected_executables,
            expected_root_anchor,
        )
        try:
            self._live_process = live_process
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(live_process, None, drain=_drain_bound_live_process)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_live_process(live_process)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        before = self._live_process.capture()
        validate_live_process_record(before)
        scratch_evidence = self._scratch_binding.verify()
        result = self._exec(
            (
                "/usr/bin/python3", "-I", "-S", "-B",
                f"/proc/self/fd/{VERIFIER_FD}",
                "tools.gate01.container_runtime", "attest-live",
                "--scratch-dev", str(scratch_evidence["dev"]),
                "--scratch-ino", str(scratch_evidence["ino"]),
                "--nonce", self._nonce,
            ),
            {VERIFIER_FD: self.capsule_descriptor},
            stdout=subprocess.PIPE,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"live mount attestation failed: {detail}")
        inside = _load_json_bytes(result.stdout, "live mount attestation")
        if inside.get("verdict") != "pass" or inside.get("nonce") != self._nonce:
            raise RuntimeError("live mount attestation did not pass")
        after = self._live_process.capture()
        validate_live_process_record(after)
        if before != after:
            raise RuntimeError("live PID1 contract changed during attestation")
        self._config_inputs.verify_coherent()
        self._scratch_binding.verify()
        assert self.contract_record is not None
        self.live_record = {"host": after, "inside": inside}
        self.contract_record["live_attestation"] = self.live_record
        self._state = LifecycleState.LIVE_ATTESTED

    def authorize_work(self) -> None:
        if self._state != LifecycleState.AUTHORIZED_ROOTFS_AUDITED:
            raise RuntimeError(
                "work authorization requires an authorized rootfs audit"
            )
        assert self._config_inputs is not None
        self._config_inputs.verify_coherent()
        self.store.verify_scope()
        self._scratch_binding.verify()
        live_process = getattr(self, "_live_process", None)
        if live_process is None or self.live_record is None:
            raise RuntimeError("work authorization lacks a held live process")
        final_live = live_process.capture()
        if final_live != self.live_record.get("host"):
            raise RuntimeError("live process changed before work authorization")
        self._state = LifecycleState.WORK_AUTHORIZED

    def execute(self, role: str, descriptors: Mapping[int, int]) -> None:
        if self._state != LifecycleState.WORK_AUTHORIZED:
            raise RuntimeError("container work exec is not authorized")
        if role not in self.execution_arguments:
            raise RuntimeError(f"unexpected container execution role: {role}")
        self._scratch_binding.verify()
        self.store.verify_scope()
        stdout: Any = self.execution_stdout.get(role, subprocess.PIPE)
        result = self._exec(self.execution_arguments[role], descriptors, stdout=stdout)
        self.execution_results[role] = result
        if result.returncode != 0:
            raise RuntimeError(f"container {role} execution failed: {result.returncode}")
        self._scratch_binding.verify()

        self.store.verify_scope()

    def stop_and_wait(self) -> None:
        backend_fields = _backend_instance_fields(self)
        if _read_stop_failure_latch(backend_fields):
            raise RuntimeError("container stop proof is terminally failed")
        if not self._started:
            return
        # Arm the terminal latch before any proof or external effect.  Failure
        # propagation then contains no recovery write that could replace the
        # original primary or reopen normal retry.
        _write_stop_failure_latch(backend_fields, True)
        transition = self._stop_and_wait_attempt()
        assert self._config_inputs is not None
        assert self.contract_record is not None
        contract_record = self.contract_record
        staged_runtime_evidence = self._config_inputs.evidence
        if staged_runtime_evidence.get("stop_projection") != transition:
            raise RuntimeError("stop projection evidence differs")
        prior_runtime_evidence = contract_record["runtime_input_binding"]
        prior_runtime_evidence_value = copy.deepcopy(prior_runtime_evidence)
        prior_live_process = self._live_process
        prior_started = self._started
        prior_conmon_present = self._conmon_present
        prior_state = self._state
        rollback_actions = (
            lambda: dict.__setitem__(
                backend_fields, "_live_process", prior_live_process
            ),
            lambda: dict.__setitem__(
                backend_fields, "_started", prior_started
            ),
            lambda: dict.__setitem__(
                backend_fields, "_conmon_present", prior_conmon_present
            ),
            lambda: dict.__setitem__(backend_fields, "_state", prior_state),
            lambda: dict.__setitem__(
                contract_record,
                "runtime_input_binding",
                prior_runtime_evidence,
            ),
            lambda: dict.clear(prior_runtime_evidence),
            lambda: dict.update(
                prior_runtime_evidence,
                prior_runtime_evidence_value,
            ),
            # A second raw pair gives an interrupted first pass a recovery
            # opportunity without delaying restoration of cleanup custody.
            lambda: dict.clear(prior_runtime_evidence),
            lambda: dict.update(
                prior_runtime_evidence,
                prior_runtime_evidence_value,
            ),
            lambda: _write_stop_failure_latch(backend_fields, True),
        )

        def restore_stop_publication(primary: BaseException) -> None:
            # Raw authority bypasses a hostile data descriptor.  The first
            # write protects retry/audit even if later restoration is cut off.
            try:
                _write_stop_failure_latch(backend_fields, True)
            except BaseException:
                _add_stop_publication_note_once(
                    primary,
                    "additional stop publication latch rollback failed",
                )
            release_failed = False
            # A helper failure can mean either that one action was skipped or
            # that the helper itself was interrupted.  Retry the complete,
            # idempotent tuple once; with one recovery interruption, one pass
            # necessarily attempts every restoration action.
            for _attempt in range(2):
                try:
                    _release_all(rollback_actions)
                except BaseException:
                    release_failed = True
                    continue
                break
            if release_failed:
                _add_stop_publication_note_once(
                    primary, "additional stop publication rollback failed"
                )

        if self._live_process is not None:
            self._live_process.close()
        self._scratch_binding.verify()
        self._config_inputs.verify_coherent()
        self._verify_conmon_descriptor_pair(require_present=False)
        # The private attempt returns before publication.  This enclosing
        # transaction therefore owns its return boundary, every local write,
        # and the final latch clear.  The public frame's own return is the
        # post-commit acknowledgement boundary.
        publication_failure: tuple[BaseException, Any] | None = None

        def publish_stop_state() -> None:
            nonlocal publication_failure
            try:
                contract_record["runtime_input_binding"] = staged_runtime_evidence
                self._live_process = None
                self._started = False
                self._conmon_present = False
                self._state = LifecycleState.STOPPED
                _write_stop_failure_latch(backend_fields, False)
            except BaseException as primary:
                # Publish the exception and traceback into an outer-owned cell
                # before this handler's compiler cleanup or function return.
                # The call guard below can therefore recover the exact primary
                # even when either boundary is interrupted.
                publication_failure = (
                    primary,
                    _base_exception_traceback(primary),
                )
                restore_stop_publication(primary)

        try:
            publish_stop_state()
        except BaseException as recovery:
            if publication_failure is None:
                direct_context = _base_exception_context(recovery)
                if isinstance(direct_context, BaseException):
                    recovered_primary = direct_context
                else:
                    # Before CPython exposes either a handler local or direct
                    # context, the lost exception object cannot be recreated.
                    # Safety still requires raw rearm and custody restoration.
                    recovered_primary = recovery
                    _add_stop_publication_note_once(
                        recovered_primary,
                        "stop publication primary was unavailable during recovery",
                    )
                publication_traceback = _base_exception_traceback(
                    recovered_primary
                )
            else:
                recovered_primary, publication_traceback = publication_failure
            publication_failure = (recovered_primary, publication_traceback)
            if recovered_primary is not recovery:
                _add_stop_publication_note_once(
                    recovered_primary,
                    "additional stop publication rollback failed",
                )
            restore_stop_publication(recovered_primary)
        if publication_failure is not None:
            publication_primary, publication_traceback = publication_failure
            raise _base_exception_with_traceback(
                publication_primary, publication_traceback
            )

    def _stop_and_wait_attempt(self) -> dict[str, Any]:
        assert self._started
        assert self._config_inputs is not None
        if self._live_process is not None:
            self._live_process.verify_identity()
        self._scratch_binding.verify()
        self.store.verify_scope()
        self._config_inputs.verify_coherent()
        self._verify_conmon_descriptor_pair(require_present=True)
        self._config_inputs.begin_stop_transition("config")
        self.store.run(("stop", "--time", "30", getattr(self, "container_id", None) or self.container))
        wait = self.store.run(("wait", getattr(self, "container_id", None) or self.container))
        status = wait.stdout.decode("ascii", errors="strict").strip()
        if status not in {"0", "137", "143"}:
            raise RuntimeError(f"container PID1 wait status is unexpected: {status}")
        self.store.verify_scope(presence_overrides={"ConmonPidFile": False})
        transition = self._config_inputs.complete_stop_transition("config")
        assert self._conmon_binding is not None
        self._verify_conmon_descriptor_pair(require_present=False)
        return transition

    def remove(self) -> None:
        failures: BaseException | None = None
        if self._started:
            try:
                self.stop_and_wait()
            except BaseException as error:
                if failures is None:
                    failures = error
                # A failed proof check or ambiguous stop side effect does not
                # discharge ownership of the original created container.
                try:
                    self.store.verify_cleanup_scope()
                    self.store.run(("stop", "--time", "30", getattr(self, "container_id", None) or self.container))
                except BaseException as cleanup:
                    failures = _retain_cleanup_failure(
                        failures,
                        cleanup,
                        "additional container stop cleanup failed",
                    )
        if self._live_process is not None:
            try:
                try:
                    _close_resource_preserving_primary(self._live_process, None, drain=_drain_bound_live_process)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_live_process(self._live_process)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException as error:
                failures = _retain_cleanup_failure(
                    failures,
                    error,
                    "additional live process cleanup failed",
                )
            self._live_process = None
        inputs = self._config_inputs
        if inputs is not None:
            try:
                inputs.verify_coherent()
            except BaseException as error:
                failures = _retain_cleanup_failure(
                    failures,
                    error,
                    "additional runtime input verification cleanup failed",
                )
            try:
                try:
                    _close_resource_preserving_primary(inputs, None, drain=_drain_watched_runtime_bindings)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_watched_runtime_bindings(inputs)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException as error:
                failures = _retain_cleanup_failure(
                    failures,
                    error,
                    "additional runtime input close cleanup failed",
                )
            self._config_inputs = None
        if self._created:
            try:
                self.store.verify_scope(
                    presence_overrides={"ConmonPidFile": self._conmon_present}
                    if self._conmon_binding is not None else None
                )
            except BaseException as error:
                failures = _retain_cleanup_failure(
                    failures,
                    error,
                    "additional Podman store scope cleanup failed",
                )
            cleanup_note = (
                "additional Podman cleanup scope verification failed"
            )
            try:
                self.store.verify_cleanup_scope()
                cleanup_note = "additional container removal cleanup failed"
                self.store.run(("rm", "--force", getattr(self, "container_id", None) or self.container))
                self._created = False
                self._started = False
                self._conmon_present = False
                self.container_id = None
            except BaseException as error:
                failures = _retain_cleanup_failure(
                    failures,
                    error,
                    cleanup_note,
                )
        try:
            self._scratch_binding.verify()
        except BaseException as error:
            failures = _retain_cleanup_failure(
                failures,
                error,
                "additional scratch verification cleanup failed",
            )
        if failures:
            raise RuntimeError("container cleanup did not fully succeed") from failures
        self._state = LifecycleState.REMOVED

    def close(self) -> None:
        """Release the scratch anchor only after its owner's final cleanup."""
        if self._owns_scratch_binding:
            try:
                _close_resource_preserving_primary(self._scratch_binding, None, drain=_drain_bound_scratch)
            except BaseException as _drain_primary:
                _drain_attempts = 2
                while _drain_attempts:
                    _drain_attempts -= 1
                    try:
                        _drain_bound_scratch(self._scratch_binding)
                        break
                    except BaseException:
                        _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                raise
@contextmanager
def _null_context() -> Iterable[None]:
    yield None
def _podman_inspect_record(store: PodmanStore, container: str) -> dict[str, Any]:
    result = store.run(("container", "inspect", container))
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Podman container inspection returned invalid JSON") from error
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise RuntimeError("Podman container inspection is ambiguous")
    return records[0]
def _exact_oci_config_path(record: Mapping[str, Any]) -> Path:
    value = record.get("OCIConfigPath")
    if not isinstance(value, str) or not value.startswith("/"):
        raise RuntimeError("Podman did not expose an absolute OCI config path")
    return Path(value)
def _mountinfo_path(value: str) -> str:
    replacements = {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value
def _verify_live_mountinfo(
    raw: bytes, specification: Mapping[str, Any], *,
    ownership_projection: Any,
    expected_uid: int | None = None, expected_gid: int | None = None,
) -> dict[str, Any]:
    """Validate and canonicalize the complete live mount graph.

    Kernel mount IDs and device numbers are volatile.  They are converted to
    exact parent-record and device-class relations; every destination, root,
    filesystem, source, option, super-option, and stacked-mount edge remains
    mandatory.
    """
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("live process mountinfo is not ASCII") from error
    mounts = specification.get("mounts")
    linux = specification.get("linux")
    if not isinstance(mounts, list) or not isinstance(linux, Mapping):
        raise RuntimeError("live process effective mount specification is invalid")
    sources = {
        item.get("destination"): item.get("source")
        for item in mounts
        if isinstance(item, Mapping)
    }
    if (
        len(sources) != len(mounts)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in sources.items())
    ):
        raise RuntimeError("live process effective mount specification is malformed")
    if (
        linux.get("maskedPaths") != list(EXPECTED_MASKED_PATHS)
        or linux.get("readonlyPaths") != list(EXPECTED_READONLY_PATHS)
    ):
        raise RuntimeError("live process Linux path contract is not exact")
    parsed_records: list[dict[str, Any]] = []
    ids: set[str] = set()
    for line in lines:
        left, separator, right = line.partition(" - ")
        left_fields = left.split()
        right_fields = right.split()
        if not separator or len(left_fields) < 6 or len(right_fields) < 3:
            raise RuntimeError("live process mountinfo record is malformed")
        if left_fields[0] in ids or not left_fields[0].isdigit() or not left_fields[1].isdigit():
            raise RuntimeError("live process mount IDs are malformed or duplicated")
        ids.add(left_fields[0])
        mountpoint = _mountinfo_path(left_fields[4])
        parsed_records.append(
            {
                "id": left_fields[0],
                "parent": left_fields[1],
                "device": left_fields[2],
                "root": _mountinfo_path(left_fields[3]),
                "mountpoint": mountpoint,
                "options": left_fields[5].split(","),
                "optional": left_fields[6:],
                "filesystem": right_fields[0],
                "source": _mountinfo_path(right_fields[1]),
                "super_options": right_fields[2].split(","),
            }
        )

    by_mountpoint: dict[str, list[dict[str, Any]]] = {}
    by_id = {record["id"]: record for record in parsed_records}
    for record in parsed_records:
        by_mountpoint.setdefault(record["mountpoint"], []).append(record)
    powercap = "/sys/devices/virtual/powercap"
    if set(path for path, values in by_mountpoint.items() if len(values) > 1) != {powercap}:
        raise RuntimeError("live process mount graph has unexpected duplicate destinations")
    if len(by_mountpoint.get(powercap, ())) != 2:
        raise RuntimeError("live process stacked powercap mount is not exact")
    power_values = by_mountpoint[powercap]
    first = next(
        (
            record for record in power_values
            if by_id.get(record["parent"], {}).get("mountpoint") == "/sys"
        ),
        None,
    )
    second = next(
        (
            record for record in power_values
            if first is not None and record["parent"] == first["id"]
        ),
        None,
    )
    if first is None or second is None or first is second:
        raise RuntimeError("live process stacked powercap parent relation is invalid")
    key_by_id: dict[str, str] = {}
    for path, values in by_mountpoint.items():
        if path == powercap:
            continue
        if len(values) != 1:
            raise RuntimeError("live process mount graph destination is ambiguous")
        key_by_id[values[0]["id"]] = path
    key_by_id[first["id"]] = powercap + "#1"
    key_by_id[second["id"]] = powercap + "#2"
    keyed = {key_by_id[record["id"]]: record for record in parsed_records}

    device_names = ("null", "zero", "full", "tty", "random", "urandom")
    masked_file_paths = (
        "/proc/kcore", "/proc/keys", "/proc/latency_stats",
        "/proc/timer_list", "/proc/interrupts",
    )
    masked_directory_paths = ("/proc/acpi", "/proc/scsi", "/sys/firmware")
    readonly_paths = tuple(EXPECTED_READONLY_PATHS)
    expected_keys = {
        "/", "/tmp", "/tmp/work", "/proc", "/dev", "/sys",
        "/dev/pts", "/dev/mqueue", "/dev/shm", "/run/.containerenv",
        "/sys/fs/cgroup", powercap + "#1", powercap + "#2",
        *masked_file_paths, *masked_directory_paths, *readonly_paths,
        *(f"/dev/{name}" for name in device_names),
    }
    if set(keyed) != expected_keys:
        missing = sorted(expected_keys - set(keyed))
        extra = sorted(set(keyed) - expected_keys)
        raise RuntimeError(
            f"live process mount graph path-set differs: missing={missing} extra={extra}"
        )

    canonical: dict[str, dict[str, Any]] = {}

    def require(
        key: str,
        *,
        parent: str,
        root: str,
        options: tuple[str, ...],
        filesystem: str,
        source: str,
        super_options: tuple[str, ...],
        device_class: str,
    ) -> None:
        record = keyed[key]
        parent_key = key_by_id.get(record["parent"], "outside")
        actual = (
            parent_key,
            record["root"],
            tuple(record["options"]),
            record["filesystem"],
            record["source"],
            tuple(record["super_options"]),
        )
        wanted = (parent, root, options, filesystem, source, super_options)
        if record["optional"] != [] or actual != wanted:
            raise RuntimeError(
                f"live process mount graph record differs at {key}: "
                f"expected={wanted!r} actual={actual!r}"
            )
        canonical[key] = {
            "device_class": device_class,
            "filesystem": filesystem,
            "key": key,
            "options": list(options),
            "parent": parent,
            "root": root,
            "source": source,
            "super_options": list(super_options),
        }

    uid = os.getuid() if expected_uid is None else expected_uid
    gid = os.getgid() if expected_gid is None else expected_gid
    projected = [
        row.outside + 5 - row.inside
        for row in ownership_projection.gid_ranges
        if row.inside <= 5 < row.inside + row.length
    ]
    if ownership_projection.allow_identity or len(projected) != 1:
        raise RuntimeError("live process devpts GID map is not exact")
    root_record = keyed["/"]
    host_device = root_record["device"]
    host_filesystem = root_record["filesystem"]
    host_source = root_record["source"]
    host_super = tuple(root_record["super_options"])
    root_spec = specification.get("root")
    if not isinstance(root_spec, Mapping) or not isinstance(root_spec.get("path"), str):
        raise RuntimeError("live process effective root path is absent")
    require(
        "/", parent="outside", root=root_spec["path"],
        options=("ro", "relatime"), filesystem=host_filesystem,
        source=host_source, super_options=host_super, device_class="hostfs",
    )
    for key, parent, root, options in (
        ("/tmp/work", "/tmp", sources["/tmp/work"], ("rw", "nosuid", "nodev", "relatime")),
        ("/run/.containerenv", "/", sources["/run/.containerenv"], ("ro", "nosuid", "nodev", "noexec", "relatime")),
    ):
        if keyed[key]["device"] != host_device:
            raise RuntimeError(f"live process host bind device differs at {key}")
        require(
            key, parent=parent, root=root, options=options,
            filesystem=host_filesystem, source=host_source,
            super_options=host_super, device_class="hostfs",
        )

    tmp_super = ("rw", f"uid={uid}", f"gid={gid}", "inode64")
    require(
        "/tmp", parent="/", root="/",
        options=("rw", "nosuid", "nodev", "relatime"),
        filesystem="tmpfs", source="tmpfs", super_options=tmp_super,
        device_class="tmpfs-work",
    )
    require(
        "/proc", parent="/", root="/",
        options=("rw", "nosuid", "nodev", "noexec", "relatime"),
        filesystem="proc", source="proc", super_options=("rw",),
        device_class="proc",
    )
    dev_super = (
        "rw", "size=65536k", "mode=755", f"uid={uid}", f"gid={gid}", "inode64"
    )
    require(
        "/dev", parent="/", root="/", options=("ro", "nosuid"),
        filesystem="tmpfs", source="tmpfs", super_options=dev_super,
        device_class="tmpfs-dev",
    )
    require(
        "/sys", parent="/", root="/",
        options=("ro", "nosuid", "nodev", "noexec", "relatime"),
        filesystem="sysfs", source="sysfs", super_options=("rw",),
        device_class="sysfs",
    )
    require(
        "/dev/pts", parent="/dev", root="/",
        options=("rw", "nosuid", "noexec", "relatime"),
        filesystem="devpts", source="devpts",
        super_options=("rw", f"gid={projected[0]}", "mode=620", "ptmxmode=666"),
        device_class="devpts",
    )
    require(
        "/dev/mqueue", parent="/dev", root="/",
        options=("rw", "nosuid", "nodev", "noexec", "relatime"),
        filesystem="mqueue", source="mqueue", super_options=("rw",),
        device_class="mqueue",
    )
    shm_super = ("rw", "size=64000k", f"uid={uid}", f"gid={gid}", "inode64")
    require(
        "/dev/shm", parent="/dev", root="/",
        options=("ro", "nosuid", "nodev", "noexec", "relatime"),
        filesystem="tmpfs", source="shm", super_options=shm_super,
        device_class="tmpfs-shm",
    )
    container_match = re.search(
        r"/vfs-containers/([0-9a-f]{64})/userdata/\.containerenv$",
        sources["/run/.containerenv"],
    )
    if container_match is None:
        raise RuntimeError("live process containerenv source identity is malformed")
    container_id = container_match.group(1)
    require(
        "/sys/fs/cgroup", parent="/sys",
        root=f"/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{container_id}",
        options=("ro", "nosuid", "nodev", "noexec", "relatime"),
        filesystem="cgroup2", source="cgroup2",
        super_options=("rw", "nsdelegate", "memory_recursiveprot", "memory_hugetlb_accounting"),
        device_class="cgroup2",
    )

    dev_records = [keyed[f"/dev/{name}"] for name in device_names]
    devtmp_device = dev_records[0]["device"]
    devtmp_super = tuple(dev_records[0]["super_options"])
    if (
        re.fullmatch(r"0:[0-9]+", devtmp_device) is None
        or len(devtmp_super) != 5
        or devtmp_super[0] != "rw"
        or re.fullmatch(r"size=[0-9]+k", devtmp_super[1]) is None
        or re.fullmatch(r"nr_inodes=[0-9]+", devtmp_super[2]) is None
        or devtmp_super[3:] != ("mode=755", "inode64")
    ):
        raise RuntimeError("live process host devtmpfs contract is malformed")
    for name in device_names:
        key = f"/dev/{name}"
        if keyed[key]["device"] != devtmp_device:
            raise RuntimeError("live process device bind device relation differs")
        require(
            key, parent="/dev", root=f"/{name}",
            options=("rw", "nosuid", "noexec"),
            filesystem="devtmpfs", source="devtmpfs",
            super_options=devtmp_super, device_class="host-devtmpfs",
        )
    for path in masked_file_paths:
        if keyed[path]["device"] != devtmp_device:
            raise RuntimeError("live process masked file device relation differs")
        require(
            path, parent="/proc", root="/null", options=("ro", "nosuid"),
            filesystem="devtmpfs", source="devtmpfs",
            super_options=devtmp_super, device_class="host-devtmpfs",
        )

    zero_super = ("rw", "size=0k", f"uid={uid}", f"gid={gid}", "inode64")
    zero_mounts = {
        "/proc/acpi": "/proc",
        "/proc/scsi": "/proc",
        "/sys/firmware": "/sys",
        powercap + "#1": "/sys",
        powercap + "#2": powercap + "#1",
    }
    zero_devices: set[str] = set()
    for key, parent in zero_mounts.items():
        record = keyed[key]
        if record["device"] in zero_devices:
            raise RuntimeError("live process zero-size mask devices are not distinct")
        zero_devices.add(record["device"])
        require(
            key, parent=parent, root="/", options=("ro", "relatime"),
            filesystem="tmpfs", source="tmpfs", super_options=zero_super,
            device_class=f"zero-tmpfs:{key}",
        )

    proc_device = keyed["/proc"]["device"]
    for path in readonly_paths:
        if keyed[path]["device"] != proc_device:
            raise RuntimeError("live process read-only proc device relation differs")
        require(
            path, parent="/proc", root=path.removeprefix("/proc"),
            options=("ro", "nosuid", "nodev", "noexec", "relatime"),
            filesystem="proc", source="proc", super_options=("rw",),
            device_class="proc",
        )
    records = [canonical[key] for key in sorted(canonical)]
    return {
        "record_count": len(records),
        "records": records,
        "root_device": root_record["device"],
        "semantic_sha256": _object_sha256(records),
    }


def validate_live_mount_graph(
    graph: Mapping[str, Any], *, expected_uid: int, expected_gid: int,
    ownership_projection: Any,
    specification: Mapping[str, Any] | None = None,
) -> None:
    """Re-run the production topology rules on canonical evidence.

    Reconstructed mount IDs/devices carry only the committed parent/class
    relations, not new observational authority. Exact round-trip equality
    rejects forged canonical classes and fields as well as topology changes.
    """
    fields = {"device_class", "filesystem", "key", "options", "parent", "root", "source", "super_options"}
    if not isinstance(graph, Mapping) or set(graph) != {"record_count", "records", "root_device", "semantic_sha256"}:
        raise RuntimeError("live mount graph schema differs")
    rows = graph["records"]
    if type(graph["record_count"]) is not int or graph["record_count"] != 33 or not isinstance(rows, list) or len(rows) != 33 or not isinstance(graph["root_device"], str) or re.fullmatch(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)", graph["root_device"]) is None:
        raise RuntimeError("live mount graph cardinality or device differs")
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise RuntimeError("live mount graph row schema differs")
        if any(not isinstance(row[key], str) or not row[key] or any(ord(char) < 32 for char in row[key]) for key in fields - {"options", "super_options"}):
            raise RuntimeError("live mount graph string is invalid")
        if any(not isinstance(row[key], list) or not row[key] or any(not isinstance(item, str) or re.fullmatch(r"[^\s,]+", item) is None for item in row[key]) for key in ("options", "super_options")):
            raise RuntimeError("live mount graph options are invalid")
    keyed = {row["key"]: row for row in rows}
    if len(keyed) != 33 or any(key not in keyed for key in ("/", "/tmp/work", "/run/.containerenv")):
        raise RuntimeError("live mount graph keys differ")
    if specification is None:
        specification = {
            "root": {"path": keyed["/"]["root"]},
            "mounts": [{"destination": key, "source": keyed[key]["root"]} for key in ("/tmp/work", "/run/.containerenv")],
            "linux": {"maskedPaths": list(EXPECTED_MASKED_PATHS), "readonlyPaths": list(EXPECTED_READONLY_PATHS)},
        }
    ids = {key: str(index + 100) for index, key in enumerate(sorted(keyed))}
    devices = {"hostfs": graph["root_device"]}
    for kind in sorted({row["device_class"] for row in rows} - {"hostfs"}):
        minor = 1000 + len(devices)
        while f"0:{minor}" in devices.values():
            minor += 1
        devices[kind] = f"0:{minor}"
    def escaped(value: str) -> str:
        return value.replace("\\", r"\134").replace(" ", r"\040")
    raw = "".join(
        f"{ids[row['key']]} {ids.get(row['parent'], '90')} {devices[row['device_class']]} "
        f"{escaped(row['root'])} {escaped(re.sub(r'#(?:1|2)$', '', row['key']))} {','.join(row['options'])} - "
        f"{escaped(row['filesystem'])} {escaped(row['source'])} {','.join(row['super_options'])}\n"
        for row in rows
    )
    try:
        observed = _verify_live_mountinfo(raw.encode("ascii"), specification, expected_uid=expected_uid, expected_gid=expected_gid, ownership_projection=ownership_projection)
    except (UnicodeError, KeyError, ValueError, RuntimeError):
        raise RuntimeError("live mount graph topology differs") from None
    if observed != graph:
        raise RuntimeError("live mount graph canonical evidence differs")


def _normalize_rootfs_path(rootfs: Path, value: str) -> tuple[str, Path]:
    if value.endswith(" (deleted)"):
        raise RuntimeError("live process maps a deleted file")
    raw = Path(value)
    if not raw.is_absolute() or ".." in raw.parts:
        raise RuntimeError("live process maps an unsafe pathname")
    root_text = os.fspath(rootfs)
    if value == root_text:
        relative = Path(".")
    elif value.startswith(root_text + os.sep):
        relative = Path(value[len(root_text) + 1 :])
    else:
        relative = Path(*raw.parts[1:])
    candidate = rootfs / relative
    normalized = "/" if relative == Path(".") else "/" + relative.as_posix()
    return normalized, candidate
def _read_proc_nul(path: Path, description: str) -> list[str]:
    value = path.read_bytes()
    if not value.endswith(b"\0"):
        raise RuntimeError(f"live process {description} is not NUL terminated")
    try:
        items = [item.decode("utf-8") for item in value[:-1].split(b"\0")]
    except UnicodeDecodeError as error:
        raise RuntimeError(f"live process {description} is not UTF-8") from error
    if len(items) != len(set(items)):
        raise RuntimeError(f"live process {description} has duplicates")
    return items


def _decode_proc_nul(value: bytes, description: str) -> list[str]:
    if not value.endswith(b"\0"):
        raise RuntimeError(f"live process {description} is not NUL terminated")
    try:
        items = [item.decode("utf-8") for item in value[:-1].split(b"\0")]
    except UnicodeDecodeError as error:
        raise RuntimeError(f"live process {description} is not UTF-8") from error
    if len(items) != len(set(items)):
        raise RuntimeError(f"live process {description} has duplicates")
    return items


def _parse_executable_maps(
    value: bytes,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Parse every executable mapping without discarding inode authority."""
    try:
        lines = value.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("live process maps are not UTF-8") from error
    files: list[dict[str, Any]] = []
    anonymous: list[dict[str, str]] = []
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            raise RuntimeError("live process maps record is malformed")
        address_range, permissions, offset, device, inode_text = fields[:5]
        pathname = fields[5] if len(fields) == 6 else ""
        if (
            re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", address_range) is None
            or re.fullmatch(r"[r-][w-][x-][ps]", permissions) is None
            or re.fullmatch(r"[0-9a-f]+", offset) is None
            or re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", device) is None
            or not inode_text.isdecimal()
        ):
            raise RuntimeError("live process maps record is malformed")
        if "x" not in permissions:
            continue
        if "w" in permissions:
            raise RuntimeError("live process has a writable executable mapping")
        if not pathname:
            raise RuntimeError("live process executable mapping has missing pathname")
        if pathname.endswith(" (deleted)"):
            raise RuntimeError("live process maps a deleted file")
        if pathname.startswith("["):
            if pathname not in {"[vdso]", "[vsyscall]"}:
                raise RuntimeError("live process has an unknown anonymous executable map")
            if int(inode_text) != 0 or device != "00:00":
                raise RuntimeError("live process anonymous executable map has file identity")
            anonymous.append(
                {
                    "name": pathname,
                    "permissions": permissions,
                    "range": address_range,
                }
            )
            continue
        if not pathname.startswith("/") or int(inode_text) <= 0:
            raise RuntimeError("live process executable mapping has unsafe file identity")
        major_text, minor_text = device.split(":", 1)
        files.append(
            {
                "device_major": int(major_text, 16),
                "device_minor": int(minor_text, 16),
                "inode": int(inode_text),
                "path": pathname,
                "permissions": permissions,
                "range": address_range,
            }
        )
    if not files:
        raise RuntimeError("live process has no file-backed executable maps")
    return files, anonymous


def _process_starttime(stat_bytes: bytes, expected_pid: int) -> int:
    try:
        prefix, separator, suffix = stat_bytes.rstrip(b"\n").rpartition(b") ")
        if not separator:
            raise RuntimeError("live process stat/starttime is malformed")
        if not prefix.startswith(f"{expected_pid} (".encode("ascii")):
            raise RuntimeError("live process stat pid differs")
        fields = suffix.split()
        value = int(fields[19])
    except (IndexError, ValueError) as error:
        raise RuntimeError("live process stat/starttime is malformed") from error
    if value <= 0:
        raise RuntimeError("live process starttime is invalid")
    return value


def _read_proc_file(proc_fd: int, relative: str, description: str) -> bytes:
    descriptor = os.open(
        relative,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=proc_fd,
    )
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _stat_version(before) != _stat_version(after):
            raise RuntimeError(f"live process {description} changed while reading")
        return b"".join(chunks)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _parse_user_namespace_map(value: bytes) -> tuple[tuple[int, int, int], ...]:
    try:
        if not value or len(value) > 65536 or not value.endswith(b"\n"):
            raise ValueError
        lines = value.decode("ascii").splitlines()
        if len(lines) > 340:
            raise ValueError
        records = []
        for line in lines:
            match = re.fullmatch(r"[ \t]*(0|[1-9][0-9]*)[ \t]+(0|[1-9][0-9]*)[ \t]+([1-9][0-9]*)[ \t]*", line)
            if match is None:
                raise ValueError
            inside, outside, length = map(int, match.groups())
            if inside + length > 2**32 - 1 or outside + length > 2**32 - 1:
                raise ValueError
            records.append((inside, outside, length))
        for field in (0, 1):
            ordered = sorted(records, key=lambda record: record[field])
            if any(left[field] + left[2] > right[field] for left, right in zip(ordered, ordered[1:])):
                raise ValueError
        return tuple(sorted(records, key=lambda record: record[1]))
    except (ValueError, UnicodeError):
        raise RuntimeError("live user namespace ID map is malformed or overlapping") from None


def _projection_from_record(value: Any) -> Any:
    from tools.gate01.oci_rootfs import OwnershipProjection
    if not isinstance(value, dict) or set(value) != {"allow_identity", "uid_ranges", "gid_ranges"} or value["allow_identity"] is not False:
        raise RuntimeError("live user namespace projection schema is invalid")
    ranges = {}
    for kind in ("uid", "gid"):
        records = value[kind + "_ranges"]
        if not isinstance(records, list) or not records or any(not isinstance(record, dict) or set(record) != {"inside", "outside", "length"} or any(type(item) is not int for item in record.values()) for record in records):
            raise RuntimeError("live user namespace projection ranges are invalid")
        encoded = "".join(f"{record['inside']} {record['outside']} {record['length']}\n" for record in records).encode("ascii")
        ranges[kind + "_ranges"] = _parse_user_namespace_map(encoded)
    return OwnershipProjection(**ranges, allow_identity=False)


class BoundLiveProcess:
    """One pidfd/proc-dir-bound PID1 identity reused until container stop."""

    def __init__(
        self,
        *,
        store: "PodmanStore",
        container: str,
        scratch: Path,
        specification: Mapping[str, Any],
        expected_executables: Mapping[str, Any],
        expected_root_anchor: Mapping[str, Any],
        pid: int,
        pidfd: int,
        proc_parent_fd: int,
        proc_fd: int,
        proc_status: os.stat_result,
        root_fd: int,
        root_status: os.stat_result,
        starttime_ticks: int,
    ) -> None:
        self.store = store
        self.container = container
        self.scratch = scratch
        self.specification = specification
        self.expected_executables = dict(expected_executables)
        self.expected_root_anchor = dict(expected_root_anchor)
        self.pid = pid
        self.pidfd = pidfd
        self.proc_parent_fd = proc_parent_fd
        self.proc_fd = proc_fd
        self.proc_status = proc_status
        self.root_fd = root_fd
        self.root_status = root_status
        self.starttime_ticks = starttime_ticks
        from tools.gate01.oci_rootfs import OwnershipProjection
        self.id_map_bytes = {
            kind: _read_proc_file(proc_fd, kind + "_map", kind + " map")
            for kind in ("uid", "gid")
        }
        self.ownership_projection = OwnershipProjection(
            uid_ranges=_parse_user_namespace_map(self.id_map_bytes["uid"]),
            gid_ranges=_parse_user_namespace_map(self.id_map_bytes["gid"]),
            allow_identity=False,
        )
        self.closed = False

    @classmethod
    def open(
        cls,
        store: "PodmanStore",
        container: str,
        scratch: Path,
        specification: Mapping[str, Any],
        expected_executables: Mapping[str, Any],
        expected_root_anchor: Mapping[str, Any],
    ) -> "BoundLiveProcess":
        inspect = _podman_inspect_record(store, container)
        state = inspect.get("State")
        if not isinstance(state, Mapping) or state.get("Running") is not True:
            raise RuntimeError("live container is not running")
        pid = state.get("Pid")
        if not isinstance(pid, int) or pid <= 1:
            raise RuntimeError("live container host PID is invalid")
        pidfd = proc_parent = proc_fd = root_fd = -1
        try:
            pidfd = os.pidfd_open(pid, 0)
            fcntl.fcntl(pidfd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            proc_parent = os.open(
                "/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            proc_fd = os.open(
                str(pid),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=proc_parent,
            )
            proc_status = os.fstat(proc_fd)
            named = os.stat(str(pid), dir_fd=proc_parent, follow_symlinks=False)
            if _stat_identity(proc_status) != _stat_identity(named):
                raise RuntimeError("live process proc directory identity changed")
            starttime = _process_starttime(
                _read_proc_file(proc_fd, "stat", "stat"), pid
            )
            root_record = specification.get("root")
            if (
                not isinstance(root_record, Mapping)
                or not isinstance(root_record.get("path"), str)
                or not Path(root_record["path"]).is_absolute()
            ):
                raise RuntimeError("effective rootfs path is absent")
            expected_root = expected_root_anchor.get("root")
            if (
                not isinstance(expected_root, Mapping)
                or not isinstance(expected_root.get("dev"), int)
                or not isinstance(expected_root.get("ino"), int)
            ):
                raise RuntimeError("audited rootfs anchor is incomplete")
            root_fd = os.open(
                "root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                dir_fd=proc_fd,
            )
            root_status = os.fstat(root_fd)
            named_root = os.stat("root", dir_fd=proc_fd, follow_symlinks=True)
            configured_root = os.lstat(root_record["path"])
            expected_identity = (expected_root["dev"], expected_root["ino"], stat.S_IFDIR)
            if (
                _stat_identity(root_status) != _stat_identity(named_root)
                or _stat_identity(root_status) != _stat_identity(configured_root)
                or _stat_identity(root_status) != expected_identity
                or not stat.S_ISDIR(root_status.st_mode)
            ):
                raise RuntimeError("live PID1 root differs from audited rootfs")
            result = cls(
                store=store,
                container=container,
                scratch=scratch,
                specification=specification,
                expected_executables=expected_executables,
                expected_root_anchor=expected_root_anchor,
                pid=pid,
                pidfd=pidfd,
                proc_parent_fd=proc_parent,
                proc_fd=proc_fd,
                proc_status=proc_status,
                root_fd=root_fd,
                root_status=root_status,
                starttime_ticks=starttime,
            )
            result.verify_identity()
            pidfd = proc_parent = proc_fd = root_fd = -1
            return result
        finally:
            primary = sys.exception()
            failure = None
            while root_fd >= 0 or proc_fd >= 0 or proc_parent >= 0 or pidfd >= 0:
                if root_fd >= 0:
                    descriptor, root_fd = root_fd, -1
                elif proc_fd >= 0:
                    descriptor, proc_fd = proc_fd, -1
                elif proc_parent >= 0:
                    descriptor, proc_parent = proc_parent, -1
                else:
                    descriptor, pidfd = pidfd, -1
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if failure is None:
                        failure = error
            if failure is not None:
                if primary is None:
                    raise failure
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")

    def verify_identity(self) -> None:
        if self.closed:
            raise RuntimeError("live process binding is closed")
        if any(_read_proc_file(self.proc_fd, kind + "_map", kind + " map") != data for kind, data in self.id_map_bytes.items()):
            raise RuntimeError("live user namespace ID mapping changed")
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise RuntimeError("live process pidfd is ready or exited")
        if _stat_identity(os.fstat(self.proc_fd)) != _stat_identity(self.proc_status):
            raise RuntimeError("live process proc directory changed")
        if _stat_version(os.fstat(self.root_fd)) != _stat_version(self.root_status):
            raise RuntimeError("live process root changed")
        named_root = os.stat("root", dir_fd=self.proc_fd, follow_symlinks=True)
        if _stat_identity(named_root) != _stat_identity(self.root_status):
            raise RuntimeError("live process root path changed")
        root_record = self.specification.get("root")
        assert isinstance(root_record, Mapping)
        configured_root = os.lstat(str(root_record["path"]))
        if _stat_identity(configured_root) != _stat_identity(self.root_status):
            raise RuntimeError("effective rootfs path was replaced")
        try:
            named = os.stat(
                str(self.pid), dir_fd=self.proc_parent_fd, follow_symlinks=False
            )
        except OSError as error:
            raise RuntimeError("live process proc path disappeared") from error
        if _stat_identity(named) != _stat_identity(self.proc_status):
            raise RuntimeError("live process PID was reused")
        current_starttime = _process_starttime(
            _read_proc_file(self.proc_fd, "stat", "stat"), self.pid
        )
        if current_starttime != self.starttime_ticks:
            raise RuntimeError("live process starttime changed or PID was reused")
        inspect = _podman_inspect_record(self.store, self.container)
        state = inspect.get("State")
        if (
            not isinstance(state, Mapping)
            or state.get("Running") is not True
            or state.get("Pid") != self.pid
        ):
            raise RuntimeError("live container PID identity changed")

    def capture(self) -> dict[str, Any]:
        self.verify_identity()
        record = _capture_live_process_record_from_bound(self)
        self.verify_identity()
        return record

    def close(self) -> None:
        if self.closed:
            return
        _release_fd_0 = self.root_fd
        _release_fd_1 = self.proc_fd
        _release_fd_2 = self.proc_parent_fd
        _release_fd_3 = self.pidfd
        self.closed = True
        self.root_fd = self.proc_fd = self.proc_parent_fd = self.pidfd = -1
        _numeric_failure = None
        _numeric_fd = _release_fd_0
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = _release_fd_1
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = _release_fd_2
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = _release_fd_3
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bound descriptor release failed") from _numeric_failure


def _expected_executable(
    expected: Mapping[str, Any], path: str
) -> Mapping[str, Any]:
    value = expected.get(path)
    keys = {"content_sha256", "dev", "gid", "ino", "mode", "size", "uid"}
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("content_sha256"))) is None
        or any(not isinstance(value.get(key), int) for key in keys - {"content_sha256"})
        or value.get("ino", 0) <= 0
        or value.get("size", 0) <= 0
        or not (int(value.get("mode", 0)) & 0o111)
    ):
        raise RuntimeError(f"live process executable is absent from audited rootfs: {path}")
    return value


def _attest_executable_descriptor(
    descriptor: int,
    path: str,
    expected_executables: Mapping[str, Any],
    *,
    ownership_projection: Any,
) -> dict[str, Any]:
    expected = _expected_executable(expected_executables, path)
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("live process maps a non-regular rootfs object")
    first_digest = _hash_descriptor(descriptor)
    middle = os.fstat(descriptor)
    second_digest = _hash_descriptor(descriptor)
    after = os.fstat(descriptor)
    if _stat_version(before) != _stat_version(after):
        raise RuntimeError("live process mapped file changed while hashing")
    if _stat_version(before) != _stat_version(middle) or first_digest != second_digest:
        raise RuntimeError("live process mapped file bytes were not stable")
    observed = {
        "content_sha256": second_digest,
        "dev": after.st_dev,
        "gid": ownership_projection.gid(after.st_gid),
        "ino": after.st_ino,
        "mode": stat.S_IMODE(after.st_mode),
        "size": after.st_size,
        "uid": ownership_projection.uid(after.st_uid),
    }
    if observed != dict(expected):
        raise RuntimeError(f"live process mapped file differs from audited rootfs: {path}")
    return {
        "dev": after.st_dev,
        "gid": observed["gid"],
        "ino": after.st_ino,
        "mode": stat.S_IMODE(after.st_mode),
        "path": path,
        "sha256": second_digest,
        "size": after.st_size,
        "uid": observed["uid"],
    }


def _open_rootfs_file(root_fd: int, path: str) -> int:
    pure = Path(path)
    if not path.startswith("/") or path == "/" or ".." in pure.parts:
        raise RuntimeError("live process mapped path is unsafe")
    encoded = os.fsencode(path)
    if b"\0" in encoded:
        raise RuntimeError("live process mapped path contains NUL")
    how = _OpenHow(
        flags=os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
        mode=0,
        resolve=_RESOLVE_IN_ROOT | _RESOLVE_NO_MAGICLINKS,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.syscall(
        ctypes.c_long(_SYS_OPENAT2),
        ctypes.c_int(root_fd),
        ctypes.c_char_p(encoded),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if descriptor < 0:
        error = ctypes.get_errno()
        raise RuntimeError(
            f"cannot resolve live executable beneath audited rootfs: {os.strerror(error)}"
        )
    return descriptor


def _read_proc_links(proc_fd: int, relative: str) -> dict[str, str]:
    directory = os.open(
        relative,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=proc_fd,
    )
    try:
        before = os.fstat(directory)
        names = sorted(os.listdir(directory), key=lambda item: int(item))
        if len(names) != len(set(names)) or any(not item.isdecimal() for item in names):
            raise RuntimeError("live process fd directory is malformed")
        result: dict[str, str] = {}
        for name in names:
            target = os.readlink(name, dir_fd=directory)
            if target.startswith("pipe:[") and target.endswith("]"):
                target = "pipe"
            result[name] = target
        if names != sorted(os.listdir(directory), key=lambda item: int(item)):
            raise RuntimeError("live process fd set changed during attestation")
        if _stat_version(before) != _stat_version(os.fstat(directory)):
            raise RuntimeError("live process fd directory changed during attestation")
        return result
    finally:
        _release_primary = sys.exception()
        try:
            os.close(directory)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _capture_live_process_record_from_bound(
    bound: BoundLiveProcess,
) -> dict[str, Any]:
    store = bound.store
    container = bound.container
    scratch = bound.scratch
    specification = bound.specification
    pid = bound.pid
    root_record = specification.get("root")
    assert isinstance(root_record, Mapping) and isinstance(root_record.get("path"), str)
    rootfs = Path(root_record["path"])

    try:
        status_lines = _read_proc_file(bound.proc_fd, "status", "status").decode(
            "ascii", errors="strict"
        ).splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("live process status is not ASCII") from error
    status_fields: dict[str, str] = {}
    for line in status_lines:
        name, separator, value = line.partition(":")
        if separator:
            status_fields[name] = value.strip()
    required_status = {
        "Uid", "Gid", "NSpid", "Threads", "NoNewPrivs", "Seccomp",
        "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
    }
    if not required_status <= set(status_fields):
        raise RuntimeError("live process status is incomplete")

    exe_target = os.readlink("exe", dir_fd=bound.proc_fd)
    exe_path, _unused = _normalize_rootfs_path(rootfs, exe_target)
    exe_descriptor = os.open(
        "exe", os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=bound.proc_fd
    )
    try:
        exe = _attest_executable_descriptor(
            exe_descriptor, exe_path, bound.expected_executables,
            ownership_projection=bound.ownership_projection,
        )
    finally:
        _release_primary = sys.exception()
        try:
            os.close(exe_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    cwd_target = os.readlink("cwd", dir_fd=bound.proc_fd)
    cwd, _unused = _normalize_rootfs_path(rootfs, cwd_target)

    first_maps_raw = _read_proc_file(bound.proc_fd, "maps", "maps")
    executable_maps, anonymous_maps = _parse_executable_maps(first_maps_raw)
    mapped_files: dict[str, dict[str, Any]] = {}
    for mapping in executable_maps:
        normalized, _unused = _normalize_rootfs_path(rootfs, mapping["path"])
        descriptor = _open_rootfs_file(bound.root_fd, normalized)
        try:
            opened = os.fstat(descriptor)
            if (
                os.major(opened.st_dev) != mapping["device_major"]
                or os.minor(opened.st_dev) != mapping["device_minor"]
                or opened.st_ino != mapping["inode"]
            ):
                raise RuntimeError(
                    "live process mapped pathname differs from mapped inode"
                )
            record = _attest_executable_descriptor(
                descriptor, normalized, bound.expected_executables,
                ownership_projection=bound.ownership_projection,
            )
            final_opened = os.fstat(descriptor)
            if (
                os.major(final_opened.st_dev) != mapping["device_major"]
                or os.minor(final_opened.st_dev) != mapping["device_minor"]
                or final_opened.st_ino != mapping["inode"]
            ):
                raise RuntimeError("live process mapped inode changed during hashing")
        finally:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        previous = mapped_files.get(normalized)
        if previous is None:
            record["ranges"] = [mapping["range"]]
            mapped_files[normalized] = record
        else:
            comparable = dict(previous)
            comparable.pop("ranges")
            if comparable != record or mapping["range"] in previous["ranges"]:
                raise RuntimeError("live process mapped file identity is inconsistent")
            previous["ranges"].append(mapping["range"])
    if exe_path not in mapped_files:
        raise RuntimeError("live process executable is absent from executable maps")
    second_maps_raw = _read_proc_file(bound.proc_fd, "maps", "maps")
    if second_maps_raw != first_maps_raw:
        raise RuntimeError("live process maps changed during attestation")

    fds = _read_proc_links(bound.proc_fd, "fd")

    top_result = store.run(("top", container, "hpid,pid,comm"))
    top_lines = top_result.stdout.decode("utf-8", errors="strict").splitlines()
    if len(top_lines) < 2:
        raise RuntimeError("Podman top process record is incomplete")
    top: list[dict[str, Any]] = []
    for line in top_lines[1:]:
        fields = line.split(None, 2)
        if len(fields) != 3:
            raise RuntimeError("Podman top process record is malformed")
        top.append({"host_pid": int(fields[0]), "pid": int(fields[1]), "comm": fields[2]})

    try:
        interface_text = _read_proc_file(bound.proc_fd, "net/dev", "network devices").decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("live process network devices are not ASCII") from error
    interface_lines = interface_text.splitlines()[2:]
    interfaces = sorted(line.split(":", 1)[0].strip() for line in interface_lines)
    listeners: list[str] = []
    for protocol in ("tcp", "tcp6", "udp", "udp6", "unix"):
        try:
            protocol_text = _read_proc_file(
                bound.proc_fd, f"net/{protocol}", f"network {protocol}"
            ).decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError("live process network table is not ASCII") from error
        for line in protocol_text.splitlines()[1:]:
            if line.strip():
                listeners.append(f"{protocol}:{line.strip()}")
    route_text = _read_proc_file(bound.proc_fd, "net/route", "network routes").decode(
        "ascii", errors="strict"
    )
    routes = [line.strip() for line in route_text.splitlines()[1:] if line.strip()]

    scratch_descriptor = os.open(
        "tmp/work",
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=bound.root_fd,
    )
    try:
        mounted_scratch_status = os.fstat(scratch_descriptor)
        names_before = tuple(sorted(os.listdir(scratch_descriptor)))
        names_after = tuple(sorted(os.listdir(scratch_descriptor)))
    finally:
        _release_primary = sys.exception()
        try:
            os.close(scratch_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    scratch_status = scratch.lstat()
    scratch_empty = (
        _stat_identity(scratch_status) == _stat_identity(mounted_scratch_status)
        and names_before == names_after == ()
    )
    mount_raw = _read_proc_file(bound.proc_fd, "mountinfo", "mountinfo")
    mount_graph = _verify_live_mountinfo(mount_raw, specification, ownership_projection=bound.ownership_projection)
    root_device = f"{os.major(bound.root_status.st_dev)}:{os.minor(bound.root_status.st_dev)}"
    if mount_graph.get("root_device") != root_device:
        raise RuntimeError("live process root mount differs from held audited root")
    mount_sha256 = hashlib.sha256(mount_raw).hexdigest()
    namespaces = {
        name: os.readlink(f"ns/{name}", dir_fd=bound.proc_fd)
        for name in ("cgroup", "ipc", "mnt", "net", "pid", "uts")
    }
    children_text = _read_proc_file(
        bound.proc_fd, f"task/{pid}/children", "children"
    ).decode("ascii", errors="strict").strip()
    children = [] if not children_text else [int(item) for item in children_text.split()]
    proc_status = os.fstat(bound.proc_fd)
    return {
        "anonymous_executable_maps": anonymous_maps,
        "ownership_projection": _json_safe(bound.ownership_projection),
        "capabilities": {
            "ambient": int(status_fields["CapAmb"], 16),
            "bounding": int(status_fields["CapBnd"], 16),
            "effective": int(status_fields["CapEff"], 16),
            "inheritable": int(status_fields["CapInh"], 16),
            "permitted": int(status_fields["CapPrm"], 16),
        },
        "children": children,
        "cgroup": _read_proc_file(bound.proc_fd, "cgroup", "cgroup").decode(
            "ascii", errors="strict"
        ).strip(),
        "cmdline": _decode_proc_nul(
            _read_proc_file(bound.proc_fd, "cmdline", "cmdline"), "cmdline"
        ),
        "cwd": cwd,
        "environment": sorted(
            _decode_proc_nul(
                _read_proc_file(bound.proc_fd, "environ", "environment"),
                "environment",
            )
        ),
        "exe": exe,
        "fds": fds,
        "gid": [int(item) for item in status_fields["Gid"].split()],
        "mapped_files": mapped_files,
        "mount_contract": "verified",
        "mount_graph": mount_graph,
        "mount_sha256": mount_sha256,
        "namespaces": namespaces,
        "network": {"interfaces": interfaces, "listeners": listeners, "routes": routes},
        "no_new_privileges": int(status_fields["NoNewPrivs"]),
        "nspid": [int(item) for item in status_fields["NSpid"].split()],
        "pid_identity": {
            "host_pid": pid,
            "pidfd_bound": True,
            "proc_dev": proc_status.st_dev,
            "proc_ino": proc_status.st_ino,
            "starttime_ticks": bound.starttime_ticks,
        },
        "scratch_empty": scratch_empty,
        "seccomp": int(status_fields["Seccomp"]),
        "threads": int(status_fields["Threads"]),
        "top": top,
        "uid": [int(item) for item in status_fields["Uid"].split()],
    }
def validate_effective_oci_spec(
    specification: Mapping[str, Any],
    *,
    scratch: Path,
    scratch_identity: tuple[int, int],
    rootfs_path: Path,
    static_directory: Path,
    runtime_directory: Path,
) -> dict[str, Any]:
    """Validate the exact Podman 5.7/crun 1.21 generated OCI config."""
    expected_top = {
        "annotations", "hostname", "linux", "mounts", "ociVersion", "process", "root"
    }
    if set(specification) != expected_top:
        if "hooks" in specification:
            raise ValueError("effective OCI hooks key must be absent")
        raise ValueError("effective OCI top-level field set is not exact")
    root = specification.get("root")
    process = specification.get("process")
    linux = specification.get("linux")
    if (
        not isinstance(root, dict)
        or set(root) != {"path", "readonly"}
        or root.get("readonly") is not True
        or root.get("path") != os.fspath(rootfs_path)
    ):
        raise ValueError("effective OCI root field contract is not exact")
    if not isinstance(process, dict) or set(process) != {
        "args", "capabilities", "cwd", "env", "noNewPrivileges", "rlimits", "user"
    }:
        raise ValueError("effective OCI process field set is not exact")
    if process.get("args") != [
        "/usr/bin/sleep", "infinity"
    ]:
        raise ValueError("effective OCI PID1 is not exact")
    expected_env = [
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC",
        "SOURCE_DATE_EPOCH=1787899659", "HOME=/tmp",
        "HOSTNAME=openmythos-builder",
    ]
    if process.get("env") != expected_env:
        raise ValueError("effective OCI ordered environment is not exact")
    if process.get("capabilities") != {}:
        raise ValueError("effective OCI capabilities are not empty")
    if (
        process.get("cwd") != "/"
        or process.get("noNewPrivileges") is not True
        or process.get("user") != {"uid": 0, "gid": 0, "umask": 18}
        or process.get("rlimits")
        != [
            {"type": "RLIMIT_NOFILE", "hard": 65535, "soft": 65535},
            {"type": "RLIMIT_NPROC", "hard": 4096, "soft": 4096},
        ]
    ):
        raise ValueError("effective OCI process security contract is not exact")
    if not isinstance(linux, dict) or set(linux) != {
        "maskedPaths", "namespaces", "readonlyPaths", "resources", "seccomp"
    }:
        raise ValueError("effective OCI linux field set is not exact")
    expected_namespaces = [
        {"type": value}
        for value in ("pid", "network", "ipc", "uts", "mount", "cgroup")
    ]
    if linux.get("namespaces") != expected_namespaces:
        raise ValueError("effective OCI namespace contract is not exact")
    if linux.get("maskedPaths") != list(EXPECTED_MASKED_PATHS):
        raise ValueError("effective OCI masked-path contract is not exact")
    if linux.get("readonlyPaths") != list(EXPECTED_READONLY_PATHS):
        raise ValueError("effective OCI read-only-path contract is not exact")
    if linux.get("resources") != {"pids": {"limit": 8192}}:
        raise ValueError("effective OCI resource contract is not exact")
    if specification.get("ociVersion") != "1.2.1":
        raise ValueError("effective OCI version is not exact")
    if specification.get("hostname") != os.uname().nodename:
        raise ValueError("effective OCI host hostname field is not exact")
    if specification.get("annotations") != {
        "io.container.manager": "libpod",
        "io.podman.annotations.label": "disable",
        "io.podman.annotations.pids-limit": "8192",
        "org.opencontainers.image.stopSignal": "15",
        "org.systemd.property.KillSignal": "15",
        "org.systemd.property.TimeoutStopUSec": "uint64 10000000",
    }:
        raise ValueError("effective OCI annotations are not exact")

    mounts = specification.get("mounts")
    if not isinstance(mounts, list):
        raise ValueError("effective OCI mount list is absent")
    scratch_status = scratch.lstat()
    if scratch.is_symlink() or not stat.S_ISDIR(scratch_status.st_mode):
        raise ValueError("effective OCI scratch source is unsafe")
    if (scratch_status.st_dev, scratch_status.st_ino) != scratch_identity:
        raise ValueError("effective OCI scratch source identity changed")
    rootfs_status = rootfs_path.lstat()
    if rootfs_path.is_symlink() or not stat.S_ISDIR(rootfs_status.st_mode):
        raise ValueError("effective OCI rootfs path is unsafe")
    static_status = static_directory.lstat()
    runtime_status = runtime_directory.lstat()
    if (
        static_directory.is_symlink()
        or runtime_directory.is_symlink()
        or not stat.S_ISDIR(static_status.st_mode)
        or not stat.S_ISDIR(runtime_status.st_mode)
    ):
        raise ValueError("effective OCI runtime directories are unsafe")
    expected_mounts = [
        ("/tmp", "tmpfs", "tmpfs", ("rw", "nosuid", "nodev", "exec", "mode=1777", "rprivate", "tmpcopyup")),
        ("/proc", "proc", "proc", ("nosuid", "noexec", "nodev")),
        ("/dev", "tmpfs", "tmpfs", ("nosuid", "strictatime", "mode=755", "size=65536k", "ro")),
        ("/sys", "sysfs", "sysfs", ("nosuid", "noexec", "nodev", "ro")),
        ("/tmp/work", "bind", os.fspath(scratch), ("rw", "rbind", "nosuid", "nodev", "rprivate")),
        ("/dev/pts", "devpts", "devpts", ("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5")),
        ("/dev/mqueue", "mqueue", "mqueue", ("nosuid", "noexec", "nodev")),
        ("/dev/shm", "bind", os.fspath(static_directory / "shm"), ("bind", "rprivate", "ro", "nosuid", "noexec", "nodev", "nosuid", "noexec", "nodev")),
        ("/run/.containerenv", "bind", os.fspath(runtime_directory / ".containerenv"), ("bind", "rprivate", "ro", "nosuid", "noexec", "nodev")),
        ("/sys/fs/cgroup", "cgroup", "cgroup", ("rprivate", "nosuid", "noexec", "nodev", "relatime", "ro")),
    ]
    normalized_mounts: list[tuple[str, str, str, tuple[str, ...]]] = []
    for item in mounts:
        if set(item) != {"destination", "type", "source", "options"} or not isinstance(item.get("options"), list):
            raise ValueError("effective OCI mount record is malformed")
        normalized_mounts.append(
            (item["destination"], item["type"], item["source"], tuple(item["options"]))
        )
    if normalized_mounts != expected_mounts:
        raise ValueError(
            "effective OCI ordered mount contract is not exact: "
            + json.dumps(
                {
                    "expected": _json_safe(expected_mounts),
                    "observed": _json_safe(normalized_mounts),
                },
                sort_keys=True,
            )
        )
    normalized_fixture = json.loads(json.dumps(specification))
    normalized_fixture["root"]["path"] = "$ROOTFS"
    normalized_fixture["hostname"] = "$HOST_HOSTNAME"
    replacements = {
        "/tmp/work": "$SCRATCH",
        "/dev/shm": "$STATIC/shm",
        "/run/.containerenv": "$RUNTIME/.containerenv",
    }
    for mount in normalized_fixture["mounts"]:
        if mount["destination"] in replacements:
            mount["source"] = replacements[mount["destination"]]
    fixture_sha256 = "ca99bb49d1e51ab415dcccf2f14f1026f7cf87911c62e0491cc619633f9d7b30"
    if _object_sha256(normalized_fixture) != fixture_sha256:
        raise ValueError("effective OCI config differs from the pinned canonical fixture")
    return {
        "canonical_fixture_sha256": fixture_sha256,
        "environment": expected_env,
        "hooks_present": False,
        "mount_destinations": [item[0] for item in expected_mounts],
        "namespace_types": [item["type"] for item in expected_namespaces],
        "pid1": process["args"],
        "root_read_only": True,
    }
def _container_config_files(runtime: Path) -> tuple[Path, Path]:
    containers = runtime / "containers.conf"
    storage = runtime / "storage.conf"
    _write_public_file(
        containers,
        (
            "[containers]\n"
            "default_capabilities=[]\n"
            "default_sysctls=[]\n"
            "env=[]\n"
            "volumes=[]\n"
            "[engine]\n"
            "events_logger=\"file\"\n"
            "hooks_dir=[]\n"
            "runtime=\"/usr/bin/crun\"\n"
        ).encode("ascii"),
    )
    # Root/runroot remain explicit CLI arguments; this file prevents ambient
    # storage options and helpers from entering the execution contract.
    _write_public_file(storage, b"[storage]\ndriver=\"vfs\"\n")
    return containers, storage
def _remove_podman_store(store: PodmanStore) -> None:
    if store._scope_closed:
        raise RuntimeError("Podman store cleanup authority has been permanently released")
    # Scope custody outlives all exact-name material cleanup, including partial
    # initialization and failed removal. It is never a success-only resource.
    try:
        _remove_podman_store_material(store)
    finally:
        _release_primary = sys.exception()
        try:
            store.close_scope()
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _remove_podman_store_material(store: PodmanStore) -> None:
    primary: BaseException | None = None
    if not store._directory_bindings and not store.base.exists():
        return
    # Explicit stale-store cleanup also starts with a held, owned base. A store
    # initialized by this invocation keeps its original bindings on every path.
    if not store._directory_bindings:
        if store._initialization_started:
            raise RuntimeError("failed store initialization has no retained base custody")
        binding = BoundScratch.open(store.base, label="store-base")
        try:
            store._directory_bindings["store-base"] = binding
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(binding, None, drain=_drain_bound_scratch)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_scratch(binding)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise
        index = 0
        while index < 3:
            label = "store-graphroot" if index == 0 else "store-runroot" if index == 1 else "store-tmpdir"
            index += 1
            path = store.graphroot if label == "store-graphroot" else store.runroot if label == "store-runroot" else store.tmpdir
            try:
                if path.exists():
                    binding = BoundScratch.open(path, label=label)
                    try:
                        store._directory_bindings[label] = binding
                    except BaseException as error:
                        try:
                            try:
                                _close_resource_preserving_primary(binding, None, drain=_drain_bound_scratch)
                            except BaseException as _drain_primary:
                                _drain_attempts = 2
                                while _drain_attempts:
                                    _drain_attempts -= 1
                                    try:
                                        _drain_bound_scratch(binding)
                                        break
                                    except BaseException:
                                        _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                                raise
                        except BaseException:
                            _add_cleanup_note(error, "additional bound descriptor cleanup failed")
                        raise
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    _add_cleanup_note(primary, "additional Podman store child acquisition failed")
    base_binding = store._directory_bindings["store-base"]
    try:
        base_binding.verify()
    except BaseException:
        if primary is None:
            raise
        _add_cleanup_note(primary, "additional Podman store base verification failed")
        # Loss of the exact base anchor revokes all pathname deletion, but it
        # must not replace an earlier acquisition failure.
        raise primary
    index = 0
    while index < 3:
        label = "store-graphroot" if index == 0 else "store-runroot" if index == 1 else "store-tmpdir"
        index += 1
        binding = store._directory_bindings.get(label)
        try:
            if binding is not None:
                binding.verify()
            else:
                # A negative pathname observation is not authority for a
                # future combined-command target. Partial stores use only
                # individually held fallback bindings.
                raise RuntimeError("Podman store command child has no original custody")
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                _add_cleanup_note(primary, "additional Podman store child verification failed")
    if not store._initialization_started and store._cleanup_arguments is None:
        try:
            store._prepare_cleanup_command()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                _add_cleanup_note(primary, "additional Podman store command preparation failed")
    completed = store._cleanup_completion
    completed[0] = None
    if primary is None:
        try:
            if store._cleanup_arguments is None or store._cleanup_pass_fds is None:
                raise RuntimeError("Podman store initialization did not prepare cleanup command")
            result = store.run(
                store._cleanup_arguments,
                pass_fds=store._cleanup_pass_fds,
                check=False,
                completed=completed,
            )
            if result.returncode != 0:
                raise RuntimeError("Podman store user-namespace cleanup failed")
        except BaseException as error:
            primary = error
    # Policy release may fail after a proven successful subprocess. Only that
    # exact retained outcome authorizes the existing recreated-child grammar;
    # an arbitrary raised run never grants authority over replacements.
    command_failed = primary is not None and not (
        completed[0] is not None and completed[0].returncode == 0
    )
    # Starting `podman unshare` may recreate its own tmp/alive bookkeeping
    # after the in-namespace rm has completed.  Once that Podman process has
    # exited, remove only the three exact invocation-owned children again.
    try:
        base_binding.verify()
        if not command_failed:
            index = 0
            while index < 3:
                label = "store-graphroot" if index == 0 else "store-runroot" if index == 1 else "store-tmpdir"
                index += 1
                try:
                    binding = store._directory_bindings.get(label)
                    if binding is not None and os.fstat(binding.descriptor).st_nlink != 0:
                        raise RuntimeError("Podman store cleanup did not remove its original directory")
                except BaseException as error:
                    if primary is None:
                        primary = error
                    else:
                        _add_cleanup_note(primary, "additional Podman store original-directory cleanup failed")
        failures: BaseException | None = None
        index = 0
        while index < 3:
            name = "root" if index == 0 else "runroot" if index == 1 else "tmp"
            index += 1
            try:
                try:
                    status = os.stat(name, dir_fd=base_binding.descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(status.st_mode) or status.st_uid != os.getuid() or status.st_gid != os.getgid():
                    raise RuntimeError("Podman store cleanup recreated unsafe metadata")
                original = store._directory_bindings.get("store-graphroot" if name == "root" else "store-runroot" if name == "runroot" else "store-tmpdir")
                if command_failed and original is None:
                    raise RuntimeError("Podman store fallback child has no original custody")
                if original is not None and (command_failed or os.fstat(original.descriptor).st_nlink != 0):
                    # A failed command may leave our original child. Its held
                    # custody remains mandatory; a replacement is not adopted.
                    original.verify()
                shutil.rmtree(name, dir_fd=base_binding.descriptor)
            except BaseException as error:
                if primary is not None:
                    _add_cleanup_note(primary, "additional Podman store child cleanup failed")
                if failures is None:
                    failures = error
        try:
            base_binding.verify()
            # Unknown children are never traversed or adopted. rmdir refuses
            # a nonempty base without an allocating enumeration/empty plan.
            os.rmdir(base_binding.name, dir_fd=base_binding.parent_descriptor)
        except BaseException as error:
            if primary is not None:
                _add_cleanup_note(primary, "additional Podman store base removal failed")
            if failures is None:
                failures = error
        if failures:
            raise RuntimeError("Podman store recreated-child cleanup failed") from failures
    except BaseException:
        if primary is None:
            raise
        _add_cleanup_note(primary, "additional Podman store material cleanup failed")
    if primary is not None:
        raise primary
def _oci_summary_fixed(arguments: argparse.Namespace) -> int:
    from tools.gate01.oci_rootfs import canonicalize_oci_archive

    value = canonicalize_oci_archive(
        OCI_ARCHIVE_FD,
        expected_archive_sha256=arguments.archive_sha256,
        expected_manifest_digest=arguments.manifest_digest,
    )
    print(
        json.dumps(
            {
                "archive_sha256": value.archive_sha256,
                "config_digest": value.config_digest,
                "diff_ids": list(value.diff_ids),
                "non_root_entry_count": len(value.entries) - 1,
                "layer_digests": list(value.layer_digests),
                "manifest_digest": value.manifest_digest,
                "root_entry": _json_safe(value.entries["/"]),
                "semantic_sha256": _object_sha256(value.entries),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0
def _lifecycle_exec_check() -> int:
    """Prove that an ordinary exec receives only its declared sealed verifier."""
    _require_sealed_regular_descriptor(VERIFIER_FD, "verifier capsule")
    try:
        os.fstat(BUILD_KEY_FD)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise RuntimeError("private key leaked into no-build lifecycle probe")
    print(json.dumps({"verdict": "pass", "verifier_fd": VERIFIER_FD}), flush=True)
    return 0

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit_worker = subparsers.add_parser("rootfs-audit-worker")
    audit_worker.add_argument("--store-root", required=True)
    audit_worker.add_argument("--runroot", required=True)
    audit_worker.add_argument("--tmpdir", required=True)
    audit_worker.add_argument("--container", required=True)
    audit_worker.add_argument(
        "--phase", required=True, choices=("before", "authorized", "after")
    )
    audit_worker.add_argument("--rootfs-path", required=True)
    audit_worker.add_argument("--archive-sha256", required=True)
    audit_worker.add_argument("--manifest-digest", required=True)
    attest = subparsers.add_parser("attest-live")
    attest.add_argument("--scratch-dev", required=True, type=int)
    attest.add_argument("--scratch-ino", required=True, type=int)
    attest.add_argument("--nonce", required=True)
    oci_summary = subparsers.add_parser("oci-summary-fixed")
    oci_summary.add_argument("--archive-sha256", required=True)
    oci_summary.add_argument("--manifest-digest", required=True)
    subparsers.add_parser("lifecycle-exec-check")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "rootfs-audit-worker":
        return _rootfs_audit_worker(arguments)
    if arguments.command == "attest-live":
        return _attest_live_container(arguments)
    if arguments.command == "oci-summary-fixed":
        return _oci_summary_fixed(arguments)
    if arguments.command == "lifecycle-exec-check":
        return _lifecycle_exec_check()
    raise AssertionError(arguments.command)


_drain_podman_policy = SealedPodmanPolicy.close
_drain_bound_scratch = BoundScratch.close
_drain_bound_store_path = BoundStorePath.close
_drain_watched_runtime_bindings = WatchedRuntimeBindings.close
_drain_bound_live_process = BoundLiveProcess.close
_drain_container_backend = PodmanContainerBackend.close


if __name__ == "__main__":
    raise SystemExit(main())
