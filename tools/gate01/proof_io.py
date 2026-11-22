"""Descriptor-custody, anonymous-output, scan, and receipt primitives for Gate 01."""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, fields, is_dataclass
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from types import TracebackType
from typing import Any, Callable, Iterable, Mapping
import zipfile

SOURCE_DATE_EPOCH = 1_787_899_659
VERIFIER_FD = 20
PUBLIC_CERTIFICATE_FD = 21
BUILD_KEY_FD = 25
BUILD_RESULT_FD = 26
ARTIFACT_FD_ROLES = {"srpm": 30, "core": 31, "modules": 32, "meta": 33}
EVIDENCE_FD_ROLES = {"rpm_manifest": 40, "installed_files": 41, "result": 42}
RECEIPT_SCHEMA_VERSION = 1
RECEIPT_PROTOCOL = "openmythos-gate01-detached-tree-v1"
EVIDENCE_RECEIPT_PROTOCOL = "openmythos-gate01-detached-evidence-v1"
HASH_CHUNK_SIZE = 1024 * 1024
OCI_ARCHIVE_FD = 18
RUNTIME_CONTAINERENV_FD = 19
SOURCE_ARCHIVE_FD = 22
CONFIG_FD = 23
SPEC_FD = 24
INPUT_AUDIT_FD_ROLES = {
    "source_lock": 50,
    "toolchain_lock": 51,
    "source_archive": 52,
    "toolchain_archive": 53,
    "config": 54,
    "config_checksum": 55,
    "config_requirements": 56,
    "public_manifest": 57,
}
EXPECTED_RPM_FILENAMES = {
    "srpm": "kernel-openmythos-6.18.48-1.openmythos.fc44.src.rpm",
    "meta": "kernel-openmythos-6.18.48-1.openmythos.fc44.x86_64.rpm",
    "core": "kernel-openmythos-core-6.18.48-1.openmythos.fc44.x86_64.rpm",
    "modules": "kernel-openmythos-modules-6.18.48-1.openmythos.fc44.x86_64.rpm",
}

@contextmanager
def _owned_resource(factory: Callable[..., Any], drain: Callable[[Any], None], /, *args: Any, **kwargs: Any) -> Iterable[Any]:
    """Delay acquisition until context entry has installed its cleanup path."""
    resource = factory(*args, **kwargs)
    try:
        yield resource
    except BaseException as primary:
        try:
            _close_resource_preserving_primary(resource, primary, drain=drain)
        except BaseException as _drain_primary:
            _drain_attempts = 2
            while _drain_attempts:
                _drain_attempts -= 1
                try:
                    drain(resource)
                    break
                except BaseException:
                    _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
            if primary is None:
                raise
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
        raise
    else:
        try:
            _close_resource_preserving_primary(resource, None, drain=drain)
        except BaseException as _drain_primary:
            _drain_attempts = 2
            while _drain_attempts:
                _drain_attempts -= 1
                try:
                    drain(resource)
                    break
                except BaseException:
                    _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
            raise

def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
def _json_safe(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _json_safe(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"value is not canonically serializable: {type(value).__name__}")
def _object_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(_json_safe(value))).hexdigest()
def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
def _stat_version(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
def _stat_identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)
def _hash_descriptor(descriptor: int) -> str:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, HASH_CHUNK_SIZE):
        digest.update(chunk)
    after = os.fstat(descriptor)
    if _stat_version(before) != _stat_version(after):
        raise RuntimeError("bound file bytes changed while hashing")
    return digest.hexdigest()
def _read_descriptor(descriptor: int) -> bytes:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, HASH_CHUNK_SIZE):
        chunks.append(chunk)
    if _stat_version(before) != _stat_version(os.fstat(descriptor)):
        raise RuntimeError("bound file bytes changed while reading")
    return b"".join(chunks)
def _open_parent_directory(path: Path) -> tuple[int, os.stat_result]:
    """Open every parent component without following a symlink."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute():
        raise ValueError("bound input path must be absolute")
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        for component in absolute.parent.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            closing, descriptor = descriptor, child
            os.close(closing)
        return descriptor, os.fstat(descriptor)
    except BaseException:
        closing, descriptor = descriptor, -1
        _release_primary = sys.exception()
        try:
            os.close(closing)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


def _write_all(descriptor: int, value: bytes | memoryview) -> None:
    """Write every byte, rejecting zero progress without ever retrying it."""
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0 or written > len(view):
            raise RuntimeError("descriptor short write made no progress")
        view = view[written:]


def _verify_written_output(descriptor: int, size: int, sha256: str) -> None:
    """Re-read the held public output before claiming its size or identity."""
    if os.fstat(descriptor).st_size != size or _hash_descriptor(descriptor) != sha256:
        raise RuntimeError("written public output identity differs")


def _release_all(actions: Iterable[Callable[[], Any]]) -> None:
    failure: BaseException | None = None
    if isinstance(actions, (tuple, list)):
        index = 0
        while index < len(actions):
            action = actions[index]
            index += 1
            try:
                action()
            except BaseException as error:
                if failure is None:
                    failure = error
    else:
        for action in actions:
            try:
                action()
            except BaseException as error:
                if failure is None:
                    failure = error
    if failure is not None:
        raise RuntimeError("bound descriptor release failed") from failure


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    """Diagnostics must never supersede a primary or interrupt later owners."""
    try:
        BaseException.add_note(primary, note)
    except BaseException:
        pass


def _close_descriptor_preserving_primary(descriptor: int, primary: BaseException | None) -> None:
    """Release one already-detached descriptor without allocating an action."""
    try:
        os.close(descriptor)
    except BaseException:
        if primary is None:
            raise
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _close_resource_preserving_primary(resource: Any, primary: BaseException | None, *, drain: Callable[[Any], None] | None = None) -> None:
    """Retain a concrete owner across a fallible custom-close handoff.

    Production callers supply a preselected unbound numeric drain. A bounded
    second entry handles an allocation fault before the first drain starts;
    an entered drain already detached each descriptor before kernel close.
    """
    try:
        resource.close()
    except BaseException as cleanup:
        if drain is not None:
            remaining = 2
            while remaining:
                remaining -= 1
                try:
                    drain(resource)
                    break
                except BaseException:
                    _add_cleanup_note(cleanup, "additional concrete descriptor drain failed")
        if primary is None:
            raise
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _close_descriptors(first: int, second: int = -1, third: int = -1, fourth: int = -1, *, primary: BaseException | None = None) -> None:
    """Small local-owner drain: no cleanup tuple, iterator, or callback allocation."""
    failure = None
    while first >= 0 or second >= 0 or third >= 0 or fourth >= 0:
        if first >= 0:
            descriptor, first = first, -1
        elif second >= 0:
            descriptor, second = second, -1
        elif third >= 0:
            descriptor, third = third, -1
        else:
            descriptor, fourth = fourth, -1
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        if primary is None:
            raise RuntimeError("bound descriptor release failed") from failure
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _close_descriptor_sequence(descriptors: Any, primary: BaseException | None = None, *, reverse: bool = False) -> None:
    """Drain an already-owned sequence without constructing a release iterator."""
    failure = None
    index = 0
    while index < len(descriptors):
        position = len(descriptors) - 1 - index if reverse else index
        descriptor = descriptors[position]
        if isinstance(descriptors, list):
            descriptors[position] = -1
        index += 1
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        if primary is None:
            raise RuntimeError("bound descriptor release failed") from failure
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _close_descriptor_mapping(descriptors: dict[Any, Any], primary: BaseException | None, *, value_index: int | None = None) -> None:
    """Drain a private ownership map without a detached aggregate snapshot."""
    failure: BaseException | None = None
    while descriptors:
        try:
            item = descriptors.popitem()
            value = item[1]
        except BaseException as error:
            if failure is None:
                failure = error
            # popitem allocates its pair before removing the entry. Retain
            # exact custody and retry through the builtin without a new iterator.
            value = dict.popitem(descriptors)[1]
        descriptor = value if value_index is None else value[value_index]
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        if primary is None:
            raise RuntimeError("bound descriptor release failed") from failure
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _close_resource_mapping(resources: dict[Any, Any], primary: BaseException | None = None, *, descriptor_attribute: str | None = None, descriptor_key: str | None = None, parent_descriptor_attribute: str | None = None, descriptor_sequence_attribute: str | None = None, closed_attribute: str | None = None, descriptor_sentinel: int | None = -1) -> None:
    """Drain only an explicit numeric contract; opaque failures retain owners."""
    failure = None
    if descriptor_attribute is None and descriptor_key is None:
        # This compatibility branch is not a terminal production drain. A
        # bounded pass retains every opaque owner whose close did not return.
        try:
            keys = tuple(resources)
        except BaseException:
            if primary is None:
                raise
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            return
        index = 0
        while index < len(keys):
            key = keys[index]
            index += 1
            value = resources[key]
            try:
                value.close()
            except BaseException as error:
                if failure is None:
                    failure = error
            else:
                del resources[key]
        if failure is not None:
            if primary is None:
                raise RuntimeError("bound descriptor release failed") from failure
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
        return
    while resources:
        # Selection does not remove authority. If iterator/key acquisition
        # fails, the caller's literal numeric fallback still owns every row.
        try:
            key = next(iter(resources))
            value = resources[key]
        except BaseException as error:
            if primary is not None:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            if failure is not None:
                _add_cleanup_note(failure, "additional bound descriptor selection failed")
                raise RuntimeError("bound descriptor release failed") from failure
            raise
        retained = False
        detached = False
        try:
            if descriptor_attribute is not None:
                descriptor = getattr(value, descriptor_attribute)
                setattr(value, descriptor_attribute, descriptor_sentinel)
                detached = True
                if descriptor is not None and descriptor >= 0:
                    os.close(descriptor)
            elif descriptor_key is not None:
                descriptor = value[descriptor_key]
                value[descriptor_key] = -1
                detached = True
                if descriptor >= 0:
                    os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
            retained = not detached
        if parent_descriptor_attribute is not None:
            detached = False
            try:
                descriptor = getattr(value, parent_descriptor_attribute)
                setattr(value, parent_descriptor_attribute, -1)
                detached = True
                if descriptor >= 0:
                    os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
                retained = retained or not detached
        if descriptor_sequence_attribute is not None:
            try:
                descriptors = getattr(value, descriptor_sequence_attribute)
                while descriptors:
                    try:
                        descriptor = descriptors.pop()
                    except BaseException as error:
                        if failure is None:
                            failure = error
                        descriptor = list.pop(descriptors)
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        if failure is None:
                            failure = error
            except BaseException as error:
                if failure is None:
                    failure = error
                retained = True
        if not retained:
            try:
                if closed_attribute is not None:
                    setattr(value, closed_attribute, True)
                del resources[key]
            except BaseException as error:
                if failure is None:
                    failure = error
                retained = True
        if retained:
            # A failed read/detach leaves this row installed. The fatal return
            # invokes the concrete caller fallback before it can discard scope.
            if primary is not None:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            raise RuntimeError("bound descriptor release failed") from failure
    if failure is not None:
        if primary is None:
            raise RuntimeError("bound descriptor release failed") from failure
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _release_preserving_primary(actions: Iterable[Callable[[], Any]], primary: BaseException | None) -> None:
    try:
        _release_all(actions)
    except BaseException:
        if primary is None:
            raise
        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
@dataclass
class _BoundFile:
    label: str
    path: Path
    name: str
    parent_descriptor: int
    parent_status: os.stat_result
    parent_names: tuple[str, ...]
    descriptor: int
    initial_status: os.stat_result
    initial_sha256: str | None
    policy: "InputMetadataPolicy"

    def close(self) -> None:
        _release_fd_0 = self.descriptor
        _release_fd_1 = self.parent_descriptor
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


@dataclass(frozen=True)
class InputMetadataPolicy:
    """Exact metadata accepted for one immutable regular-file input role."""

    mode: int
    uid: int
    gid: int
    nlink: int = 1

    def validate(self, status: os.stat_result, label: str) -> None:
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != self.mode
            or status.st_uid != self.uid
            or status.st_gid != self.gid
            or status.st_nlink != self.nlink
            or self.nlink != 1
            or self.mode & 0o022
        ):
            raise ValueError(f"bound input metadata policy failed: {label}")


class BoundInputs:
    """A simultaneously held set of exact regular input files."""

    def __init__(self, records: dict[str, _BoundFile]) -> None:
        self._records = records
        self._closed = False

    @classmethod
    def open(
        cls,
        paths: Mapping[str, Path],
        *,
        policies: Mapping[str, InputMetadataPolicy],
        secret_labels: Iterable[str] = (),
    ) -> "BoundInputs":
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("bound input labels must be a non-empty unique set")
        secrets = set(secret_labels)
        if not secrets <= set(paths):
            raise ValueError("secret labels must name bound inputs")
        if set(policies) != set(paths):
            raise ValueError("bound input metadata policies must match every role exactly")
        records: dict[str, _BoundFile] = {}
        try:
            for label in sorted(paths):
                raw_path = Path(paths[label])
                path = Path(os.path.abspath(os.fspath(raw_path)))
                parent_descriptor = -1
                descriptor = -1
                try:
                    parent_descriptor, parent_status = _open_parent_directory(path)
                    parent_names = tuple(sorted(os.listdir(parent_descriptor)))
                    named = os.stat(
                        path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if not stat.S_ISREG(named.st_mode):
                        raise ValueError(f"bound input must be a regular file: {label}")
                    policies[label].validate(named, label)
                    descriptor = os.open(
                        path.name,
                        os.O_RDONLY
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW
                        | os.O_NONBLOCK,
                        dir_fd=parent_descriptor,
                    )
                    opened = os.fstat(descriptor)
                    if _stat_identity(named) != _stat_identity(opened):
                        raise RuntimeError(f"bound input path identity changed: {label}")
                    policies[label].validate(opened, label)
                    digest = None if label in secrets else _hash_descriptor(descriptor)
                    if _stat_version(opened) != _stat_version(os.fstat(descriptor)):
                        raise RuntimeError(f"bound input changed while opening: {label}")
                    records[label] = _BoundFile(
                        label=label,
                        path=path,
                        name=path.name,
                        parent_descriptor=parent_descriptor,
                        parent_status=parent_status,
                        parent_names=parent_names,
                        descriptor=descriptor,
                        initial_status=opened,
                        initial_sha256=digest,
                        policy=policies[label],
                    )
                    parent_descriptor = -1
                    descriptor = -1
                finally:
                    primary = sys.exception()
                    failure = None
                    while descriptor >= 0 or parent_descriptor >= 0:
                        if descriptor >= 0:
                            closing, descriptor = descriptor, -1
                        else:
                            closing, parent_descriptor = parent_descriptor, -1
                        try:
                            os.close(closing)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                    if failure is not None:
                        if primary is None:
                            raise failure
                        _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            result = cls(records)
            result.verify_coherent()
            return result
        except BaseException as primary:
            try:
                _close_resource_mapping(records, primary, descriptor_attribute="descriptor", parent_descriptor_attribute="parent_descriptor")
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
                    _raw_fd = _raw_owner.parent_descriptor
                    _raw_owner.parent_descriptor = -1
                    if _raw_fd >= 0:
                        try:
                            os.close(_raw_fd)
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            raise

    def descriptor(self, label: str) -> int:
        return self._records[label].descriptor

    def status(self, label: str) -> os.stat_result:
        return os.fstat(self.descriptor(label))

    def read(self, label: str) -> bytes:
        return _read_descriptor(self.descriptor(label))

    @property
    def hashes(self) -> dict[str, str]:
        return {
            label: record.initial_sha256
            for label, record in sorted(self._records.items())
            if record.initial_sha256 is not None
        }

    def verify_coherent(
        self, *, after_first_pass: Callable[[], None] | None = None
    ) -> dict[str, str]:
        if self._closed:
            raise RuntimeError("bound inputs are closed")
        first = {
            label: (
                _hash_descriptor(record.descriptor)
                if record.initial_sha256 is not None
                else None
            )
            for label, record in sorted(self._records.items())
        }
        if after_first_pass is not None:
            after_first_pass()
        second = {
            label: (
                _hash_descriptor(record.descriptor)
                if record.initial_sha256 is not None
                else None
            )
            for label, record in sorted(self._records.items())
        }
        for label, record in sorted(self._records.items()):
            current = os.fstat(record.descriptor)
            parent = os.fstat(record.parent_descriptor)
            try:
                named = os.stat(
                    record.name,
                    dir_fd=record.parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise RuntimeError(
                    f"bound input path identity changed: {label}"
                ) from error
            if _stat_identity(named) != _stat_identity(record.initial_status):
                raise RuntimeError(f"bound input path identity changed: {label}")
            try:
                record.policy.validate(current, label)
                record.policy.validate(named, label)
            except ValueError as error:
                raise RuntimeError(
                    f"bound input changed after binding: {label}"
                ) from error
            if (
                first[label] != second[label]
                or first[label] != record.initial_sha256
                or _stat_version(current) != _stat_version(record.initial_status)
                or _stat_version(named) != _stat_version(record.initial_status)
            ):
                raise RuntimeError(f"bound input changed after binding: {label}")
            if (
                _stat_version(parent) != _stat_version(record.parent_status)
                or tuple(sorted(os.listdir(record.parent_descriptor)))
                != record.parent_names
            ):
                raise RuntimeError(f"bound input parent changed: {label}")

            reopened_parent, reopened_status = _open_parent_directory(record.path)
            try:
                if _stat_identity(reopened_status) != _stat_identity(
                    record.parent_status
                ):
                    raise RuntimeError(
                        f"bound input parent path identity changed: {label}"
                    )
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(reopened_parent)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        return {label: value for label, value in second.items() if value is not None}

    def close(self) -> None:
        if self._closed:
            return
        records = self._records
        try:
            try:
                _close_resource_mapping(records, descriptor_attribute="descriptor", parent_descriptor_attribute="parent_descriptor")
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
                    _raw_fd = _raw_owner.parent_descriptor
                    _raw_owner.parent_descriptor = -1
                    if _raw_fd >= 0:
                        try:
                            os.close(_raw_fd)
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                raise
        finally:
            self._closed = not records

    def __enter__(self) -> "BoundInputs":
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


SCOPED_DIFF_BASE = "cfc94e5437dac3f80deed3bad70c3d56ae4840a1"
SCOPED_DIFF_ROOTS = (
    "tools/gate01", "scripts/gate01", "tests/gate01",
    "os/kernel/config", "os/kernel/packaging",
)
SCOPED_DIFF_FILES = (
    "tools/__init__.py", "Makefile", "os/kernel/Containerfile.builder",
    "os/kernel/README.md", "os/kernel/source.lock.json",
    "docs/superpowers/plans/2026-09-03-stone-boot-proof.md",
    "docs/superpowers/specs/2026-08-31-openmythos-os-architecture-design.md",
    "os/build/toolchain.lock.json",
)
SCOPED_DIFF_FORBIDDEN = ("os/kernel/keys", "build", ".git", ".superpowers")


def _scoped_path(path: bytes) -> bool:
    return path in tuple(os.fsencode(item) for item in SCOPED_DIFF_FILES) or any(
        path == os.fsencode(root) or path.startswith(os.fsencode(root) + b"/")
        for root in SCOPED_DIFF_ROOTS
    )


def _scoped_base_entries(repository: Path) -> dict[bytes, dict[str, str]]:
    result = subprocess.run(
        ["/usr/bin/git", "--no-replace-objects", "--no-optional-locks",
         "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
         "-C", os.fspath(repository), "ls-tree", "-rtz", "--full-tree", SCOPED_DIFF_BASE],
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0 or result.stderr or (result.stdout and not result.stdout.endswith(b"\0")):
        raise RuntimeError("scoped committed-base inventory failed")
    entries: dict[bytes, dict[str, str]] = {}
    for row in result.stdout.split(b"\0")[:-1]:
        header, separator, path = row.partition(b"\t")
        if not separator or not path or path.startswith(b"/") or any(component in {b"", b".", b".."} for component in path.split(b"/")):
            raise RuntimeError("scoped committed-base record is malformed")
        match = re.fullmatch(rb"(100644|100755|040000) (blob|tree) ([0-9a-f]{40})", header)
        if not _scoped_path(path):
            continue
        if match is None or (match[1] == b"040000") != (match[2] == b"tree") or path in entries:
            raise RuntimeError("scoped committed-base type is unsupported")
        entries[path] = {"git_mode": match[1].decode("ascii"), "git_oid": match[3].decode("ascii")}
    return entries


class BoundScopedDiff:
    """Index-independent public source identity held through final cleanup.

    Only the sealed positive scope is traversed. Private key/secrets roots are
    rejected before any directory or content open; ancestor-only descriptors
    are checked by identity, not by timestamps of unrelated build activity.
    """

    def __init__(self, repository: Path) -> None:
        self.repository = repository
        self._nodes: dict[bytes, dict[str, Any]] = {}
        self._missing: set[bytes] = set()
        self._parent = -1
        self._closed = False

    @classmethod
    def open(cls, repository: Path) -> "BoundScopedDiff":
        result = cls(Path(os.path.abspath(repository)))
        try:
            for path in (*SCOPED_DIFF_ROOTS, *SCOPED_DIFF_FILES):
                if not path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")) or any(path == private or path.startswith(private + "/") or private.startswith(path + "/") for private in SCOPED_DIFF_FORBIDDEN):
                    raise RuntimeError("scoped policy overlaps forbidden private paths")
            result._base = _scoped_base_entries(result.repository)
            parent, parent_status = _open_parent_directory(result.repository)
            try:
                result._parent_status = parent_status
                result._parent = parent
            except BaseException as primary:
                _release_primary = primary
                try:
                    os.close(parent)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            root = os.open(result.repository.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=result._parent)
            try:
                result._nodes[b""] = {"fd": root, "status": None, "scoped": False}
            except BaseException as error:
                _release_primary = error
                try:
                    os.close(root)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            result._nodes[b""]["status"] = os.fstat(root)
            for relative in (*SCOPED_DIFF_ROOTS, *SCOPED_DIFF_FILES):
                result._capture(os.fsencode(relative), recursive=relative in SCOPED_DIFF_ROOTS)
            result.verify_coherent()
            current = {path: node["record"] for path, node in result._nodes.items() if node["scoped"]}
            result.manifest = {
                "schema_version": 1, "kind": "task6-scoped-diff-v1", "base_commit": SCOPED_DIFF_BASE,
                "scope_policy": {
                    "roots": list(SCOPED_DIFF_ROOTS), "files": list(SCOPED_DIFF_FILES),
                    "forbidden_private_paths_and_roots": list(SCOPED_DIFF_FORBIDDEN),
                    "excluded_cache_components": ["__pycache__"], "supported_types": ["directory", "regular"],
                    "xattrs": "reject", "regular_hardlinks": "reject",
                },
                "entries": [{"path_hex": path.hex(), "base": result._base.get(path), "current": current.get(path)} for path in sorted(set(result._base) | set(current))],
            }
            result.sha256 = _object_sha256(result.manifest)
            return result
        except BaseException as error:
            _release_primary = error
            try:
                try:
                    _close_resource_preserving_primary(result, None, drain=_drain_bound_scoped_diff)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_scoped_diff(result)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise

    def _names(self, path: bytes, descriptor: int) -> tuple[bytes, ...]:
        names = []
        for value in os.listdir(descriptor):
            name = os.fsencode(value)
            child = path + b"/" + name if path else name
            if name == b"__pycache__" and not any(item == child or item.startswith(child + b"/") for item in self._base):
                continue
            names.append(name)
        return tuple(sorted(names))

    def _capture(self, path: bytes, *, recursive: bool = False, scoped: bool = True) -> None:
        if any(path == os.fsencode(private) or path.startswith(os.fsencode(private) + b"/") for private in SCOPED_DIFF_FORBIDDEN):
            raise RuntimeError("scoped traversal reached a forbidden private path")
        if path in self._missing:
            return
        if path not in self._nodes:
            parent, _, name = path.rpartition(b"/")
            if parent not in self._nodes:
                self._capture(parent, scoped=False)
            if parent in self._missing:
                self._missing.add(path)
                return
            parent_fd = self._nodes[parent]["fd"]
            try:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                self._missing.add(path)
                return
            if not stat.S_ISDIR(named.st_mode) and (not scoped or not stat.S_ISREG(named.st_mode)):
                raise RuntimeError("scoped source node type is unsupported")
            if path in tuple(os.fsencode(item) for item in SCOPED_DIFF_FILES) and not stat.S_ISREG(named.st_mode):
                raise RuntimeError("scoped explicit public file is not regular")
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if stat.S_ISDIR(named.st_mode) else 0), dir_fd=parent_fd)
            try:
                self._nodes[path] = {"fd": descriptor, "status": None, "scoped": False}
            except BaseException as error:
                _release_primary = error
                try:
                    os.close(descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            opened = os.fstat(descriptor)
            self._nodes[path]["status"] = opened
            if _stat_version(opened) != _stat_version(named):
                raise RuntimeError("scoped source path changed during capture")
        node = self._nodes[path]
        if scoped and not node["scoped"]:
            status = node["status"]
            if os.listxattr(node["fd"]) or (stat.S_ISREG(status.st_mode) and status.st_nlink != 1):
                raise RuntimeError("scoped source metadata is unsupported")
            node["scoped"] = True
            node["record"] = {"type": "directory" if stat.S_ISDIR(status.st_mode) else "regular", "mode": f"{stat.S_IMODE(status.st_mode):04o}"}
            if stat.S_ISREG(status.st_mode):
                node["record"].update(size=status.st_size, sha256=_hash_descriptor(node["fd"]))
            else:
                node["names"] = self._names(path, node["fd"])
        if recursive:
            if not stat.S_ISDIR(node["status"].st_mode):
                # A root replaced by a regular file remains represented;
                # descendants from the pinned base are explicit deletions.
                return
            for name in node["names"]:
                self._capture(path + b"/" + name, recursive=True)

    def verify_coherent(self) -> None:
        if self._closed:
            raise RuntimeError("scoped source custody is closed")
        try:
            for _ in range(2):
                for path, node in sorted(self._nodes.items()):
                    if node["scoped"] and stat.S_ISREG(node["status"].st_mode) and _hash_descriptor(node["fd"]) != node["record"]["sha256"]:
                        raise RuntimeError("scoped source bytes changed")
                # Terminal sweep catches an earlier node mutated/restored
                # while hashing a later node in this same pass.
                for path, node in sorted(self._nodes.items()):
                    parent, _, name = path.rpartition(b"/")
                    named = os.stat(name if path else self.repository.name, dir_fd=self._nodes[parent]["fd"] if path else self._parent, follow_symlinks=False)
                    current = os.fstat(node["fd"])
                    compare = _stat_version if node["scoped"] else _stat_identity
                    if compare(current) != compare(node["status"]) or compare(named) != compare(node["status"]):
                        raise RuntimeError("scoped source identity or version changed")
                    if node["scoped"] and (os.listxattr(node["fd"]) or (stat.S_ISDIR(current.st_mode) and self._names(path, node["fd"]) != node["names"])):
                        raise RuntimeError("scoped source metadata or names changed")
                for path in self._missing:
                    parent, _, name = path.rpartition(b"/")
                    if parent not in self._nodes:
                        continue
                    try:
                        os.stat(name, dir_fd=self._nodes[parent]["fd"], follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise RuntimeError("scoped absent source appeared")
            reopened, status = _open_parent_directory(self.repository)
            try:
                if _stat_identity(status) != _stat_identity(self._parent_status):
                    raise RuntimeError("scoped repository ancestor changed")
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(reopened)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        except (OSError, ValueError) as error:
            raise RuntimeError("scoped source revalidation failed") from error

    def verify_closure(self, authority: Mapping[str, Any]) -> None:
        self.verify_coherent()
        for path in authority["ordered_paths"]:
            node = self._nodes.get(os.fsencode(path))
            expected = {"type": "regular", **authority["files"][path]}
            if node is None or node.get("record") != expected:
                raise RuntimeError("scoped source differs from executed bootstrap closure")
        if hasattr(self, "manifest") and _object_sha256(self.manifest) != self.sha256:
            raise RuntimeError("scoped evidence manifest changed")

    def close(self) -> None:
        if self._closed:
            return
        nodes = self._nodes
        parent = self._parent
        self._parent = -1
        failure = None
        try:
            try:
                _close_resource_mapping(nodes, descriptor_key="fd")
            except BaseException as _map_primary:
                # The map remains installed until this literal numeric fallback drains it.
                _raw_records = nodes
                while _raw_records:
                    try:
                        _raw_owner = _raw_records.popitem()[1]
                    except BaseException:
                        _raw_owner = dict.popitem(_raw_records)[1]
                    _raw_fd = _raw_owner["fd"]
                    _raw_owner["fd"] = -1
                    if _raw_fd is not None and _raw_fd >= 0:
                        try:
                            os.close(_raw_fd)
                        except BaseException:
                            _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                raise
        except BaseException as error:
            failure = error
        finally:
            try:
                _numeric_failure = None
                _numeric_fd = parent
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
            self._closed = not nodes
        if failure is not None:
            raise failure

    def __enter__(self) -> "BoundScopedDiff":
        return self

    def __exit__(self, *exception: Any) -> None:
        _release_primary = exception[1]
        try:
            self.close()
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


def _regular_input_policies(
    paths: Mapping[str, Path],
    *,
    mode: int = 0o644,
    uid: int | None = None,
    gid: int | None = None,
) -> dict[str, InputMetadataPolicy]:
    expected_uid = os.geteuid() if uid is None else uid
    expected_gid = os.getegid() if gid is None else gid
    return {
        label: InputMetadataPolicy(mode, expected_uid, expected_gid)
        for label in paths
    }


class FixedDescriptors:
    """Temporarily map held descriptors to exact inherited descriptor numbers.

    The mapping is installed only around the child launch. Existing descriptors
    at those numbers are restored, all targets are inheritable for the duration,
    and the caller's source offsets are not changed by ``dup2``.
    """

    def __init__(self, mapping: Mapping[int, int]) -> None:
        if not mapping or any(target < 3 for target in mapping):
            raise ValueError("fixed descriptor targets must be a non-empty safe set")
        if any(source < 0 for source in mapping.values()):
            raise ValueError("fixed descriptor sources must be open descriptors")
        self._mapping = dict(mapping)
        self._saved: dict[int, tuple[int, bool] | None] = {}
        self._installed: set[int] = set()
        self._entered = False

    def __enter__(self) -> "FixedDescriptors":
        if self._entered:
            raise RuntimeError("fixed descriptor mapping is not reentrant")
        self._entered = True
        reserved_minimum = max(*self._mapping.keys(), *self._mapping.values()) + 1
        temporary: dict[int, int] = {}
        try:
            for target in sorted(self._mapping):
                try:
                    inheritable = os.get_inheritable(target)
                    saved = fcntl.fcntl(target, fcntl.F_DUPFD_CLOEXEC, reserved_minimum)
                    try:
                        self._saved[target] = (saved, inheritable)
                    except BaseException as primary:
                        _release_primary = primary
                        try:
                            os.close(saved)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                        raise
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                    self._saved[target] = None
            # Duplicate the sources first because a source can itself be one of
            # the target numbers. The temporary copies make the operation safe.
            try:
                for target, source in self._mapping.items():
                    duplicate = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, reserved_minimum)
                    try:
                        temporary[target] = duplicate
                    except BaseException as primary:
                        _release_primary = primary
                        try:
                            os.close(duplicate)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                        raise
                for target, source in sorted(temporary.items()):
                    self._installed.add(target)
                    os.dup2(source, target, inheritable=True)
            finally:
                _close_descriptor_mapping(temporary, sys.exception())
            return self
        except BaseException as primary:
            self.__exit__(type(primary), primary, primary.__traceback__)
            raise

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exception_type, traceback
        failures: BaseException | None = None
        saved_roles, installed = self._saved, self._installed
        while saved_roles:
            try:
                item = saved_roles.popitem()
            except BaseException as error:
                if failures is None:
                    failures = error
                item = dict.popitem(saved_roles)
            target = item[0]
            saved = item[1]
            try:
                if target in installed:
                    if saved is None:
                        os.close(target)
                    else:
                        os.dup2(saved[0], target, inheritable=saved[1])
            except BaseException as error:
                if not (saved is None and isinstance(error, OSError) and error.errno == errno.EBADF):
                    if failures is None:
                        failures = error
            finally:
                if saved is not None:
                    try:
                        os.close(saved[0])
                    except BaseException as error:
                        if failures is None:
                            failures = error
        try:
            installed.clear()
        except BaseException as error:
            if failures is None:
                failures = error
            set.clear(installed)
        self._entered = False
        if failures:
            if exception is not None:
                _add_cleanup_note(exception, "additional fixed descriptor restoration failed")
                return
            raise RuntimeError("fixed descriptor restoration failed") from failures
@dataclass
class SealedCapsule:
    fd: int
    sha256: str
    size: int

    def read(self) -> bytes:
        return _read_descriptor(self.fd)

    def close(self) -> None:
        descriptor, self.fd = self.fd, -1
        if descriptor >= 0:
            os.close(descriptor)
@dataclass
class SealedSecret:
    fd: int
    size: int

    def read(self) -> bytes:
        return _read_descriptor(self.fd)

    def close(self) -> None:
        descriptor, self.fd = self.fd, -1
        if descriptor >= 0:
            os.close(descriptor)
@dataclass
class _DescriptorResource:
    fd: int

    def close(self) -> None:
        descriptor, self.fd = self.fd, -1
        if descriptor >= 0:
            os.close(descriptor)
def copy_public_to_sealed_memfd(inputs: BoundInputs, label: str) -> SealedCapsule:
    source = inputs.descriptor(label)
    before = os.fstat(source)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise RuntimeError(f"public input is not nonempty regular data: {label}")
    descriptor = os.memfd_create(
        f"openmythos-gate01-{label}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        os.lseek(source, 0, os.SEEK_SET)
        while chunk := os.read(source, HASH_CHUNK_SIZE):
            _write_all(descriptor, chunk)
        os.fsync(descriptor)
        if _stat_version(before) != _stat_version(os.fstat(source)):
            raise RuntimeError(f"public input changed while being sealed: {label}")
        digest = _hash_descriptor(descriptor)
        if digest != inputs.hashes[label]:
            raise RuntimeError(f"sealed public input digest differs: {label}")
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return SealedCapsule(descriptor, digest, before.st_size)
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
def seal_public_bytes(value: bytes, name: str) -> SealedCapsule:
    descriptor = os.memfd_create(
        f"openmythos-gate01-{name}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
        _verify_written_output(descriptor, len(value), hashlib.sha256(value).hexdigest())
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return SealedCapsule(
            descriptor, hashlib.sha256(value).hexdigest(), len(value)
        )
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
def copy_secret_to_sealed_memfd(inputs: BoundInputs, label: str) -> SealedSecret:
    source = inputs.descriptor(label)
    before = os.fstat(source)
    descriptor = os.memfd_create(
        "openmythos-gate01-secret",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        os.lseek(source, 0, os.SEEK_SET)
        while chunk := os.read(source, HASH_CHUNK_SIZE):
            _write_all(descriptor, chunk)
        os.fsync(descriptor)
        if _stat_version(before) != _stat_version(os.fstat(source)):
            raise RuntimeError("secret input changed while being sealed")
        if os.fstat(descriptor).st_size != before.st_size:
            raise RuntimeError("sealed secret copy has the wrong size")
        # Compare bytes directly.  No digest of private material is created.
        os.lseek(source, 0, os.SEEK_SET)
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            left = os.read(source, HASH_CHUNK_SIZE)
            right = os.read(descriptor, HASH_CHUNK_SIZE)
            if left != right:
                raise RuntimeError("sealed secret bytes differ from bound input")
            if not left:
                break
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return SealedSecret(descriptor, before.st_size)
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
def _zip_entry(name: str, content: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_STORED
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | 0o444) << 16
    return entry, content
def build_verifier_capsule(
    inputs: BoundInputs, relative_paths: Iterable[str]
) -> SealedCapsule:
    paths = tuple(sorted(relative_paths))
    if not paths or len(paths) != len(set(paths)):
        raise ValueError("verifier capsule paths must be non-empty and unique")
    members: dict[str, bytes] = {}
    for relative in paths:
        pure = PurePosixPath(relative)
        if (
            not relative
            or relative.startswith("/")
            or pure.as_posix() != relative
            or "." in pure.parts
            or ".." in pure.parts
        ):
            raise ValueError(f"unsafe verifier capsule path: {relative}")
        members[relative] = inputs.read(relative)
    member_manifest = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in sorted(members.items())
    }
    launcher = (
        "import runpy,sys\n"
        "if len(sys.argv) < 2: raise SystemExit('missing module')\n"
        "module=sys.argv.pop(1)\n"
        "runpy.run_module(module,run_name='__main__',alter_sys=True)\n"
    ).encode("ascii")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", allowZip64=True) as archive:
        for name, content in sorted(members.items()):
            entry, value = _zip_entry(name, content)
            archive.writestr(entry, value)
        entry, value = _zip_entry(
            "OPENMYTHOS-MANIFEST.json", _canonical_json(member_manifest)
        )
        archive.writestr(entry, value)
        entry, value = _zip_entry("__main__.py", launcher)
        archive.writestr(entry, value)
    value = buffer.getvalue()
    descriptor = os.memfd_create(
        "openmythos-gate01-verifier",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
        _verify_written_output(descriptor, len(value), hashlib.sha256(value).hexdigest())
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return SealedCapsule(
            fd=descriptor,
            sha256=hashlib.sha256(value).hexdigest(),
            size=len(value),
        )
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
def _json_object_descriptor(descriptor: int, description: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field in {description}")
            result[key] = value
        return result

    try:
        value = json.loads(
            _read_descriptor(descriptor).decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant in {description}: {constant}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {description} JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a JSON object")
    return value
@dataclass
class ArtifactSet:
    _descriptors: dict[str, int]
    identities: dict[str, dict[str, Any]]

    def descriptor(self, role: str) -> int:
        return self._descriptors[role]

    def read(self, role: str) -> bytes:
        return _read_descriptor(self.descriptor(role))

    def close(self) -> None:
        # Closing the owned read descriptor releases its read lease too.
        _numeric_failure = None
        _numeric_values = self._descriptors
        while _numeric_values:
            try:
                _numeric_fd = _numeric_values.popitem()[1]
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
                _numeric_fd = dict.popitem(_numeric_values)[1]
            if _numeric_fd >= 0:
                try:
                    os.close(_numeric_fd)
                except BaseException as _numeric_error:
                    if _numeric_failure is None:
                        _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bound descriptor release failed") from _numeric_failure
class AnonymousOutputs:
    """Small/large disk-backed anonymous output channels for container exec."""

    def __init__(self, descriptors: dict[str, int]) -> None:
        self._descriptors = descriptors
        self._read_descriptors: dict[str, int] = {}
        self._closed = False

    @classmethod
    def create(cls, directory: Path, roles: Iterable[str]) -> "AnonymousOutputs":
        names = tuple(roles)
        if not names or len(names) != len(set(names)):
            raise ValueError("anonymous output roles must be non-empty and unique")
        status = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(status.st_mode):
            raise ValueError("anonymous output backing directory is unsafe")
        descriptors: dict[str, int] = {}
        try:
            for role in names:
                descriptor = os.open(
                    directory, os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600
                )
                try:
                    descriptors[role] = descriptor
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
            return cls(descriptors)
        except BaseException:
            _close_descriptor_mapping(descriptors, sys.exception())
            raise

    def descriptor(self, role: str) -> int:
        return self._descriptors[role]

    def read(self, role: str, *, maximum: int | None = None) -> bytes:
        descriptor = self.descriptor(role)
        status = os.fstat(descriptor)
        if maximum is not None and status.st_size > maximum:
            raise RuntimeError(f"anonymous output exceeds limit: {role}")
        return _read_descriptor(descriptor)

    def reopen_read_only(
        self, *, require_nonempty: bool = True,
        process_probe: Callable[[Mapping[str, tuple[int, int]]], None] | None = None,
        lease_acquirer: Callable[[int], None] | None = None,
    ) -> dict[str, int]:
        if self._closed or not self._descriptors:
            raise RuntimeError("anonymous outputs were already transitioned")
        allowed = tuple(self._descriptors.values())
        probe = process_probe or (lambda expected: _assert_artifact_writer_custody(expected, allowed))
        acquire_lease = lease_acquirer or _acquire_read_lease
        reopened: dict[str, int] = {}
        try:
            first: dict[str, tuple[tuple[int, ...], str]] = {}
            expected_writers: dict[str, tuple[int, int]] = {}
            for role, descriptor in self._descriptors.items():
                os.fsync(descriptor)
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 0:
                    raise RuntimeError(f"anonymous output is not unlinked regular data: {role}")
                if require_nonempty and status.st_size <= 0:
                    raise RuntimeError(f"anonymous output is empty: {role}")
                first[role] = (_stat_version(status), _hash_descriptor(descriptor))
                expected_writers[role] = (status.st_dev, status.st_ino)
            try:
                probe(expected_writers)
            except Exception as error:
                raise RuntimeError("anonymous output writer custody check failed") from error
            for role, descriptor in self._descriptors.items():
                read_descriptor = os.open(
                    f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC
                )
                try:
                    reopened[role] = read_descriptor
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(read_descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
            _close_descriptor_mapping(self._descriptors, None)
            try:
                probe(expected_writers)
            except Exception as error:
                raise RuntimeError("anonymous output writer custody remains after close") from error
            for descriptor in reopened.values():
                try:
                    acquire_lease(descriptor)
                except Exception as error:
                    raise RuntimeError("anonymous output read lease could not be acquired") from error
            for role, descriptor in reopened.items():
                status = os.fstat(descriptor)
                expected_status, expected_hash = first[role]
                if (
                    _stat_version(status) != expected_status
                    or _hash_descriptor(descriptor) != expected_hash
                    or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
                    != os.O_RDONLY
                ):
                    raise RuntimeError(f"anonymous output read-only transition failed: {role}")
            self.identities = {
                role: {"stat_version": version, "sha256": digest}
                for role, (version, digest) in first.items()
            }
            # Ownership stays with this already-registered resource. Consumers
            # borrow the returned descriptors; a parse failure cannot leak them.
            self._read_descriptors = reopened
            return dict(reopened)
        except BaseException:
            _close_descriptor_mapping(reopened, sys.exception())
            raise

    def close(self) -> None:
        if self._closed:
            return
        descriptors = self._descriptors
        readers = self._read_descriptors
        failure = None
        try:
            _numeric_failure = None
            _numeric_values = descriptors
            while _numeric_values:
                try:
                    _numeric_fd = _numeric_values.popitem()[1]
                except BaseException as _numeric_error:
                    if _numeric_failure is None:
                        _numeric_failure = _numeric_error
                    _numeric_fd = dict.popitem(_numeric_values)[1]
                if _numeric_fd >= 0:
                    try:
                        os.close(_numeric_fd)
                    except BaseException as _numeric_error:
                        if _numeric_failure is None:
                            _numeric_failure = _numeric_error
            if _numeric_failure is not None:
                raise RuntimeError("bound descriptor release failed") from _numeric_failure
        except BaseException as error:
            failure = error
        finally:
            try:
                _numeric_failure = None
                _numeric_values = readers
                while _numeric_values:
                    try:
                        _numeric_fd = _numeric_values.popitem()[1]
                    except BaseException as _numeric_error:
                        if _numeric_failure is None:
                            _numeric_failure = _numeric_error
                        _numeric_fd = dict.popitem(_numeric_values)[1]
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
            self._closed = not descriptors and not readers
        if failure is not None:
            raise failure

    def __enter__(self) -> "AnonymousOutputs":
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
def _acquire_read_lease(descriptor: int) -> None:
    if not hasattr(fcntl, "F_SETLEASE"):
        raise OSError(errno.ENOTSUP, "file leases are unavailable")
    signal.signal(signal.SIGIO, lambda _signal, _frame: None)
    fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_RDLCK)
class ArtifactSlots:
    def __init__(self, descriptors: dict[str, int]) -> None:
        self._descriptors = descriptors
        self._transitioned = False

    @classmethod
    def create(cls, directory: Path) -> "ArtifactSlots":
        status = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(status.st_mode):
            raise ValueError("artifact slot directory must be a non-symlink directory")
        descriptors: dict[str, int] = {}
        try:
            for role in ARTIFACT_FD_ROLES:
                descriptor = os.open(
                    directory,
                    os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    descriptors[role] = descriptor
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
            return cls(descriptors)
        except BaseException:
            _close_descriptor_mapping(descriptors, sys.exception())
            raise

    def descriptor(self, role: str) -> int:
        return self._descriptors[role]

    def write_for_test(self, role: str, value: bytes) -> None:
        descriptor = self.descriptor(role)
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        _write_all(descriptor, value)

    def transition_to_read_only(
        self,
        *,
        process_probe: Callable[[Mapping[str, tuple[int, int]]], None],
        lease_acquirer: Callable[[int], None] = _acquire_read_lease,
    ) -> ArtifactSet:
        if self._transitioned:
            raise RuntimeError("artifact slots were already transitioned")
        expected_writers: dict[str, tuple[int, int]] = {}
        first: dict[str, dict[str, Any]] = {}
        for role, descriptor in self._descriptors.items():
            os.fsync(descriptor)
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 0:
                raise RuntimeError(f"artifact slot is not anonymous regular data: {role}")
            if status.st_size <= 0:
                raise RuntimeError(f"artifact slot is empty: {role}")
            expected_writers[role] = (status.st_dev, status.st_ino)
            first[role] = {
                "device": status.st_dev,
                "inode": status.st_ino,
                "size": status.st_size,
                "sha256": _hash_descriptor(descriptor),
            }
        try:
            process_probe(expected_writers)
        except BaseException as error:
            raise RuntimeError("artifact writer custody check failed") from error

        read_only: dict[str, int] = {}
        try:
            for role, descriptor in self._descriptors.items():
                reopened = os.open(
                    f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC
                )
                try:
                    read_only[role] = reopened
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(reopened)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                status = os.fstat(reopened)
                if (
                    (status.st_dev, status.st_ino, status.st_size)
                    != (
                        first[role]["device"],
                        first[role]["inode"],
                        first[role]["size"],
                    )
                    or _hash_descriptor(reopened) != first[role]["sha256"]
                    or fcntl.fcntl(reopened, fcntl.F_GETFL) & os.O_ACCMODE
                    != os.O_RDONLY
                ):
                    raise RuntimeError(f"artifact read-only reopen mismatch: {role}")

            _close_descriptor_mapping(self._descriptors, None)
            self._transitioned = True
            try:
                process_probe(expected_writers)
            except BaseException as error:
                raise RuntimeError("artifact writer custody remains after close") from error
            for descriptor in read_only.values():
                try:
                    lease_acquirer(descriptor)
                except BaseException as error:
                    raise RuntimeError("artifact read lease could not be acquired") from error
            for role, descriptor in read_only.items():
                status = os.fstat(descriptor)
                if (
                    status.st_nlink != 0
                    or status.st_size != first[role]["size"]
                    or _hash_descriptor(descriptor) != first[role]["sha256"]
                ):
                    raise RuntimeError(f"artifact changed after writer closure: {role}")
            return ArtifactSet(read_only, first)
        except BaseException:
            _close_descriptor_mapping(read_only, sys.exception())
            raise

    def close(self) -> None:
        _numeric_failure = None
        _numeric_values = self._descriptors
        while _numeric_values:
            try:
                _numeric_fd = _numeric_values.popitem()[1]
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
                _numeric_fd = dict.popitem(_numeric_values)[1]
            if _numeric_fd >= 0:
                try:
                    os.close(_numeric_fd)
                except BaseException as _numeric_error:
                    if _numeric_failure is None:
                        _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bound descriptor release failed") from _numeric_failure

    def __enter__(self) -> "ArtifactSlots":
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
def _directory_names(directory: Path) -> tuple[str, ...]:
    status = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(status.st_mode):
        raise RuntimeError(f"exact RPM output topology has an unsafe directory: {directory}")
    return tuple(sorted(entry.name for entry in os.scandir(directory)))
def export_exact_rpm_set(
    rpm_root: Path,
    srpm_directory: Path,
    slots: ArtifactSlots,
    *,
    after_first_pass: Callable[[], None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Acquire the exact rpmbuild outputs directly into anonymous held slots."""
    architecture_directory = rpm_root / "x86_64"
    if _directory_names(rpm_root) != ("x86_64",):
        raise RuntimeError("exact RPM output topology requires only RPMS/x86_64")
    if _directory_names(architecture_directory) != tuple(
        sorted(EXPECTED_RPM_FILENAMES[role] for role in ("meta", "core", "modules"))
    ):
        raise RuntimeError("exact RPM output topology has the wrong binary set")
    if _directory_names(srpm_directory) != (EXPECTED_RPM_FILENAMES["srpm"],):
        raise RuntimeError("exact RPM output topology has the wrong source set")
    paths = {
        "srpm": srpm_directory / EXPECTED_RPM_FILENAMES["srpm"],
        **{
            role: architecture_directory / EXPECTED_RPM_FILENAMES[role]
            for role in ("core", "modules", "meta")
        },
    }
    root_status = rpm_root.lstat()
    architecture_status = architecture_directory.lstat()
    source_status = srpm_directory.lstat()
    with _owned_resource(BoundInputs.open, _drain_bound_inputs,
        paths, policies=_regular_input_policies(paths)
    ) as inputs:
        if after_first_pass is not None:
            after_first_pass()
        try:
            inputs.verify_coherent()
        except RuntimeError as error:
            raise RuntimeError("RPM output changed during acquisition") from error
        identities: dict[str, dict[str, Any]] = {}
        for role in ("srpm", "core", "modules", "meta"):
            source = inputs.descriptor(role)
            status = os.fstat(source)
            if status.st_size <= 0:
                raise RuntimeError(f"RPM output is empty: {role}")
            destination = slots.descriptor(role)
            os.ftruncate(destination, 0)
            os.lseek(destination, 0, os.SEEK_SET)
            os.lseek(source, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while chunk := os.read(source, HASH_CHUNK_SIZE):
                digest.update(chunk)
                _write_all(destination, chunk)
            os.fsync(destination)
            copied = os.fstat(destination)
            if copied.st_size != status.st_size:
                raise RuntimeError(f"RPM output copy is incomplete: {role}")
            _verify_written_output(destination, status.st_size, digest.hexdigest())
            identities[role] = {
                "filename": EXPECTED_RPM_FILENAMES[role],
                "sha256": digest.hexdigest(),
                "size": status.st_size,
            }
        try:
            inputs.verify_coherent()
        except RuntimeError as error:
            raise RuntimeError("RPM output changed during acquisition") from error
    if (
        _stat_version(rpm_root.lstat()) != _stat_version(root_status)
        or _stat_version(architecture_directory.lstat())
        != _stat_version(architecture_status)
        or _stat_version(srpm_directory.lstat()) != _stat_version(source_status)
        or _directory_names(rpm_root) != ("x86_64",)
        or _directory_names(architecture_directory)
        != tuple(
            sorted(
                EXPECTED_RPM_FILENAMES[role]
                for role in ("meta", "core", "modules")
            )
        )
        or _directory_names(srpm_directory)
        != (EXPECTED_RPM_FILENAMES["srpm"],)
    ):
        raise RuntimeError("exact RPM output topology changed during acquisition")
    return identities
def complete_output_scan(
    *,
    key_descriptor: int,
    roots: Mapping[str, int],
    artifact_descriptors: Mapping[str, int],
    scan_descriptors: Callable[[int, int], Iterable[str]],
    scan_artifact: Callable[[int, int], bool],
) -> dict[str, Any]:
    """Scan every proof/output byte against the exact held signing key."""
    required_roots = {"build", "inspection", "candidate"}
    if set(roots) != required_roots:
        raise ValueError("complete output scan requires exact root roles")
    if set(artifact_descriptors) != set(ARTIFACT_FD_ROLES):
        raise ValueError("complete output scan requires exact artifact roles")
    failures: list[str] = []
    for role, descriptor in roots.items():
        if tuple(scan_descriptors(key_descriptor, descriptor)):
            failures.append(role)
    for role, descriptor in artifact_descriptors.items():
        if scan_artifact(key_descriptor, descriptor):
            failures.append(f"artifact:{role}")
    if failures:
        raise RuntimeError(
            "private key leakage detected in complete proof boundary: "
            + ", ".join(failures)
        )
    return {
        "artifact_roles": sorted(artifact_descriptors),
        "root_roles": sorted(roots),
        "verdict": "pass",
    }
def _write_descriptor_exact(descriptor: int, value: bytes) -> None:
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeError("result descriptor must be regular data")
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("result descriptor short write")
        view = view[written:]
    os.fsync(descriptor)
    _verify_written_output(descriptor, len(value), hashlib.sha256(value).hexdigest())
    os.lseek(descriptor, 0, os.SEEK_SET)
def run_verifier_capsule(
    capsule_descriptor: int,
    module: str,
    arguments: Iterable[str],
    *,
    descriptors: Mapping[int, int] | None = None,
    environment: Mapping[str, str] | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    mapping = {VERIFIER_FD: capsule_descriptor, **dict(descriptors or {})}
    if len(mapping) != 1 + len(descriptors or {}):
        raise ValueError("verifier descriptor roles collide")
    with FixedDescriptors(mapping):
        return subprocess.run(
            [
                "/usr/bin/python3", "-I", "-S", "-B",
                f"/proc/self/fd/{VERIFIER_FD}", module, *arguments,
            ],
            env=dict(environment) if environment is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            pass_fds=tuple(sorted(mapping)),
            check=False,
        )
class ReceiptError(RuntimeError):
    pass
def _safe_relative(value: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or pure.as_posix() != value
        or "." in pure.parts
        or ".." in pure.parts
    ):
        raise ReceiptError(f"unsafe output allowlist path: {value!r}")
    return pure
def _expected_tree_paths(allowed_files: Mapping[str, str]) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for value in allowed_files:
        pure = _safe_relative(value)
        if value in files:
            raise ReceiptError("duplicate output allowlist path")
        files.add(value)
        for parent in pure.parents:
            if parent == PurePosixPath("."):
                break
            directories.add(parent.as_posix())
    if files & directories:
        raise ReceiptError("output allowlist file/directory collision")
    return files, directories
def _validate_expected_owner(expected_uid: int, expected_gid: int) -> None:
    if any(type(value) is not int or value <= 0 or value >= 2**32 - 1 for value in (expected_uid, expected_gid)):
        raise ReceiptError("public output owner authority must be explicit nonzero UID/GID")


@contextmanager
def _bound_public_tree(root: Path, allowed_files: Mapping[str, str], *, expected_uid: int, expected_gid: int, synchronize: bool = False) -> Iterable[tuple[BoundInputs, list[dict[str, Any]]]]:
    """Hold the exact public tree through two hash passes and terminal sweeps."""
    _validate_expected_owner(expected_uid, expected_gid)
    root = Path(os.path.abspath(root))
    expected_files, expected_directories = _expected_tree_paths(allowed_files)
    expected_children = BoundAcceptedTree._expected_children(expected_files, expected_directories)
    directories: dict[str, tuple[int, Path, os.stat_result, tuple[str, ...]]] = {}
    files: BoundInputs | None = None
    try:
        for relative in sorted({"", *expected_directories}, key=lambda name: (len(PurePosixPath(name).parts), name)):
            path = root / relative
            descriptor, status = _open_parent_directory(path / ".public-tree-anchor")
            try:
                directories[relative] = (descriptor, path, status, ())
            except BaseException as primary:
                _release_primary = primary
                try:
                    os.close(descriptor)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                raise
            names = tuple(sorted(os.listdir(descriptor)))
            directories[relative] = (descriptor, path, status, names)
            if names != expected_children[relative]:
                raise ReceiptError("output tree does not match the exact allowlist")
            if not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o755 or status.st_uid != expected_uid or status.st_gid != expected_gid:
                raise ReceiptError("output tree has forbidden directory type or owner")
            if os.listxattr(descriptor):
                raise ReceiptError("candidate output tree contains uncommitted xattrs")
        try:
            files = BoundInputs.open(
                {relative: root / relative for relative in sorted(expected_files)},
                policies={relative: InputMetadataPolicy(0o644, expected_uid, expected_gid) for relative in expected_files},
            )
        except ValueError:
            raise ReceiptError("output tree has forbidden file type or metadata") from None
        def verify() -> None:
            files.verify_coherent()
            for relative in expected_files:
                if os.listxattr(files.descriptor(relative)):
                    raise ReceiptError("candidate output tree contains uncommitted xattrs")
            for descriptor, path, before, names in directories.values():
                if _stat_version(os.fstat(descriptor)) != _stat_version(before) or tuple(sorted(os.listdir(descriptor))) != names:
                    raise ReceiptError("public tree directory changed during terminal sweep")
                if os.listxattr(descriptor):
                    raise ReceiptError("candidate output tree contains uncommitted xattrs")
                reopened, observed = _open_parent_directory(path / ".public-tree-anchor")
                try:
                    if _stat_version(observed) != _stat_version(before):
                        raise ReceiptError("public tree ancestry changed during terminal sweep")
                finally:
                    _release_primary = sys.exception()
                    try:
                        os.close(reopened)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        verify()
        if synchronize:
            for relative in sorted(expected_files):
                os.fsync(files.descriptor(relative))
            for descriptor, _path, _status, _names in reversed(tuple(directories.values())):
                os.fsync(descriptor)
        records = [
            {"gid": status.st_gid, "mode": "0755", "path": relative or ".", "type": "directory", "uid": status.st_uid}
            for relative, (_descriptor, _path, status, _names) in directories.items()
        ]
        for relative, digest in files.hashes.items():
            status = files.status(relative)
            records.append({"gid": status.st_gid, "mode": "0644", "path": relative, "sha256": digest, "size": status.st_size, "type": "file", "uid": status.st_uid})
        records.sort(key=lambda record: record["path"])
        yield files, records
        verify()
    finally:
        primary = sys.exception()
        failure = None
        try:
            if files is not None:
                try:
                    _close_resource_preserving_primary(files, None, drain=_drain_bound_inputs)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_bound_inputs(files)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
        except BaseException as error:
            failure = error
            if primary is not None:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
        finally:
            _close_descriptor_mapping(directories, primary or failure, value_index=0)
        if failure is not None and primary is None:
            raise failure


def _tree_manifest(root: Path, allowed_files: Mapping[str, str], *, expected_uid: int, expected_gid: int) -> list[dict[str, Any]]:
    with _bound_public_tree(root, allowed_files, expected_uid=expected_uid, expected_gid=expected_gid) as (_files, records):
        return records
def create_detached_receipt(
    candidate: Path,
    *,
    intended_path: Path,
    allowed_files: Mapping[str, str],
    source_capsule_sha256: str,
    rpm_manifest_sha256: str,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Any]:
    _validate_expected_owner(expected_uid, expected_gid)
    for name, value in (
        ("source capsule", source_capsule_sha256),
        ("RPM manifest", rpm_manifest_sha256),
    ):
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ReceiptError(f"{name} SHA-256 is malformed")
    with _bound_public_tree(candidate, allowed_files, expected_uid=expected_uid, expected_gid=expected_gid) as (files, tree):
        try:
            report_value = _json_object_descriptor(files.descriptor("build-report.json"), "build report")
        except (OSError, ValueError, KeyError):
            raise ReceiptError("build report is missing or invalid") from None
        if report_value.get("acceptance") != "pending-detached-receipt":
            raise ReceiptError("build report must remain pending-detached-receipt")
    records_by_path = {record["path"]: record for record in tree}
    if {"source-capsule.json", "rpm-artifacts.json"} <= set(allowed_files):
        if (
            records_by_path["source-capsule.json"].get("sha256")
            != source_capsule_sha256
        ):
            raise ReceiptError(
                "source capsule SHA-256 differs from the committed file"
            )
        if (
            records_by_path["rpm-artifacts.json"].get("sha256")
            != rpm_manifest_sha256
        ):
            raise ReceiptError(
                "RPM manifest SHA-256 differs from the committed file"
            )
    tree_sha256 = hashlib.sha256(_canonical_json(tree)).hexdigest()
    return {
        "intended_path": os.fspath(Path(os.path.abspath(intended_path))),
        "protocol": RECEIPT_PROTOCOL,
        "rpm_manifest_sha256": rpm_manifest_sha256,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "source_capsule_sha256": source_capsule_sha256,
        "tree": tree,
        "tree_sha256": tree_sha256,
    }
def _fsync_tree(root: Path, allowed_files: Mapping[str, str], *, expected_uid: int, expected_gid: int) -> None:
    with _bound_public_tree(root, allowed_files, expected_uid=expected_uid, expected_gid=expected_gid, synchronize=True):
        pass
def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), os.fspath(destination))
def _publish_receipt(path: Path, value: Mapping[str, Any]) -> None:
    """Install a synced marker; the caller owns final parent durability."""
    data = _canonical_json(value)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".pending"
    )
    installed = False
    try:
        temporary = Path(temporary_name)
        _write_descriptor_bytes(descriptor, data, mode=0o444)
        closing, descriptor = descriptor, -1
        os.close(closing)
        _rename_noreplace(temporary, path)
        installed = True
    except BaseException:
        if descriptor >= 0:
            closing, descriptor = descriptor, -1
            _release_primary = sys.exception()
            try:
                os.close(closing)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        if installed:
            _release_primary = sys.exception()
            try:
                path.unlink(missing_ok=True)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            try:
                parent = os.open(
                    path.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                try:
                    os.fsync(parent)
                finally:
                    _release_primary = sys.exception()
                    try:
                        os.close(parent)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            except OSError:
                pass
        else:
            _release_primary = sys.exception()
            try:
                os.unlink(temporary_name)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


def _best_effort_release(action: Callable[[], Any]) -> None:
    try:
        action()
    except BaseException:
        _post_receipt_warning()


def _post_receipt_warning() -> None:
    try:
        os.write(2, b"warning: post-receipt local cleanup or diagnostic failed\n")
    except BaseException:
        pass


def publish_candidate(
    candidate: Path,
    final: Path,
    receipt: Path,
    receipt_value: Mapping[str, Any],
    *,
    expected_uid: int,
    expected_gid: int,
    rename_noreplace: Callable[[Path, Path], None] = _rename_noreplace,
    publish_receipt: Callable[[Path, Mapping[str, Any]], None] = _publish_receipt,
    before_receipt: Callable[[], None] | None = None,
) -> None:
    _validate_expected_owner(expected_uid, expected_gid)
    if candidate.parent != final.parent or receipt.parent != final.parent:
        raise ReceiptError("candidate, final tree, and receipt must be siblings")
    if final.exists() or final.is_symlink() or receipt.exists() or receipt.is_symlink():
        raise ReceiptError("final tree or receipt already exists")
    _fsync_tree(candidate, {record["path"]: record["type"] for record in receipt_value.get("tree", []) if isinstance(record, dict) and isinstance(record.get("path"), str) and record.get("type") == "file"}, expected_uid=expected_uid, expected_gid=expected_gid)
    observed_before = _tree_manifest(candidate, {
        record["path"]: record["type"] for record in receipt_value.get("tree", [])
        if isinstance(record, dict) and isinstance(record.get("path"), str)
        and record.get("type") == "file"
    }, expected_uid=expected_uid, expected_gid=expected_gid)
    if (
        observed_before != receipt_value.get("tree")
        or hashlib.sha256(_canonical_json(observed_before)).hexdigest()
        != receipt_value.get("tree_sha256")
    ):
        raise ReceiptError("candidate changed before atomic publish boundary")
    final_installed = False
    committed = False
    parent = -1
    try:
        rename_noreplace(candidate, final)
        final_installed = True
        parent, _parent_status = _open_parent_directory(final)
        os.fsync(parent)
        observed_after = _tree_manifest(final, {
            record["path"]: record["type"] for record in receipt_value.get("tree", [])
            if isinstance(record, dict) and isinstance(record.get("path"), str)
            and record.get("type") == "file"
        }, expected_uid=expected_uid, expected_gid=expected_gid)
        if (
            observed_after != receipt_value.get("tree")
            or hashlib.sha256(_canonical_json(observed_after)).hexdigest()
            != receipt_value.get("tree_sha256")
        ):
            raise ReceiptError("candidate changed at atomic publish boundary")
        if before_receipt is not None:
            before_receipt()
        publish_receipt(receipt, receipt_value)
        accepted_files = {
            record["path"]: record["type"]
            for record in receipt_value.get("tree", [])
            if isinstance(record, dict)
            and isinstance(record.get("path"), str)
            and record.get("type") == "file"
        }
        with _owned_resource(BoundAcceptedTree.open, _drain_bound_accepted_tree,
            final, receipt, allowed_files=accepted_files, expected_uid=expected_uid, expected_gid=expected_gid
        ) as boundary:
            if before_receipt is not None:
                before_receipt()
            boundary.verify_coherent()
        # Last fallible acceptance operation. No reopens, callbacks, or
        # validation may run after this confirmed directory fsync.
        os.fsync(parent)
        committed = True
    except BaseException as primary:
        rollback_failures: BaseException | None = None
        try:
            receipt.unlink(missing_ok=True)
        except BaseException as error:
            if rollback_failures is None:
                rollback_failures = error
            _add_cleanup_note(primary, "additional tree receipt rollback failed")
        if final_installed:
            try:
                rename_noreplace(final, candidate)
                rollback_parent = os.open(
                    candidate.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                try:
                    os.fsync(rollback_parent)
                finally:
                    _release_primary = sys.exception()
                    try:
                        os.close(rollback_parent)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            except BaseException as rollback_error:
                if rollback_failures is None:
                    rollback_failures = rollback_error
                _add_cleanup_note(primary, "additional tree rename rollback failed")
        raise
    finally:
        if parent >= 0:
            descriptor, parent = parent, -1
            if committed:
                try:
                    os.close(descriptor)
                except BaseException:
                    _post_receipt_warning()
            else:
                _close_descriptor_preserving_primary(descriptor, sys.exception())
def _load_receipt(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        value = _json_object_descriptor(descriptor, "detached receipt")
    except (OSError, UnicodeError, ValueError) as error:
        raise ReceiptError("detached receipt is missing or invalid") from error
    finally:
        if descriptor >= 0:
            _release_primary = sys.exception()
            try:
                os.close(descriptor)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    expected = {
        "intended_path",
        "protocol",
        "rpm_manifest_sha256",
        "schema_version",
        "source_capsule_sha256",
        "tree",
        "tree_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ReceiptError("detached receipt has an invalid schema")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != RECEIPT_SCHEMA_VERSION
        or value["protocol"] != RECEIPT_PROTOCOL
    ):
        raise ReceiptError("detached receipt protocol is unsupported")
    return value
def validate_detached_receipt(
    final: Path, receipt: Path, *, allowed_files: Mapping[str, str], expected_uid: int, expected_gid: int
) -> dict[str, Any]:
    with _owned_resource(BoundAcceptedTree.open, _drain_bound_accepted_tree, final, receipt, allowed_files=allowed_files, expected_uid=expected_uid, expected_gid=expected_gid) as tree:
        tree.verify_coherent()
        return tree.receipt


@dataclass
class _BoundDirectory:
    relative: str
    path: Path
    descriptor: int
    initial_status: os.stat_result
    names: tuple[str, ...]

    def close(self) -> None:
        descriptor, self.descriptor = self.descriptor, -1
        if descriptor >= 0:
            os.close(descriptor)


class BoundAcceptedTree:
    """A complete accepted tree and receipt held across one consumer action."""

    def __init__(
        self,
        *,
        final: Path,
        receipt_path: Path,
        allowed_files: Mapping[str, str],
        files: BoundInputs,
        directories: dict[str, _BoundDirectory],
        receipt: dict[str, Any],
    ) -> None:
        self.final = final
        self.receipt_path = receipt_path
        self.allowed_files = dict(allowed_files)
        self._files = files
        self._directories = directories
        self.receipt = receipt
        self.receipt_sha256 = _hash_descriptor(files.descriptor("receipt"))
        self.tree_sha256 = receipt["tree_sha256"]
        self._closed = False

    @staticmethod
    def _expected_children(
        files: set[str], directories: set[str]
    ) -> dict[str, tuple[str, ...]]:
        children: dict[str, set[str]] = {"": set()}
        for directory in directories:
            children.setdefault(directory, set())
            pure = PurePosixPath(directory)
            parent = "" if pure.parent == PurePosixPath(".") else pure.parent.as_posix()
            children.setdefault(parent, set()).add(pure.name)
        for filename in files:
            pure = PurePosixPath(filename)
            parent = "" if pure.parent == PurePosixPath(".") else pure.parent.as_posix()
            children.setdefault(parent, set()).add(pure.name)
        return {key: tuple(sorted(value)) for key, value in children.items()}

    @classmethod
    def open(
        cls,
        final: Path,
        receipt_path: Path,
        *,
        allowed_files: Mapping[str, str],
        expected_uid: int,
        expected_gid: int,
    ) -> "BoundAcceptedTree":
        _validate_expected_owner(expected_uid, expected_gid)
        final = Path(os.path.abspath(final))
        receipt_path = Path(os.path.abspath(receipt_path))
        if final.parent != receipt_path.parent:
            raise ReceiptError("accepted tree and receipt must be siblings")
        expected_files, expected_directories = _expected_tree_paths(allowed_files)
        bound_paths = {"receipt": receipt_path}
        bound_paths.update(
            {f"file:{relative}": final / relative for relative in expected_files}
        )
        files: BoundInputs | None = None
        directories: dict[str, _BoundDirectory] = {}
        try:
            try:
                files = BoundInputs.open(
                    bound_paths,
                    policies={
                        label: InputMetadataPolicy(
                            0o444 if label == "receipt" else 0o644,
                            expected_uid,
                            expected_gid,
                        )
                        for label in bound_paths
                    },
                )
            except (OSError, ValueError) as error:
                raise ReceiptError(
                    "accepted tree or receipt metadata is unsafe"
                ) from error
            for label in bound_paths:
                if os.listxattr(files.descriptor(label)):
                    raise ReceiptError("accepted tree or receipt contains uncommitted xattrs")
            expected_children = cls._expected_children(
                expected_files, expected_directories
            )
            for relative in sorted(
                {"", *expected_directories},
                key=lambda item: (len(PurePosixPath(item).parts), item),
            ):
                path = final if not relative else final / relative
                descriptor = -1
                try:
                    descriptor, status = _open_parent_directory(
                        path / ".tree-anchor"
                    )
                    if os.listxattr(descriptor):
                        raise ReceiptError("accepted tree contains uncommitted xattrs")
                    names = tuple(sorted(os.listdir(descriptor)))
                    if names != expected_children[relative]:
                        raise ReceiptError(
                            "accepted tree directory allowlist listing is not exact: "
                            f"{relative or '/'}"
                        )
                    directories[relative] = _BoundDirectory(
                        relative=relative,
                        path=path,
                        descriptor=descriptor,
                        initial_status=status,
                        names=names,
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

            root_status = directories[""].initial_status
            if (
                stat.S_IMODE(root_status.st_mode) != 0o755
                or root_status.st_uid != expected_uid
                or root_status.st_gid != expected_gid
            ):
                raise ReceiptError("accepted tree root metadata is unsafe")

            try:
                receipt = _json_object_descriptor(files.descriptor("receipt"), "detached receipt")
            except (UnicodeError, json.JSONDecodeError, ValueError) as error:
                raise ReceiptError("detached receipt is missing or invalid") from error
            expected_receipt_fields = {
                "intended_path",
                "protocol",
                "rpm_manifest_sha256",
                "schema_version",
                "source_capsule_sha256",
                "tree",
                "tree_sha256",
            }
            if (
                not isinstance(receipt, dict)
                or set(receipt) != expected_receipt_fields
                or type(receipt["schema_version"]) is not int
                or receipt["schema_version"] != RECEIPT_SCHEMA_VERSION
                or receipt["protocol"] != RECEIPT_PROTOCOL
                or receipt["intended_path"] != os.fspath(final)
            ):
                raise ReceiptError("detached receipt identity is not exact")

            receipt_status = os.fstat(files.descriptor("receipt"))
            if (
                not stat.S_ISREG(receipt_status.st_mode)
                or receipt_status.st_nlink != 1
                or stat.S_IMODE(receipt_status.st_mode) != 0o444
                or receipt_status.st_uid != expected_uid
                or receipt_status.st_gid != expected_gid
            ):
                raise ReceiptError("detached receipt metadata is unsafe")

            records: list[dict[str, Any]] = []
            for relative in sorted({"", *expected_directories}):
                status = directories[relative].initial_status
                if (
                    stat.S_IMODE(status.st_mode) != 0o755
                    or status.st_uid != expected_uid
                    or status.st_gid != expected_gid
                ):
                    raise ReceiptError(
                        "accepted tree directory metadata is unsafe: "
                        f"{relative or '/'}"
                    )
                records.append(
                    {
                        "gid": status.st_gid,
                        "mode": f"{stat.S_IMODE(status.st_mode):04o}",
                        "path": relative or ".",
                        "type": "directory",
                        "uid": status.st_uid,
                    }
                )
            for relative in sorted(expected_files):
                descriptor = files.descriptor(f"file:{relative}")
                status = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(status.st_mode)
                    or status.st_nlink != 1
                    or stat.S_IMODE(status.st_mode) != 0o644
                    or status.st_uid != expected_uid
                    or status.st_gid != expected_gid
                ):
                    raise ReceiptError(
                        f"accepted tree file metadata is unsafe: {relative}"
                    )
                records.append(
                    {
                        "gid": status.st_gid,
                        "mode": f"{stat.S_IMODE(status.st_mode):04o}",
                        "path": relative,
                        "sha256": _hash_descriptor(descriptor),
                        "size": status.st_size,
                        "type": "file",
                        "uid": status.st_uid,
                    }
                )
            records.sort(key=lambda record: record["path"])
            if (
                _canonical_json(receipt.get("tree")) != _canonical_json(records)
                or receipt.get("tree_sha256")
                != hashlib.sha256(_canonical_json(records)).hexdigest()
            ):
                raise ReceiptError("detached receipt tree commitment does not match")
            result = cls(
                final=final,
                receipt_path=receipt_path,
                allowed_files=allowed_files,
                files=files,
                directories=directories,
                receipt=receipt,
            )
            result.expected_uid = expected_uid
            result.expected_gid = expected_gid
            result.verify_coherent()
            return result
        except BaseException as primary:
            try:
                try:
                    _close_resource_mapping(directories, primary, descriptor_attribute="descriptor")
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
                    _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
            except BaseException:
                _add_cleanup_note(primary, "additional accepted directory cleanup failed")
            finally:
                if files is not None:
                    try:
                        try:
                            _close_resource_mapping(files._records, primary, descriptor_attribute="descriptor", parent_descriptor_attribute="parent_descriptor")
                        except BaseException as _map_primary:
                            # The map remains installed until this literal numeric fallback drains it.
                            _raw_records = files._records
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
                            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
                    except BaseException:
                        _add_cleanup_note(primary, "additional accepted file cleanup failed")
                    files._closed = not files._records
                    files = None
            raise

    def descriptor(self, relative: str) -> int:
        if relative not in self.allowed_files:
            raise KeyError(relative)
        return self._files.descriptor(f"file:{relative}")

    def verify_coherent(self) -> None:
        if self._closed:
            raise RuntimeError("accepted tree binding is closed")
        self._files.verify_coherent()
        for label in ("receipt", *(f"file:{relative}" for relative in self.allowed_files)):
            if os.listxattr(self._files.descriptor(label)):
                raise ReceiptError("accepted tree or receipt contains uncommitted xattrs")
        for relative, directory in sorted(self._directories.items()):
            if os.listxattr(directory.descriptor):
                raise ReceiptError("accepted tree contains uncommitted xattrs")
            if (
                _stat_version(os.fstat(directory.descriptor))
                != _stat_version(directory.initial_status)
                or tuple(sorted(os.listdir(directory.descriptor))) != directory.names
            ):
                raise RuntimeError(
                    f"accepted tree directory changed: {relative or '/'}"
                )
            reopened, status = _open_parent_directory(
                directory.path / ".tree-anchor"
            )
            try:
                if _stat_version(status) != _stat_version(directory.initial_status):
                    raise RuntimeError(
                        f"accepted tree directory path identity changed: "
                        f"{relative or '/'}"
                    )
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(reopened)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

    def close(self) -> None:
        if self._closed:
            return
        directories = self._directories
        files = self._files
        failure = None
        try:
            try:
                _close_resource_mapping(directories, descriptor_attribute="descriptor")
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
                raise
        except BaseException as error:
            failure = error
        finally:
            try:
                if files is not None:
                    try:
                        _close_resource_mapping(
                            files._records,
                            descriptor_attribute="descriptor",
                            parent_descriptor_attribute="parent_descriptor",
                        )
                    except BaseException as _map_primary:
                        # The map remains installed until this literal numeric fallback drains it.
                        _raw_records = files._records
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
                        raise
            except BaseException as error:
                if failure is None:
                    failure = error
            finally:
                if files is not None:
                    files._closed = not files._records
                    if files._closed:
                        self._files = None
            self._closed = not directories and self._files is None
        if failure is not None:
            raise failure

    def __enter__(self) -> "BoundAcceptedTree":
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


def _validate_evidence_inputs(values: Mapping[str, str]) -> dict[str, str]:
    if not values:
        raise ReceiptError("evidence receipt input commitment must not be empty")
    normalized: dict[str, str] = {}
    for name, digest in sorted(values.items()):
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", name) is None
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ReceiptError("evidence receipt input commitment is malformed")
        normalized[name] = digest
    return normalized


def _rename_noreplace_at(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_parent,
        os.fsencode(source_name),
        destination_parent,
        os.fsencode(destination_name),
        1,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination_name)


def _open_unique_pending(parent_descriptor: int, basename: str) -> tuple[int, str]:
    for _attempt in range(128):
        suffix = os.urandom(12).hex()
        name = f".{basename}.{suffix}.pending"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        try:
            return descriptor, name
        except BaseException as primary:
            try:
                _close_descriptor_preserving_primary(descriptor, primary)
            finally:
                try:
                    os.unlink(name, dir_fd=parent_descriptor)
                except BaseException:
                    _add_cleanup_note(primary, "additional evidence candidate rollback failed")
            raise
    raise ReceiptError("could not allocate a unique evidence candidate")


def _write_descriptor_bytes(descriptor: int, value: bytes, *, mode: int) -> None:
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short evidence write")
        view = view[written:]
    os.fchmod(descriptor, mode)
    os.fsync(descriptor)
    _verify_written_output(descriptor, len(value), hashlib.sha256(value).hexdigest())


def _evidence_payload_record(
    descriptor: int, *, basename: str, expected_uid: int, expected_gid: int
) -> dict[str, Any]:
    _validate_expected_owner(expected_uid, expected_gid)
    status = os.fstat(descriptor)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or stat.S_IMODE(status.st_mode) != 0o444
        or status.st_uid != expected_uid
        or status.st_gid != expected_gid
        or os.listxattr(descriptor)
    ):
        raise ReceiptError("evidence payload metadata is not exact")
    return {
        "gid": status.st_gid,
        "mode": "0444",
        "path": basename,
        "sha256": _hash_descriptor(descriptor),
        "size": status.st_size,
        "type": "file",
        "uid": status.st_uid,
    }


def _publish_evidence_receipt_at(
    parent_descriptor: int, basename: str, value: Mapping[str, Any]
) -> None:
    descriptor, temporary = _open_unique_pending(parent_descriptor, basename)
    try:
        _write_descriptor_bytes(descriptor, _canonical_json(value), mode=0o444)
        closing, descriptor = descriptor, -1
        os.close(closing)
        _rename_noreplace_at(
            parent_descriptor, temporary, parent_descriptor, basename
        )
    except BaseException:
        if descriptor >= 0:
            closing, descriptor = descriptor, -1
            _release_primary = sys.exception()
            try:
                os.close(closing)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        _release_primary = sys.exception()
        try:
            try:
                os.unlink(temporary, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


def publish_evidence_file(
    payload: bytes,
    *,
    final: Path,
    receipt: Path,
    kind: str,
    input_sha256: Mapping[str, str],
    expected_uid: int,
    expected_gid: int,
    publish_receipt: Callable[[int, str, Mapping[str, Any]], None]
    | None = None,
    before_receipt: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Publish one immutable evidence file and its detached commit marker.

    The held parent directory and payload descriptor remain authoritative until
    the receipt has been installed and the complete two-name boundary has been
    swept.  The receipt is deliberately not self-referential.
    """
    _validate_expected_owner(expected_uid, expected_gid)
    if not isinstance(payload, bytes) or not payload:
        raise ReceiptError("evidence payload must be nonempty bytes")
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", kind) is None:
        raise ReceiptError("evidence receipt kind is malformed")
    final = Path(os.path.abspath(final))
    receipt = Path(os.path.abspath(receipt))
    if (
        final.parent != receipt.parent
        or final.name in {"", ".", ".."}
        or receipt.name in {"", ".", ".."}
        or final.name == receipt.name
    ):
        raise ReceiptError("evidence payload and receipt must be distinct siblings")
    inputs = _validate_evidence_inputs(input_sha256)
    parent_descriptor, parent_before = _open_parent_directory(final)
    payload_descriptor = -1
    receipt_descriptor = -1
    payload_temporary: str | None = None
    payload_installed = False
    receipt_installed = False
    committed = False
    try:
        for name in (final.name, receipt.name):
            try:
                os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ReceiptError("evidence payload or receipt already exists")
        names_before = tuple(sorted(os.listdir(parent_descriptor)))
        payload_descriptor, payload_temporary = _open_unique_pending(
            parent_descriptor, final.name
        )
        _write_descriptor_bytes(payload_descriptor, payload, mode=0o444)
        record = _evidence_payload_record(
            payload_descriptor, basename=final.name, expected_uid=expected_uid, expected_gid=expected_gid
        )
        value = {
            "input_sha256": inputs,
            "intended_path": os.fspath(final),
            "kind": kind,
            "payload": record,
            "protocol": EVIDENCE_RECEIPT_PROTOCOL,
            "schema_version": RECEIPT_SCHEMA_VERSION,
        }
        _rename_noreplace_at(
            parent_descriptor,
            payload_temporary,
            parent_descriptor,
            final.name,
        )
        payload_temporary = None
        payload_installed = True
        os.fsync(parent_descriptor)
        payload_status = os.fstat(payload_descriptor)
        if before_receipt is not None:
            before_receipt()
        publisher = publish_receipt or _publish_evidence_receipt_at
        # Once the publisher is entered, cleanup must assume it may have
        # installed the commit marker before reporting failure.
        receipt_installed = True
        publisher(parent_descriptor, receipt.name, value)
        receipt_descriptor = os.open(
            receipt.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
        receipt_status = os.fstat(receipt_descriptor)
        published_parent_status = os.fstat(parent_descriptor)
        expected_names = tuple(
            sorted((*names_before, final.name, receipt.name))
        )

        def verify_publication() -> None:
            if _evidence_payload_record(payload_descriptor, basename=final.name, expected_uid=expected_uid, expected_gid=expected_gid) != record:
                raise ReceiptError("evidence payload metadata differs at publication")
            _evidence_payload_record(receipt_descriptor, basename=receipt.name, expected_uid=expected_uid, expected_gid=expected_gid)
            observed = os.stat(
                final.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            current_payload = os.fstat(payload_descriptor)
            if (
                _stat_version(observed) != _stat_version(payload_status)
                or _stat_version(current_payload) != _stat_version(payload_status)
                or _hash_descriptor(payload_descriptor) != record["sha256"]
            ):
                raise ReceiptError(
                    "evidence payload path identity changed at publication"
                )
            observed_receipt = os.stat(
                receipt.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                _stat_version(observed_receipt)
                != _stat_version(receipt_status)
                or _stat_version(os.fstat(receipt_descriptor))
                != _stat_version(receipt_status)
            ):
                raise ReceiptError(
                    "evidence receipt metadata changed at publication"
                )
            if _read_descriptor(receipt_descriptor) != _canonical_json(value):
                raise ReceiptError("evidence receipt bytes changed at publication")
            if (
                _stat_version(os.fstat(parent_descriptor))
                != _stat_version(published_parent_status)
                or tuple(sorted(os.listdir(parent_descriptor))) != expected_names
            ):
                raise ReceiptError(
                    "evidence parent topology changed at publication"
                )
            reopened_parent, reopened_status = _open_parent_directory(final)
            try:
                if _stat_identity(reopened_status) != _stat_identity(parent_before):
                    raise ReceiptError("evidence parent path identity changed")
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(reopened_parent)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

        verify_publication()
        if before_receipt is not None:
            before_receipt()
        verify_publication()
        os.fsync(parent_descriptor)
        committed = True
        return value
    except BaseException as primary:
        rollback_failures: BaseException | None = None
        index = 0
        while index < 2:
            installed = receipt_installed if index == 0 else payload_installed
            name = receipt.name if index == 0 else final.name
            index += 1
            if installed:
                try:
                    os.unlink(name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
                except BaseException as rollback_error:
                    if rollback_failures is None:
                        rollback_failures = rollback_error
                    _add_cleanup_note(primary, "additional evidence installed-file rollback failed")
        if payload_temporary is not None:
            try:
                os.unlink(payload_temporary, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except BaseException as rollback_error:
                if rollback_failures is None:
                    rollback_failures = rollback_error
                _add_cleanup_note(primary, "additional evidence temporary-file rollback failed")
        try:
            os.fsync(parent_descriptor)
        except BaseException as rollback_error:
            if rollback_failures is None:
                rollback_failures = rollback_error
            _add_cleanup_note(primary, "additional evidence directory-sync rollback failed")
        raise
    finally:
        primary = sys.exception()
        failure = None
        while receipt_descriptor >= 0 or payload_descriptor >= 0 or parent_descriptor >= 0:
            if receipt_descriptor >= 0:
                descriptor, receipt_descriptor = receipt_descriptor, -1
            elif payload_descriptor >= 0:
                descriptor, payload_descriptor = payload_descriptor, -1
            else:
                descriptor, parent_descriptor = parent_descriptor, -1
            try:
                os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            if committed:
                try:
                    os.write(2, b"warning: post-receipt local cleanup or diagnostic failed\n")
                except BaseException:
                    pass
            elif primary is None:
                raise failure
            else:
                _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


class BoundEvidenceReceipt:
    """Held evidence payload and receipt for one complete consumer action."""

    def __init__(
        self,
        files: BoundInputs,
        value: dict[str, Any],
    ) -> None:
        self._files = files
        self.value = value
        self._closed = False

    @classmethod
    def open(
        cls,
        final: Path,
        receipt: Path,
        *,
        kind: str,
        expected_input_sha256: Mapping[str, str],
        expected_uid: int,
        expected_gid: int,
    ) -> "BoundEvidenceReceipt":
        _validate_expected_owner(expected_uid, expected_gid)
        final = Path(os.path.abspath(final))
        receipt = Path(os.path.abspath(receipt))
        if final.parent != receipt.parent:
            raise ReceiptError(
                "evidence payload and receipt must be sibling paths"
            )
        expected_inputs = _validate_evidence_inputs(expected_input_sha256)
        files: BoundInputs | None = None
        try:
            bound_paths = {"payload": final, "receipt": receipt}
            try:
                files = BoundInputs.open(
                    bound_paths,
                    policies={
                        label: InputMetadataPolicy(
                            0o444, expected_uid, expected_gid
                        )
                        for label in bound_paths
                    },
                )
            except (OSError, ValueError) as error:
                raise ReceiptError(
                    "evidence payload or receipt metadata is unsafe"
                ) from error
            try:
                value = _json_object_descriptor(files.descriptor("receipt"), "evidence receipt")
            except (UnicodeError, json.JSONDecodeError, ValueError) as error:
                raise ReceiptError(
                    "evidence receipt is missing or invalid"
                ) from error
            if not isinstance(value, dict) or set(value) != {
                "input_sha256",
                "intended_path",
                "kind",
                "payload",
                "protocol",
                "schema_version",
            }:
                raise ReceiptError("evidence receipt schema is not exact")
            if (
                value["protocol"] != EVIDENCE_RECEIPT_PROTOCOL
                or type(value["schema_version"]) is not int
                or value["schema_version"] != RECEIPT_SCHEMA_VERSION
                or value["intended_path"] != os.fspath(final)
                or value["kind"] != kind
                or value["input_sha256"] != expected_inputs
            ):
                raise ReceiptError("evidence receipt identity does not match")
            receipt_status = os.fstat(files.descriptor("receipt"))
            if (
                not stat.S_ISREG(receipt_status.st_mode)
                or receipt_status.st_nlink != 1
                or stat.S_IMODE(receipt_status.st_mode) != 0o444
                or receipt_status.st_uid != expected_uid
                or receipt_status.st_gid != expected_gid
                or os.listxattr(files.descriptor("receipt"))
            ):
                raise ReceiptError("evidence receipt metadata is unsafe")
            observed = _evidence_payload_record(
                files.descriptor("payload"), basename=final.name, expected_uid=expected_uid, expected_gid=expected_gid
            )
            if _canonical_json(value["payload"]) != _canonical_json(observed):
                raise ReceiptError(
                    "evidence receipt payload commitment does not match"
                )
            result = cls(files, value)
            result.verify_coherent()
            return result
        except BaseException as primary:
            if files is not None:
                _release_primary = primary
                try:
                    try:
                        _close_resource_preserving_primary(files, None, drain=_drain_bound_inputs)
                    except BaseException as _drain_primary:
                        _drain_attempts = 2
                        while _drain_attempts:
                            _drain_attempts -= 1
                            try:
                                _drain_bound_inputs(files)
                                break
                            except BaseException:
                                _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                        raise
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise

    def descriptor(self) -> int:
        if self._closed:
            raise RuntimeError("evidence receipt binding is closed")
        return self._files.descriptor("payload")

    def read(self) -> bytes:
        return self._files.read("payload")

    def verify_coherent(self) -> None:
        if self._closed:
            raise RuntimeError("evidence receipt binding is closed")
        self._files.verify_coherent()
        if any(os.listxattr(self._files.descriptor(label)) for label in ("payload", "receipt")):
            raise ReceiptError("evidence payload or receipt contains uncommitted xattrs")

    def close(self) -> None:
        if self._closed:
            return
        try:
            _drain_bound_inputs(self._files)
        finally:
            self._closed = self._files._closed

    def __enter__(self) -> "BoundEvidenceReceipt":
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


def validate_evidence_receipt(
    final: Path,
    receipt: Path,
    *,
    kind: str,
    expected_input_sha256: Mapping[str, str],
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Any]:
    with _owned_resource(BoundEvidenceReceipt.open, _drain_bound_evidence_receipt,
        final,
        receipt,
        kind=kind,
        expected_input_sha256=expected_input_sha256, expected_uid=expected_uid, expected_gid=expected_gid
    ) as bound:
        bound.verify_coherent()
        return dict(bound.value)
def _require_sealed_regular_descriptor(descriptor: int, description: str) -> None:
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode) or status.st_size <= 0:
        raise RuntimeError(f"{description} descriptor is not nonempty regular data")
    required = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    try:
        observed = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as error:
        raise RuntimeError(f"{description} descriptor is not sealable") from error
    if observed & required != required:
        raise RuntimeError(f"{description} descriptor is not fully sealed")
def _copy_descriptor_to_path(
    descriptor: int, destination: Path, *, mode: int
) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise RuntimeError(f"staged input is not regular data: {destination.name}")
    output = os.open(
        destination,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, HASH_CHUNK_SIZE):
            digest.update(chunk)
            _write_all(output, chunk)
        os.fchmod(output, mode)
        os.fsync(output)
        _verify_written_output(output, before.st_size, digest.hexdigest())
    except BaseException as primary:
        _release_primary = primary
        try:
            _unlink_held_output(output, destination)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
    finally:
        _release_primary = sys.exception()
        try:
            os.close(output)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    os.utime(destination, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH), follow_symlinks=False)
    if _stat_version(before) != _stat_version(os.fstat(descriptor)):
        raise RuntimeError(f"sealed input changed while staging: {destination.name}")
    return digest.hexdigest()
def _publish_descriptor(
    source: int, destination: Path, *, expected_sha256: str | None = None
) -> str:
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    before = os.fstat(source)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise RuntimeError(f"published descriptor is not nonempty: {destination.name}")
    descriptor = os.open(
        destination,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
    )
    try:
        digest = hashlib.sha256()
        os.lseek(source, 0, os.SEEK_SET)
        while chunk := os.read(source, HASH_CHUNK_SIZE):
            digest.update(chunk)
            _write_all(descriptor, chunk)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        _verify_written_output(descriptor, before.st_size, digest.hexdigest())
    except BaseException as primary:
        _release_primary = primary
        try:
            _unlink_held_output(descriptor, destination)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    observed = digest.hexdigest()
    if expected_sha256 is not None and observed != expected_sha256:
        raise RuntimeError(f"published descriptor digest differs: {destination.name}")
    if _stat_version(before) != _stat_version(os.fstat(source)):
        raise RuntimeError(f"published descriptor changed while copied: {destination.name}")
    os.utime(destination, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH), follow_symlinks=False)
    return observed
def _write_public_file(destination: Path, value: bytes) -> str:
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
    )
    try:
        _write_all(descriptor, value)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        _verify_written_output(descriptor, len(value), hashlib.sha256(value).hexdigest())
    finally:
        _release_primary = sys.exception()
        try:
            os.close(descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    os.utime(destination, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH), follow_symlinks=False)
    return hashlib.sha256(value).hexdigest()
def _publish_build_log(
    source: int, destination: Path, transcript: Mapping[str, Any]
) -> str:
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    source_before = os.fstat(source)
    output = os.open(
        destination,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
    )
    try:
        digest = hashlib.sha256()
        expected_size = 0
        for value in (
            b"OPENMYTHOS_GATE01_SUPERVISOR="
            + json.dumps(_json_safe(transcript), sort_keys=True).encode("utf-8")
            + b"\n",
        ):
            expected_size += len(value)
            digest.update(value)
            _write_all(output, value)
        os.lseek(source, 0, os.SEEK_SET)
        while chunk := os.read(source, HASH_CHUNK_SIZE):
            expected_size += len(chunk)
            digest.update(chunk)
            _write_all(output, chunk)
        footer = b"\nOPENMYTHOS_GATE01_SUPERVISOR_COMPLETE\n"
        expected_size += len(footer)
        digest.update(footer)
        _write_all(output, footer)
        os.fchmod(output, 0o644)
        os.fsync(output)
        _verify_written_output(output, expected_size, digest.hexdigest())
        if _stat_version(source_before) != _stat_version(os.fstat(source)):
            raise RuntimeError("build log source changed while copying")
    except BaseException as primary:
        _release_primary = primary
        try:
            _unlink_held_output(output, destination)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise
    finally:
        _release_primary = sys.exception()
        try:
            os.close(output)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    os.utime(destination, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH), follow_symlinks=False)
    return digest.hexdigest()
def _unlink_held_output(descriptor: int, path: os.PathLike[str] | str) -> None:
    opened = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    if _stat_identity(opened) != _stat_identity(named):
        raise RuntimeError("public output rollback identity changed")
    os.unlink(path)
def _require_direct_child(path: Path, parent: Path, names: set[str]) -> Path:
    absolute = Path(os.path.abspath(path))
    expected_parent = Path(os.path.abspath(parent))
    if absolute.parent != expected_parent or absolute.name not in names:
        raise RuntimeError(f"refusing unsafe scoped path: {absolute}")
    return absolute
def _remove_scoped_path(path: Path, parent: Path, names: set[str]) -> None:
    absolute = _require_direct_child(path, parent, names)
    if not absolute.exists() and not absolute.is_symlink():
        return
    if absolute.is_symlink() or absolute.is_file():
        absolute.unlink()
    else:
        shutil.rmtree(absolute)
def _assert_artifact_writer_custody(
    expected: Mapping[str, tuple[int, int]], allowed_descriptors: Iterable[int]
) -> None:
    expected_inodes = set(expected.values())
    allowed: set[tuple[int, int]] = set()
    for descriptor in allowed_descriptors:
        try:
            status = os.fstat(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        allowed.add((os.getpid(), descriptor))
        if expected_inodes and (status.st_dev, status.st_ino) not in expected_inodes:
            raise RuntimeError("allowed writer descriptor has the wrong inode")
    for process_path in sorted(Path("/proc").glob("[0-9]*")):
        try:
            process_status = process_path.stat()
        except OSError:
            continue
        if process_status.st_uid != os.getuid():
            continue
        fd_directory = process_path / "fd"
        try:
            names = tuple(fd_directory.iterdir())
        except OSError:
            continue
        for fd_path in names:
            try:
                descriptor_number = int(fd_path.name)
                status = fd_path.stat()
                info = (process_path / "fdinfo" / fd_path.name).read_text(
                    encoding="ascii"
                )
            except (OSError, ValueError, UnicodeError):
                continue
            if (status.st_dev, status.st_ino) not in expected_inodes:
                continue
            flags_line = next(
                (line for line in info.splitlines() if line.startswith("flags:\t")),
                None,
            )
            if flags_line is None:
                raise RuntimeError("artifact writer fdinfo lacks flags")
            flags = int(flags_line.split("\t", 1)[1], 8)
            if flags & os.O_ACCMODE != os.O_RDONLY and (
                int(process_path.name), descriptor_number
            ) not in allowed:
                raise RuntimeError("unexpected process retains an artifact writer")
def _scan_tree_with_capsule(
    capsule_descriptor: int, key_descriptor: int, root: Path | int,
    environment: Mapping[str, str],
) -> None:
    root_descriptor = os.dup(root) if isinstance(root, int) else os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        result = run_verifier_capsule(
            capsule_descriptor,
            "tools.gate01.module_key",
            ("scan-fixed-fds",),
            descriptors={BUILD_KEY_FD: key_descriptor, 50: root_descriptor},
            environment=environment,
        )
    finally:
        _release_primary = sys.exception()
        try:
            os.close(root_descriptor)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    if result.returncode != 0:
        raise RuntimeError("private key leakage detected")
def _scan_artifacts_with_capsule(
    capsule_descriptor: int,
    key_descriptor: int,
    artifacts: ArtifactSet,
    environment: Mapping[str, str],
) -> None:
    result = run_verifier_capsule(
        capsule_descriptor,
        "tools.gate01.module_key",
        ("scan-artifacts-fixed-fds",),
        descriptors={
            BUILD_KEY_FD: key_descriptor,
            **{
                ARTIFACT_FD_ROLES[role]: artifacts.descriptor(role)
                for role in ARTIFACT_FD_ROLES
            },
        },
        environment=environment,
    )
    if result.returncode != 0:
        raise RuntimeError("private key leakage detected in held artifacts")


# Resolve concrete unbound drain functions before any lazy factory acquires an
# owner. These aliases never perform a post-acquisition bound-method lookup.
_drain_bound_inputs = BoundInputs.close
_drain_bound_scoped_diff = BoundScopedDiff.close
_drain_bound_accepted_tree = BoundAcceptedTree.close
_drain_bound_evidence_receipt = BoundEvidenceReceipt.close
_drain_sealed_capsule = SealedCapsule.close
_drain_sealed_secret = SealedSecret.close
_drain_descriptor_resource = _DescriptorResource.close
_drain_artifact_set = ArtifactSet.close
_drain_artifact_slots = ArtifactSlots.close
_drain_anonymous_outputs = AnonymousOutputs.close
