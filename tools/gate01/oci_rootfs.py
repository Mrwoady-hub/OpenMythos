"""Canonicalize locked OCI root filesystems and audit materialized trees.

The archive side consumes an already-open file descriptor and never extracts a
layer. The VFS side walks from held directory descriptors and performs two
complete snapshots before accepting an audit.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from collections.abc import Iterable, Mapping
import ctypes
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from functools import lru_cache
import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import select
import signal
import stat
import struct
import sys
import tarfile
import zlib
from types import MappingProxyType
from typing import Any, TypeVar

from tools.gate01.proof_io import _add_cleanup_note, _canonical_json, _close_descriptors, _close_resource_mapping, _close_resource_preserving_primary, _json_safe, _owned_resource


SHA256_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    }
)
MAX_JSON_SIZE = 16 * 1024 * 1024
READ_CHUNK = 1024 * 1024


class OciRootfsError(ValueError):
    """An OCI archive or materialized rootfs failed closed validation."""


class RootfsMismatchError(OciRootfsError):
    """Two independently obtained rootfs views do not agree."""


@dataclass(frozen=True, order=True)
class SemanticEntry:
    """Path-independent semantics for one visible rootfs object."""

    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    mtime_ns: int
    size: int
    content_sha256: str | None = None
    symlink_target: bytes | None = None
    xattrs: tuple[tuple[str, bytes], ...] = ()
    hardlink_group: str | None = None


@dataclass(frozen=True)
class OciRootfsManifest:
    """Verified OCI identities plus its unique, path-keyed rootfs manifest."""

    entries: Mapping[str, SemanticEntry]
    archive_sha256: str
    manifest_digest: str
    config_digest: str
    layer_digests: tuple[str, ...]
    diff_ids: tuple[str, ...]
    architecture: str = "amd64"
    operating_system: str = "linux"
    descriptor_platform: tuple[tuple[str, str], ...] | None = None
    history: tuple[tuple[tuple[str, Any], ...], ...] = ()


@dataclass(frozen=True, order=True)
class RawStat:
    dev: int
    ino: int
    nlink: int
    mode: int
    uid: int
    gid: int
    rdev: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, order=True)
class RawEntry:
    path: str
    name: str
    parent_dev: int
    parent_ino: int
    dev: int
    ino: int
    nlink: int
    mode: int
    uid: int
    gid: int
    rdev: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, order=True)
class PathAnchor:
    basename: str
    parent: RawStat
    name: RawStat
    root: RawStat


@dataclass(frozen=True)
class RootfsAudit:
    entries: Mapping[str, SemanticEntry]
    raw_entries: Mapping[str, RawEntry]
    before_anchor: PathAnchor
    after_anchor: PathAnchor


@dataclass(frozen=True, order=True)
class IdMapRange:
    inside: int
    outside: int
    length: int

    def __post_init__(self) -> None:
        if self.inside < 0 or self.outside < 0 or self.length <= 0:
            raise ValueError("invalid user namespace ID-map range")


@dataclass(frozen=True)
class OwnershipProjection:
    """Project on-disk IDs to container-visible IDs."""

    uid_ranges: tuple[IdMapRange | tuple[int, int, int], ...] = ()
    gid_ranges: tuple[IdMapRange | tuple[int, int, int], ...] = ()
    allow_identity: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "uid_ranges", self._normalize(self.uid_ranges, "uid"))
        object.__setattr__(self, "gid_ranges", self._normalize(self.gid_ranges, "gid"))

    @staticmethod
    def _normalize(
        ranges: tuple[IdMapRange | tuple[int, int, int], ...], label: str
    ) -> tuple[IdMapRange, ...]:
        normalized = tuple(
            item if isinstance(item, IdMapRange) else IdMapRange(*item)
            for item in ranges
        )
        ordered = tuple(sorted(normalized, key=lambda item: item.outside))
        previous_end = -1
        for item in ordered:
            if item.outside < previous_end:
                raise ValueError(f"overlapping {label} ID-map ranges")
            previous_end = item.outside + item.length
        return ordered

    @classmethod
    def single_user_namespace(
        cls, *, outside_uid: int, outside_gid: int
    ) -> OwnershipProjection:
        return cls(
            uid_ranges=(IdMapRange(0, outside_uid, 1),),
            gid_ranges=(IdMapRange(0, outside_gid, 1),),
            allow_identity=False,
        )

    def uid(self, value: int) -> int:
        return self._project(value, self.uid_ranges, "uid")

    def gid(self, value: int) -> int:
        return self._project(value, self.gid_ranges, "gid")

    def _project(
        self, value: int, ranges: tuple[IdMapRange, ...], label: str
    ) -> int:
        for item in ranges:
            if item.outside <= value < item.outside + item.length:
                return item.inside + value - item.outside
        if self.allow_identity:
            return value
        raise OciRootfsError(f"unmapped {label}: {value}")


_V = TypeVar("_V")


def _frozen_mapping(values: Mapping[str, _V]) -> Mapping[str, _V]:
    return MappingProxyType(dict(sorted(values.items())))


def _raw_stat(value: os.stat_result) -> RawStat:
    return RawStat(
        dev=value.st_dev,
        ino=value.st_ino,
        nlink=value.st_nlink,
        mode=value.st_mode,
        uid=value.st_uid,
        gid=value.st_gid,
        rdev=value.st_rdev,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


class _PreadFile(io.RawIOBase):
    """A seekable view that does not alter the caller's file cursor."""

    def __init__(self, fd: int, size: int) -> None:
        self._fd = fd
        self._size = size
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("invalid seek origin")
        if position < 0:
            raise OSError(errno.EINVAL, "negative seek position")
        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = max(0, self._size - self._position)
        if size == 0:
            return b""
        data = os.pread(self._fd, size, self._position)
        self._position += len(data)
        return data

    def readinto(self, buffer: Any) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def _stable_fd_identity(fd: int, description: str) -> RawStat:
    try:
        value = os.fstat(fd)
    except OSError as error:
        raise OciRootfsError(f"cannot stat {description}: {error}") from error
    if not stat.S_ISREG(value.st_mode):
        raise OciRootfsError(f"{description} must be a regular file descriptor")
    return _raw_stat(value)


def _sha256_fd(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        data = os.pread(fd, min(READ_CHUNK, size - offset), offset)
        if not data:
            raise OciRootfsError("OCI archive changed while hashing")
        digest.update(data)
        offset += len(data)
    if os.pread(fd, 1, size):
        raise OciRootfsError("OCI archive grew while hashing")
    return digest.hexdigest()


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OciRootfsError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise OciRootfsError(f"non-finite JSON value: {value}")


def _load_json(data: bytes, description: str) -> dict[str, Any]:
    if len(data) > MAX_JSON_SIZE:
        raise OciRootfsError(f"{description} exceeds the JSON size limit")
    try:
        value = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OciRootfsError(f"invalid {description}: {error}") from error
    if not isinstance(value, dict):
        raise OciRootfsError(f"{description} must be a JSON object")
    return value


def _require_fields(
    value: Mapping[str, Any],
    required: set[str],
    allowed: set[str],
    description: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing or unknown:
        raise OciRootfsError(
            f"invalid {description} fields: missing={sorted(missing)} "
            f"unknown={sorted(unknown)}"
        )


def _digest_hex(value: Any, description: str) -> str:
    if not isinstance(value, str):
        raise OciRootfsError(f"invalid {description} digest")
    match = SHA256_RE.fullmatch(value)
    if match is None:
        raise OciRootfsError(f"invalid {description} digest")
    return match.group(1)


def _archive_path(name: str) -> str:
    if not name or name.startswith("/") or "\x00" in name:
        raise OciRootfsError(f"OCI archive path traversal: {name!r}")
    components = name.split("/")
    if any(component == ".." for component in components):
        raise OciRootfsError(f"OCI archive path traversal: {name!r}")
    normalized = "/".join(
        component for component in components if component not in ("", ".")
    )
    if not normalized:
        raise OciRootfsError(f"OCI archive path traversal: {name!r}")
    return normalized


def _index_oci_archive(
    archive: tarfile.TarFile,
) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    try:
        iterator = iter(archive)
        for member in iterator:
            path = _archive_path(member.name)
            if path in members:
                raise OciRootfsError(f"duplicate OCI archive path: {path}")
            if not (member.isdir() or member.isreg()):
                raise OciRootfsError(f"unsupported OCI archive entry: {path}")
            if member.isdir():
                if path not in {"blobs", "blobs/sha256"}:
                    raise OciRootfsError(f"unexpected OCI archive directory: {path}")
            elif path not in {"index.json", "oci-layout"} and not re.fullmatch(
                r"blobs/sha256/[0-9a-f]{64}", path
            ):
                raise OciRootfsError(f"unexpected OCI archive file: {path}")
            members[path] = member
    except tarfile.TarError as error:
        raise OciRootfsError(f"invalid OCI archive tar: {error}") from error
    for required in ("index.json", "oci-layout"):
        if required not in members or not members[required].isreg():
            raise OciRootfsError(f"OCI archive is missing {required}")
    return members


def _read_archive_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    description: str,
    *,
    maximum: int | None = None,
) -> bytes:
    if maximum is not None and member.size > maximum:
        raise OciRootfsError(f"{description} exceeds its size limit")
    source = archive.extractfile(member)
    if source is None:
        raise OciRootfsError(f"cannot read {description}")
    output = bytearray()
    while True:
        chunk = source.read(READ_CHUNK)
        if not chunk:
            break
        output.extend(chunk)
        if maximum is not None and len(output) > maximum:
            raise OciRootfsError(f"{description} exceeds its size limit")
    if len(output) != member.size:
        raise OciRootfsError(f"short read for {description}")
    return bytes(output)


@dataclass(frozen=True)
class _Descriptor:
    digest: str
    size: int
    media_type: str

    @property
    def blob_path(self) -> str:
        return f"blobs/sha256/{self.digest.removeprefix('sha256:')}"


def _parse_descriptor(
    value: Any, description: str, allowed_media_types: set[str] | frozenset[str]
) -> _Descriptor:
    if not isinstance(value, dict):
        raise OciRootfsError(f"{description} descriptor must be an object")
    _require_fields(
        value,
        {"mediaType", "digest", "size"},
        {"mediaType", "digest", "size", "annotations", "platform"},
        f"{description} descriptor",
    )
    media_type = value["mediaType"]
    if media_type not in allowed_media_types:
        raise OciRootfsError(f"unsupported {description} media type: {media_type!r}")
    digest_hex = _digest_hex(value["digest"], description)
    size = value["size"]
    if type(size) is not int or size < 0:
        raise OciRootfsError(f"invalid {description} descriptor size")
    if "annotations" in value and not isinstance(value["annotations"], dict):
        raise OciRootfsError(f"invalid {description} annotations")
    if "platform" in value and not isinstance(value["platform"], dict):
        raise OciRootfsError(f"invalid {description} platform")
    return _Descriptor(f"sha256:{digest_hex}", size, media_type)


def _verify_descriptor_blob(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: _Descriptor,
    description: str,
) -> tarfile.TarInfo:
    member = members.get(descriptor.blob_path)
    if member is None or not member.isreg():
        raise OciRootfsError(f"missing {description} blob: {descriptor.digest}")
    if member.size != descriptor.size:
        raise OciRootfsError(
            f"{description} descriptor size mismatch: "
            f"expected {descriptor.size}, got {member.size}"
        )
    source = archive.extractfile(member)
    if source is None:
        raise OciRootfsError(f"cannot read {description} blob")
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = source.read(READ_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
        count += len(chunk)
    if count != descriptor.size:
        raise OciRootfsError(f"short read for {description} blob")
    actual = digest.hexdigest()
    expected = descriptor.digest.removeprefix("sha256:")
    if actual != expected:
        raise OciRootfsError(
            f"{description} descriptor SHA-256 mismatch: "
            f"expected {expected}, got {actual}"
        )
    return member


def _parse_oci_documents(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    expected_manifest_digest: str,
) -> tuple[
    _Descriptor,
    _Descriptor,
    tuple[_Descriptor, ...],
    tuple[str, ...],
    tuple[tuple[tuple[str, Any], ...], ...],
    tuple[tuple[str, str], ...] | None,
]:
    layout = _load_json(
        _read_archive_member(
            archive, members["oci-layout"], "oci-layout", maximum=MAX_JSON_SIZE
        ),
        "oci-layout",
    )
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise OciRootfsError("unsupported or non-canonical oci-layout")

    index = _load_json(
        _read_archive_member(
            archive, members["index.json"], "index.json", maximum=MAX_JSON_SIZE
        ),
        "index.json",
    )
    _require_fields(
        index,
        {"schemaVersion", "manifests"},
        {"schemaVersion", "manifests", "annotations"},
        "OCI index",
    )
    if index["schemaVersion"] != 2:
        raise OciRootfsError("OCI index schemaVersion must be 2")
    if not isinstance(index["manifests"], list) or len(index["manifests"]) != 1:
        raise OciRootfsError("OCI index must contain exactly one manifest")
    manifest_value = index["manifests"][0]
    manifest_descriptor = _parse_descriptor(
        manifest_value, "manifest", {OCI_MANIFEST_MEDIA_TYPE}
    )
    platform = manifest_value.get("platform")
    if platform is not None:
        if not isinstance(platform, dict):
            raise OciRootfsError("invalid manifest platform")
        _require_fields(
            platform,
            {"architecture", "os"},
            {"architecture", "os"},
            "manifest platform",
        )
        if platform != {"architecture": "amd64", "os": "linux"}:
            raise OciRootfsError("OCI image platform must be linux/amd64")
    expected_hex = _digest_hex(expected_manifest_digest, "locked manifest")
    if manifest_descriptor.digest != f"sha256:{expected_hex}":
        raise OciRootfsError(
            "manifest digest does not match the locked image identity"
        )
    manifest_member = _verify_descriptor_blob(
        archive, members, manifest_descriptor, "manifest"
    )
    manifest = _load_json(
        _read_archive_member(
            archive, manifest_member, "OCI manifest", maximum=MAX_JSON_SIZE
        ),
        "OCI manifest",
    )
    _require_fields(
        manifest,
        {"schemaVersion", "mediaType", "config", "layers"},
        {"schemaVersion", "mediaType", "config", "layers", "annotations"},
        "OCI manifest",
    )
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST_MEDIA_TYPE:
        raise OciRootfsError("invalid OCI image manifest identity")
    config_descriptor = _parse_descriptor(
        manifest["config"], "config", {OCI_CONFIG_MEDIA_TYPE}
    )
    layer_values = manifest["layers"]
    if not isinstance(layer_values, list) or not layer_values:
        raise OciRootfsError("OCI manifest must contain at least one layer")
    layers = tuple(
        _parse_descriptor(value, f"layer {index}", LAYER_MEDIA_TYPES)
        for index, value in enumerate(layer_values)
    )

    config_member = _verify_descriptor_blob(
        archive, members, config_descriptor, "config"
    )
    config = _load_json(
        _read_archive_member(
            archive, config_member, "OCI config", maximum=MAX_JSON_SIZE
        ),
        "OCI config",
    )
    _require_fields(
        config,
        {"architecture", "os", "rootfs"},
        {
            "architecture",
            "os",
            "rootfs",
            "config",
            "created",
            "author",
            "history",
            "variant",
            "os.version",
            "os.features",
        },
        "OCI config",
    )
    if config["architecture"] != "amd64" or config["os"] != "linux":
        raise OciRootfsError("OCI image platform must be linux/amd64")
    if platform is not None and (
        platform["architecture"] != config["architecture"]
        or platform["os"] != config["os"]
    ):
        raise OciRootfsError("OCI descriptor and config platform differ")
    rootfs = config["rootfs"]
    if not isinstance(rootfs, dict):
        raise OciRootfsError("OCI config rootfs must be an object")
    _require_fields(rootfs, {"type", "diff_ids"}, {"type", "diff_ids"}, "rootfs")
    if rootfs["type"] != "layers" or not isinstance(rootfs["diff_ids"], list):
        raise OciRootfsError("OCI config rootfs must describe layers")
    if len(rootfs["diff_ids"]) != len(layers):
        raise OciRootfsError("OCI config diff_ids count does not match layers")
    diff_ids = tuple(
        f"sha256:{_digest_hex(value, f'diff_id {index}')}"
        for index, value in enumerate(rootfs["diff_ids"])
    )
    history_value = config.get("history")
    if not isinstance(history_value, list) or not history_value:
        raise OciRootfsError("OCI config history must be a non-empty list")
    history: list[tuple[tuple[str, Any], ...]] = []
    nonempty_history = 0
    allowed_history = {"created", "created_by", "author", "comment", "empty_layer"}
    for history_index, item in enumerate(history_value):
        if not isinstance(item, dict):
            raise OciRootfsError(f"OCI history {history_index} must be an object")
        _require_fields(item, set(), allowed_history, f"OCI history {history_index}")
        if not item:
            raise OciRootfsError(f"OCI history {history_index} is empty")
        for field in ("created", "created_by", "author", "comment"):
            if field in item and not isinstance(item[field], str):
                raise OciRootfsError(
                    f"OCI history {history_index} field {field} must be a string"
                )
        if "empty_layer" in item and type(item["empty_layer"]) is not bool:
            raise OciRootfsError(
                f"OCI history {history_index} empty_layer must be boolean"
            )
        if item.get("empty_layer") is not True:
            nonempty_history += 1
        history.append(tuple(sorted(item.items())))
    if nonempty_history != len(diff_ids):
        raise OciRootfsError(
            "OCI nonempty history count does not match rootfs diff_ids"
        )
    descriptor_platform = (
        None
        if platform is None
        else tuple(sorted((str(key), str(value)) for key, value in platform.items()))
    )
    return (
        manifest_descriptor,
        config_descriptor,
        layers,
        diff_ids,
        tuple(history),
        descriptor_platform,
    )


@dataclass(frozen=True)
class _Metadata:
    mode: int
    uid: int
    gid: int
    mtime_ns: int
    xattrs: tuple[tuple[str, bytes], ...]


@dataclass(eq=False)
class _Node:
    kind: str
    metadata: _Metadata
    size: int = 0
    content_sha256: str | None = None
    symlink_target: bytes | None = None


@dataclass(frozen=True)
class _LayerRecord:
    path: str
    kind: str
    node: _Node | None = None
    target: str | None = None


class _HashingReader(io.RawIOBase):
    def __init__(self, source: Any) -> None:
        self.source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        if data:
            self.digest.update(data)
            self.size += len(data)
        return data

    def readinto(self, buffer: Any) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def _layer_path(name: str, description: str = "layer path") -> str:
    if not isinstance(name, str) or name.startswith("/") or "\x00" in name:
        raise OciRootfsError(f"{description} traversal: {name!r}")
    components = name.split("/")
    if any(component == ".." for component in components):
        raise OciRootfsError(f"{description} traversal: {name!r}")
    parts = [component for component in components if component not in ("", ".")]
    return "/" + "/".join(parts) if parts else "/"


def _mtime_ns(member: tarfile.TarInfo) -> int:
    raw_value: Any = member.pax_headers.get("mtime", member.mtime)
    try:
        nanoseconds = Decimal(str(raw_value)) * Decimal(1_000_000_000)
    except InvalidOperation as error:
        raise OciRootfsError(f"invalid mtime for layer path {member.name!r}") from error
    integral = nanoseconds.to_integral_value()
    if nanoseconds != integral:
        raise OciRootfsError(
            f"layer mtime has sub-nanosecond precision: {member.name!r}"
        )
    value = int(integral)
    if value < -(2**63) or value >= 2**63:
        raise OciRootfsError(f"layer mtime is out of range: {member.name!r}")
    return value


def _member_metadata(member: tarfile.TarInfo) -> _Metadata:
    if type(member.uid) is not int or member.uid < 0:
        raise OciRootfsError(f"invalid uid for layer path {member.name!r}")
    if type(member.gid) is not int or member.gid < 0:
        raise OciRootfsError(f"invalid gid for layer path {member.name!r}")
    if type(member.mode) is not int or member.mode < 0 or member.mode > 0o7777:
        raise OciRootfsError(f"invalid mode for layer path {member.name!r}")
    return _Metadata(
        mode=member.mode,
        uid=member.uid,
        gid=member.gid,
        mtime_ns=_mtime_ns(member),
        xattrs=_decode_pax_xattrs(member),
    )


def _acl_permissions(value: str) -> int:
    if len(value) != 3:
        raise OciRootfsError(f"invalid POSIX ACL permissions: {value!r}")
    result = 0
    for character, expected, bit in zip(value, "rwx", (4, 2, 1), strict=True):
        if character == expected:
            result |= bit
        elif character != "-":
            raise OciRootfsError(f"invalid POSIX ACL permissions: {value!r}")
    return result


def _acl_xattr(value: str) -> bytes:
    tags = {
        ("user", False): 0x01,
        ("user", True): 0x02,
        ("group", False): 0x04,
        ("group", True): 0x08,
        ("mask", False): 0x10,
        ("other", False): 0x20,
    }
    records: list[bytes] = []
    seen: set[tuple[int, int]] = set()
    for raw_entry in value.split(","):
        fields = raw_entry.strip().split(":")
        if len(fields) not in (3, 4):
            raise OciRootfsError(f"invalid SCHILY POSIX ACL entry: {raw_entry!r}")
        kind, qualifier, permissions = fields[:3]
        named = bool(qualifier)
        tag = tags.get((kind, named))
        if tag is None:
            raise OciRootfsError(f"invalid SCHILY POSIX ACL entry: {raw_entry!r}")
        identifier = 0xFFFFFFFF
        if named:
            identifier_text = fields[3] if len(fields) == 4 else qualifier
            if not identifier_text.isdecimal():
                raise OciRootfsError(
                    f"named SCHILY ACL lacks a numeric ID: {raw_entry!r}"
                )
            identifier = int(identifier_text)
            if identifier >= 0xFFFFFFFF:
                raise OciRootfsError(f"SCHILY ACL ID is out of range: {raw_entry!r}")
        elif len(fields) == 4 and fields[3] not in ("", "-1"):
            raise OciRootfsError(f"invalid SCHILY ACL ID: {raw_entry!r}")
        key = (tag, identifier)
        if key in seen:
            raise OciRootfsError(f"duplicate SCHILY ACL entry: {raw_entry!r}")
        seen.add(key)
        records.append(struct.pack("<HHI", tag, _acl_permissions(permissions), identifier))
    if not records:
        raise OciRootfsError("empty SCHILY POSIX ACL")
    return struct.pack("<I", 2) + b"".join(records)


def _decode_base64(value: str, description: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        return base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise OciRootfsError(f"invalid base64 {description}") from error


def _validate_xattr_name(name: str) -> str:
    if (
        not name
        or "\x00" in name
        or not name.startswith(("user.", "security.", "system.", "trusted."))
    ):
        raise OciRootfsError(f"invalid extended attribute name: {name!r}")
    return name


def _decode_pax_xattrs(member: tarfile.TarInfo) -> tuple[tuple[str, bytes], ...]:
    values: dict[str, bytes] = {}

    def add(name: str, value: bytes) -> None:
        validated = _validate_xattr_name(name)
        if validated in values:
            raise OciRootfsError(
                f"duplicate extended attribute for {member.name!r}: {validated}"
            )
        values[validated] = value

    for key, value in sorted(member.pax_headers.items()):
        if key.startswith("SCHILY.xattr."):
            name = key.removeprefix("SCHILY.xattr.")
            add(name, value.encode("utf-8", "surrogateescape"))
        elif key.startswith("LIBARCHIVE.xattr."):
            encoded_name = key.removeprefix("LIBARCHIVE.xattr.")
            name_bytes = _decode_base64(encoded_name, "xattr name")
            try:
                name = name_bytes.decode("utf-8")
            except UnicodeDecodeError as error:
                raise OciRootfsError("non-UTF-8 extended attribute name") from error
            add(name, _decode_base64(value, f"xattr value for {name}"))
        elif key == "SCHILY.acl.access":
            add("system.posix_acl_access", _acl_xattr(value))
        elif key == "SCHILY.acl.default":
            add("system.posix_acl_default", _acl_xattr(value))
    return tuple(sorted(values.items()))


def _hash_member_payload(
    archive: tarfile.TarFile, member: tarfile.TarInfo
) -> tuple[str, int]:
    source = archive.extractfile(member)
    if source is None:
        raise OciRootfsError(f"cannot read layer file payload: {member.name!r}")
    digest = hashlib.sha256()
    count = 0
    while True:
        chunk = source.read(READ_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
        count += len(chunk)
    if count != member.size:
        raise OciRootfsError(f"short layer file payload: {member.name!r}")
    return digest.hexdigest(), count


def _whiteout_record(path: str, member: tarfile.TarInfo) -> _LayerRecord | None:
    basename = path.rsplit("/", 1)[-1]
    if not basename.startswith(".wh."):
        return None
    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.size != 0:
        raise OciRootfsError(f"invalid whiteout entry: {member.name!r}")
    parent = path.rsplit("/", 1)[0] or "/"
    if basename == ".wh..wh..opq":
        return _LayerRecord(parent, "opaque")
    target_name = basename.removeprefix(".wh.")
    if not target_name:
        raise OciRootfsError(f"invalid whiteout entry: {member.name!r}")
    target = f"/{target_name}" if parent == "/" else f"{parent}/{target_name}"
    return _LayerRecord(target, "whiteout")


def _layer_record(
    archive: tarfile.TarFile, member: tarfile.TarInfo, path: str
) -> _LayerRecord:
    whiteout = _whiteout_record(path, member)
    if whiteout is not None:
        return whiteout
    if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.sparse:
        digest, size = _hash_member_payload(archive, member)
        node = _Node(
            "file",
            _member_metadata(member),
            size=size,
            content_sha256=digest,
        )
        return _LayerRecord(path, "file", node=node)
    if member.type == tarfile.DIRTYPE:
        if member.size != 0:
            raise OciRootfsError(f"directory has a payload: {member.name!r}")
        return _LayerRecord(path, "directory", node=_Node("directory", _member_metadata(member)))
    if member.type == tarfile.SYMTYPE:
        if member.size != 0:
            raise OciRootfsError(f"symlink has a payload: {member.name!r}")
        target = member.linkname.encode("utf-8", "surrogateescape")
        if not target or b"\x00" in target:
            raise OciRootfsError(f"invalid symlink target: {member.name!r}")
        return _LayerRecord(
            path,
            "symlink",
            node=_Node(
                "symlink",
                _member_metadata(member),
                size=len(target),
                symlink_target=target,
            ),
        )
    if member.type == tarfile.LNKTYPE:
        if member.size != 0:
            raise OciRootfsError(f"hardlink has a payload: {member.name!r}")
        target = _layer_path(member.linkname, "hardlink target")
        return _LayerRecord(path, "hardlink", target=target)
    raise OciRootfsError(
        f"unsupported layer entry for {member.name!r}: type={member.type!r}"
    )


def _read_layer_records(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    descriptor: _Descriptor,
    diff_id: str,
) -> tuple[_LayerRecord, ...]:
    compressed = archive.extractfile(member)
    if compressed is None:
        raise OciRootfsError(f"cannot read layer blob: {descriptor.digest}")
    if descriptor.media_type.endswith("+gzip"):
        source: Any = gzip.GzipFile(fileobj=compressed, mode="rb")
    else:
        source = compressed
    hashing_source = _HashingReader(source)
    records: list[_LayerRecord] = []
    seen: set[str] = set()
    try:
        with tarfile.open(
            fileobj=hashing_source,
            mode="r|",
            bufsize=512,
            encoding="utf-8",
            errors="surrogateescape",
        ) as layer:
            for layer_member in layer:
                path = _layer_path(layer_member.name)
                if path in seen:
                    raise OciRootfsError(f"duplicate layer path: {path}")
                seen.add(path)
                records.append(_layer_record(layer, layer_member, path))
        while hashing_source.read(READ_CHUNK):
            pass
    except OciRootfsError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, OSError) as error:
        raise OciRootfsError(
            f"invalid layer tar {descriptor.digest}: {error}"
        ) from error
    actual_diff_id = f"sha256:{hashing_source.digest.hexdigest()}"
    if actual_diff_id != diff_id:
        raise OciRootfsError(
            f"layer diff_id mismatch for {descriptor.digest}: "
            f"expected {diff_id}, got {actual_diff_id}"
        )
    return tuple(records)


_IMPLICIT_DIRECTORY = _Node(
    "directory", _Metadata(mode=0o755, uid=0, gid=0, mtime_ns=0, xattrs=())
)


def _is_descendant(path: str, parent: str) -> bool:
    return path != parent and (parent == "/" or path.startswith(parent + "/"))


def _remove_subtree(filesystem: dict[str, _Node], path: str) -> None:
    if path == "/":
        raise OciRootfsError("a layer cannot whiteout the root directory")
    for candidate in tuple(filesystem):
        if candidate == path or _is_descendant(candidate, path):
            del filesystem[candidate]


def _parent_paths(path: str) -> tuple[str, ...]:
    if path == "/":
        return ()
    parts = path.removeprefix("/").split("/")[:-1]
    parents: list[str] = []
    current = ""
    for part in parts:
        current += "/" + part
        parents.append(current)
    return tuple(parents)


def _ensure_parents(filesystem: dict[str, _Node], path: str) -> None:
    for parent in _parent_paths(path):
        node = filesystem.get(parent)
        if node is None:
            filesystem[parent] = _Node(
                "directory", _IMPLICIT_DIRECTORY.metadata
            )
        elif node.kind != "directory":
            raise OciRootfsError(
                f"layer path traverses a non-directory ancestor: {parent}"
            )


def _apply_layer(
    filesystem: dict[str, _Node], records: tuple[_LayerRecord, ...]
) -> None:
    lower_paths = frozenset(filesystem)
    for record in records:
        if record.kind == "opaque":
            for candidate in lower_paths:
                if _is_descendant(candidate, record.path):
                    filesystem.pop(candidate, None)
        elif record.kind == "whiteout":
            _remove_subtree(filesystem, record.path)

    pending: list[_LayerRecord] = []
    for record in records:
        if record.kind in {"opaque", "whiteout"}:
            continue
        if record.path == "/" and record.kind != "directory":
            raise OciRootfsError("the root layer entry must be a directory")
        _ensure_parents(filesystem, record.path)
        if record.kind == "directory":
            if record.node is None:
                raise OciRootfsError("internal directory record lacks a node")
            existing = filesystem.get(record.path)
            if existing is not None and existing.kind != "directory":
                _remove_subtree(filesystem, record.path)
            filesystem[record.path] = record.node
        elif record.kind in {"file", "symlink"}:
            if record.node is None:
                raise OciRootfsError("internal filesystem record lacks a node")
            if record.path in filesystem:
                _remove_subtree(filesystem, record.path)
            filesystem[record.path] = record.node
        elif record.kind == "hardlink":
            target = filesystem.get(record.target or "")
            if target is None:
                pending.append(record)
            elif target.kind not in {"file", "symlink"}:
                raise OciRootfsError(
                    f"hardlink target is not linkable: {record.target}"
                )
            else:
                if record.path in filesystem:
                    _remove_subtree(filesystem, record.path)
                filesystem[record.path] = target
        else:  # pragma: no cover - internal exhaustiveness guard
            raise AssertionError(record.kind)

    while pending:
        remaining: list[_LayerRecord] = []
        progress = False
        for record in pending:
            target = filesystem.get(record.target or "")
            if target is None:
                remaining.append(record)
                continue
            if target.kind not in {"file", "symlink"}:
                raise OciRootfsError(
                    f"hardlink target is not linkable: {record.target}"
                )
            if record.path in filesystem:
                _remove_subtree(filesystem, record.path)
            filesystem[record.path] = target
            progress = True
        if not progress:
            unresolved = ", ".join(
                f"{record.path}->{record.target}" for record in remaining
            )
            raise OciRootfsError(f"unresolved or cyclic hardlink target: {unresolved}")
        pending = remaining


def _semantic_entries(filesystem: Mapping[str, _Node]) -> Mapping[str, SemanticEntry]:
    root = filesystem.get("/")
    if root is None or root.kind != "directory":
        raise OciRootfsError("rootfs has no directory root")
    inode_paths: dict[int, list[str]] = defaultdict(list)
    for path, node in filesystem.items():
        if node.kind in {"file", "symlink"}:
            inode_paths[id(node)].append(path)
    hardlink_groups = {
        identity: min(paths)
        for identity, paths in inode_paths.items()
        if len(paths) > 1
    }
    result: dict[str, SemanticEntry] = {}
    for path, node in filesystem.items():
        metadata = node.metadata
        result[path] = SemanticEntry(
            path=path,
            kind=node.kind,
            mode=metadata.mode,
            uid=metadata.uid,
            gid=metadata.gid,
            mtime_ns=metadata.mtime_ns,
            size=node.size,
            content_sha256=node.content_sha256,
            symlink_target=node.symlink_target,
            xattrs=metadata.xattrs,
            hardlink_group=hardlink_groups.get(id(node)),
        )
    return _frozen_mapping(result)


def canonicalize_oci_archive(
    archive_fd: int,
    *,
    expected_archive_sha256: str,
    expected_manifest_digest: str,
) -> OciRootfsManifest:
    """Verify and semantically merge a locked OCI image archive.

    ``archive_fd`` remains owned by the caller and its file offset is not
    changed. Both locked identities are mandatory so an otherwise valid but
    substituted OCI image is rejected.
    """

    if type(archive_fd) is not int or archive_fd < 0:
        raise OciRootfsError("archive_fd must be an open file descriptor")
    if expected_archive_sha256.startswith("sha256:"):
        expected_archive_sha256 = expected_archive_sha256.removeprefix("sha256:")
    if RAW_SHA256_RE.fullmatch(expected_archive_sha256) is None:
        raise OciRootfsError("invalid locked archive SHA-256")
    before = _stable_fd_identity(archive_fd, "OCI archive")
    archive_sha256 = _sha256_fd(archive_fd, before.size)
    if archive_sha256 != expected_archive_sha256:
        raise OciRootfsError(
            "archive SHA-256 mismatch: "
            f"expected {expected_archive_sha256}, got {archive_sha256}"
        )

    pread_file = _PreadFile(archive_fd, before.size)
    try:
        with tarfile.open(
            fileobj=pread_file,
            mode="r:",
            encoding="utf-8",
            errors="surrogateescape",
        ) as archive:
            members = _index_oci_archive(archive)
            (
                manifest,
                config,
                layers,
                diff_ids,
                history,
                descriptor_platform,
            ) = _parse_oci_documents(
                archive, members, expected_manifest_digest
            )
            referenced = {
                manifest.blob_path,
                config.blob_path,
                *(layer.blob_path for layer in layers),
            }
            present = {
                path for path in members if path.startswith("blobs/sha256/")
            }
            if present != referenced:
                raise OciRootfsError(
                    "OCI archive blob set differs from the referenced descriptor set"
                )

            filesystem: dict[str, _Node] = {
                "/": _Node("directory", _IMPLICIT_DIRECTORY.metadata)
            }
            for index, (layer, diff_id) in enumerate(zip(layers, diff_ids, strict=True)):
                member = _verify_descriptor_blob(
                    archive, members, layer, f"layer {index}"
                )
                records = _read_layer_records(archive, member, layer, diff_id)
                _apply_layer(filesystem, records)
            entries = _semantic_entries(filesystem)
    except OciRootfsError:
        raise
    except (tarfile.TarError, OSError) as error:
        raise OciRootfsError(f"invalid OCI archive: {error}") from error

    after = _stable_fd_identity(archive_fd, "OCI archive")
    if after != before:
        raise OciRootfsError("OCI archive identity changed during canonicalization")
    return OciRootfsManifest(
        entries=entries,
        archive_sha256=archive_sha256,
        manifest_digest=manifest.digest,
        config_digest=config.digest,
        layer_digests=tuple(layer.digest for layer in layers),
        diff_ids=diff_ids,
        architecture="amd64",
        operating_system="linux",
        descriptor_platform=descriptor_platform,
        history=history,
    )


def _secure_open_root(root: os.PathLike[str] | str) -> tuple[int, int, str]:
    absolute = os.path.abspath(os.fspath(root))
    if "\x00" in absolute:
        raise OciRootfsError("rootfs path contains NUL")
    components = [part for part in absolute.split(os.sep) if part]
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open(os.sep, directory_flags)
    root_fd = -1
    try:
        if not components:
            root_fd = os.dup(current)
            return current, root_fd, "."
        for component in components[:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current)
            except OSError as error:
                raise OciRootfsError(
                    f"rootfs path contains a symlink or non-directory: {component!r}"
                ) from error
            closing, current = current, next_fd
            os.close(closing)
        name = components[-1]
        try:
            name_stat = os.stat(name, dir_fd=current, follow_symlinks=False)
        except OSError as error:
            raise OciRootfsError(f"cannot lstat rootfs name: {error}") from error
        if stat.S_ISLNK(name_stat.st_mode):
            raise OciRootfsError("rootfs name is a symlink")
        if not stat.S_ISDIR(name_stat.st_mode):
            raise OciRootfsError("rootfs name is not a directory")
        try:
            root_fd = os.open(name, directory_flags, dir_fd=current)
        except OSError as error:
            raise OciRootfsError(f"cannot open rootfs directory: {error}") from error
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (name_stat.st_dev, name_stat.st_ino):
            raise OciRootfsError("rootfs name changed while opening")
        return current, root_fd, name
    except BaseException:
        _close_descriptors(root_fd, current, primary=sys.exception())
        raise


def _capture_anchor(parent_fd: int, root_fd: int, name: str) -> PathAnchor:
    try:
        parent = os.fstat(parent_fd)
        root = os.fstat(root_fd)
        name_value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise OciRootfsError(f"cannot capture rootfs anchor: {error}") from error
    if not stat.S_ISDIR(name_value.st_mode):
        raise OciRootfsError("rootfs name became a symlink or non-directory")
    if (root.st_dev, root.st_ino) != (name_value.st_dev, name_value.st_ino):
        raise OciRootfsError("rootfs name no longer identifies the held directory")
    return PathAnchor(
        basename=name,
        parent=_raw_stat(parent),
        name=_raw_stat(name_value),
        root=_raw_stat(root),
    )


def _raw_entry(
    path: str,
    name: str,
    parent: os.stat_result,
    value: os.stat_result,
) -> RawEntry:
    return RawEntry(
        path=path,
        name=name,
        parent_dev=parent.st_dev,
        parent_ino=parent.st_ino,
        dev=value.st_dev,
        ino=value.st_ino,
        nlink=value.st_nlink,
        mode=value.st_mode,
        uid=value.st_uid,
        gid=value.st_gid,
        rdev=value.st_rdev,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _read_fd_xattrs(fd: int, path: str) -> tuple[tuple[str, bytes], ...]:
    try:
        names_before = sorted(os.listxattr(fd))
        values = tuple((name, os.getxattr(fd, name)) for name in names_before)
        names_after = sorted(os.listxattr(fd))
    except OSError as error:
        raise OciRootfsError(f"cannot read xattrs for {path}: {error}") from error
    if names_before != names_after:
        raise OciRootfsError(f"xattr names changed while auditing {path}")
    return values


def _read_symlink_xattrs(
    parent_fd: int, name: str, path: str
) -> tuple[tuple[str, bytes], ...]:
    anchored = f"/proc/self/fd/{parent_fd}/{name}"
    try:
        names_before = sorted(os.listxattr(anchored, follow_symlinks=False))
        values = tuple(
            (
                attribute,
                os.getxattr(anchored, attribute, follow_symlinks=False),
            )
            for attribute in names_before
        )
        names_after = sorted(os.listxattr(anchored, follow_symlinks=False))
    except OSError as error:
        raise OciRootfsError(f"cannot read symlink xattrs for {path}: {error}") from error
    if names_before != names_after:
        raise OciRootfsError(f"symlink xattr names changed while auditing {path}")
    return values


def _hash_open_file(fd: int, expected_size: int, path: str) -> str:
    digest = hashlib.sha256()
    count = 0
    while True:
        data = os.read(fd, READ_CHUNK)
        if not data:
            break
        digest.update(data)
        count += len(data)
    if count != expected_size:
        raise OciRootfsError(
            f"file size changed while hashing {path}: expected {expected_size}, got {count}"
        )
    return digest.hexdigest()


def project_runtime_bind_file(
    manifest: OciRootfsManifest,
    source_fd: int,
    *,
    target: str,
    projection: OwnershipProjection | None = None,
) -> OciRootfsManifest:
    """Add one exact runtime-created regular bind target to OCI semantics.

    Podman creates ``/run/.containerenv`` outside the sealed image layers and
    names its exact read-only source in the already-audited OCI config.  This
    routine derives that target's complete semantic record from a held source
    descriptor; it never trusts target bytes or a mutable source pathname.
    """
    pure = PurePosixPath(target)
    if (
        not target.startswith("/")
        or pure.as_posix() != target
        or target == "/"
        or "." in pure.parts
        or ".." in pure.parts
    ):
        raise OciRootfsError("runtime bind target is unsafe")
    if target in manifest.entries:
        raise OciRootfsError("runtime bind target already exists in OCI rootfs")
    parent = pure.parent.as_posix()
    if not parent.startswith("/"):
        parent = "/" + parent
    parent_entry = manifest.entries.get(parent)
    if parent_entry is None or parent_entry.kind != "directory":
        raise OciRootfsError("runtime bind target parent is absent")
    selected_projection = projection or OwnershipProjection()
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink < 1:
        raise OciRootfsError("runtime bind source is not a linked regular file")
    os.lseek(source_fd, 0, os.SEEK_SET)
    first_digest = _hash_open_file(source_fd, before.st_size, target)
    first_xattrs = _read_fd_xattrs(source_fd, target)
    middle = os.fstat(source_fd)
    _require_same_stat(before, middle, target)
    os.lseek(source_fd, 0, os.SEEK_SET)
    second_digest = _hash_open_file(source_fd, before.st_size, target)
    second_xattrs = _read_fd_xattrs(source_fd, target)
    after = os.fstat(source_fd)
    _require_same_stat(before, after, target)
    if first_digest != second_digest or first_xattrs != second_xattrs:
        raise OciRootfsError("runtime bind source changed during projection")
    state = _ScanState(selected_projection, {}, {}, {})
    entry = _semantic_from_stat(
        state,
        target,
        "file",
        after,
        size=after.st_size,
        content_sha256=second_digest,
        xattrs=second_xattrs,
    )
    entries = dict(manifest.entries)
    entries[target] = entry
    return replace(manifest, entries=_frozen_mapping(entries))


def _require_same_stat(
    before: os.stat_result, after: os.stat_result, path: str
) -> None:
    if _raw_stat(before) != _raw_stat(after):
        raise OciRootfsError(f"filesystem object changed while auditing {path}")


@dataclass
class _ScanState:
    projection: OwnershipProjection
    entries: dict[str, SemanticEntry]
    raw_entries: dict[str, RawEntry]
    file_cache: dict[tuple[int, int], tuple[RawStat, str, tuple[tuple[str, bytes], ...]]]


def _semantic_from_stat(
    state: _ScanState,
    path: str,
    kind: str,
    value: os.stat_result,
    *,
    size: int,
    content_sha256: str | None = None,
    symlink_target: bytes | None = None,
    xattrs: tuple[tuple[str, bytes], ...] = (),
) -> SemanticEntry:
    return SemanticEntry(
        path=path,
        kind=kind,
        mode=stat.S_IMODE(value.st_mode),
        uid=state.projection.uid(value.st_uid),
        gid=state.projection.gid(value.st_gid),
        mtime_ns=value.st_mtime_ns,
        size=size,
        content_sha256=content_sha256,
        symlink_target=symlink_target,
        xattrs=xattrs,
    )


def _matching_open_stat(
    name_stat: os.stat_result, opened_stat: os.stat_result, path: str
) -> None:
    if _raw_stat(name_stat) != _raw_stat(opened_stat):
        raise OciRootfsError(f"filesystem name changed while opening {path}")


def _scan_regular_file(
    state: _ScanState,
    parent_fd: int,
    parent_stat: os.stat_result,
    name: str,
    path: str,
    name_stat: os.stat_result,
) -> None:
    path_flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        path_fd = os.open(name, path_flags, dir_fd=parent_fd)
    except OSError as error:
        raise OciRootfsError(f"cannot hold regular file {path}: {error}") from error
    try:
        held = os.fstat(path_fd)
        _matching_open_stat(name_stat, held, path)
        if not stat.S_ISREG(held.st_mode):
            raise OciRootfsError(f"filesystem type changed while opening {path}")
        flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
        exact_path = f"/proc/self/fd/{path_fd}"
        try:
            fd = os.open(exact_path, flags)
        except OSError as error:
            raise OciRootfsError(
                f"cannot open held regular file {path}: {error}"
            ) from error
        try:
            opened = os.fstat(fd)
            _matching_open_stat(held, opened, path)
            cache_key = (opened.st_dev, opened.st_ino)
            cached = state.file_cache.get(cache_key)
            if cached is None:
                digest = _hash_open_file(fd, opened.st_size, path)
                xattrs = _read_fd_xattrs(fd, path)
                state.file_cache[cache_key] = (_raw_stat(opened), digest, xattrs)
            else:
                cached_stat, digest, xattrs = cached
                if cached_stat != _raw_stat(opened):
                    raise OciRootfsError(
                        f"hardlinked inode metadata differs at {path}"
                    )
            after = os.fstat(fd)
            _require_same_stat(opened, after, path)
        finally:
            _release_primary = sys.exception()
            try:
                os.close(fd)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        _require_same_stat(held, os.fstat(path_fd), path)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(path_fd)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    final_name = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require_same_stat(name_stat, final_name, path)
    state.entries[path] = _semantic_from_stat(
        state,
        path,
        "file",
        opened,
        size=opened.st_size,
        content_sha256=digest,
        xattrs=xattrs,
    )
    state.raw_entries[path] = _raw_entry(path, name, parent_stat, opened)


def _scan_symlink(
    state: _ScanState,
    parent_fd: int,
    parent_stat: os.stat_result,
    name: str,
    path: str,
    name_stat: os.stat_result,
) -> None:
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise OciRootfsError(f"cannot hold symlink {path}: {error}") from error
    try:
        opened = os.fstat(fd)
        _matching_open_stat(name_stat, opened, path)
        if not stat.S_ISLNK(opened.st_mode):
            raise OciRootfsError(f"filesystem type changed while opening {path}")
        target_before = os.readlink(name, dir_fd=parent_fd)
        xattrs = _read_symlink_xattrs(parent_fd, name, path)
        target_after = os.readlink(name, dir_fd=parent_fd)
        if target_before != target_after:
            raise OciRootfsError(f"symlink target changed while auditing {path}")
        after = os.fstat(fd)
        _require_same_stat(opened, after, path)
    finally:
        _release_primary = sys.exception()
        try:
            os.close(fd)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
    final_name = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require_same_stat(name_stat, final_name, path)
    target = os.fsencode(target_before)
    state.entries[path] = _semantic_from_stat(
        state,
        path,
        "symlink",
        opened,
        size=len(target),
        symlink_target=target,
        xattrs=xattrs,
    )
    state.raw_entries[path] = _raw_entry(path, name, parent_stat, opened)


def _directory_names(fd: int, path: str) -> tuple[str, ...]:
    try:
        with os.scandir(fd) as iterator:
            names = tuple(sorted(entry.name for entry in iterator))
    except OSError as error:
        raise OciRootfsError(f"cannot enumerate directory {path}: {error}") from error
    if len(names) != len(set(names)):
        raise OciRootfsError(f"duplicate directory name while auditing {path}")
    return names


def _scan_directory(
    state: _ScanState,
    fd: int,
    parent_stat: os.stat_result,
    name: str,
    path: str,
    opened: os.stat_result,
) -> None:
    if not stat.S_ISDIR(opened.st_mode):
        raise OciRootfsError(f"expected directory while auditing {path}")
    xattrs = _read_fd_xattrs(fd, path)
    names_before = _directory_names(fd, path)
    for child_name in names_before:
        child_path = (
            f"/{child_name}" if path == "/" else f"{path}/{child_name}"
        )
        try:
            child_stat = os.stat(child_name, dir_fd=fd, follow_symlinks=False)
        except OSError as error:
            raise OciRootfsError(f"cannot lstat {child_path}: {error}") from error
        if stat.S_ISREG(child_stat.st_mode):
            _scan_regular_file(
                state, fd, opened, child_name, child_path, child_stat
            )
        elif stat.S_ISLNK(child_stat.st_mode):
            _scan_symlink(state, fd, opened, child_name, child_path, child_stat)
        elif stat.S_ISDIR(child_stat.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                child_fd = os.open(child_name, flags, dir_fd=fd)
            except OSError as error:
                raise OciRootfsError(
                    f"cannot open directory {child_path}: {error}"
                ) from error
            try:
                child_opened = os.fstat(child_fd)
                _matching_open_stat(child_stat, child_opened, child_path)
                _scan_directory(
                    state,
                    child_fd,
                    opened,
                    child_name,
                    child_path,
                    child_opened,
                )
            finally:
                _release_primary = sys.exception()
                try:
                    os.close(child_fd)
                except BaseException:
                    if _release_primary is None:
                        raise
                    _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            final_child = os.stat(
                child_name, dir_fd=fd, follow_symlinks=False
            )
            _require_same_stat(child_stat, final_child, child_path)
        else:
            raise OciRootfsError(
                f"unsupported actual rootfs entry type at {child_path}"
            )
    names_after = _directory_names(fd, path)
    if names_after != names_before:
        raise OciRootfsError(f"directory names changed while auditing {path}")
    after = os.fstat(fd)
    _require_same_stat(opened, after, path)
    state.entries[path] = _semantic_from_stat(
        state,
        path,
        "directory",
        opened,
        size=0,
        xattrs=xattrs,
    )
    state.raw_entries[path] = _raw_entry(path, name, parent_stat, opened)


def _assign_actual_hardlink_groups(
    entries: dict[str, SemanticEntry], raw_entries: Mapping[str, RawEntry]
) -> None:
    groups: dict[tuple[int, int], list[str]] = defaultdict(list)
    for path, entry in entries.items():
        if entry.kind in {"file", "symlink"}:
            raw = raw_entries[path]
            groups[(raw.dev, raw.ino)].append(path)
    for paths in groups.values():
        for path in paths:
            if raw_entries[path].nlink != len(paths):
                raise OciRootfsError(
                    f"hardlink count includes an alias outside the audited root at {path}"
                )
        if len(paths) < 2:
            continue
        representative = min(paths)
        for path in paths:
            entries[path] = replace(
                entries[path], hardlink_group=representative
            )


def _scan_once(
    parent_fd: int,
    root_fd: int,
    root_name: str,
    projection: OwnershipProjection,
) -> tuple[Mapping[str, SemanticEntry], Mapping[str, RawEntry]]:
    state = _ScanState(projection, {}, {}, {})
    parent_stat = os.fstat(parent_fd)
    root_stat = os.fstat(root_fd)
    _scan_directory(state, root_fd, parent_stat, root_name, "/", root_stat)
    _assign_actual_hardlink_groups(state.entries, state.raw_entries)
    return _frozen_mapping(state.entries), _frozen_mapping(state.raw_entries)


def _verify_raw_ledger(
    parent_fd: int, root_fd: int, root_name: str,
    expected: Mapping[str, RawEntry],
) -> None:
    """Revalidate every name/version after hashing, using only O(depth) FDs."""
    children: dict[str, list[str]] = defaultdict(list)
    for path in expected:
        if path != "/":
            pure = PurePosixPath(path)
            children[pure.parent.as_posix()].append(pure.name)

    def walk(fd: int, parent: os.stat_result, name: str, path: str) -> None:
        opened = os.fstat(fd)
        if _raw_entry(path, name, parent, opened) != expected[path]:
            raise OciRootfsError("rootfs raw entry changed during terminal sweep")
        names = tuple(sorted(children[path]))
        if _directory_names(fd, path) != names:
            raise OciRootfsError("rootfs listing changed during terminal sweep")
        for child_name in names:
            child_path = f"/{child_name}" if path == "/" else f"{path}/{child_name}"
            status = os.stat(child_name, dir_fd=fd, follow_symlinks=False)
            if _raw_entry(child_path, child_name, opened, status) != expected[child_path]:
                raise OciRootfsError("rootfs raw entry changed during terminal sweep")
            if stat.S_ISDIR(status.st_mode):
                child_fd = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    walk(child_fd, opened, child_name, child_path)
                finally:
                    _release_primary = sys.exception()
                    try:
                        os.close(child_fd)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                if _raw_entry(child_path, child_name, opened, os.stat(child_name, dir_fd=fd, follow_symlinks=False)) != expected[child_path]:
                    raise OciRootfsError("rootfs directory name changed during terminal sweep")
        if _directory_names(fd, path) != names or _raw_entry(path, name, parent, os.fstat(fd)) != expected[path]:
            raise OciRootfsError("rootfs directory changed during terminal sweep")

    walk(root_fd, os.fstat(parent_fd), root_name, "/")


def audit_rootfs(
    root: os.PathLike[str] | str,
    *,
    projection: OwnershipProjection | None = None,
) -> RootfsAudit:
    """Obtain two stable, exact snapshots of a materialized rootfs.

    Every ancestor and the root name itself must be a real directory rather
    than a symlink. The parent/name/root anchor is held throughout both walks.
    """

    projection = projection or OwnershipProjection()
    parent_fd, root_fd, root_name = _secure_open_root(root)
    try:
        before_anchor = _capture_anchor(parent_fd, root_fd, root_name)
        first_entries, first_raw = _scan_once(
            parent_fd, root_fd, root_name, projection
        )
        middle_anchor = _capture_anchor(parent_fd, root_fd, root_name)
        second_entries, second_raw = _scan_once(
            parent_fd, root_fd, root_name, projection
        )
        _verify_raw_ledger(parent_fd, root_fd, root_name, second_raw)
        after_anchor = _capture_anchor(parent_fd, root_fd, root_name)
    finally:
        owned_root, root_fd = root_fd, -1
        owned_parent, parent_fd = parent_fd, -1
        _close_descriptors(owned_root, owned_parent, primary=sys.exception())
    if before_anchor != middle_anchor or middle_anchor != after_anchor:
        raise OciRootfsError("rootfs parent/name/root anchor changed during audit")
    if first_entries != second_entries:
        raise OciRootfsError("rootfs semantic manifest changed between audit passes")
    if first_raw != second_raw:
        raise OciRootfsError("rootfs raw ledger changed between audit passes")
    return RootfsAudit(
        entries=second_entries,
        raw_entries=second_raw,
        before_anchor=before_anchor,
        after_anchor=after_anchor,
    )


def _open_directory_beneath(root_fd: int, path: str) -> int:
    if path == "/":
        return os.dup(root_fd)
    pure = PurePosixPath(path)
    if not path.startswith("/") or pure.as_posix() != path:
        raise OciRootfsError(f"unsafe normalization directory: {path!r}")
    current = os.dup(root_fd)
    try:
        for component in pure.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            closing, current = current, child
            os.close(closing)
        return current
    except BaseException:
        _release_primary = sys.exception()
        try:
            os.close(current)
        except BaseException:
            if _release_primary is None:
                raise
            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        raise


_RENAME_EXCHANGE = 2


_FAN_METADATA = struct.Struct("=IBBHQii")


def _normalization_fid(descriptor: int, filesystem_descriptor: int) -> bytes:
    """Bind opaque filesystem identity and handle without causing an event."""
    libc = ctypes.CDLL(None, use_errno=True)
    handle = ctypes.create_string_buffer(struct.pack("=Ii", 128, 0) + bytes(128))
    mount_id = ctypes.c_int()
    if libc.name_to_handle_at(ctypes.c_int(descriptor), ctypes.c_char_p(b""), handle, ctypes.byref(mount_id), ctypes.c_int(0x1200)) != 0:
        raise OciRootfsError("normalization inode handle is unsupported")
    length, kind = struct.unpack_from("=Ii", handle.raw)
    if not 0 < length <= 128 or kind <= 0:
        raise OciRootfsError("normalization inode handle profile is unsupported")
    # Gate 01's sealed execution target is Linux x86-64: statfs has seven
    # leading 64-bit words, followed by the opaque eight-byte filesystem ID.
    filesystem = ctypes.create_string_buffer(120)
    if ctypes.sizeof(ctypes.c_long) != 8 or libc.fstatfs(ctypes.c_int(filesystem_descriptor), filesystem) != 0:
        raise OciRootfsError("normalization filesystem identity is unsupported")
    return filesystem.raw[56:64] + handle.raw[:8 + length]


def _read_normalization_fanotify(descriptor: int) -> list[tuple[int, bytes]]:
    events: list[tuple[int, bytes]] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, 65536)
        except BlockingIOError:
            return events
        if not chunk:
            raise OciRootfsError("normalization inode event stream ended")
        total += len(chunk)
        if total > 1048576:
            raise OciRootfsError("normalization inode event stream exceeds bound")
        offset = 0
        while offset < len(chunk):
            if len(chunk) - offset < 24:
                raise OciRootfsError("normalization inode event header is truncated")
            length, version, reserved, metadata_length, mask, event_fd, pid = _FAN_METADATA.unpack_from(chunk, offset)
            if version != 3 or reserved != 0 or metadata_length != 24 or event_fd != -1 or pid != 0 or length < 44 or length > 172 or offset + length > len(chunk):
                raise OciRootfsError("normalization inode event metadata is unsupported")
            info_type, padding, info_length = struct.unpack_from("=BBH", chunk, offset + 24)
            handle_length, handle_type = struct.unpack_from("=Ii", chunk, offset + 36)
            if info_type != 1 or padding != 0 or info_length != length - 24 or info_length != 20 + handle_length or not 0 < handle_length <= 128 or handle_type <= 0 or mask not in (4, 0x800, 0x40000004):
                raise OciRootfsError("normalization inode event identity is unsupported")
            events.append((mask, chunk[offset + 28:offset + length]))
            if len(events) > 2:
                raise OciRootfsError("normalization inode event cardinality differs")
            offset += length


def _run_normalization_syscall(operation: str, arguments: tuple[Any, ...]) -> None:
    """One prepared raw mutation in a fresh child; no Python mutation hook.

    The child's actor identity separates its fanotify record from concurrent
    actors even where unprivileged notification metadata redacts every PID.
    PID values themselves never authorize an event.
    """
    if os.listdir("/proc/self/task") != [str(os.getpid())]:
        raise OciRootfsError("normalization syscall helper requires one thread")
    if signal.getsignal(signal.SIGPIPE) != signal.SIG_IGN:
        raise OciRootfsError("normalization syscall helper requires ignored SIGPIPE")
    libc = ctypes.CDLL(None, use_errno=True)
    if operation == "link":
        source, parent, name = arguments
        function, values = libc.linkat, (ctypes.c_int(-100), ctypes.c_char_p(os.fsencode(f"/proc/self/fd/{source}")), ctypes.c_int(parent), ctypes.c_char_p(os.fsencode(name)), ctypes.c_int(0x400))
    elif operation == "exchange":
        old_parent, old_name, new_parent, new_name = arguments
        function, values = libc.renameat2, (ctypes.c_int(old_parent), ctypes.c_char_p(os.fsencode(old_name)), ctypes.c_int(new_parent), ctypes.c_char_p(os.fsencode(new_name)), ctypes.c_uint(_RENAME_EXCHANGE))
    elif operation == "unlink":
        parent, name = arguments
        function, values = libc.unlinkat, (ctypes.c_int(parent), ctypes.c_char_p(os.fsencode(name)), ctypes.c_int(0))
    elif operation == "chmod":
        descriptor, mode = arguments
        function, values = libc.fchmod, (ctypes.c_int(descriptor), ctypes.c_uint(mode))
    elif operation == "utime":
        descriptor, nanoseconds = arguments
        seconds, remainder = divmod(nanoseconds, 1000000000)
        times = (ctypes.c_long * 4)(seconds, remainder, seconds, remainder)
        function, values = libc.futimens, (ctypes.c_int(descriptor), times)
    else:
        raise OciRootfsError("normalization syscall operation is unsupported")
    token = ctypes.create_string_buffer(1)
    reader = writer = -1
    child = 0
    pidfd = -1
    authenticated = False
    try:
        reader, writer = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            try:
                if libc.close(ctypes.c_int(writer)) != 0:
                    libc._exit(2)
                if libc.read(ctypes.c_int(reader), token, ctypes.c_size_t(1)) != 1 or token.raw != b"\x01":
                    libc._exit(2)
                if libc.close(ctypes.c_int(reader)) != 0:
                    libc._exit(2)
                result = function(*values)
            except BaseException:
                libc._exit(2)
            libc._exit(0 if result == 0 else 1)
        closing, reader = reader, -1
        os.close(closing)
        # The child cannot mutate or finish normally before its pidfd exists.
        # Setup failure closes the writer: EOF exits the child without ever
        # signalling an unbound/reused numeric PID.
        pidfd = os.pidfd_open(child, 0)
        written = os.write(writer, b"\x01")
        if type(written) is not int or written != 1:
            raise OciRootfsError("normalization syscall helper authorization write failed")
        authenticated = True
        closing, writer = writer, -1
        os.close(closing)
        if not select.select((pidfd,), (), (), 30)[0]:
            raise OciRootfsError("normalization syscall helper timed out")
        waited, status = os.waitpid(child, 0)
        if waited != child:
            raise OciRootfsError("normalization syscall helper wait identity differs")
        child = 0
        if status != 0:
            raise OciRootfsError("normalization syscall helper failed")
    finally:
        primary = sys.exception()
        failure = None
        if writer >= 0:
            closing, writer = writer, -1
            try:
                os.close(closing)
            except BaseException as error:
                failure = error
        if child and pidfd >= 0 and authenticated:
            remaining = 3
            while remaining:
                remaining -= 1
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    break
                except ProcessLookupError:
                    break
                except BaseException as error:
                    if failure is None:
                        failure = error
        if child:
            remaining = 3
            while remaining:
                remaining -= 1
                try:
                    waited, _status = os.waitpid(child, 0)
                    if waited != child:
                        raise OciRootfsError("normalization helper cleanup wait identity differs")
                    child = 0
                    break
                except ChildProcessError:
                    break
                except BaseException as error:
                    if failure is None:
                        failure = error
        owned_reader, reader = reader, -1
        owned_pidfd, pidfd = pidfd, -1
        try:
            _close_descriptors(owned_reader, owned_pidfd)
        except BaseException as error:
            if failure is None:
                failure = error
        if failure is not None:
            if primary is None:
                raise RuntimeError("normalization helper cleanup failed") from failure
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")


def _checked_normalization_syscall(operation: str, arguments: tuple[Any, ...], endpoints: tuple[tuple[int, int, str, bool], ...], masks: tuple[int, ...], before: Any, after: Any) -> tuple[RawStat, ...]:
    """At most two one-inode groups; all transfer and teardown stays local."""
    if not 1 <= len(endpoints) <= 2 or len(endpoints) != len(masks):
        raise OciRootfsError("normalization inode watch cardinality is invalid")
    groups = [-1, -1]
    identities: list[bytes] = []
    statuses: list[RawStat] = []
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        for index, (descriptor, parent, name, symlink) in enumerate(endpoints):
            statuses.append(_raw_stat(os.fstat(descriptor)))
            identities.append(_normalization_fid(descriptor, parent))
            groups[index] = libc.fanotify_init(ctypes.c_uint(0x203), ctypes.c_uint(os.O_RDONLY | os.O_CLOEXEC))
            if groups[index] < 0:
                raise OciRootfsError("normalization inode event watch is unavailable")
            marked_path = os.fsencode(name if symlink else f"/proc/self/fd/{descriptor}")
            mark_parent = parent if symlink else -100
            if libc.fanotify_mark(ctypes.c_int(groups[index]), ctypes.c_uint(1 | (4 if symlink else 0)), ctypes.c_uint64(4 | 0x800 | (0x40000000 if stat.S_ISDIR(statuses[-1].mode) else 0)), ctypes.c_int(mark_parent), ctypes.c_char_p(marked_path)) != 0:
                raise OciRootfsError("normalization inode event mark is unsupported")
            if _normalization_fid(descriptor, parent) != identities[-1] or _raw_stat(os.fstat(descriptor)) != statuses[-1]:
                raise OciRootfsError("normalization inode changed while installing watch")
        before()
        for index in range(len(endpoints)):
            if _read_normalization_fanotify(groups[index]):
                raise OciRootfsError("normalization inode event baseline is not empty")
        _run_normalization_syscall(operation, arguments)
        for index in range(len(endpoints)):
            if _read_normalization_fanotify(groups[index]) != [(masks[index], identities[index])]:
                raise OciRootfsError("normalization inode event sequence differs")
        after()
        result = tuple(_raw_stat(os.fstat(endpoint[0])) for endpoint in endpoints)
        for index in range(len(endpoints)):
            if _read_normalization_fanotify(groups[index]):
                raise OciRootfsError("normalization inode terminal event queue is not empty")
        return result
    finally:
        first = groups[0]
        second = groups[1]
        groups[0] = groups[1] = -1
        _close_descriptors(first, second, primary=sys.exception())


def _raw_entry_stat(value: RawEntry) -> RawStat:
    return RawStat(
        value.dev,
        value.ino,
        value.nlink,
        value.mode,
        value.uid,
        value.gid,
        value.rdev,
        value.size,
        value.mtime_ns,
        value.ctime_ns,
    )


def _inode_identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


@dataclass
class _SymlinkHardlinkRepair:
    representative: str
    target: str
    source_parent: int
    target_parent: int
    source_fd: int
    target_fd: int
    source_status: os.stat_result
    target_status: os.stat_result
    temporary_name: str
    temporary_created: bool = False

    def close(self) -> None:
        _release_fd_0 = self.target_fd
        _release_fd_1 = self.source_fd
        _release_fd_2 = self.target_parent
        _release_fd_3 = self.source_parent
        self.target_fd = self.source_fd = self.target_parent = self.source_parent = -1
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


def _cleanup_repair_plan(plan: list[_SymlinkHardlinkRepair | None]) -> None:
    """Retain failed material authority for the caller's bounded retry."""
    failure = None
    index = 0
    while index < len(plan):
        repair = plan[index]
        index += 1
        if repair is None:
            continue
        try:
            if repair.temporary_created:
                try:
                    current = os.stat(repair.temporary_name, dir_fd=repair.target_parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if _inode_identity(current) != _inode_identity(repair.source_status) and _inode_identity(current) != _inode_identity(repair.target_status):
                        raise OciRootfsError("repair cleanup temporary identity changed")
                    os.unlink(repair.temporary_name, dir_fd=repair.target_parent)
                repair.temporary_created = False
        except BaseException as error:
            if failure is None:
                failure = error
            continue
        try:
            repair.close()
        except BaseException as error:
            if failure is None:
                failure = error
        else:
            plan[index - 1] = None
    if failure is not None:
        raise RuntimeError("hardlink repair cleanup failed") from failure
    plan.clear()


def _hold_exact_symlink(
    root_fd: int,
    path: str,
    observed: RootfsAudit,
) -> tuple[int, int, os.stat_result]:
    pure = PurePosixPath(path)
    parent_path = pure.parent.as_posix()
    if not parent_path.startswith("/"):
        parent_path = "/"
    parent = _open_directory_beneath(root_fd, parent_path)
    descriptor = -1
    try:
        expected_raw = observed.raw_entries[path]
        parent_status = os.fstat(parent)
        if (
            parent_status.st_dev != expected_raw.parent_dev
            or parent_status.st_ino != expected_raw.parent_ino
        ):
            raise OciRootfsError(
                f"symlink parent changed before hardlink repair: {path}"
            )
        named = os.stat(pure.name, dir_fd=parent, follow_symlinks=False)
        if _raw_stat(named) != _raw_entry_stat(expected_raw):
            raise OciRootfsError(
                f"symlink identity changed before hardlink repair: {path}"
            )
        descriptor = os.open(
            pure.name,
            os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        if _raw_stat(opened) != _raw_entry_stat(expected_raw):
            raise OciRootfsError(
                f"symlink identity changed while holding hardlink repair: {path}"
            )
        expected_semantic = observed.entries[path]
        if (
            expected_semantic.kind != "symlink"
            or os.fsencode(os.readlink(pure.name, dir_fd=parent))
            != expected_semantic.symlink_target
            or _read_symlink_xattrs(parent, pure.name, path)
            != expected_semantic.xattrs
        ):
            raise OciRootfsError(
                f"symlink semantics changed before hardlink repair: {path}"
            )
        return parent, descriptor, opened
    except BaseException:
        _close_descriptors(descriptor, parent, primary=sys.exception())
        raise


class _NormalizationLedger:
    """Account only syscall-authorized raw transitions, never adopt a new baseline."""

    def __init__(self, parent_fd: int, root_fd: int, root_name: str, audit: RootfsAudit):
        self.parent_fd, self.root_fd, self.root_name = parent_fd, root_fd, root_name
        self.raw = dict(audit.raw_entries)
        children: dict[str, list[str]] = defaultdict(list)
        for path in self.raw:
            if path != "/":
                pure = PurePosixPath(path)
                children[pure.parent.as_posix()].append(pure.name)
        self.children = {path: tuple(sorted(names)) for path, names in children.items()}
        self.operations: list[dict[str, Any]] = []

    def current(self, path: str) -> RawEntry:
        if path == "/":
            return _raw_entry(path, self.root_name, os.fstat(self.parent_fd), os.fstat(self.root_fd))
        pure = PurePosixPath(path)
        parent = _open_directory_beneath(self.root_fd, pure.parent.as_posix())
        try:
            return _raw_entry(path, pure.name, os.fstat(parent), os.stat(pure.name, dir_fd=parent, follow_symlinks=False))
        finally:
            _release_primary = sys.exception()
            try:
                os.close(parent)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

    def begin(self, paths: Iterable[str]) -> dict[str, RawEntry]:
        result = {}
        for path in sorted(set(paths)):
            current = self.current(path)
            if current != self.raw[path]:
                raise OciRootfsError("unrecorded raw change before normalization operation")
            result[path] = current
        return result

    def finish(self, operation: str, before: Mapping[str, RawEntry], allowed: Mapping[str, set[str]], required: Mapping[str, Mapping[str, int]]) -> None:
        changes = {}
        for path, previous in before.items():
            current = self.current(path)
            if any(getattr(previous, field) != getattr(current, field) for field in RawEntry.__dataclass_fields__ if field not in allowed[path]):
                raise OciRootfsError("normalization operation changed an unauthorized raw field")
            if any(getattr(current, field) != value for field, value in required.get(path, {}).items()):
                raise OciRootfsError("normalization operation result differs from exact authority")
            if current != previous:
                changes[path] = {"before": previous, "result": current}
            self.raw[path] = current
        if operation == "symlink_hardlink" and set(changes) != set(before):
            raise OciRootfsError("normalization repair raw transition is ambiguous")
        if changes:
            self.operations.append({"operation": operation, "entries": changes})

    def verify(self) -> None:
        _verify_raw_ledger(self.parent_fd, self.root_fd, self.root_name, self.raw)


_REPAIR_EVENT_HEADER = struct.Struct("=iIII")
_REPAIR_EVENT_MASK = 0x0000EFCE  # mutation, namespace, self/loss; never reads
_REPAIR_WATCH_PROFILE = "linux-inotify-fanotify-vfs-normalization-v3"
_NORMALIZATION_SCHEMA_FIELDS = {"schema_version", "watch_profile", "initial_raw_ledger", "repair_groups", "directory_mtimes", "hardlinks", "runtime_bind_targets", "raw_operations"}
_RAW_LEDGER_CODEC = "zlib-base64-canonical-raw-ledger-v1"
_RAW_LEDGER_MAX_BYTES = 256 * 1024 * 1024
_RAW_LEDGER_MAX_ENCODED = 16 * 1024 * 1024
_RAW_LEDGER_MAX_ENTRIES = 250000


def _encode_normalization_ledger(raw: Mapping[str, RawEntry]) -> Mapping[str, Any]:
    data = _canonical_json(_json_safe(raw))
    if not 0 < len(raw) <= _RAW_LEDGER_MAX_ENTRIES or len(data) > _RAW_LEDGER_MAX_BYTES:
        raise OciRootfsError("normalization initial ledger exceeds bounds")
    encoded = base64.b64encode(zlib.compress(data, level=9)).decode("ascii")
    if len(encoded) > _RAW_LEDGER_MAX_ENCODED:
        raise OciRootfsError("normalization encoded ledger exceeds bound")
    return _frozen_mapping({"encoding": _RAW_LEDGER_CODEC, "entry_count": len(raw), "uncompressed_size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "data": encoded})


def _decode_normalization_ledger(value: Any) -> Mapping[str, RawEntry]:
    if not isinstance(value, dict) or set(value) != {"encoding", "entry_count", "uncompressed_size", "sha256", "data"} or value["encoding"] != _RAW_LEDGER_CODEC:
        raise OciRootfsError("normalization ledger encoding schema differs")
    if type(value["entry_count"]) is not int or not 0 < value["entry_count"] <= _RAW_LEDGER_MAX_ENTRIES or type(value["uncompressed_size"]) is not int or not 0 < value["uncompressed_size"] <= _RAW_LEDGER_MAX_BYTES or not isinstance(value["data"], str) or len(value["data"]) > _RAW_LEDGER_MAX_ENCODED or not isinstance(value["sha256"], str) or RAW_SHA256_RE.fullmatch(value["sha256"]) is None:
        raise OciRootfsError("normalization ledger encoding bounds differ")
    return _decode_canonical_raw_ledger(value["data"], value["uncompressed_size"], value["sha256"], value["entry_count"])


@lru_cache(maxsize=2)
def _decode_canonical_raw_ledger(encoded: str, size: int, digest: str, count: int) -> Mapping[str, RawEntry]:
    # Only immutable public input and immutable rows enter this bounded cache.
    # Repeated consumers still replay their own untrusted transition list.
    try:
        compressed = base64.b64decode(encoded, validate=True)
        if base64.b64encode(compressed).decode("ascii") != encoded:
            raise OciRootfsError("normalization ledger base64 is not canonical")
        decoder = zlib.decompressobj()
        data = decoder.decompress(compressed, size + 1)
        if len(data) != size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or hashlib.sha256(data).hexdigest() != digest:
            raise OciRootfsError("normalization ledger compressed identity differs")
        if zlib.compress(data, level=9) != compressed:
            raise OciRootfsError("normalization ledger compression is not canonical")
        parsed = json.loads(data, object_pairs_hook=_reject_duplicate_json_pairs)
    except (ValueError, zlib.error) as error:
        raise OciRootfsError("normalization ledger encoding is invalid") from error
    if not isinstance(parsed, dict) or len(parsed) != count or "/" not in parsed or _canonical_json(parsed) != data:
        raise OciRootfsError("normalization ledger canonical path set differs")
    rows: dict[str, RawEntry] = {}
    classes: dict[tuple[int, int], list[str]] = defaultdict(list)
    fields = set(RawEntry.__dataclass_fields__)
    for path, record in parsed.items():
        pure = PurePosixPath(path)
        if not path.startswith("/") or "\0" in path or pure.as_posix() != path or ".." in pure.parts or not isinstance(record, dict) or set(record) != fields or record["path"] != path or not isinstance(record["name"], str) or not record["name"] or "\0" in record["name"] or "/" in record["name"] or (path != "/" and record["name"] != pure.name):
            raise OciRootfsError("normalization ledger raw path differs")
        if any(type(record[field]) is not int or record[field] < 0 for field in fields - {"path", "name"}) or not record["ino"] or not record["nlink"]:
            raise OciRootfsError("normalization ledger raw metadata differs")
        rows[path] = RawEntry(**record)
        if stat.S_IFMT(record["mode"]) in {stat.S_IFREG, stat.S_IFLNK}:
            classes[(record["dev"], record["ino"])].append(path)
    if not stat.S_ISDIR(rows["/"].mode):
        raise OciRootfsError("normalization ledger root is not a directory")
    for path, record in rows.items():
        if path != "/":
            parent = rows.get(PurePosixPath(path).parent.as_posix())
            if parent is None or not stat.S_ISDIR(parent.mode) or (record.parent_dev, record.parent_ino) != (parent.dev, parent.ino):
                raise OciRootfsError("normalization ledger parent linkage differs")
    for paths in classes.values():
        first = rows[paths[0]]
        for path in paths:
            row = rows[path]
            if row.nlink != len(paths) or _raw_entry_stat(row) != _raw_entry_stat(first):
                raise OciRootfsError("normalization ledger inode equivalence class differs")
    return _frozen_mapping(rows)


def _open_repair_watch() -> int:
    descriptor = ctypes.CDLL(None, use_errno=True).inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        raise OciRootfsError("repair parent watch allocation failed")
    return descriptor


def _add_repair_watch(descriptor: int, parent: int, *, directory: bool = True) -> int:
    watch = ctypes.CDLL(None, use_errno=True).inotify_add_watch(descriptor, ctypes.c_char_p(os.fsencode(f"/proc/self/fd/{parent}")), ctypes.c_uint32(_REPAIR_EVENT_MASK | (0x01000000 if directory else 0)))
    if watch < 0:
        raise OciRootfsError("repair parent watch registration failed")
    return int(watch)


def _add_symlink_repair_watch(descriptor: int, parent: int, name: str) -> int:
    watch = ctypes.CDLL(None, use_errno=True).inotify_add_watch(descriptor, ctypes.c_char_p(os.fsencode(f"/proc/self/fd/{parent}/{name}")), ctypes.c_uint32(_REPAIR_EVENT_MASK | 0x02000000))
    if watch < 0:
        raise OciRootfsError("normalization symlink watch registration failed")
    return int(watch)


def _read_repair_watch(descriptor: int) -> list[tuple[int, int, int, bytes]]:
    events: list[tuple[int, int, int, bytes]] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, 65536)
        except BlockingIOError:
            return events
        if not chunk:
            raise OciRootfsError("repair parent watch was lost")
        total += len(chunk)
        if total > 1024 * 1024:
            raise OciRootfsError("repair parent watch event bound exceeded")
        offset = 0
        while offset < len(chunk):
            if len(chunk) - offset < _REPAIR_EVENT_HEADER.size:
                raise OciRootfsError("repair parent watch header is malformed")
            watch, mask, cookie, length = _REPAIR_EVENT_HEADER.unpack_from(chunk, offset)
            offset += _REPAIR_EVENT_HEADER.size
            if length > 256 or length % 16 or offset + length > len(chunk):
                raise OciRootfsError("repair parent watch name is malformed")
            encoded = chunk[offset:offset + length]
            offset += length
            name = encoded.split(b"\0", 1)[0]
            if length and (not name or encoded != name + b"\0" * (length - len(name)) or len(name) == length or b"/" in name):
                raise OciRootfsError("repair parent watch padding is malformed")
            events.append((watch, mask, cookie, name))


class _RepairParentWatch:
    """Exact v3 name grammar supplements held endpoints and inode events.

    Draining at each syscall boundary prevents ambiguity between repairs. No
    coalesced repair profile is accepted: each temporary name is used once and
    each expected consecutive mask/name differs. Directory utime is separate.
    """

    def __init__(self, ledger: _NormalizationLedger):
        self.ledger = ledger
        self.descriptor = -1
        self.parents: dict[str, dict[str, Any]] = {}
        self.targets: dict[str, dict[str, Any]] = {}
        self.inodes: dict[tuple[int, int], dict[str, Any]] = {}
        self.anchor_parent: dict[str, Any] | None = None
        self.mutable_directories: set[str] = set()
        self.states: dict[tuple[str, str], str] = {}

    @classmethod
    def open(cls, ledger: _NormalizationLedger, plan: list[_SymlinkHardlinkRepair], *, directory_mtimes: Iterable[str] = (), runtime_targets: Iterable[str] = (), group_members: Iterable[str] = ()) -> "_RepairParentWatch":
        result = cls(ledger)
        try:
            directories = set(directory_mtimes) | {PurePosixPath(repair.target).parent.as_posix() for repair in plan}
            result.mutable_directories = directories
            targets = set(runtime_targets)
            paths = sorted(directories | {PurePosixPath(path).parent.as_posix() for path in directories | targets | set(group_members) if path != "/"})
            inode_authorities = {}
            for repair in plan:
                inode_authorities[_inode_identity(repair.source_status)] = (repair.source_fd, repair.representative, repair.source_status)
                inode_authorities[_inode_identity(repair.target_status)] = (repair.target_fd, repair.target, repair.target_status)
            if len(paths) + len(targets) + len(inode_authorities) + int("/" in directories) > 2 * _RAW_LEDGER_MAX_ENTRIES + 1:
                raise OciRootfsError("repair parent watch count exceeds bound")
            if paths:
                descriptor = _open_repair_watch()
                try:
                    result.descriptor = descriptor
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
            for path in paths:
                descriptor = _open_directory_beneath(ledger.root_fd, path)
                try:
                    result.parents[path] = {"descriptor": descriptor}
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                record = result.parents[path]
                record["raw"] = ledger.raw[path]
                record["names"] = ledger.children.get(path, ())
                record["watch"] = _add_repair_watch(result.descriptor, descriptor)
                if sum(item.get("watch") == record["watch"] for item in result.parents.values()) != 1:
                    raise OciRootfsError("repair parent watch identity is ambiguous")
            if "/" in directories:
                descriptor = os.dup(ledger.parent_fd)
                try:
                    result.anchor_parent = {"descriptor": descriptor}
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                result.anchor_parent["raw"] = _raw_stat(os.fstat(descriptor))
                result.anchor_parent["watch"] = _add_repair_watch(result.descriptor, descriptor)
            for path in sorted(targets):
                pure = PurePosixPath(path)
                descriptor = os.open(pure.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=result.parents[pure.parent.as_posix()]["descriptor"])
                try:
                    result.targets[path] = {"descriptor": descriptor, "raw": ledger.raw[path]}
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                result.targets[path]["watch"] = _add_repair_watch(result.descriptor, descriptor, directory=False)
            for identity, (held, path, status) in sorted(inode_authorities.items()):
                descriptor = os.dup(held)
                try:
                    result.inodes[identity] = {"descriptor": descriptor, "raw": _raw_stat(status)}
                except BaseException as primary:
                    _release_primary = primary
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                    raise
                pure = PurePosixPath(path)
                result.inodes[identity]["watch"] = _add_symlink_repair_watch(result.descriptor, result.parents[pure.parent.as_posix()]["descriptor"], pure.name)
            watches = [record["watch"] for record in (*result.parents.values(), *result.targets.values(), *result.inodes.values(), *((result.anchor_parent,) if result.anchor_parent is not None else ()))]
            if len(watches) != len(set(watches)):
                raise OciRootfsError("normalization watch identities are not unique")
            result.states = {(PurePosixPath(repair.target).parent.as_posix(), repair.temporary_name): "absent" for repair in plan}
            # Unwatched paths cannot gain a new baseline: each future operation
            # revalidates its exact rows, and the terminal full ledger catches
            # untouched paths. Metadata watches are therefore operation-local.
            if plan:
                ledger.verify()
            else:
                ledger.begin(set(paths) | targets)
            result.verify_endpoints()
            result.idle()
            return result
        except BaseException as primary:
            _release_primary = primary
            try:
                try:
                    _close_resource_preserving_primary(result, None, drain=_drain_repair_parent_watch)
                except BaseException as _drain_primary:
                    _drain_attempts = 2
                    while _drain_attempts:
                        _drain_attempts -= 1
                        try:
                            _drain_repair_parent_watch(result)
                            break
                        except BaseException:
                            _add_cleanup_note(_drain_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
            raise

    def idle(self) -> None:
        if self.descriptor >= 0 and _read_repair_watch(self.descriptor):
            raise OciRootfsError("repair parent watch observed an unplanned mutation")

    def complete(self, repair: _SymlinkHardlinkRepair, operation: str) -> None:
        path = PurePosixPath(repair.target).parent.as_posix()
        record = self.parents[path]
        watch, temporary, target = record["watch"], os.fsencode(repair.temporary_name), os.fsencode(PurePosixPath(repair.target).name)
        key = (path, repair.temporary_name)
        stages = {"create": ("absent", "created"), "exchange": ("created", "exchanged"), "unlink": ("exchanged", "removed")}
        previous, following = stages[operation]
        if self.states[key] != previous:
            raise OciRootfsError("repair parent watch state differs")
        events = _read_repair_watch(self.descriptor)
        source = self.inodes[_inode_identity(repair.source_status)]
        displaced = self.inodes[_inode_identity(repair.target_status)]
        changes = {}
        if operation == "exchange":
            if len(events) != 6:
                raise OciRootfsError("repair parent exchange event count differs")
            first, second = events[0][2], events[3][2]
            if not first or not second or first == second:
                raise OciRootfsError("repair parent rename cookies are ambiguous")
            expected = [(watch, 0x40, first, temporary), (watch, 0x80, first, target), (source["watch"], 0x800, 0, b""), (watch, 0x40, second, target), (watch, 0x80, second, temporary), (displaced["watch"], 0x800, 0, b"")]
            changes = {_inode_identity(repair.source_status): 0, _inode_identity(repair.target_status): 0}
        else:
            inode = source if operation == "create" else displaced
            expected = [(inode["watch"], 0x4, 0, b""), (watch, 0x100 if operation == "create" else 0x200, 0, temporary)]
            changes = {_inode_identity(repair.source_status if operation == "create" else repair.target_status): 1 if operation == "create" else -1}
        if events != expected:
            raise OciRootfsError("repair parent event profile differs")
        self.states[key] = following
        for identity, delta in changes.items():
            inode = self.inodes[identity]
            current = _raw_stat(os.fstat(inode["descriptor"]))
            if replace(inode["raw"], nlink=inode["raw"].nlink + delta, ctime_ns=current.ctime_ns) != current:
                raise OciRootfsError("normalization watched inode transition differs")
            inode["raw"] = current
        self.verify_endpoints()

    def verify_endpoints(self) -> None:
        for record in self.inodes.values():
            if _raw_stat(os.fstat(record["descriptor"])) != record["raw"]:
                raise OciRootfsError("normalization watched inode changed")
        if self.anchor_parent is not None and _raw_stat(os.fstat(self.anchor_parent["descriptor"])) != self.anchor_parent["raw"]:
            raise OciRootfsError("normalization external parent changed")
        for path, record in self.parents.items():
            current = self.ledger.current(path)
            original = record["raw"]
            allowed = replace(original, size=current.size, mtime_ns=current.mtime_ns, ctime_ns=current.ctime_ns) if path in self.mutable_directories else original
            if allowed != current or _raw_stat(os.fstat(record["descriptor"])) != _raw_entry_stat(current):
                raise OciRootfsError("repair parent held identity changed")
            temporary = [name for (parent, name), state in self.states.items() if parent == path and state in {"created", "exchanged"}]
            if path in self.mutable_directories and tuple(sorted(os.listdir(record["descriptor"]))) != tuple(sorted((*record["names"], *temporary))):
                raise OciRootfsError("repair parent exact listing changed")
        for path, record in self.targets.items():
            current, original = self.ledger.current(path), record["raw"]
            if replace(original, mode=current.mode, mtime_ns=current.mtime_ns, ctime_ns=current.ctime_ns) != current or _raw_stat(os.fstat(record["descriptor"])) != _raw_entry_stat(current):
                raise OciRootfsError("normalization runtime held target changed")

    def finish_directory_mtime(self, path: str) -> None:
        pure = PurePosixPath(path)
        parent = pure.parent.as_posix()
        expected = []
        if path == "/" and self.anchor_parent is not None:
            expected.append((self.anchor_parent["watch"], 0x40000004, 0, os.fsencode(self.ledger.root_name)))
        # Linux reports the named child notification before the inode's own
        # self notification when both directories have registered watches.
        if path != "/" and parent in self.parents:
            expected.append((self.parents[parent]["watch"], 0x40000004, 0, os.fsencode(pure.name)))
        if path in self.parents:
            expected.append((self.parents[path]["watch"], 0x40000004, 0, b""))
        if not expected:
            self.idle()
            return
        if _read_repair_watch(self.descriptor) != expected:
            raise OciRootfsError("repair parent directory-mtime profile differs")
        if path in self.parents and path not in self.mutable_directories:
            record = self.parents[path]
            current = self.ledger.current(path)
            if replace(record["raw"], mtime_ns=current.mtime_ns, ctime_ns=current.ctime_ns) != current:
                raise OciRootfsError("normalization parent metadata transition differs")
            record["raw"] = current
        self.verify_endpoints()

    def finish_runtime_attribute(self, path: str) -> None:
        pure = PurePosixPath(path)
        parent = pure.parent.as_posix()
        if parent not in self.parents:
            self.idle()
            return
        expected = [(self.parents[parent]["watch"], 0x4, 0, os.fsencode(pure.name))]
        if path in self.targets:
            expected.append((self.targets[path]["watch"], 0x4, 0, b""))
        if _read_repair_watch(self.descriptor) != expected:
            raise OciRootfsError("repair parent runtime-attribute profile differs")
        self.verify_endpoints()

    def finish(self) -> None:
        if any(state != "removed" for state in self.states.values()):
            raise OciRootfsError("repair parent watch has unfinished operations")
        self.verify_endpoints()
        self.idle()

    def retire_displaced_inodes(self) -> None:
        """Explicitly retire only zero-link, fully accounted displaced inodes.

        Some filesystems emit DELETE_SELF when a held alias dentry is released,
        even while another held alias keeps the inode alive. Remove its watch
        before repair-plan release and require exactly our own IN_IGNORED event.
        No accepted pathname refers to these inodes; their held raw identity
        remains checked through terminal audit.
        """
        self.finish()
        for record in sorted(self.inodes.values(), key=lambda item: item["watch"]):
            if record["raw"].nlink != 0:
                continue
            self.idle()
            if ctypes.CDLL(None, use_errno=True).inotify_rm_watch(self.descriptor, record["watch"]) != 0:
                raise OciRootfsError("normalization displaced watch retirement failed")
            if _read_repair_watch(self.descriptor) != [(record["watch"], 0x8000, 0, b"")]:
                raise OciRootfsError("normalization displaced watch retirement profile differs")

    def close(self) -> None:
        # Close the watch first: final fput of a displaced zero-link inode may
        # legitimately emit DELETE_SELF/IGNORED, only after terminal acceptance.
        descriptor = self.descriptor
        parents = self.parents
        targets = self.targets
        inodes = self.inodes
        anchor = self.anchor_parent
        self.descriptor = -1
        self.anchor_parent = None
        failure = None
        try:
            _numeric_failure = None
            _numeric_fd = descriptor
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
        index = 0
        while index < 3:
            records = parents if index == 0 else targets if index == 1 else inodes
            index += 1
            try:
                try:
                    _close_resource_mapping(records, descriptor_key="descriptor")
                except BaseException as _map_primary:
                    # The map remains installed until this literal numeric fallback drains it.
                    _raw_records = records
                    while _raw_records:
                        try:
                            _raw_owner = _raw_records.popitem()[1]
                        except BaseException:
                            _raw_owner = dict.popitem(_raw_records)[1]
                        _raw_fd = _raw_owner["descriptor"]
                        _raw_owner["descriptor"] = -1
                        if _raw_fd is not None and _raw_fd >= 0:
                            try:
                                os.close(_raw_fd)
                            except BaseException:
                                _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                    raise
            except BaseException as error:
                if failure is None:
                    failure = error
        if anchor is not None:
            descriptor = anchor["descriptor"]
            anchor["descriptor"] = -1
            try:
                _numeric_failure = None
                _numeric_fd = descriptor
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
        if failure is not None:
            raise failure

    def __enter__(self) -> "_RepairParentWatch":
        return self

    def __exit__(self, kind, exception, traceback) -> None:
        try:
            if exception is None:
                self.finish()
        finally:
            _release_primary = exception if exception is not None else sys.exception()
            try:
                self.close()
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")


_drain_repair_parent_watch = _RepairParentWatch.close


def normalize_vfs_materialization(
    root: os.PathLike[str] | str,
    expected: OciRootfsManifest,
    *,
    projection: OwnershipProjection | None = None,
    runtime_bind_targets: Iterable[str] = (),
) -> tuple[RootfsAudit, Mapping[str, Any]]:
    """One-time normalize two documented VFS import representation losses.

    Podman's VFS importer does not restore directory mtimes after creating
    descendants and materializes tar hardlinks-to-symlinks as independent
    symlink inodes.  Before the first accepted rootfs baseline, validate that
    *only* those fields differ, restore them from sealed OCI semantics, and
    then require a complete exact audit.  Later lifecycle audits never call
    this routine, so an in-work mutation cannot be normalized away.
    """
    selected = projection or OwnershipProjection()
    runtime_target_values = tuple(runtime_bind_targets)
    runtime_targets = frozenset(runtime_target_values)
    if len(runtime_targets) != len(runtime_target_values):
        raise OciRootfsError("runtime bind normalization targets are duplicated")
    if not runtime_targets <= set(expected.entries):
        raise OciRootfsError("runtime bind normalization target is absent")
    observed = audit_rootfs(root, projection=selected)
    if set(observed.entries) != set(expected.entries):
        missing = sorted(set(expected.entries) - set(observed.entries))
        extra = sorted(set(observed.entries) - set(expected.entries))
        raise RootfsMismatchError(
            f"VFS normalization path-set mismatch: missing={missing[:8]} "
            f"extra={extra[:8]}"
        )
    groups: dict[str, list[str]] = defaultdict(list)
    directory_mtimes: dict[str, dict[str, int]] = {}
    runtime_normalizations: dict[str, dict[str, int]] = {}
    actual_inode_groups: dict[tuple[int, int], list[str]] = defaultdict(list)
    for path, entry in observed.entries.items():
        if entry.kind in {"file", "symlink"}:
            raw = observed.raw_entries[path]
            actual_inode_groups[(raw.dev, raw.ino)].append(path)
    for paths in actual_inode_groups.values():
        if len(paths) < 2:
            continue
        expected_groups = {expected.entries[path].hardlink_group for path in paths}
        if len(expected_groups) != 1 or None in expected_groups:
            raise RootfsMismatchError(
                f"materialized rootfs has cross-linked expected groups: {sorted(paths)}"
            )
    for path in sorted(expected.entries):
        wanted = expected.entries[path]
        actual = observed.entries[path]
        adjusted = actual
        if wanted.kind == "directory":
            if actual.mtime_ns != wanted.mtime_ns:
                directory_mtimes[path] = {
                    "from_mtime_ns": actual.mtime_ns,
                    "to_mtime_ns": wanted.mtime_ns,
                }
            adjusted = replace(adjusted, mtime_ns=wanted.mtime_ns)
        if path in runtime_targets:
            if wanted.kind != "file" or actual.kind != "file":
                raise RootfsMismatchError(
                    f"runtime bind normalization target is not regular: {path}"
                )
            if actual.mode != wanted.mode or actual.mtime_ns != wanted.mtime_ns:
                runtime_normalizations[path] = {
                    "from_mode": actual.mode,
                    "from_mtime_ns": actual.mtime_ns,
                    "to_mode": wanted.mode,
                    "to_mtime_ns": wanted.mtime_ns,
                }
            adjusted = replace(
                adjusted,
                mode=wanted.mode,
                mtime_ns=wanted.mtime_ns,
            )
        if wanted.hardlink_group is not None:
            if wanted.kind != "symlink":
                if actual.hardlink_group != wanted.hardlink_group:
                    raise RootfsMismatchError(
                        f"regular hardlink topology is non-normalizable at {path}"
                    )
            else:
                adjusted = replace(adjusted, hardlink_group=wanted.hardlink_group)
                groups[wanted.hardlink_group].append(path)
        if adjusted != wanted:
            raise RootfsMismatchError(
                f"non-normalizable VFS semantic difference at {path}: "
                f"expected={wanted!r} actual={actual!r}"
            )

    normalized_hardlinks: list[dict[str, Any]] = []
    parent_fd, root_fd, root_name = _secure_open_root(root)
    repair_plan: list[_SymlinkHardlinkRepair] = []
    repair_watch: _RepairParentWatch | None = None
    try:
        initial_anchor = _capture_anchor(parent_fd, root_fd, root_name)
        if initial_anchor != observed.after_anchor:
            raise OciRootfsError("rootfs anchor changed before VFS normalization")
        ledger = _NormalizationLedger(parent_fd, root_fd, root_name, observed)
        ledger.verify()
        for representative, paths in sorted(groups.items()):
            if representative not in paths or len(paths) < 2:
                raise OciRootfsError(
                    f"invalid expected hardlink group: {representative}"
                )
            for path in sorted(paths):
                if path == representative:
                    continue
                source_parent = source_fd = target_parent = target_fd = -1
                try:
                    source_parent, source_fd, source_status = _hold_exact_symlink(
                        root_fd, representative, observed
                    )
                    target_parent, target_fd, target_status = _hold_exact_symlink(
                        root_fd, path, observed
                    )
                    if _inode_identity(source_status) == _inode_identity(target_status):
                        continue
                    temporary_name = (
                        f".openmythos-hardlink-{secrets.token_hex(16)}"
                    )
                    try:
                        os.stat(
                            temporary_name,
                            dir_fd=target_parent,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise OciRootfsError(
                            "hardlink repair temporary name already exists"
                        )
                    repair_plan.append(
                        _SymlinkHardlinkRepair(
                            representative,
                            path,
                            source_parent,
                            target_parent,
                            source_fd,
                            target_fd,
                            source_status,
                            target_status,
                            temporary_name,
                        )
                    )
                    source_parent = source_fd = target_parent = target_fd = -1
                finally:
                    _release_fd_0 = target_fd
                    _release_fd_1 = source_fd
                    _release_fd_2 = target_parent
                    _release_fd_3 = source_parent
                    target_fd = source_fd = target_parent = source_parent = -1
                    _close_descriptors(_release_fd_0, _release_fd_1, _release_fd_2, _release_fd_3, primary=sys.exception())

        repair_watch = _RepairParentWatch.open(ledger, repair_plan, group_members={path for repair in repair_plan for path in groups[repair.representative]})
        try:
            affected: dict[str, set[str]] = {}
            required: dict[str, dict[str, int]] = {}
            for repair in repair_plan:
                for path in groups[repair.representative]:
                    affected.setdefault(path, {"nlink", "ctime_ns"})
                    required[path] = {"ino": repair.source_status.st_ino, "nlink": len(groups[repair.representative])}
                affected[repair.target].add("ino")
                affected[PurePosixPath(repair.target).parent.as_posix()] = {"size", "mtime_ns", "ctime_ns"}
            repair_before = ledger.begin(affected)
            remaining_aliases = {identity: set(paths) for identity, paths in actual_inode_groups.items()}
            # Create every replacement link from its already-held source FD
            # before the first destructive name operation.
            for repair in repair_plan:
                repair_watch.idle()
                repair.temporary_created = True
                _checked_normalization_syscall("link", (repair.source_fd, repair.target_parent, repair.temporary_name), ((repair.source_fd, repair.source_parent, PurePosixPath(repair.representative).name, True),), (4,), repair_watch.idle, lambda: repair_watch.complete(repair, "create"))
                temporary_status = os.stat(
                    repair.temporary_name,
                    dir_fd=repair.target_parent,
                    follow_symlinks=False,
                )
                if _inode_identity(temporary_status) != _inode_identity(
                    repair.source_status
                ):
                    raise OciRootfsError(
                        f"hardlink repair source identity changed: {repair.representative}"
                    )

            for repair in repair_plan:
                repair_watch.idle()
                target_name = PurePosixPath(repair.target).name
                named_before = os.stat(
                    target_name,
                    dir_fd=repair.target_parent,
                    follow_symlinks=False,
                )
                if (
                    _raw_stat(named_before) != _raw_stat(repair.target_status)
                    or _raw_stat(os.fstat(repair.target_fd))
                    != _raw_stat(repair.target_status)
                ):
                    raise OciRootfsError(
                        f"hardlink target changed before repair: {repair.target}"
                    )
                _checked_normalization_syscall("exchange", (repair.target_parent, repair.temporary_name, repair.target_parent, target_name), ((repair.source_fd, repair.target_parent, repair.temporary_name, True), (repair.target_fd, repair.target_parent, target_name, True)), (0x800, 0x800), repair_watch.idle, lambda: repair_watch.complete(repair, "exchange"))
                result_status = os.stat(
                    target_name,
                    dir_fd=repair.target_parent,
                    follow_symlinks=False,
                )
                displaced = os.stat(
                    repair.temporary_name,
                    dir_fd=repair.target_parent,
                    follow_symlinks=False,
                )
                if (
                    _inode_identity(result_status)
                    != _inode_identity(repair.source_status)
                    or _inode_identity(displaced)
                    != _inode_identity(repair.target_status)
                    or _inode_identity(os.fstat(repair.target_fd))
                    != _inode_identity(repair.target_status)
                ):
                    raise OciRootfsError(
                        f"filesystem name changed during hardlink repair: {repair.target}"
                    )
                _checked_normalization_syscall("unlink", (repair.target_parent, repair.temporary_name), ((repair.target_fd, repair.target_parent, repair.temporary_name, True),), (4,), repair_watch.idle, lambda: repair_watch.complete(repair, "unlink"))
                repair.temporary_created = False
                displaced_status = os.fstat(repair.target_fd)
                aliases = remaining_aliases[(repair.target_status.st_dev, repair.target_status.st_ino)]
                aliases_before = sorted(aliases)
                aliases.remove(repair.target)
                if displaced_status.st_nlink != len(aliases):
                    raise OciRootfsError(
                        f"displaced hardlink target alias count differs: {repair.target}"
                    )
                # Exchange/unlink changes the same displaced inode seen by all
                # remaining names. Account only its nlink/ctime transition and
                # carry that exact intermediate state to the next held target.
                previous_raw = _raw_stat(repair.target_status)
                current_raw = _raw_stat(displaced_status)
                if replace(previous_raw, nlink=current_raw.nlink, ctime_ns=current_raw.ctime_ns) != current_raw:
                    raise OciRootfsError("displaced hardlink inode changed outside alias accounting")
                for alias in sorted(aliases):
                    if _raw_entry_stat(ledger.current(alias)) != current_raw:
                        raise OciRootfsError("remaining displaced hardlink alias differs")
                for pending in repair_plan:
                    if pending.target in aliases:
                        if _raw_stat(pending.target_status) != previous_raw:
                            raise OciRootfsError("displaced hardlink intermediate authority differs")
                        pending.target_status = displaced_status
                normalized_hardlinks.append(
                    {
                        "field": "hardlink_group",
                        "path": repair.target,
                        "representative": repair.representative,
                        "displaced": {"aliases_before": aliases_before, "aliases_after": sorted(aliases), "before": previous_raw, "result": current_raw},
                        "before": {
                            "dev": observed.raw_entries[repair.target].dev,
                            "ino": observed.raw_entries[repair.target].ino,
                            "nlink": observed.raw_entries[repair.target].nlink,
                        },
                        "result": {
                            "dev": result_status.st_dev,
                            "ino": result_status.st_ino,
                            "nlink": result_status.st_nlink,
                        },
                    }
                )
            ledger.finish("symlink_hardlink", repair_before, affected, required)
            repair_watch.finish()
            repair_watch.retire_displaced_inodes()
        finally:
            _release_primary = sys.exception()
            try:
                _cleanup_repair_plan(repair_plan)
            except BaseException:
                if _release_primary is None:
                    raise
                _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

        for path in sorted(runtime_normalizations):
            with _owned_resource(_RepairParentWatch.open, _drain_repair_parent_watch, ledger, [], runtime_targets=(path,)) as operation_watch:
                repair_watch.idle()
                operation_before = ledger.begin((path,))
                target_path = PurePosixPath(path)
                parent_path = target_path.parent.as_posix()
                if not parent_path.startswith("/"):
                    parent_path = "/"
                target_parent = _open_directory_beneath(root_fd, parent_path)
                try:
                    descriptor = os.open(
                        target_path.name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=target_parent,
                    )
                    try:
                        status = os.fstat(descriptor)
                        observed_raw = observed.raw_entries[path]
                        if (
                            _raw_stat(status)
                            != RawStat(
                                observed_raw.dev,
                                observed_raw.ino,
                                observed_raw.nlink,
                                observed_raw.mode,
                                observed_raw.uid,
                                observed_raw.gid,
                                observed_raw.rdev,
                                observed_raw.size,
                                observed_raw.mtime_ns,
                                observed_raw.ctime_ns,
                            )
                            or not stat.S_ISREG(status.st_mode)
                        ):
                            raise OciRootfsError(
                                f"runtime bind target changed before normalization: {path}"
                            )
                        wanted = expected.entries[path]
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        if (
                            _hash_open_file(descriptor, status.st_size, path)
                            != observed.entries[path].content_sha256
                            or _read_fd_xattrs(descriptor, path)
                            != observed.entries[path].xattrs
                        ):
                            raise OciRootfsError(
                                f"runtime bind target semantics changed before normalization: {path}"
                            )
                        if stat.S_IMODE(status.st_mode) != wanted.mode:
                            repair_watch.idle()
                            _checked_normalization_syscall("chmod", (descriptor, wanted.mode), ((descriptor, target_parent, target_path.name, False),), (4,), lambda: (repair_watch.idle(), operation_watch.idle()), lambda: (operation_watch.finish_runtime_attribute(path), repair_watch.finish_runtime_attribute(path)))
                        if status.st_mtime_ns != wanted.mtime_ns:
                            repair_watch.idle()
                            _checked_normalization_syscall("utime", (descriptor, wanted.mtime_ns), ((descriptor, target_parent, target_path.name, False),), (4,), lambda: (repair_watch.idle(), operation_watch.idle()), lambda: (operation_watch.finish_runtime_attribute(path), repair_watch.finish_runtime_attribute(path)))
                        ledger.finish("runtime_bind_target", operation_before, {path: {"mode", "mtime_ns", "ctime_ns"}}, {path: {"mode": stat.S_IFREG | wanted.mode, "mtime_ns": wanted.mtime_ns}})
                    finally:
                        _release_primary = sys.exception()
                        try:
                            os.close(descriptor)
                        except BaseException:
                            if _release_primary is None:
                                raise
                            _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
                finally:
                    _release_primary = sys.exception()
                    try:
                        os.close(target_parent)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")

        directories = [
            path for path, entry in expected.entries.items()
            if entry.kind == "directory"
        ]
        for path in sorted(
            directories,
            key=lambda value: (value.count("/"), value),
            reverse=True,
        ):
            if ledger.raw[path].mtime_ns == expected.entries[path].mtime_ns:
                continue
            with _owned_resource(_RepairParentWatch.open, _drain_repair_parent_watch, ledger, [], directory_mtimes=(path,)) as operation_watch:
                operation_before = ledger.begin((path,))
                directory_mtimes[path] = {"from_mtime_ns": ledger.raw[path].mtime_ns, "to_mtime_ns": expected.entries[path].mtime_ns}
                descriptor = _open_directory_beneath(root_fd, path)
                try:
                    wanted = expected.entries[path]
                    status = os.fstat(descriptor)
                    observed_raw = observed.raw_entries[path]
                    current_semantic = SemanticEntry(
                        path=path,
                        kind="directory",
                        mode=stat.S_IMODE(status.st_mode),
                        uid=selected.uid(status.st_uid),
                        gid=selected.gid(status.st_gid),
                        mtime_ns=wanted.mtime_ns,
                        size=status.st_size,
                        xattrs=_read_fd_xattrs(descriptor, path),
                    )
                    expected_semantic = replace(wanted, size=status.st_size)
                    if (
                        status.st_dev != observed_raw.dev
                        or status.st_ino != observed_raw.ino
                        or stat.S_IFMT(status.st_mode) != stat.S_IFDIR
                        or current_semantic != expected_semantic
                    ):
                        raise OciRootfsError(
                            f"directory changed before mtime normalization: {path}"
                        )
                    repair_watch.idle()
                    _checked_normalization_syscall("utime", (descriptor, wanted.mtime_ns), ((descriptor, descriptor, "", False),), (0x40000004,), lambda: (repair_watch.idle(), operation_watch.idle()), lambda: (operation_watch.finish_directory_mtime(path), repair_watch.finish_directory_mtime(path), ledger.finish("directory_mtime", operation_before, {path: {"mtime_ns", "ctime_ns"}}, {path: {"mtime_ns": wanted.mtime_ns}})))
                finally:
                    _release_primary = sys.exception()
                    try:
                        os.close(descriptor)
                    except BaseException:
                        if _release_primary is None:
                            raise
                        _add_cleanup_note(_release_primary, "additional bound descriptor cleanup failed")
        final_anchor = _capture_anchor(parent_fd, root_fd, root_name)
        if (
            initial_anchor.basename != final_anchor.basename
            or initial_anchor.parent != final_anchor.parent
            or initial_anchor.name.dev != final_anchor.name.dev
            or initial_anchor.name.ino != final_anchor.name.ino
        ):
            raise OciRootfsError("rootfs anchor changed during VFS normalization")
        ledger.verify()
        normalized = audit_rootfs(root, projection=selected)
        if normalized.raw_entries != ledger.raw or normalized.before_anchor != final_anchor:
            raise OciRootfsError("rootfs raw ledger changed after normalization operations")
        assert_semantic_equal(expected, normalized)
        repair_watch.finish()
    finally:
        primary = sys.exception()
        failure = None
        try:
            _cleanup_repair_plan(repair_plan)
        except BaseException as error:
            failure = error
        finally:
            # This is the last authorized material attempt. Failed entries
            # stayed held for the outer retry above; release their remaining
            # custody separately without retrying by a reacquired pathname.
            while repair_plan:
                repair = repair_plan[-1]
                if repair is not None:
                    # Keep the plan owner installed through the scalar drain:
                    # even creating a bound close method can fail before entry.
                    closing, repair.target_fd = repair.target_fd, -1
                    if closing >= 0:
                        try:
                            os.close(closing)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                    closing, repair.source_fd = repair.source_fd, -1
                    if closing >= 0:
                        try:
                            os.close(closing)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                    closing, repair.target_parent = repair.target_parent, -1
                    if closing >= 0:
                        try:
                            os.close(closing)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                    closing, repair.source_parent = repair.source_parent, -1
                    if closing >= 0:
                        try:
                            os.close(closing)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                try:
                    repair_plan.pop()
                except BaseException as error:
                    if failure is None:
                        failure = error
                    else:
                        _add_cleanup_note(failure, "additional repair owner transition failed")
                    list.pop(repair_plan)
            try:
                if repair_watch is not None:
                    # Keep the concrete owner installed until every numeric
                    # field is drained, even if close fails before entry.
                    try:
                        repair_watch.close()
                    finally:
                        closing, repair_watch.descriptor = repair_watch.descriptor, -1
                        if closing >= 0:
                            try:
                                os.close(closing)
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                        index = 0
                        while index < 3:
                            records = repair_watch.parents if index == 0 else repair_watch.targets if index == 1 else repair_watch.inodes
                            index += 1
                            try:
                                try:
                                    _close_resource_mapping(records, descriptor_key="descriptor")
                                except BaseException as _map_primary:
                                    # The map remains installed until this literal numeric fallback drains it.
                                    _raw_records = records
                                    while _raw_records:
                                        try:
                                            _raw_owner = _raw_records.popitem()[1]
                                        except BaseException:
                                            _raw_owner = dict.popitem(_raw_records)[1]
                                        _raw_fd = _raw_owner["descriptor"]
                                        _raw_owner["descriptor"] = -1
                                        if _raw_fd is not None and _raw_fd >= 0:
                                            try:
                                                os.close(_raw_fd)
                                            except BaseException:
                                                _add_cleanup_note(_map_primary, "additional concrete descriptor drain failed")
                                    raise
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                        anchor = repair_watch.anchor_parent
                        if anchor is not None:
                            closing, anchor["descriptor"] = anchor["descriptor"], -1
                            if closing >= 0:
                                try:
                                    os.close(closing)
                                except BaseException as error:
                                    if failure is None:
                                        failure = error
                        repair_watch.anchor_parent = None
                        repair_watch = None
            except BaseException as error:
                if failure is None:
                    failure = error
            finally:
                owned_root, root_fd = root_fd, -1
                owned_parent, parent_fd = parent_fd, -1
                try:
                    _close_descriptors(owned_root, owned_parent)
                except BaseException as error:
                    if failure is None:
                        failure = error
        if failure is not None:
            if primary is None:
                raise RuntimeError("normalization cleanup failed") from failure
            _add_cleanup_note(primary, "additional bound descriptor cleanup failed")
    return normalized, _frozen_mapping(
        {
            "schema_version": 3,
            "watch_profile": _REPAIR_WATCH_PROFILE,
            "initial_raw_ledger": _encode_normalization_ledger(observed.raw_entries),
            "repair_groups": {representative: sorted(groups[representative]) for representative in sorted({repair["representative"] for repair in normalized_hardlinks})},
            "directory_mtimes": _frozen_mapping(directory_mtimes),
            "hardlinks": tuple(normalized_hardlinks),
            "runtime_bind_targets": _frozen_mapping(runtime_normalizations),
            "raw_operations": tuple(ledger.operations),
        }
    )


def assert_semantic_equal(
    expected: OciRootfsManifest | RootfsAudit,
    actual: OciRootfsManifest | RootfsAudit,
) -> None:
    """Require exact path set and exact semantics at every path."""

    expected_paths = set(expected.entries)
    actual_paths = set(actual.entries)
    if expected_paths != actual_paths:
        missing = sorted(expected_paths - actual_paths)
        extra = sorted(actual_paths - expected_paths)
        raise RootfsMismatchError(
            f"rootfs path-set mismatch: missing={missing[:8]} extra={extra[:8]}"
        )
    mismatches = [
        path
        for path in sorted(expected_paths)
        if expected.entries[path] != actual.entries[path]
    ]
    if mismatches:
        details = "; ".join(
            f"{path}: expected={expected.entries[path]!r} "
            f"actual={actual.entries[path]!r}"
            for path in mismatches[:8]
        )
        raise RootfsMismatchError(
            f"rootfs semantic mismatch at {mismatches[:8]}: {details}"
        )


def assert_audits_equal(before: RootfsAudit, after: RootfsAudit) -> None:
    """Require two audits to bind the same semantics, topology, and anchors."""

    if before.entries != after.entries:
        raise RootfsMismatchError("audit semantic manifests differ")
    if before.raw_entries != after.raw_entries:
        raise RootfsMismatchError("audit raw ledgers differ")
    if before.before_anchor != after.before_anchor:
        raise RootfsMismatchError("audit root parent/name anchors differ")
