from __future__ import annotations

import base64
import errno
from dataclasses import replace
import gzip
import hashlib
import io
import json
import os
import struct
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import tools.gate01.oci_rootfs as oci_rootfs


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _tar_info(
    name: str,
    *,
    kind: str = "file",
    data: bytes = b"",
    linkname: str = "",
    mode: int | None = None,
    mtime: int = 1,
    pax_headers: dict[str, str] | None = None,
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = mtime
    info.pax_headers = dict(pax_headers or {})
    if kind == "file":
        info.type = tarfile.REGTYPE
        info.mode = 0o644 if mode is None else mode
        info.size = len(data)
    elif kind == "dir":
        info.type = tarfile.DIRTYPE
        info.mode = 0o755 if mode is None else mode
        info.size = 0
        data = b""
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.mode = 0o777 if mode is None else mode
        info.size = 0
        info.linkname = linkname
        data = b""
    elif kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.mode = 0o644 if mode is None else mode
        info.size = 0
        info.linkname = linkname
        data = b""
    elif kind == "fifo":
        info.type = tarfile.FIFOTYPE
        info.mode = 0o644 if mode is None else mode
        info.size = 0
        data = b""
    else:  # pragma: no cover - fixture author guard
        raise AssertionError(kind)
    return info, data


def _layer_bytes(
    entries: list[tuple[tarfile.TarInfo, bytes]],
) -> tuple[bytes, bytes]:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if info.isreg() else None)
    uncompressed = raw.getvalue()
    compressed_buffer = io.BytesIO()
    with gzip.GzipFile(
        fileobj=compressed_buffer, mode="wb", filename="", mtime=0
    ) as compressor:
        compressor.write(uncompressed)
    return compressed_buffer.getvalue(), uncompressed


def _descriptor(data: bytes, media_type: str) -> dict[str, object]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "size": len(data),
    }


def _outer_archive(entries: list[tuple[str, bytes, str]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
            elif kind == "file":
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.mode = 0o777
                info.linkname = data.decode("utf-8")
                info.size = 0
                archive.addfile(info)
            else:  # pragma: no cover - fixture author guard
                raise AssertionError(kind)
    return output.getvalue()


def _oci_archive(
    layers: list[list[tuple[tarfile.TarInfo, bytes]]],
    *,
    wrong_diff_id: bool = False,
    wrong_layer_size: bool = False,
    corrupt_first_layer_blob: bool = False,
    extra_outer_entries: list[tuple[str, bytes, str]] | None = None,
    architecture: str = "amd64",
    operating_system: str = "linux",
    index_platform: dict[str, object] | None = None,
    history: list[dict[str, object]] | None = None,
    omit_config_field: str | None = None,
) -> tuple[bytes, str]:
    layer_blobs: list[bytes] = []
    diff_ids: list[str] = []
    for entries in layers:
        compressed, uncompressed = _layer_bytes(entries)
        layer_blobs.append(compressed)
        diff_ids.append(f"sha256:{hashlib.sha256(uncompressed).hexdigest()}")
    if wrong_diff_id:
        diff_ids[0] = f"sha256:{'0' * 64}"

    config_value: dict[str, object] = {
            "architecture": architecture,
            "config": {},
            "history": (
                [{"created_by": f"fixture layer {index}"} for index in range(len(layers))]
                if history is None
                else history
            ),
            "os": operating_system,
            "rootfs": {"type": "layers", "diff_ids": diff_ids},
        }
    if omit_config_field is not None:
        config_value.pop(omit_config_field)
    config = _json_bytes(config_value)
    config_descriptor = _descriptor(
        config, "application/vnd.oci.image.config.v1+json"
    )
    layer_descriptors = [
        _descriptor(blob, "application/vnd.oci.image.layer.v1.tar+gzip")
        for blob in layer_blobs
    ]
    if wrong_layer_size:
        layer_descriptors[0]["size"] = int(layer_descriptors[0]["size"]) + 1
    manifest = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": layer_descriptors,
        }
    )
    manifest_descriptor = _descriptor(
        manifest, "application/vnd.oci.image.manifest.v1+json"
    )
    manifest_descriptor["platform"] = (
        {"architecture": "amd64", "os": "linux"}
        if index_platform is None
        else index_platform
    )
    index = _json_bytes({"schemaVersion": 2, "manifests": [manifest_descriptor]})

    blob_entries: list[tuple[str, bytes, str]] = []
    for blob in [config, manifest, *layer_blobs]:
        digest = hashlib.sha256(blob).hexdigest()
        stored = blob
        if corrupt_first_layer_blob and blob is layer_blobs[0]:
            stored = blob[:-1] + bytes((blob[-1] ^ 1,))
        blob_entries.append((f"blobs/sha256/{digest}", stored, "file"))
    outer_entries = [
        ("blobs", b"", "dir"),
        ("blobs/sha256", b"", "dir"),
        ("oci-layout", _json_bytes({"imageLayoutVersion": "1.0.0"}), "file"),
        ("index.json", index, "file"),
        *sorted(blob_entries),
        *(extra_outer_entries or []),
    ]
    return _outer_archive(outer_entries), str(manifest_descriptor["digest"])


def _libarchive_xattr(name: str, value: bytes) -> tuple[str, str]:
    # Padding cannot occur in a PAX key because '=' separates key and value.
    encoded_name = base64.b64encode(name.encode("utf-8")).decode("ascii").rstrip("=")
    encoded_value = base64.b64encode(value).decode("ascii")
    return f"LIBARCHIVE.xattr.{encoded_name}", encoded_value


def _canonicalize(
    directory: Path,
    archive_bytes: bytes,
    manifest_digest: str,
    *,
    archive_digest: str | None = None,
):
    archive = directory / "image.oci.tar"
    archive.write_bytes(archive_bytes)
    fd = os.open(archive, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return oci_rootfs.canonicalize_oci_archive(
            fd,
            expected_archive_sha256=(
                archive_digest or hashlib.sha256(archive_bytes).hexdigest()
            ),
            expected_manifest_digest=manifest_digest,
        )
    finally:
        os.close(fd)


class OciCanonicalizationTests(unittest.TestCase):
    def test_nonlexical_tar_hardlink_target_has_canonical_minimum_group_label(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            archive, digest = _oci_archive([[_tar_info("z", kind="symlink", linkname="target"), _tar_info("a", kind="hardlink", linkname="z")]])
            manifest = _canonicalize(Path(name), archive, digest)
            self.assertEqual(manifest.entries["/z"].hardlink_group, "/a")
            self.assertEqual(manifest.entries["/a"].hardlink_group, "/a")

    def test_platform_and_history_are_exact_and_agree_with_descriptors(self) -> None:
        layer = [[_tar_info(".", kind="dir")]]
        cases = (
            ({"architecture": "arm64"}, "linux/amd64"),
            ({"operating_system": "windows"}, "linux/amd64"),
            ({"index_platform": {"architecture": "arm64", "os": "linux"}}, "linux/amd64"),
            ({"index_platform": {"architecture": "amd64"}}, "platform"),
            ({"history": []}, "history"),
            ({"history": [{"created_by": "one", "empty_layer": True}]}, "history"),
            ({"history": [{"created_by": "one", "unknown": "bad"}]}, "history"),
            ({"history": [{"created_by": "one", "empty_layer": "false"}]}, "history"),
            ({"omit_config_field": "architecture"}, "OCI config fields"),
            ({"omit_config_field": "os"}, "OCI config fields"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (options, message) in enumerate(cases):
                archive, manifest_digest = _oci_archive(layer, **options)
                case = root / str(index)
                case.mkdir()
                with self.subTest(options=options):
                    with self.assertRaisesRegex(oci_rootfs.OciRootfsError, message):
                        _canonicalize(case, archive, manifest_digest)

            archive, manifest_digest = _oci_archive(
                layer,
                history=[
                    {"created_by": "metadata", "empty_layer": True},
                    {"created_by": "payload"},
                ],
            )
            accepted = root / "accepted"
            accepted.mkdir()
            result = _canonicalize(accepted, archive, manifest_digest)
            self.assertEqual(result.architecture, "amd64")
            self.assertEqual(result.operating_system, "linux")
            self.assertEqual(len(result.history), 2)

    def test_layers_merge_whiteouts_hardlinks_xattrs_and_implicit_ancestors(self) -> None:
        capability = bytes.fromhex("0100000200000000000000000000000000000000")
        capability_header, capability_value = _libarchive_xattr(
            "security.capability", capability
        )
        layers = [
            [
                _tar_info(".", kind="dir"),
                _tar_info("etc", kind="dir"),
                _tar_info("etc/lower", data=b"removed by whiteout"),
                _tar_info("etc/opaque-old", data=b"removed by opaque marker"),
                _tar_info("usr", kind="dir"),
                _tar_info("usr/bin", kind="dir"),
                _tar_info(
                    "usr/bin/tool",
                    data=b"tool-payload",
                    pax_headers={
                        "SCHILY.xattr.user.origin": "base",
                        "SCHILY.acl.access": "user::rw-,group::r--,other::---",
                        capability_header: capability_value,
                    },
                ),
                _tar_info(
                    "usr/bin/alias", kind="hardlink", linkname="usr/bin/tool"
                ),
                _tar_info(
                    "objects/link.file", kind="symlink", linkname="../../target"
                ),
            ],
            [
                _tar_info("etc/.wh.lower"),
                _tar_info("etc/.wh..wh..opq"),
                _tar_info("etc/new", data=b"new"),
                _tar_info(
                    "usr/bin/cross", kind="hardlink", linkname="usr/bin/tool"
                ),
                _tar_info(
                    "usr/bin/forward", kind="hardlink", linkname="usr/bin/later"
                ),
                _tar_info("usr/bin/later", data=b"later"),
                _tar_info("implicit/deep/value", data=b"implicit parents"),
                _tar_info("unicode-link", kind="symlink", linkname="café"),
                _tar_info(
                    "deployment/link",
                    kind="hardlink",
                    linkname="objects/link.file",
                ),
            ],
        ]
        archive, manifest_digest = _oci_archive(layers)

        with tempfile.TemporaryDirectory() as temporary:
            result = _canonicalize(Path(temporary), archive, manifest_digest)

        self.assertNotIn("/etc/lower", result.entries)
        self.assertNotIn("/etc/opaque-old", result.entries)
        self.assertEqual(
            result.entries["/etc/new"].content_sha256,
            hashlib.sha256(b"new").hexdigest(),
        )
        self.assertEqual(
            result.entries["/unicode-link"].symlink_target, b"caf\xc3\xa9"
        )
        self.assertEqual(result.entries["/implicit"].kind, "directory")
        self.assertEqual(result.entries["/implicit/deep"].kind, "directory")
        self.assertEqual(
            result.entries["/usr/bin/forward"].hardlink_group,
            "/usr/bin/forward",
        )
        self.assertEqual(
            result.entries["/usr/bin/later"].hardlink_group,
            "/usr/bin/forward",
        )
        for path in ("/usr/bin/alias", "/usr/bin/cross", "/usr/bin/tool"):
            self.assertEqual(
                result.entries[path].hardlink_group, "/usr/bin/alias", path
            )
        for path in ("/deployment/link", "/objects/link.file"):
            self.assertEqual(result.entries[path].kind, "symlink")
            self.assertEqual(result.entries[path].symlink_target, b"../../target")
            self.assertEqual(
                result.entries[path].hardlink_group, "/deployment/link", path
            )
        xattrs = dict(result.entries["/usr/bin/tool"].xattrs)
        self.assertEqual(xattrs["user.origin"], b"base")
        self.assertEqual(xattrs["security.capability"], capability)
        self.assertEqual(
            xattrs["system.posix_acl_access"],
            bytes.fromhex(
                "02000000"
                "01000600ffffffff"
                "04000400ffffffff"
                "20000000ffffffff"
            ),
        )
        self.assertEqual(list(result.entries), sorted(result.entries))
        self.assertEqual(len(result.entries), len(set(result.entries)))

    def test_descriptor_digest_size_diff_id_and_locked_id_are_all_enforced(self) -> None:
        layer = [[_tar_info(".", kind="dir"), _tar_info("file", data=b"ok")]]
        cases = (
            (dict(corrupt_first_layer_blob=True), None, "descriptor SHA-256"),
            (dict(wrong_layer_size=True), None, "descriptor size"),
            (dict(wrong_diff_id=True), None, "diff_id"),
            ({}, "0" * 64, "archive SHA-256"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for index, (options, archive_digest, message) in enumerate(cases):
                with self.subTest(message=message):
                    archive, manifest_digest = _oci_archive(layer, **options)
                    case_dir = directory / str(index)
                    case_dir.mkdir()
                    with self.assertRaisesRegex(oci_rootfs.OciRootfsError, message):
                        _canonicalize(
                            case_dir,
                            archive,
                            manifest_digest,
                            archive_digest=archive_digest,
                        )

            archive, manifest_digest = _oci_archive(layer)
            locked_id_dir = directory / "locked-id"
            locked_id_dir.mkdir()
            with self.assertRaisesRegex(oci_rootfs.OciRootfsError, "manifest digest"):
                _canonicalize(
                    locked_id_dir,
                    archive,
                    f"sha256:{'f' * 64}",
                )

    def test_layer_rejects_traversal_canonical_duplicates_and_special_files(self) -> None:
        cases = (
            ([_tar_info("../escape", data=b"bad")], "traversal"),
            (
                [
                    _tar_info("safe", data=b"one"),
                    _tar_info("./safe", data=b"two"),
                ],
                "duplicate layer path",
            ),
            ([_tar_info("pipe", kind="fifo")], "unsupported layer entry"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for index, (entries, message) in enumerate(cases):
                with self.subTest(message=message):
                    archive, manifest_digest = _oci_archive([entries])
                    case_dir = directory / str(index)
                    case_dir.mkdir()
                    with self.assertRaisesRegex(oci_rootfs.OciRootfsError, message):
                        _canonicalize(case_dir, archive, manifest_digest)

    def test_outer_archive_rejects_duplicate_and_escaping_members(self) -> None:
        base_layer = [[_tar_info(".", kind="dir")]]
        cases = (
            ([("index.json", b"{}", "file")], "duplicate OCI archive path"),
            ([("../outside", b"bad", "file")], "OCI archive path traversal"),
            (
                [("unexpected-link", b"target", "symlink")],
                "unsupported OCI archive entry",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for index, (extra, message) in enumerate(cases):
                with self.subTest(message=message):
                    archive, manifest_digest = _oci_archive(
                        base_layer, extra_outer_entries=extra
                    )
                    case_dir = directory / str(index)
                    case_dir.mkdir()
                    with self.assertRaisesRegex(oci_rootfs.OciRootfsError, message):
                        _canonicalize(case_dir, archive, manifest_digest)

    def test_missing_and_cyclic_hardlink_targets_are_rejected(self) -> None:
        cases = (
            (
                [_tar_info("link", kind="hardlink", linkname="missing")],
                "hardlink target",
            ),
            (
                [
                    _tar_info("one", kind="hardlink", linkname="two"),
                    _tar_info("two", kind="hardlink", linkname="one"),
                ],
                "hardlink target",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for index, (entries, message) in enumerate(cases):
                with self.subTest(index=index):
                    archive, manifest_digest = _oci_archive([entries])
                    case_dir = directory / str(index)
                    case_dir.mkdir()
                    with self.assertRaisesRegex(oci_rootfs.OciRootfsError, message):
                        _canonicalize(case_dir, archive, manifest_digest)


class RootfsAuditTests(unittest.TestCase):
    def test_helper_prerequisites_reject_live_native_thread_and_nonignored_sigpipe(self) -> None:
        import signal
        import threading
        ready, release = threading.Event(), threading.Event()
        def worker():
            ready.set()
            release.wait()
        thread = threading.Thread(target=worker)
        baseline = len(os.listdir("/proc/self/fd"))
        thread.start()
        ready.wait()
        try:
            with mock.patch.object(os, "pipe2") as pipe, mock.patch.object(os, "fork") as fork:
                with self.assertRaisesRegex(oci_rootfs.OciRootfsError, "one thread"):
                    oci_rootfs._run_normalization_syscall("chmod", (-1, 0o600))
                pipe.assert_not_called()
                fork.assert_not_called()
        finally:
            release.set()
            thread.join()
        with mock.patch.object(signal, "getsignal", return_value=signal.SIG_DFL), mock.patch.object(os, "pipe2") as pipe, mock.patch.object(os, "fork") as fork:
            with self.assertRaisesRegex(oci_rootfs.OciRootfsError, "SIGPIPE"):
                oci_rootfs._run_normalization_syscall("chmod", (-1, 0o600))
            pipe.assert_not_called()
            fork.assert_not_called()
        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_helper_cleanup_retries_exact_pidfd_and_reap_without_losing_primary(self) -> None:
        for phase in ("terminate", "reap", "reap-wrong"):
            with self.subTest(phase=phase), tempfile.TemporaryFile() as target:
                primary = ValueError("injected helper body")
                original_fork, original_wait, original_signal = os.fork, os.waitpid, oci_rootfs.signal.pidfd_send_signal
                children, attempts = [], []
                def fork():
                    child = original_fork()
                    if child: children.append(child)
                    return child
                def send(*args):
                    attempts.append("terminate")
                    if phase == "terminate" and attempts.count("terminate") == 1:
                        raise OSError(errno.EIO, "injected exact termination")
                    return original_signal(*args)
                def wait(*args):
                    attempts.append("reap")
                    if phase.startswith("reap") and attempts.count("reap") == 1:
                        if phase == "reap-wrong": return 0, 0
                        raise OSError(errno.EIO, "injected exact reap")
                    return original_wait(*args)
                baseline = len(os.listdir("/proc/self/fd"))
                try:
                    with mock.patch.object(os, "fork", side_effect=fork), mock.patch.object(os, "waitpid", side_effect=wait), mock.patch.object(oci_rootfs.signal, "pidfd_send_signal", side_effect=send), mock.patch.object(oci_rootfs.select, "select", side_effect=primary), mock.patch.object(os, "kill") as numeric:
                        with self.assertRaises(ValueError) as caught:
                            oci_rootfs._run_normalization_syscall("chmod", (target.fileno(), 0o600))
                    self.assertIs(caught.exception, primary)
                    self.assertTrue(primary.__notes__)
                    self.assertGreaterEqual(attempts.count("terminate" if phase == "terminate" else "reap"), 2)
                    numeric.assert_not_called()
                    self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                    for child in children:
                        with self.assertRaises(ChildProcessError): original_wait(child, os.WNOHANG)
                finally:
                    for child in children:
                        try: original_wait(child, 0)
                        except ChildProcessError: pass

    def test_fanotify_parser_requires_exact_bounded_unprivileged_fid_records(self) -> None:
        def event(payload=bytes(8), mask=4):
            info = struct.pack("=BBH", 1, 0, 20 + len(payload)) + b"filesystem"[:8] + struct.pack("=Ii", len(payload), 1) + payload
            return struct.pack("=IBBHQii", 24 + len(info), 3, 0, 24, mask, -1, 0) + info
        valid = event()
        for payload in (bytes(8), bytes(12), bytes(128)):
            for mask in (4, 0x800, 0x40000004):
                raw = event(payload, mask)
                with mock.patch.object(os, "read", side_effect=[raw, BlockingIOError()]):
                    self.assertEqual(oci_rootfs._read_normalization_fanotify(90), [(mask, raw[28:])])
        mutations = {"truncated": valid[:-1], "header": valid[:12], "eof": b"", "extra": valid + b"x", "third": valid * 3}
        for label, offset, replacement in (("version", 4, b"\x02"), ("reserved", 5, b"\x01"), ("metadata-size", 6, b"\x10\x00"), ("overflow", 8, struct.pack("=Q", 0x4000)), ("fd", 16, struct.pack("=i", 9)), ("pid", 20, struct.pack("=i", 1)), ("info-type", 24, b"\x02"), ("padding", 25, b"\x01"), ("info-length", 26, b"\x10\x00"), ("handle-length", 36, struct.pack("=I", 129)), ("handle-type", 40, struct.pack("=i", -1))):
            mutations[label] = valid[:offset] + replacement + valid[offset + len(replacement):]
        for label, raw in mutations.items():
            with self.subTest(label=label), mock.patch.object(os, "read", side_effect=[raw, BlockingIOError()]):
                with self.assertRaises(oci_rootfs.OciRootfsError): oci_rootfs._read_normalization_fanotify(90)

    def test_helper_ipc_status_and_completed_close_fault_matrix(self) -> None:
        import contextlib
        phases = ("tasks", "pipe", "reader-close", "writer-close", "pidfd-close", "write-error", "write-zero", "write-bool", "write-token", "timeout", "wait-wrong", "wait-eintr", "child-read", "child-close", "child-exception", "child-signal")
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryFile() as target:
                primary = OSError(errno.EIO, "injected helper IPC")
                original_fork, original_wait, original_close, original_write = os.fork, os.waitpid, os.close, os.write
                original_libc = oci_rootfs.ctypes.CDLL(None, use_errno=True)
                children, closed = [], []
                failed_wait = False
                def fork():
                    child = original_fork()
                    if child: children.append(child)
                    return child
                def closing(fd):
                    identity = os.fstat(fd)
                    original_close(fd)
                    closed.append((fd, identity.st_dev, identity.st_ino))
                    if len(closed) == {"reader-close": 1, "writer-close": 2, "pidfd-close": 3}.get(phase): raise primary
                def writing(fd, data):
                    if phase == "write-error": raise primary
                    if phase == "write-zero": return 0
                    if phase == "write-bool": return True
                    return original_write(fd, b"x" if phase == "write-token" else data)
                def waiting(pid, options):
                    nonlocal failed_wait
                    if not failed_wait and phase in {"wait-wrong", "wait-eintr"}:
                        failed_wait = True
                        if phase == "wait-wrong": return 0, 0
                        raise InterruptedError("injected interrupted wait")
                    return original_wait(pid, options)
                class Libc:
                    def __getattr__(self, name):
                        if phase == "child-read" and name == "read": return lambda *args: -1
                        if phase == "child-close" and name == "close":
                            def close(*args):
                                original_libc.close(*args)
                                return -1
                            return close
                        if name == "fchmod" and phase in {"child-exception", "child-signal"}:
                            def mutate(*args):
                                if phase == "child-signal": os.kill(os.getpid(), oci_rootfs.signal.SIGKILL)
                                raise MemoryError("injected child syscall")
                            return mutate
                        return getattr(original_libc, name)
                baseline = len(os.listdir("/proc/self/fd"))
                try:
                    with contextlib.ExitStack() as patches:
                        patches.enter_context(mock.patch.object(os, "fork", side_effect=fork))
                        patches.enter_context(mock.patch.object(os, "waitpid", side_effect=waiting))
                        patches.enter_context(mock.patch.object(os, "close", side_effect=closing))
                        patches.enter_context(mock.patch.object(os, "write", side_effect=writing))
                        patches.enter_context(mock.patch.object(oci_rootfs.ctypes, "CDLL", return_value=Libc()))
                        if phase == "tasks": patches.enter_context(mock.patch.object(os, "listdir", side_effect=primary))
                        if phase == "pipe": patches.enter_context(mock.patch.object(os, "pipe2", side_effect=primary))
                        if phase == "timeout": patches.enter_context(mock.patch.object(oci_rootfs.select, "select", return_value=([], [], [])))
                        with self.assertRaises(BaseException) as caught:
                            oci_rootfs._run_normalization_syscall("chmod", (target.fileno(), 0o600))
                    if phase in {"tasks", "pipe", "reader-close", "writer-close", "write-error"}: self.assertIs(caught.exception, primary)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                    self.assertEqual(len(closed), len(set(closed)))
                    for child in children:
                        with self.assertRaises(ChildProcessError): original_wait(child, os.WNOHANG)
                finally:
                    for child in children:
                        try: original_wait(child, 0)
                        except ChildProcessError: pass

    def test_operation_local_fanotify_setup_drain_and_release_fault_matrix(self) -> None:
        import contextlib
        phases = ("init-first", "init-second", "mark-first", "mark-second", "fid-unavailable", "fid-changed", "baseline", "read-error", "transition-extra", "transition-mask", "terminal", "close-first", "close-second")
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                (root / "a").write_bytes(b"a")
                (root / "b").write_bytes(b"b")
                with contextlib.ExitStack() as owners:
                    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    owners.callback(os.close, parent)
                    descriptors = [os.open(root / item, os.O_RDONLY) for item in ("a", "b")]
                    for fd in descriptors: owners.callback(os.close, fd)
                    endpoints = tuple((fd, parent, item, False) for fd, item in zip(descriptors, ("a", "b")))
                    original_libc = oci_rootfs.ctypes.CDLL(None, use_errno=True)
                    original_read, original_fid, original_close = oci_rootfs._read_normalization_fanotify, oci_rootfs._normalization_fid, os.close
                    groups, closes = [], []
                    counts = {"init": 0, "mark": 0, "read": 0, "fid": 0}
                    primary = OSError(errno.EIO, "injected inode watch boundary")
                    class Libc:
                        def __getattr__(self, key):
                            if key == "fanotify_init":
                                def initialize(*args):
                                    counts["init"] += 1
                                    if counts["init"] == {"init-first": 1, "init-second": 2}.get(phase): return -1
                                    fd = original_libc.fanotify_init(*args)
                                    if fd >= 0: groups.append(fd)
                                    return fd
                                return initialize
                            if key == "fanotify_mark":
                                def mark(*args):
                                    counts["mark"] += 1
                                    if counts["mark"] == {"mark-first": 1, "mark-second": 2}.get(phase): return -1
                                    return original_libc.fanotify_mark(*args)
                                return mark
                            return getattr(original_libc, key)
                    def identity(*args):
                        counts["fid"] += 1
                        if phase == "fid-unavailable": raise primary
                        value = original_fid(*args)
                        return value + b"x" if phase == "fid-changed" and counts["fid"] == 2 else value
                    def read(fd):
                        counts["read"] += 1
                        if phase == "read-error": raise primary
                        events = original_read(fd)
                        if phase == "baseline" and counts["read"] == 1: return [(4, b"foreign")]
                        if phase == "transition-extra" and counts["read"] == 3: return events * 2
                        if phase == "transition-mask" and counts["read"] == 3: return [(4, events[0][1])]
                        if phase == "terminal" and counts["read"] == 5: return [(4, b"foreign")]
                        return events
                    def close(fd):
                        original_close(fd)
                        if fd in groups:
                            closes.append(fd)
                            if len(closes) == {"close-first": 1, "close-second": 2}.get(phase): raise primary
                    baseline = len(os.listdir("/proc/self/fd"))
                    with mock.patch.object(oci_rootfs.ctypes, "CDLL", return_value=Libc()), mock.patch.object(oci_rootfs, "_normalization_fid", side_effect=identity), mock.patch.object(oci_rootfs, "_read_normalization_fanotify", side_effect=read), mock.patch.object(os, "close", side_effect=close):
                        with self.assertRaises(BaseException) as caught:
                            oci_rootfs._checked_normalization_syscall("exchange", (parent, "a", parent, "b"), endpoints, (0x800, 0x800), lambda: None, lambda: None)
                    if phase in {"fid-unavailable", "read-error"}: self.assertIs(caught.exception, primary)
                    self.assertCountEqual(closes, groups)
                    self.assertLessEqual(len(groups), 2)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_raw_syscall_helper_faults_reap_exact_child_and_release_pidfd(self) -> None:
        for phase in ("fork", "pidfd", "select", "wait-before", "wait-after", "wait-no-child", "syscall"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY)
                primary = OSError(errno.EIO, "injected helper boundary")
                original_fork, original_wait = os.fork, os.waitpid
                children = []
                def fork():
                    if phase == "fork": raise primary
                    pid = original_fork()
                    if pid: children.append(pid)
                    return pid
                failed = False
                def wait(pid, options):
                    nonlocal failed
                    if not failed and phase.startswith("wait"):
                        failed = True
                        if phase == "wait-after": original_wait(pid, options)
                        if phase == "wait-no-child": raise ChildProcessError("injected spurious child status")
                        raise primary
                    return original_wait(pid, options)
                baseline = len(os.listdir("/proc/self/fd"))
                try:
                    with mock.patch.object(os, "fork", side_effect=fork), mock.patch.object(os, "waitpid", side_effect=wait):
                        import contextlib
                        with contextlib.ExitStack() as stack:
                            if phase == "pidfd": stack.enter_context(mock.patch.object(os, "pidfd_open", side_effect=primary))
                            if phase == "select": stack.enter_context(mock.patch.object(oci_rootfs.select, "select", side_effect=primary))
                            with self.assertRaises(BaseException) as caught:
                                oci_rootfs._run_normalization_syscall("chmod", (-1 if phase == "syscall" else descriptor, 0o700))
                    if phase == "wait-no-child": self.assertIsInstance(caught.exception, ChildProcessError)
                    elif phase != "syscall": self.assertIs(caught.exception, primary)
                    else: self.assertIsInstance(caught.exception, oci_rootfs.OciRootfsError)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                    for pid in children:
                        with self.assertRaises(ChildProcessError): original_wait(pid, os.WNOHANG)
                finally:
                    for pid in children:
                        try: original_wait(pid, 0)
                        except ChildProcessError: pass
                    os.close(descriptor)

    def test_helper_never_signals_numeric_pid_after_child_was_reaped_before_pidfd(self) -> None:
        import signal
        original_wait, original_kill = os.waitpid, os.kill
        primary = ProcessLookupError("injected reaped child before pidfd")
        def reaped(pid, flags):
            try: original_kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            original_wait(pid, 0)
            raise primary
        baseline = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(os, "pidfd_open", side_effect=reaped), mock.patch.object(os, "kill") as kill:
            with self.assertRaises(BaseException) as caught: oci_rootfs._run_normalization_syscall("chmod", (-1, 0o600))
        self.assertIs(caught.exception, primary)
        kill.assert_not_called()
        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_helper_never_signals_unauthenticated_reused_pidfd_after_epipe(self) -> None:
        import signal
        original_wait, original_kill = os.waitpid, os.kill
        def reused(pid, flags):
            try: original_kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            original_wait(pid, 0)
            return os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        baseline = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(os, "pidfd_open", side_effect=reused), mock.patch.object(os, "kill") as numeric, mock.patch.object(oci_rootfs.signal, "pidfd_send_signal") as bound:
            with self.assertRaises(BrokenPipeError): oci_rootfs._run_normalization_syscall("chmod", (-1, 0o600))
        numeric.assert_not_called()
        bound.assert_not_called()
        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_external_alias_churn_cannot_coalesce_with_authorized_inode_event(self) -> None:
        for role, order in (("symlink", "before"), ("runtime", "after")):
            for separate_process in (False, True):
                with self.subTest(role=role, order=order, separate_process=separate_process), tempfile.TemporaryDirectory() as name:
                    root, external = Path(name) / "root", Path(name) / "external"
                    root.mkdir()
                    external.mkdir()
                    target = root / "one"
                    if role == "symlink":
                        target.symlink_to("missing")
                        (root / "two").symlink_to("missing")
                    else:
                        target.write_bytes(b"public")
                    initial = oci_rootfs.audit_rootfs(root)
                    entries = dict(initial.entries)
                    if role == "symlink":
                        entries = {path: replace(row, hardlink_group="/one") if row.kind == "symlink" else row for path, row in entries.items()}
                    else:
                        entries["/one"] = replace(entries["/one"], mode=0o600)
                    expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                    original_link = os.link
                    injected = False
                    def churn():
                        original_link(target, external / "alias", follow_symlinks=False)
                        (external / "alias").unlink()
                    def inject():
                        if separate_process:
                            pid = os.fork()
                            if pid == 0:
                                try: churn()
                                finally: os._exit(0)
                            self.assertEqual(os.waitpid(pid, 0), (pid, 0))
                        else: churn()
                    original = oci_rootfs._run_normalization_syscall
                    def boundary(operation, arguments):
                        nonlocal injected
                        selected = not injected and operation == ("link" if role == "symlink" else "chmod")
                        if selected:
                            injected = True
                            if order == "before": inject()
                        result = original(operation, arguments)
                        if selected and order == "after": inject()
                        return result
                    baseline = len(os.listdir("/proc/self/fd"))
                    with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=boundary):
                        with self.assertRaises(oci_rootfs.OciRootfsError):
                            oci_rootfs.normalize_vfs_materialization(root, expected, runtime_bind_targets=("/one",) if role == "runtime" else ())
                    self.assertTrue(injected)
                    self.assertFalse((external / "alias").exists())
                    self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_cross_directory_member_parent_and_root_mtimes_advance_only_exact_authority(self) -> None:
        for directory in ("/source", "/"):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "root"
                for parent in ("source", "target"): (root / parent).mkdir(parents=True)
                for path in ("source/one", "target/two"): (root / path).symlink_to("missing")
                initial = oci_rootfs.audit_rootfs(root)
                entries = {path: replace(row, hardlink_group="/source/one") if row.kind == "symlink" else row for path, row in initial.entries.items()}
                entries[directory] = replace(entries[directory], mtime_ns=1)
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                normalized, _ = oci_rootfs.normalize_vfs_materialization(root, expected)
                oci_rootfs.assert_semantic_equal(expected, normalized)

    def test_directory_normalization_scales_with_operation_local_watch_custody(self) -> None:
        for count in (100, 300, 4097):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "root"
                root.mkdir()
                for index in range(count): (root / f"directory-{index:05d}").mkdir()
                initial = oci_rootfs.audit_rootfs(root)
                entries = {path: replace(row, mtime_ns=1) for path, row in initial.entries.items()}
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                original_open, original_add = oci_rootfs._open_repair_watch, oci_rootfs._add_repair_watch
                watches, maximum = {}, []
                def opening():
                    fd = original_open()
                    watches[fd] = 0
                    return fd
                def adding(fd, *args, **kwargs):
                    watches[fd] += 1
                    maximum.append(watches[fd])
                    return original_add(fd, *args, **kwargs)
                original_current = oci_rootfs._NormalizationLedger.current
                calls = []
                def current(ledger, path):
                    calls.append(path)
                    return original_current(ledger, path)
                baseline = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(oci_rootfs, "_open_repair_watch", side_effect=opening), mock.patch.object(oci_rootfs, "_add_repair_watch", side_effect=adding), mock.patch.object(oci_rootfs._NormalizationLedger, "current", current):
                    normalized, _ = oci_rootfs.normalize_vfs_materialization(root, expected)
                oci_rootfs.assert_semantic_equal(expected, normalized)
                self.assertLessEqual(max(maximum), 3)
                self.assertLessEqual(len(calls), 25 * (count + 1))
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_cross_directory_repair_watches_every_source_member_inode(self) -> None:
        for mutation in ("source-utime", "member-utime"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "root"
                for parent in ("source", "target"): (root / parent).mkdir(parents=True)
                (root / "source/one").symlink_to("missing")
                os.link(root / "source/one", root / "source/alias", follow_symlinks=False)
                (root / "target/two").symlink_to("missing")
                baseline = oci_rootfs.audit_rootfs(root)
                entries = {path: replace(row, hardlink_group="/source/alias") if row.kind == "symlink" else row for path, row in baseline.entries.items()}
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                original, changed = oci_rootfs._run_normalization_syscall, False
                def linking(operation, arguments):
                    nonlocal changed
                    original(operation, arguments)
                    if not changed and operation == "link":
                        changed = True
                        path = root / ("source/alias" if mutation == "source-utime" else "source/one")
                        status = path.lstat()
                        os.utime(path, ns=(1, 1), follow_symlinks=False)
                        os.utime(path, ns=(status.st_atime_ns, status.st_mtime_ns), follow_symlinks=False)
                count = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=linking):
                    with self.assertRaises(oci_rootfs.OciRootfsError): oci_rootfs.normalize_vfs_materialization(root, expected)
                self.assertTrue(changed)
                self.assertEqual(len(os.listdir("/proc/self/fd")), count)

    def test_metadata_only_normalization_rejects_transient_mutations_at_syscall_boundary(self) -> None:
        for role, mutation in (("directory", "child"), ("directory", "mode"), ("runtime", "content"), ("runtime", "mode"), ("runtime", "xattr")):
            with self.subTest(role=role, mutation=mutation), tempfile.TemporaryDirectory() as name:
                root = Path(name) / "root"
                root.mkdir()
                target = root if role == "directory" else root / "runtime"
                if role == "runtime": target.write_bytes(b"original")
                baseline = oci_rootfs.audit_rootfs(root)
                entries = dict(baseline.entries)
                path = "/" if role == "directory" else "/runtime"
                entries[path] = replace(entries[path], mtime_ns=1, **({"mode": 0o600} if role == "runtime" else {}))
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                original = oci_rootfs._run_normalization_syscall
                injected = False
                def mutate(operation, arguments):
                    nonlocal injected
                    if not injected and operation == ("utime" if role == "directory" else "chmod"):
                        injected = True
                        if mutation == "child":
                            (root / "unrelated").touch()
                            (root / "unrelated").unlink()
                        elif mutation == "mode":
                            mode = target.stat().st_mode & 0o7777
                            target.chmod(mode ^ 0o010)
                            target.chmod(mode)
                        elif mutation == "content":
                            target.write_bytes(b"mutated!")
                            target.write_bytes(b"original")
                        else:
                            os.setxattr(target, "user.fixture", b"temporary")
                            os.removexattr(target, "user.fixture")
                    return original(operation, arguments)
                count = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=mutate):
                    with self.assertRaises(oci_rootfs.OciRootfsError):
                        oci_rootfs.normalize_vfs_materialization(root, expected, runtime_bind_targets=(path,) if role == "runtime" else ())
                self.assertTrue(injected)
                self.assertEqual(len(os.listdir("/proc/self/fd")), count)

    def test_complete_ledger_codec_rejects_noncanonical_and_unbounded_authority(self) -> None:
        from tools.gate01 import proof_io
        import copy
        import zlib
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "file").touch()
            actual = oci_rootfs.audit_rootfs(root)
            value = proof_io._json_safe(oci_rootfs._encode_normalization_ledger(actual.raw_entries))
            self.assertEqual(dict(oci_rootfs._decode_normalization_ledger(value)), dict(actual.raw_entries))
            def encode(raw):
                return {**value, "data": base64.b64encode(zlib.compress(raw)).decode("ascii"), "uncompressed_size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            raw = proof_io._canonical_json(proof_io._json_safe(actual.raw_entries))
            for fault in ("nul", "alternate-compression", "trailing", "multistream", "truncated", "base64", "size", "count", "hash", "extra", "version", "duplicate", "noncanonical", "parent", "alias", "numeric", "entry-bound", "byte-bound"):
                forged = copy.deepcopy(value)
                if fault == "alternate-compression": forged["data"] = base64.b64encode(zlib.compress(raw, level=1)).decode("ascii")
                elif fault == "nul":
                    rows = proof_io._json_safe(actual.raw_entries)
                    row = rows.pop("/file")
                    row["path"], row["name"] = "/fi\0le", "fi\0le"
                    rows[row["path"]] = row
                    forged = encode(proof_io._canonical_json(rows))
                elif fault in {"parent", "alias", "numeric"}:
                    rows = proof_io._json_safe(actual.raw_entries)
                    rows["/file"][{"parent": "parent_ino", "alias": "nlink", "numeric": "uid"}[fault]] = True if fault == "numeric" else 2
                    forged = encode(proof_io._canonical_json(rows))
                elif fault == "duplicate": forged = encode(b'{"/":' + raw.split(b'"/":', 1)[1].split(b',"/file":', 1)[0] + b',' + raw[1:])
                elif fault == "noncanonical": forged = encode(b" " + raw)
                elif fault in {"trailing", "multistream", "truncated"}:
                    compressed = base64.b64decode(forged["data"])
                    compressed = compressed[:-1] if fault == "truncated" else compressed + (b"trailing" if fault == "trailing" else zlib.compress(b"{}"))
                    forged["data"] = base64.b64encode(compressed).decode("ascii")
                elif fault == "base64": forged["data"] += "\n"
                elif fault == "size": forged["uncompressed_size"] -= 1
                elif fault == "count": forged["entry_count"] += 1
                elif fault == "hash": forged["sha256"] = "0" * 64
                elif fault == "extra": forged["extra"] = True
                elif fault == "version": forged["encoding"] = "v0"
                elif fault == "entry-bound": forged["entry_count"] = oci_rootfs._RAW_LEDGER_MAX_ENTRIES + 1
                elif fault == "byte-bound": forged["uncompressed_size"] = oci_rootfs._RAW_LEDGER_MAX_BYTES + 1
                with self.subTest(fault=fault), self.assertRaises(oci_rootfs.OciRootfsError):
                    oci_rootfs._decode_normalization_ledger(forged)

    def test_production_runtime_consumer_rejects_forged_genuine_complete_normalization(self) -> None:
        from tools.gate01 import kernel_build, proof_io
        from tests.gate01.test_kernel_build import ComparisonAndMetaProofTests, _runtime_evidence
        import copy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            self._normalization_groups(root, (False, False))
            # A complete real filesystem fixture, not a symbolic cardinality.
            # Bounded-size hardlink classes avoid both disk payload growth and
            # filesystem per-inode link-count limits.
            for index in range(138614):
                path = root / f"fixture-{index:06d}"
                if index % 10000 == 0: path.touch()
                else: os.link(root / f"fixture-{index - index % 10000:06d}", path)
            before = oci_rootfs.audit_rootfs(root)
            self.assertEqual(len(before.raw_entries), 138621)
            entries = dict(before.entries)
            for parent in ("/0", "/1"):
                for suffix in ("one", "two"):
                    path = parent + "/" + suffix
                    entries[path] = replace(entries[path], hardlink_group=parent + "/one")
            expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
            actual, delta = oci_rootfs.normalize_vfs_materialization(root, expected)
            capsule = ComparisonAndMetaProofTests()._source_capsule()
            capsule["oci_rootfs"]["root_entry"] = proof_io._json_safe(actual.entries["/"])
            repository, probe = Path("/synthetic-evidence"), Path("/synthetic-evidence/probe")
            rootfs, contract = _runtime_evidence(repository, "builder-a", capsule, probe_root=probe, normalization_audit=(actual, delta))
            del rootfs["inspection"], contract["inspection"]
            rootfs["probe"] = rootfs.pop("build")
            contract["probe"] = contract.pop("build")
            contract["key_scope"] = {"probe": False}
            def validate(value):
                kernel_build._validate_runtime_evidence(rootfs, value, capsule, repository=repository, builder="builder-a", expected_uid=os.getuid(), expected_gid=os.getgid(), probe_root=probe)
            validate(contract)
            for mutation in ("representatives", "parents", "not-present", "local-chain"):
                forged = copy.deepcopy(contract)
                normalization = forged["probe"]["vfs_normalization"]
                if mutation == "not-present":
                    for repair in normalization["hardlinks"]: repair["representative"] = "/not-present"
                else:
                    for operation in normalization["raw_operations"]:
                        for path in tuple(operation["entries"]):
                            if mutation == "representatives" and path in {"/0/one", "/1/one"}: del operation["entries"][path]
                            elif mutation == "parents" and operation["operation"] == "symlink_hardlink" and path in {"/0", "/1"}: del operation["entries"][path]
                            elif mutation == "local-chain" and path == "/0":
                                operation["entries"][path]["result"]["ctime_ns"] += 7
                                if operation["operation"] != "symlink_hardlink": operation["entries"][path]["before"]["ctime_ns"] += 7
                with self.subTest(mutation=mutation), self.assertRaises((proof_io.ReceiptError, RuntimeError)):
                    validate(forged)

    def test_genuine_normalization_rejects_missing_authority_and_local_chain_forgeries(self) -> None:
        from tools.gate01 import kernel_build, proof_io
        import copy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            expected = self._normalization_groups(root, (False, False))
            actual, delta = oci_rootfs.normalize_vfs_materialization(root, expected)
            value = proof_io._json_safe(delta)
            anchor = proof_io._json_safe(actual.raw_entries["/"])
            kernel_build._validate_normalization_operations(value, anchor, final_raw_sha256=proof_io._object_sha256(actual.raw_entries), final_entry_count=len(actual.raw_entries))
            for mutation in ("representatives", "parents", "not-present", "local-chain"):
                forged = copy.deepcopy(value)
                if mutation == "not-present":
                    for repair in forged["hardlinks"]: repair["representative"] = "/not-present"
                else:
                    for operation in forged["raw_operations"]:
                        for path in tuple(operation["entries"]):
                            if mutation == "representatives" and path in {repair["representative"] for repair in forged["hardlinks"]}:
                                del operation["entries"][path]
                            elif mutation == "parents" and operation["operation"] == "symlink_hardlink" and path in {"/0", "/1"}:
                                del operation["entries"][path]
                            elif mutation == "local-chain" and path == "/0":
                                change = operation["entries"][path]
                                change["result"]["ctime_ns"] += 7
                                if operation["operation"] != "symlink_hardlink": change["before"]["ctime_ns"] += 7
                with self.subTest(mutation=mutation), self.assertRaises((proof_io.ReceiptError, RuntimeError)):
                    kernel_build._validate_normalization_operations(forged, anchor, final_raw_sha256=proof_io._object_sha256(actual.raw_entries), final_entry_count=len(actual.raw_entries))

    def test_directory_mtime_child_events_are_accounted_at_each_watched_parent(self) -> None:
        for nested_watch in (False, True):
            with self.subTest(nested_watch=nested_watch), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                (root / "child/grandchild").mkdir(parents=True)
                for parent in (root, root / "child") if nested_watch else (root,):
                    for name in ("one", "two"):
                        (parent / name).symlink_to("target")
                        os.utime(parent / name, ns=(1_000_000_000, 1_000_000_000), follow_symlinks=False)
                before = oci_rootfs.audit_rootfs(root)
                entries = {path: replace(entry, mtime_ns=1_000_000_000) if entry.kind == "directory" else replace(entry, hardlink_group=str(Path(path).parent / "one")) for path, entry in before.entries.items()}
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                baseline = len(os.listdir("/proc/self/fd"))
                actual, _ = oci_rootfs.normalize_vfs_materialization(root, expected)
                oci_rootfs.assert_semantic_equal(expected, actual)
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_repair_watch_fails_closed_on_allocation_read_loss_and_event_forgery(self) -> None:
        for fault in ("allocate", "register", "read", "lost", "overflow", "ignored", "malformed", "unknown-mask", "unrelated-name", "cookie", "coalesced"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                expected = self._normalization_groups(root, (False, False))
                original_open, original_read = oci_rootfs._open_repair_watch, os.read
                watch = -1
                injected = False
                def opening():
                    nonlocal watch, injected
                    if fault == "allocate":
                        injected = True
                        raise OSError(errno.EMFILE, "injected watch allocation")
                    watch = original_open()
                    return watch
                def reading(fd, size):
                    nonlocal injected
                    if fd != watch or injected: return original_read(fd, size)
                    if fault == "read":
                        injected = True
                        raise OSError(errno.EIO, "injected watch read")
                    data = original_read(fd, size)
                    if not data: return data
                    number, mask, cookie, length = struct.unpack_from("=iIII", data)
                    if fault in {"cookie", "coalesced"} and mask != 0x40: return data
                    injected = True
                    if fault == "lost": return b""
                    if fault == "overflow": return struct.pack("=iIII", -1, 0x4000, 0, 0)
                    if fault == "ignored": return struct.pack("=iIII", number, 0x8000, 0, 0)
                    if fault == "malformed": return data[:-1]
                    if fault == "unknown-mask": return struct.pack("=iIII", number, mask | 1, cookie, length) + data[16:]
                    if fault == "unrelated-name": return data[:16] + b"x" + data[17:]
                    if fault == "cookie": return struct.pack("=iIII", number, mask, cookie + 9, length) + data[16:]
                    if fault == "coalesced": return data[:16 + length]
                    return data
                baseline = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(oci_rootfs, "_open_repair_watch", side_effect=opening), mock.patch.object(oci_rootfs.os, "read", side_effect=reading):
                    if fault == "register":
                        with mock.patch.object(oci_rootfs, "_add_repair_watch", side_effect=OSError(errno.ENOSPC, "injected watch registration")):
                            with self.assertRaises(OSError): oci_rootfs.normalize_vfs_materialization(root, expected)
                        injected = True
                    else:
                        with self.assertRaises((OSError, oci_rootfs.OciRootfsError)):
                            oci_rootfs.normalize_vfs_materialization(root, expected)
                self.assertTrue(injected)
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                self.assertFalse(any(path.name.startswith(".openmythos-hardlink-") for path in root.rglob("*")))

    def test_real_repair_watch_profile_has_exact_names_masks_and_cookie_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            expected = self._normalization_groups(root, (False,))
            read = oci_rootfs._read_repair_watch
            batches = []
            def reading(fd):
                events = read(fd)
                if events: batches.append(events)
                return events
            baseline = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(oci_rootfs, "_read_repair_watch", side_effect=reading):
                actual, _ = oci_rootfs.normalize_vfs_materialization(root, expected)
            self.assertEqual(oci_rootfs._REPAIR_WATCH_PROFILE, "linux-inotify-fanotify-vfs-normalization-v3")
            self.assertEqual([[event[1] for event in batch] for batch in batches], [[0x4, 0x100], [0x40, 0x80, 0x800, 0x40, 0x80, 0x800], [0x4, 0x200], [0x8000], [0x40000004, 0x40000004], [0x40000004, 0x40000004]])
            temporary = batches[0][1][3]
            self.assertRegex(temporary, rb"^\.openmythos-hardlink-[0-9a-f]{32}$")
            self.assertEqual([event[3] for event in batches[1]], [temporary, b"two", b"", b"two", temporary, b""])
            self.assertEqual(batches[1][0][2], batches[1][1][2])
            self.assertEqual(batches[1][3][2], batches[1][4][2])
            self.assertNotEqual(batches[1][0][2], batches[1][3][2])
            self.assertEqual(batches[2][1][3], temporary)
            oci_rootfs.assert_semantic_equal(expected, actual)
            self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_repair_parent_watch_rejects_unrelated_transient_mutations(self) -> None:
        for count in (1, 3):
            for mutation in ("chmod-restore", "child-create-remove"):
                with self.subTest(count=count, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "root"
                    parent = root / "group"
                    parent.mkdir(parents=True)
                    for index in range(count):
                        for suffix in ("a", "b"):
                            path = parent / f"{index}-{suffix}"
                            path.symlink_to("target")
                            os.utime(path, ns=(1_000_000_000, 1_000_000_000), follow_symlinks=False)
                    baseline = oci_rootfs.audit_rootfs(root)
                    entries = {path: replace(entry, hardlink_group=path[:-1] + "a") if entry.kind == "symlink" else entry for path, entry in baseline.entries.items()}
                    expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                    original = oci_rootfs._run_normalization_syscall
                    injected = False
                    def linking(operation, arguments):
                        nonlocal injected
                        original(operation, arguments)
                        if not injected and operation == "link":
                            injected = True
                            if mutation == "chmod-restore":
                                mode = parent.stat().st_mode & 0o7777
                                parent.chmod(mode ^ 0o010)
                                parent.chmod(mode)
                            else:
                                extra = parent / "unrelated"
                                extra.write_bytes(b"transient")
                                extra.unlink()
                    count_before = len(os.listdir("/proc/self/fd"))
                    with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=linking):
                        with self.assertRaises(oci_rootfs.OciRootfsError):
                            oci_rootfs.normalize_vfs_materialization(root, expected)
                    self.assertTrue(injected)
                    self.assertFalse(any(path.name.startswith(".openmythos-hardlink-") for path in parent.iterdir()))
                    self.assertEqual(len(os.listdir("/proc/self/fd")), count_before)

    def test_partially_linked_symlink_classes_repair_with_exact_remaining_aliases(self) -> None:
        for classes in ((('a',), ('b', 'c')), (('a', 'b'), ('c',)), (('a', 'b'), ('c', 'd'))):
            with self.subTest(classes=classes), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                for names in classes:
                    (root / names[0]).symlink_to("target")
                    os.utime(root / names[0], ns=(1_000_000_000, 1_000_000_000), follow_symlinks=False)
                    for name in names[1:]: os.link(root / names[0], root / name, follow_symlinks=False)
                initial = oci_rootfs.audit_rootfs(root)
                entries = {path: replace(entry, hardlink_group="/a") if entry.kind == "symlink" else entry for path, entry in initial.entries.items()}
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                baseline = len(os.listdir("/proc/self/fd"))
                actual, delta = oci_rootfs.normalize_vfs_materialization(root, expected)
                oci_rootfs.assert_semantic_equal(expected, actual)
                count = sum(map(len, classes))
                self.assertEqual({(record.ino, record.nlink) for path, record in actual.raw_entries.items() if path != "/"}, {(initial.raw_entries["/a"].ino, count)})
                self.assertEqual(len(delta["hardlinks"]), len(classes[1]))
                from tools.gate01 import kernel_build, proof_io
                kernel_build._validate_normalization_operations(proof_io._json_safe(delta), proof_io._json_safe(actual.raw_entries["/"]), final_raw_sha256=proof_io._object_sha256(actual.raw_entries), final_entry_count=len(actual.raw_entries))
                self.assertEqual(set(os.listdir(root)), {name for names in classes for name in names})
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_real_normalization_delta_validates_and_rejects_rehashed_operation_forgery(self) -> None:
        from tools.gate01 import kernel_build, proof_io
        import copy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            expected = self._normalization_groups(root, (False, False))
            normalized, delta = oci_rootfs.normalize_vfs_materialization(root, expected)
            value = proof_io._json_safe(delta)
            anchor = proof_io._json_safe(normalized.raw_entries["/"])
            self.assertTrue(value["raw_operations"])
            kernel_build._validate_normalization_operations(value, anchor, final_raw_sha256=proof_io._object_sha256(normalized.raw_entries), final_entry_count=len(normalized.raw_entries))
            for mutation in ("missing", "extra-field", "wrong-kind", "unrelated-inode", "ctime-only", "wrong-from-mtime", "duplicate", "reordered", "extra-directory-field", "missing-member", "wrong-alias", "wrong-original", "noop"):
                forged = copy.deepcopy(value)
                if mutation == "missing": forged["raw_operations"].pop(0)
                elif mutation == "extra-field": forged["raw_operations"][0]["unexpected"] = True
                elif mutation == "wrong-kind": forged["raw_operations"][0]["operation"] = "arbitrary"
                elif mutation == "duplicate": forged["raw_operations"].append(copy.deepcopy(forged["raw_operations"][0]))
                elif mutation == "reordered": forged["raw_operations"].reverse()
                elif mutation == "extra-directory-field": next(iter(forged["directory_mtimes"].values()))["extra"] = True
                elif mutation == "missing-member": next(iter(forged["repair_groups"].values())).pop()
                elif mutation == "wrong-alias": forged["hardlinks"][0]["displaced"]["aliases_before"] = ["/not-present"]
                elif mutation == "wrong-original": next(iter(forged["raw_operations"][0]["entries"].values()))["before"]["ctime_ns"] += 1
                elif mutation == "noop":
                    row = next(iter(forged["raw_operations"][0]["entries"].values()))
                    row["result"] = copy.deepcopy(row["before"])
                elif mutation == "unrelated-inode":
                    operation = forged["raw_operations"][0]
                    alias = next(path for path in operation["entries"] if path.endswith("/one"))
                    operation["entries"][alias]["result"]["ino"] += 1
                else:
                    operation = next(item for item in forged["raw_operations"] if item["operation"] == "directory_mtime")
                    path, change = next(iter(operation["entries"].items()))
                    if mutation == "ctime-only":
                        change["before"]["mtime_ns"] = change["result"]["mtime_ns"]
                        forged["directory_mtimes"][path]["from_mtime_ns"] = change["result"]["mtime_ns"]
                    else: forged["directory_mtimes"][path]["from_mtime_ns"] += 1
                with self.subTest(mutation=mutation), self.assertRaises((proof_io.ReceiptError, RuntimeError)):
                    kernel_build._validate_normalization_operations(forged, anchor, final_raw_sha256=proof_io._object_sha256(normalized.raw_entries), final_entry_count=len(normalized.raw_entries))

    def test_normalization_rejects_unrelated_changes_across_initial_root_reopen(self) -> None:
        for mutation in ("restore", "replace", "mode", "directory", "symlink", "xattr"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                target = root / "payload"
                target.write_bytes(b"original")
                (root / "directory").mkdir()
                (root / "link").symlink_to("payload")
                baseline = oci_rootfs.audit_rootfs(root)
                expected = oci_rootfs.OciRootfsManifest(baseline.entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                original = oci_rootfs._secure_open_root
                visits = 0
                def opening(value):
                    nonlocal visits
                    visits += 1
                    if visits == 2:
                        status = target.stat()
                        if mutation == "restore":
                            target.write_bytes(b"mutated!")
                            target.write_bytes(b"original")
                        elif mutation == "replace":
                            target.unlink()
                            target.write_bytes(b"original")
                        elif mutation == "mode":
                            target.chmod(0o777)
                            target.chmod(status.st_mode & 0o7777)
                        elif mutation == "directory":
                            directory_mode = (root / "directory").stat().st_mode & 0o7777
                            (root / "directory").chmod(0o777)
                            (root / "directory").chmod(directory_mode)
                        elif mutation == "symlink":
                            link_status = (root / "link").lstat()
                            (root / "link").unlink()
                            (root / "link").symlink_to("payload")
                            os.utime(root / "link", ns=(link_status.st_atime_ns, link_status.st_mtime_ns), follow_symlinks=False)
                        else:
                            os.setxattr(target, "user.test", b"changed")
                            os.removexattr(target, "user.test")
                        os.utime(target, ns=(status.st_atime_ns, status.st_mtime_ns))
                    return original(value)
                with mock.patch.object(oci_rootfs, "_secure_open_root", side_effect=opening):
                    with self.assertRaises(oci_rootfs.OciRootfsError):
                        oci_rootfs.normalize_vfs_materialization(root, expected)

    def test_noop_normalization_does_not_modify_correct_inode_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            (root / "runtime").write_bytes(b"public")
            before = oci_rootfs.audit_rootfs(root)
            expected = oci_rootfs.OciRootfsManifest(before.entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
            after, delta = oci_rootfs.normalize_vfs_materialization(root, expected, runtime_bind_targets=("/runtime",))
            self.assertEqual(before.raw_entries, after.raw_entries)
            self.assertEqual(delta["raw_operations"], ())

    def test_normalization_records_complete_raw_delta_and_rejects_adjacent_change(self) -> None:
        for adjacent in (False, True):
            with self.subTest(adjacent=adjacent), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                target = root / "payload"
                target.write_bytes(b"original")
                before = oci_rootfs.audit_rootfs(root)
                entries = dict(before.entries)
                entries["/"] = replace(entries["/"], mtime_ns=1_000_000_000)
                expected = oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())
                original = oci_rootfs._run_normalization_syscall
                def touching(operation, arguments):
                    original(operation, arguments)
                    if adjacent and operation == "utime":
                        status = target.stat()
                        target.write_bytes(b"mutated!")
                        target.write_bytes(b"original")
                        os.utime(target, ns=(status.st_atime_ns, status.st_mtime_ns))
                with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=touching):
                    if adjacent:
                        with self.assertRaises(oci_rootfs.OciRootfsError):
                            oci_rootfs.normalize_vfs_materialization(root, expected)
                    else:
                        actual, delta = oci_rootfs.normalize_vfs_materialization(root, expected)
                        self.assertIn("raw_operations", delta)
                        operation, = delta["raw_operations"]
                        self.assertEqual(operation["operation"], "directory_mtime")
                        self.assertEqual(set(operation["entries"]), {"/"})
                        self.assertEqual(operation["entries"]["/"]["before"], before.raw_entries["/"])
                        self.assertEqual(operation["entries"]["/"]["result"], actual.raw_entries["/"])

    def _normalization_groups(self, root, intact):
        for index, linked in enumerate(intact):
            directory = root / str(index)
            directory.mkdir(parents=True)
            (directory / "one").symlink_to("target")
            if linked:
                os.link(directory / "one", directory / "two", follow_symlinks=False)
            else:
                (directory / "two").symlink_to("target")
        baseline = oci_rootfs.audit_rootfs(root)
        entries = dict(baseline.entries)
        for index in range(len(intact)):
            for name in ("one", "two"):
                path = f"/{index}/{name}"
                entries[path] = replace(entries[path], hardlink_group=f"/{index}/one")
        return oci_rootfs.OciRootfsManifest(entries, "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, (), ())

    def test_intact_and_mixed_symlink_groups_release_each_descriptor_once(self) -> None:
        for intact in ((True,), (False, True)):
            with self.subTest(intact=intact), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                expected = self._normalization_groups(root, intact)
                baseline = len(os.listdir("/proc/self/fd"))
                try:
                    actual, _ = oci_rootfs.normalize_vfs_materialization(root, expected)
                except Exception as error:
                    self.fail(f"valid symlink normalization failed: {type(error).__name__}")
                oci_rootfs.assert_semantic_equal(expected, actual)
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_partial_symlink_plan_failure_releases_earlier_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            expected = self._normalization_groups(root, (False, False))
            original = oci_rootfs._hold_exact_symlink
            primary = ValueError("second pair failed")
            def holding(root_fd, path, observed):
                if path == "/1/two":
                    raise primary
                return original(root_fd, path, observed)
            baseline = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(oci_rootfs, "_hold_exact_symlink", side_effect=holding):
                with self.assertRaises(Exception) as caught:
                    oci_rootfs.normalize_vfs_materialization(root, expected)
            self.assertIs(caught.exception, primary)
            self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_repair_close_fault_releases_all_once_and_is_not_suppressed(self) -> None:
        for failed_index in (0, 2):
            with self.subTest(index=failed_index):
                descriptors = [os.open("/dev/null", os.O_RDONLY) for _ in range(4)]
                status = os.fstat(descriptors[0])
                repair = oci_rootfs._SymlinkHardlinkRepair("/a", "/b", *descriptors, status, status, "tmp")
                original = os.close
                attempted = []
                def closing(fd):
                    attempted.append(fd)
                    original(fd)
                    if fd == descriptors[failed_index]:
                        raise OSError(errno.EIO, "injected post-close error")
                with mock.patch.object(oci_rootfs.os, "close", side_effect=closing):
                    with self.assertRaises(Exception):
                        repair.close()
                    repair.close()
                self.assertCountEqual(attempted, descriptors)

    def test_repair_cleanup_retains_failed_material_custody_until_retry(self) -> None:
        for operation in ("stat", "unlink"):
            for failed_group in (0, 1):
                with self.subTest(operation=operation, group=failed_group), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "root"
                    self._normalization_groups(root, (False, False, False))
                    observed = oci_rootfs.audit_rootfs(root)
                    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    baseline = len(os.listdir("/proc/self/fd"))
                    repairs, plan = [], []
                    primary = MemoryError("injected repair cleanup observation")
                    try:
                        for group in range(3):
                            source_parent, source_fd, source_status = oci_rootfs._hold_exact_symlink(root_fd, f"/{group}/one", observed)
                            target_parent, target_fd, target_status = oci_rootfs._hold_exact_symlink(root_fd, f"/{group}/two", observed)
                            name = f".openmythos-hardlink-test-{group}"
                            os.link("one", name, src_dir_fd=source_parent, dst_dir_fd=target_parent, follow_symlinks=False)
                            repair = oci_rootfs._SymlinkHardlinkRepair(f"/{group}/one", f"/{group}/two", source_parent, target_parent, source_fd, target_fd, source_status, target_status, name, True)
                            repairs.append(repair)
                            plan.append(repair)
                        original = getattr(os, operation)
                        def failing(name, *args, **kwargs):
                            if name == repairs[failed_group].temporary_name:
                                raise primary
                            return original(name, *args, **kwargs)
                        with mock.patch.object(os, operation, side_effect=failing):
                            with self.assertRaises(RuntimeError) as caught:
                                oci_rootfs._cleanup_repair_plan(plan)
                        self.assertIs(caught.exception.__cause__, primary)
                        self.assertEqual([item for item in plan if item is not None], [repairs[failed_group]])
                        self.assertTrue(repairs[failed_group].temporary_created)
                        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline + 4)
                        for group, repair in enumerate(repairs):
                            self.assertEqual(os.path.lexists(root / str(group) / repair.temporary_name), group == failed_group)
                        oci_rootfs._cleanup_repair_plan(plan)
                        self.assertEqual(plan, [])
                        self.assertFalse(repairs[failed_group].temporary_created)
                        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                        self.assertFalse(any(root.rglob(".openmythos-hardlink-*")))
                    finally:
                        for repair in repairs: repair.close()
                        os.close(root_fd)

    def test_repair_cleanup_actual_caller_retries_then_releases_persistent_failure(self) -> None:
        for operation in ("stat", "unlink"):
            for persistent in (False, True):
                for failed_group in ("0", "1"):
                    with self.subTest(operation=operation, persistent=persistent, group=failed_group), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary) / "root"
                        expected = self._normalization_groups(root, (False, False, False))
                        primary = ValueError("injected hardlink exchange failure")
                        original_syscall = oci_rootfs._run_normalization_syscall
                        original = getattr(os, operation)
                        attempts = []
                        interrupted = False
                        def syscall(kind, arguments):
                            nonlocal interrupted
                            if kind == "exchange":
                                interrupted = True
                                raise primary
                            return original_syscall(kind, arguments)
                        def failing(name, *args, **kwargs):
                            if interrupted and str(name).startswith(".openmythos-hardlink-"):
                                group = Path(os.readlink(f"/proc/self/fd/{kwargs['dir_fd']}")).name
                                attempts.append(group)
                                if group == failed_group and (persistent or attempts.count(group) == 1):
                                    raise MemoryError("injected material cleanup failure")
                            return original(name, *args, **kwargs)
                        baseline = len(os.listdir("/proc/self/fd"))
                        with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=syscall), mock.patch.object(os, operation, side_effect=failing):
                            with self.assertRaises(ValueError) as caught:
                                oci_rootfs.normalize_vfs_materialization(root, expected)
                        self.assertIs(caught.exception, primary)
                        self.assertEqual(attempts, ["0", "1", "2", failed_group])
                        self.assertEqual(primary.__notes__, ["additional bound descriptor cleanup failed"] * (2 if persistent else 1))
                        self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)
                        self.assertEqual(len(list(root.rglob(".openmythos-hardlink-*"))), int(persistent))

    def test_repair_cleanup_unlink_failure_attempts_every_plan(self) -> None:
        for failed_group in ("0", "1"):
            with self.subTest(group=failed_group), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                expected = self._normalization_groups(root, (False, False, False))
                original_unlink = os.unlink
                original_close = oci_rootfs._SymlinkHardlinkRepair.close
                attempts = []
                released = []
                primary = ValueError("execution interrupted")
                original_syscall = oci_rootfs._run_normalization_syscall
                def syscall(operation, arguments):
                    if operation == "exchange": raise primary
                    return original_syscall(operation, arguments)
                def unlinking(name, *, dir_fd=None):
                    if str(name).startswith(".openmythos-hardlink-"):
                        group = Path(os.readlink(f"/proc/self/fd/{dir_fd}")).name
                        attempts.append(group)
                        if group == failed_group:
                            raise OSError(errno.EIO, "unlink failure")
                    return original_unlink(name, dir_fd=dir_fd)
                def closing(repair):
                    released.append(repair.target)
                    original_close(repair)
                baseline = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(oci_rootfs, "_run_normalization_syscall", side_effect=syscall), mock.patch.object(oci_rootfs.os, "unlink", side_effect=unlinking), mock.patch.object(oci_rootfs._SymlinkHardlinkRepair, "close", new=closing):
                    with self.assertRaises(Exception) as caught:
                        oci_rootfs.normalize_vfs_materialization(root, expected)
                self.assertIs(caught.exception, primary)
                self.assertEqual(attempts, ["0", "1", "2", failed_group])
                # The failed material owner reaches the terminal direct-FD
                # fallback; successful siblings use their ordinary close.
                self.assertCountEqual(released, [f"/{group}/two" for group in ("0", "1", "2") if group != failed_group])
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_audit_root_release_attempts_both_and_preserves_primary(self) -> None:
        for primary in (None, ValueError("original audit failure")):
            with self.subTest(primary=primary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                original_open = oci_rootfs._secure_open_root
                original_close = os.close
                held = []
                attempted = []
                def opening(value):
                    result = original_open(value)
                    held.extend(result[:2])
                    return result
                def closing(fd):
                    original_close(fd)
                    if fd in held:
                        attempted.append(fd)
                        raise OSError(errno.EIO, "injected post-close failure")
                baseline = len(os.listdir("/proc/self/fd"))
                patches = [mock.patch.object(oci_rootfs, "_secure_open_root", side_effect=opening),
                           mock.patch.object(oci_rootfs.os, "close", side_effect=closing)]
                with patches[0], patches[1]:
                    if primary is None:
                        with self.assertRaises(Exception):
                            oci_rootfs.audit_rootfs(root)
                    else:
                        with mock.patch.object(oci_rootfs, "_scan_once", side_effect=primary):
                            with self.assertRaises(Exception) as caught:
                                oci_rootfs.audit_rootfs(root)
                        self.assertIs(caught.exception, primary)
                        self.assertTrue(primary.__notes__)
                self.assertCountEqual(attempted, held)
                self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_terminal_sweep_rejects_earlier_leaf_change_in_second_hash_pass(self) -> None:
        for restore in (False, True):
            with self.subTest(restore=restore), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                early = root / "a"
                early.write_bytes(b"original")
                (root / "z").write_bytes(b"lastfile")
                before = early.stat()
                visits = 0
                original = oci_rootfs._hash_open_file
                def hashing(fd, size, path):
                    nonlocal visits
                    if path == "/z":
                        visits += 1
                        if visits == 2:
                            early.write_bytes(b"mutated!")
                            if restore:
                                early.write_bytes(b"original")
                                os.utime(early, ns=(before.st_atime_ns, before.st_mtime_ns))
                    return original(fd, size, path)
                with mock.patch.object(oci_rootfs, "_hash_open_file", side_effect=hashing):
                    with self.assertRaises(oci_rootfs.OciRootfsError):
                        oci_rootfs.audit_rootfs(root)
                self.assertEqual(visits, 2)

    def test_terminal_audit_failure_blocks_authorized_and_post_stop_consumers(self) -> None:
        from tools.gate01.container_runtime import ContainerLifecycleError, run_container_lifecycle
        for failing_phase in ("authorized", "after"):
            with self.subTest(phase=failing_phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                early = root / "a"
                early.write_bytes(b"original")
                (root / "z").write_bytes(b"lastfile")
                events = []
                class Backend:
                    def create(self): events.append("create")
                    def initialize(self): pass
                    def audit_effective_spec(self): pass
                    def start(self): pass
                    def attest_live(self): pass
                    def authorize_work(self): events.append("authorize")
                    def execute(self, role, descriptors): events.append("execute")
                    def stop_and_wait(self): events.append("stop")
                    def remove(self): events.append("remove")
                    def audit_rootfs(self, phase):
                        visits = 0
                        before = early.stat()
                        original = oci_rootfs._hash_open_file
                        def hashing(fd, size, path):
                            nonlocal visits
                            if path == "/z":
                                visits += 1
                                if phase == failing_phase and visits == 2:
                                    early.write_bytes(b"mutated!")
                                    early.write_bytes(b"original")
                                    os.utime(early, ns=(before.st_atime_ns, before.st_mtime_ns))
                            return original(fd, size, path)
                        with mock.patch.object(oci_rootfs, "_hash_open_file", side_effect=hashing):
                            oci_rootfs.audit_rootfs(root)
                        return {"semantic_sha256": "a" * 64, "raw_sha256": "b" * 64,
                                "non_root_entry_count": 2, "root_entry": {"path": "/"}}
                with self.assertRaisesRegex(oci_rootfs.OciRootfsError, "terminal sweep"):
                    run_container_lifecycle(Backend(), executions=(("probe", {}),), allow_key_role=None)
                self.assertEqual(events[-1], "remove")
                self.assertEqual("execute" in events, failing_phase == "after")

    def test_stable_wide_tree_audit_has_depth_bounded_descriptor_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            for index in range(12):
                directory = root / str(index)
                directory.mkdir()
                for leaf in range(40):
                    (directory / str(leaf)).write_bytes(b"stable")
            baseline = len(os.listdir("/proc/self/fd"))
            peak = baseline
            original = oci_rootfs.os.open
            def opening(*args, **kwargs):
                nonlocal peak
                result = original(*args, **kwargs)
                peak = max(peak, len(os.listdir("/proc/self/fd")))
                return result
            with mock.patch.object(oci_rootfs.os, "open", side_effect=opening):
                audit = oci_rootfs.audit_rootfs(root)
            self.assertEqual(len(audit.entries), 493)
            self.assertLessEqual(peak - baseline, 10)
            self.assertEqual(len(os.listdir("/proc/self/fd")), baseline)

    def test_symlink_hardlink_normalization_detects_last_instant_name_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            links = root / "links"
            links.mkdir(parents=True)
            one = links / "one"
            two = links / "two"
            one.symlink_to("target")
            os.link(one, two, follow_symlinks=False)
            timestamp = 1_000_000_000
            os.utime(one, ns=(timestamp, timestamp), follow_symlinks=False)
            os.utime(links, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))
            audited = oci_rootfs.audit_rootfs(root)
            expected = oci_rootfs.OciRootfsManifest(
                entries=audited.entries,
                archive_sha256="a" * 64,
                manifest_digest="sha256:" + "b" * 64,
                config_digest="sha256:" + "c" * 64,
                layer_digests=(),
                diff_ids=(),
            )
            two.unlink()
            two.symlink_to("target")
            os.utime(two, ns=(timestamp, timestamp), follow_symlinks=False)
            os.utime(links, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))

            real_exchange = oci_rootfs._run_normalization_syscall
            injected = False

            def swap_then_exchange(operation, arguments) -> None:
                nonlocal injected
                if not injected and operation == "exchange":
                    injected = True
                    old_parent, old_name, new_parent, new_name = arguments
                    os.unlink(new_name, dir_fd=new_parent)
                    os.symlink("target", new_name, dir_fd=new_parent)
                    os.utime(
                        new_name,
                        ns=(timestamp, timestamp),
                        dir_fd=new_parent,
                        follow_symlinks=False,
                    )
                real_exchange(operation, arguments)

            with mock.patch.object(
                oci_rootfs, "_run_normalization_syscall", side_effect=swap_then_exchange
            ):
                with self.assertRaisesRegex(
                oci_rootfs.OciRootfsError, "changed during hardlink repair|repair parent exchange|inode event"
                ):
                    oci_rootfs.normalize_vfs_materialization(root, expected)

    def test_audit_rejects_hardlink_aliases_outside_the_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            root.mkdir()
            inside = root / "payload"
            inside.write_bytes(b"payload")
            os.link(inside, Path(temporary) / "outside-alias")
            with self.assertRaisesRegex(
                oci_rootfs.OciRootfsError, "hardlink count"
            ):
                oci_rootfs.audit_rootfs(root)

    def test_vfs_normalizer_never_repairs_regular_hardlinks_or_cross_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            root.mkdir()
            first = root / "first"
            second = root / "second"
            first.write_bytes(b"same")
            os.chmod(first, 0o644)
            os.link(first, second)
            timestamp = 1_000_000_000
            os.utime(first, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))
            audited = oci_rootfs.audit_rootfs(root)
            expected = oci_rootfs.OciRootfsManifest(
                entries=audited.entries,
                archive_sha256="a" * 64,
                manifest_digest="sha256:" + "b" * 64,
                config_digest="sha256:" + "c" * 64,
                layer_digests=(),
                diff_ids=(),
            )
            second.unlink()
            second.write_bytes(b"same")
            os.chmod(second, 0o644)
            os.utime(second, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))
            with self.assertRaisesRegex(
                oci_rootfs.RootfsMismatchError, "regular hardlink"
            ):
                oci_rootfs.normalize_vfs_materialization(root, expected)

            # Two expected groups must not be accepted when the materialized
            # tree cross-links them into one inode, even transiently.
            third = root / "third"
            fourth = root / "fourth"
            third.write_bytes(b"same")
            os.chmod(third, 0o644)
            os.link(third, fourth)
            os.utime(third, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))
            cross_audit = oci_rootfs.audit_rootfs(root)
            cross_expected = oci_rootfs.OciRootfsManifest(
                entries=cross_audit.entries,
                archive_sha256="a" * 64,
                manifest_digest="sha256:" + "b" * 64,
                config_digest="sha256:" + "c" * 64,
                layer_digests=(),
                diff_ids=(),
            )
            # Restore the first pair, then link the two distinct expected
            # groups together through one inode.
            second.unlink()
            os.link(first, second)
            fourth.unlink()
            os.link(first, fourth)
            third.unlink()
            os.link(first, third)
            os.utime(root, ns=(timestamp, timestamp))
            with self.assertRaisesRegex(
                oci_rootfs.RootfsMismatchError, "cross-linked"
            ):
                oci_rootfs.normalize_vfs_materialization(root, cross_expected)

    def test_runtime_bind_projection_is_exact_and_descriptor_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / "rootfs"
            run = root / "run"
            run.mkdir(parents=True)
            timestamp = 1_000_000_000
            os.chmod(root, 0o755)
            os.chmod(run, 0o755)
            os.utime(run, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))
            base = oci_rootfs.audit_rootfs(root)
            expected = oci_rootfs.OciRootfsManifest(
                entries=base.entries,
                archive_sha256="a" * 64,
                manifest_digest="sha256:" + "b" * 64,
                config_digest="sha256:" + "c" * 64,
                layer_digests=(),
                diff_ids=(),
            )
            source = directory / ".containerenv"
            source.write_bytes(b"engine=podman\n")
            os.chmod(source, 0o444)
            os.utime(source, ns=(timestamp, timestamp))
            descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                projected = oci_rootfs.project_runtime_bind_file(
                    expected,
                    descriptor,
                    target="/run/.containerenv",
                )
                (run / ".containerenv").write_bytes(source.read_bytes())
                os.chmod(run / ".containerenv", 0o444)
                os.utime(run / ".containerenv", ns=(timestamp, timestamp))
                os.utime(run, ns=(timestamp, timestamp))
                actual = oci_rootfs.audit_rootfs(root)
                oci_rootfs.assert_semantic_equal(projected, actual)

                (run / ".containerenv").unlink()
                (run / ".containerenv").write_bytes(b"forged\n")
                os.chmod(run / ".containerenv", 0o444)
                os.utime(run / ".containerenv", ns=(timestamp, timestamp))
                os.utime(run, ns=(timestamp, timestamp))
                tampered = oci_rootfs.audit_rootfs(root)
                with self.assertRaisesRegex(
                    oci_rootfs.RootfsMismatchError, "/run/.containerenv"
                ):
                    oci_rootfs.assert_semantic_equal(projected, tampered)
            finally:
                os.close(descriptor)

    def test_vfs_normalization_repairs_only_directory_mtime_and_expected_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            links = root / "links"
            links.mkdir(parents=True)
            runtime_file = root / "runtime"
            runtime_file.write_bytes(b"")
            os.chmod(runtime_file, 0o644)
            os.symlink("target", links / "one")
            os.link(
                links / "one",
                links / "two",
                follow_symlinks=False,
            )
            timestamp = 1_000_000_000
            os.utime(links / "one", ns=(timestamp, timestamp), follow_symlinks=False)
            os.utime(runtime_file, ns=(timestamp, timestamp))
            os.utime(links, ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))
            expected_audit = oci_rootfs.audit_rootfs(root)
            expected = oci_rootfs.OciRootfsManifest(
                entries=expected_audit.entries,
                archive_sha256="a" * 64,
                manifest_digest="sha256:" + "b" * 64,
                config_digest="sha256:" + "c" * 64,
                layer_digests=(),
                diff_ids=(),
            )

            (links / "two").unlink()
            os.symlink("target", links / "two")
            os.utime(links / "two", ns=(timestamp, timestamp), follow_symlinks=False)
            os.chmod(runtime_file, 0o700)
            os.utime(runtime_file, ns=(timestamp + 7, timestamp + 7))
            os.utime(links, ns=(timestamp + 9, timestamp + 9))
            os.utime(root, ns=(timestamp + 8, timestamp + 8))
            normalized, normalization = oci_rootfs.normalize_vfs_materialization(
                root, expected, runtime_bind_targets=("/runtime",)
            )
            oci_rootfs.assert_semantic_equal(expected, normalized)
            from tools.gate01 import kernel_build, proof_io
            kernel_build._validate_normalization_operations(proof_io._json_safe(normalization), proof_io._json_safe(normalized.raw_entries["/"]), final_raw_sha256=proof_io._object_sha256(normalized.raw_entries), final_entry_count=len(normalized.raw_entries))
            self.assertEqual(
                set(normalization["directory_mtimes"]), {"/", "/links"}
            )
            self.assertEqual(len(normalization["hardlinks"]), 1)
            hardlink_evidence = normalization["hardlinks"][0]
            self.assertEqual(
                {
                    key: hardlink_evidence[key]
                    for key in ("field", "path", "representative")
                },
                {
                    "field": "hardlink_group",
                    "path": "/links/two",
                    "representative": "/links/one",
                },
            )
            self.assertEqual(hardlink_evidence["before"]["nlink"], 1)
            self.assertEqual(hardlink_evidence["result"]["nlink"], 2)
            self.assertNotEqual(
                hardlink_evidence["before"]["ino"],
                hardlink_evidence["result"]["ino"],
            )
            self.assertEqual(
                normalization["runtime_bind_targets"],
                {
                    "/runtime": {
                        "from_mode": 0o700,
                        "from_mtime_ns": timestamp + 7,
                        "to_mode": 0o644,
                        "to_mtime_ns": timestamp,
                    }
                },
            )
            self.assertEqual(
                normalized.raw_entries["/links/one"].ino,
                normalized.raw_entries["/links/two"].ino,
            )

            (links / "two").unlink()
            os.symlink("forged", links / "two")
            with self.assertRaisesRegex(
                oci_rootfs.RootfsMismatchError, "non-normalizable"
            ):
                oci_rootfs.normalize_vfs_materialization(
                    root, expected, runtime_bind_targets=("/runtime",)
                )

    def test_audit_and_oci_semantics_match_with_projected_ownership(self) -> None:
        proof_name, proof_value = _libarchive_xattr("user.proof", b"\x00proof")
        layer = [
            _tar_info(".", kind="dir", mode=0o755),
            _tar_info("bin", kind="dir", mode=0o755),
            _tar_info(
                "bin/alias", kind="hardlink", linkname="bin/tool", mode=0o755
            ),
            _tar_info(
                "bin/tool",
                data=b"tool\n",
                mode=0o755,
                pax_headers={proof_name: proof_value},
            ),
            _tar_info("bin/current", kind="symlink", linkname="tool"),
        ]
        archive, manifest_digest = _oci_archive([layer])

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive_dir = directory / "archive"
            archive_dir.mkdir()
            expected = _canonicalize(archive_dir, archive, manifest_digest)
            root = directory / "rootfs"
            (root / "bin").mkdir(parents=True)
            tool = root / "bin/tool"
            tool.write_bytes(b"tool\n")
            os.chmod(tool, 0o755)
            os.setxattr(tool, "user.proof", b"\x00proof")
            os.link(tool, root / "bin/alias")
            os.symlink("tool", root / "bin/current")
            timestamp = 1_000_000_000
            os.utime(tool, ns=(timestamp, timestamp))
            os.utime(
                root / "bin/current",
                ns=(timestamp, timestamp),
                follow_symlinks=False,
            )
            os.chmod(root / "bin", 0o755)
            os.chmod(root, 0o755)
            os.utime(root / "bin", ns=(timestamp, timestamp))
            os.utime(root, ns=(timestamp, timestamp))

            projection = oci_rootfs.OwnershipProjection.single_user_namespace(
                outside_uid=os.getuid(), outside_gid=os.getgid()
            )
            actual = oci_rootfs.audit_rootfs(root, projection=projection)
            oci_rootfs.assert_semantic_equal(expected, actual)
            unchanged = oci_rootfs.audit_rootfs(root, projection=projection)
            oci_rootfs.assert_audits_equal(actual, unchanged)

            self.assertEqual(actual.before_anchor, actual.after_anchor)
            self.assertEqual(actual.raw_entries["/bin/tool"].nlink, 2)
            self.assertEqual(
                actual.raw_entries["/bin/tool"].ino,
                actual.raw_entries["/bin/alias"].ino,
            )
            tool.write_bytes(b"tampered\n")
            tampered = oci_rootfs.audit_rootfs(root, projection=projection)
            with self.assertRaisesRegex(oci_rootfs.RootfsMismatchError, "/bin"):
                oci_rootfs.assert_semantic_equal(expected, tampered)
            with self.assertRaisesRegex(oci_rootfs.RootfsMismatchError, "audit"):
                oci_rootfs.assert_audits_equal(actual, tampered)

    def test_actual_walk_never_double_counts_directories_like_146278_vs_138619(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            (root / "a").mkdir(parents=True)
            (root / "b").mkdir()
            (root / "a/one").write_bytes(b"1")
            (root / "b/two").write_bytes(b"2")
            projection = oci_rootfs.OwnershipProjection.single_user_namespace(
                outside_uid=os.getuid(), outside_gid=os.getgid()
            )

            audit = oci_rootfs.audit_rootfs(root, projection=projection)

        self.assertEqual(
            set(audit.entries), {"/", "/a", "/a/one", "/b", "/b/two"}
        )
        self.assertEqual(len(audit.entries), 5)
        self.assertEqual(len(audit.raw_entries), 5)
        self.assertNotEqual(len(audit.entries), 7)  # old 5 + 2 directories bug

    def test_audit_rejects_symlink_root_and_unmapped_owners(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root = directory / "root"
            root.mkdir()
            (root / "file").write_bytes(b"value")
            link = directory / "link"
            link.symlink_to(root, target_is_directory=True)
            projection = oci_rootfs.OwnershipProjection(
                uid_ranges=(), gid_ranges=(), allow_identity=False
            )
            with self.assertRaisesRegex(oci_rootfs.OciRootfsError, "symlink"):
                oci_rootfs.audit_rootfs(link)
            with self.assertRaisesRegex(oci_rootfs.OciRootfsError, "unmapped uid"):
                oci_rootfs.audit_rootfs(root, projection=projection)


if __name__ == "__main__":
    unittest.main()
