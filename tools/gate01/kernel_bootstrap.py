"""Minimal stdlib-only clean-launch bootstrap for the Gate 01 supervisor.

Opening ``BOOTSTRAP_FD`` in the privileged-shell launcher is the clean-launch
TCB instant.  This module imports no repository package.  It binds the exact
named executable closure, proves that its own executing descriptor is that
bound source, and executes only a fully sealed deterministic ZIP authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
from typing import Callable
import zipfile


BOOTSTRAP_FD = 60
CAPSULE_FD = 61
AUTHORITY_FD = 62
BOOTSTRAP_SOURCE_PATHS = (
    "scripts/gate01/build-kernel.sh",
    "tools/__init__.py",
    "tools/gate01/__init__.py",
    "tools/gate01/container_runtime.py",
    "tools/gate01/inputs.py",
    "tools/gate01/kernel_bootstrap.py",
    "tools/gate01/kernel_build.py",
    "tools/gate01/kernel_config.py",
    "tools/gate01/module_key.py",
    "tools/gate01/oci_rootfs.py",
    "tools/gate01/proof_io.py",
    "tools/gate01/rpm_artifacts.py",
    "tools/gate01/toolchain.py",
)
_PYTHON_SOURCE_PATHS = tuple(
    path for path in BOOTSTRAP_SOURCE_PATHS if path.endswith(".py")
)
_SEALS = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)
_READ_CHUNK = 1024 * 1024


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    try:
        BaseException.add_note(primary, note)
    except BaseException:
        pass


def _close_descriptors(descriptors: tuple[int, ...]) -> None:
    failure = None
    index = 0
    while index < len(descriptors):
        descriptor = descriptors[index]
        index += 1
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise RuntimeError("bootstrap descriptor release failed") from failure


def _close_two(first: int, second: int = -1, *, primary: BaseException | None = None) -> None:
    failure = None
    while first >= 0 or second >= 0:
        if first >= 0:
            descriptor, first = first, -1
        else:
            descriptor, second = second, -1
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        if primary is None:
            raise RuntimeError("bootstrap descriptor release failed") from failure
        try:
            _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
        except BaseException:
            pass


def _close_preserving_primary(descriptors: tuple[int, ...], primary: BaseException | None) -> None:
    try:
        _close_descriptors(descriptors)
    except BaseException:
        if primary is None:
            raise
        try:
            _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
        except BaseException:
            pass


def _status_tuple(value: os.stat_result) -> tuple[int, ...]:
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


def _identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _read_stable(descriptor: int) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, _READ_CHUNK):
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if _status_tuple(before) != _status_tuple(after):
        raise RuntimeError("bootstrap closure changed while reading")
    return b"".join(chunks), after


def _open_parent(path: Path) -> tuple[int, os.stat_result]:
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        for component in path.parent.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            closing, descriptor = descriptor, child
            os.close(closing)
        return descriptor, os.fstat(descriptor)
    except BaseException as primary:
        closing, descriptor = descriptor, -1
        try:
            os.close(closing)
        except BaseException:
            try:
                _add_cleanup_note(primary, "additional bootstrap parent cleanup failed")
            except BaseException:
                pass
        raise


@dataclass
class _HeldSource:
    relative: str
    path: Path
    parent_fd: int
    parent_status: os.stat_result
    parent_listing: tuple[str, ...]
    fd: int
    status: os.stat_result
    content: bytes

    def verify(self) -> None:
        content, current = _read_stable(self.fd)
        try:
            named = os.stat(
                self.path.name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise RuntimeError("bootstrap closure changed after binding") from error
        if (
            content != self.content
            or _status_tuple(current) != _status_tuple(self.status)
            or _status_tuple(named) != _status_tuple(self.status)
            or _status_tuple(os.fstat(self.parent_fd))
            != _status_tuple(self.parent_status)
            or tuple(sorted(os.listdir(self.parent_fd))) != self.parent_listing
        ):
            raise RuntimeError("bootstrap closure changed after binding")
        reopened_parent, reopened_status = _open_parent(self.path)
        try:
            if _identity(reopened_status) != _identity(self.parent_status):
                raise RuntimeError("bootstrap closure parent path changed")
        finally:
            primary = sys.exception()
            closing, reopened_parent = reopened_parent, -1
            try:
                os.close(closing)
            except BaseException as error:
                if primary is None:
                    raise RuntimeError("bootstrap descriptor release failed") from error
                try:
                    _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
                except BaseException:
                    pass

    def close(self) -> None:
        first = self.fd
        second = self.parent_fd
        self.fd = self.parent_fd = -1
        _numeric_failure = None
        _numeric_fd = first
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = second
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bootstrap descriptor release failed") from _numeric_failure


@dataclass
class BootstrapCapsule:
    capsule_fd: int
    authority_fd: int
    capsule_sha256: str
    authority_sha256: str

    def close(self) -> None:
        first = self.capsule_fd
        second = self.authority_fd
        self.capsule_fd = self.authority_fd = -1
        _numeric_failure = None
        _numeric_fd = first
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        _numeric_fd = second
        if _numeric_fd >= 0:
            try:
                os.close(_numeric_fd)
            except BaseException as _numeric_error:
                if _numeric_failure is None:
                    _numeric_failure = _numeric_error
        if _numeric_failure is not None:
            raise RuntimeError("bootstrap descriptor release failed") from _numeric_failure


def _seal_bytes(name: str, value: bytes) -> tuple[int, str]:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("bootstrap sealed write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != len(value) or os.pread(descriptor, len(value), 0) != value:
            raise RuntimeError("bootstrap written public output differs")
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _SEALS)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & _SEALS != _SEALS:
            raise RuntimeError("bootstrap descriptor was not fully sealed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, hashlib.sha256(value).hexdigest()
    except BaseException as primary:
        closing, descriptor = descriptor, -1
        try:
            os.close(closing)
        except BaseException:
            try:
                _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
            except BaseException:
                pass
        raise


def _open_source(repository: Path, relative: str) -> _HeldSource:
    path = repository / relative
    parent_fd, parent_status = _open_parent(path)
    descriptor = -1
    try:
        parent_listing = tuple(sorted(os.listdir(parent_fd)))
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        expected_mode = 0o755 if relative == "scripts/gate01/build-kernel.sh" else 0o644
        if (
            not stat.S_ISREG(named.st_mode)
            or stat.S_IMODE(named.st_mode) != expected_mode
            or named.st_uid != os.geteuid()
            or named.st_gid != os.getegid()
            or named.st_nlink != 1
            or named.st_mode & 0o022
        ):
            raise RuntimeError("bootstrap closure metadata is unsafe")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if _status_tuple(named) != _status_tuple(opened):
            raise RuntimeError("bootstrap closure path changed while opening")
        content, current = _read_stable(descriptor)
        if _status_tuple(opened) != _status_tuple(current):
            raise RuntimeError("bootstrap closure changed while opening")
        result = _HeldSource(
            relative,
            path,
            parent_fd,
            parent_status,
            parent_listing,
            descriptor,
            current,
            content,
        )
        parent_fd = -1
        descriptor = -1
        return result
    finally:
        primary = sys.exception()
        failure = None
        while descriptor >= 0 or parent_fd >= 0:
            if descriptor >= 0:
                closing, descriptor = descriptor, -1
            else:
                closing, parent_fd = parent_fd, -1
            try:
                os.close(closing)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            if primary is None:
                raise failure
            try:
                _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
            except BaseException:
                pass


def _capsule_bytes(records: dict[str, _HeldSource]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        main = zipfile.ZipInfo("__main__.py", (2026, 1, 1, 0, 0, 0))
        main.create_system = 3
        main.external_attr = 0o100644 << 16
        archive.writestr(
            main,
            (
                "import runpy,sys\n"
                "if len(sys.argv) < 2: raise SystemExit('missing sealed entry')\n"
                "if sys.argv[1] == '--sealed-supervisor-entry':\n"
                " sys.argv.pop(1)\n"
                " from tools.gate01.kernel_build import sealed_main\n"
                " raise SystemExit(sealed_main())\n"
                "module=sys.argv.pop(1)\n"
                "runpy.run_module(module,run_name='__main__',alter_sys=True)\n"
            ).encode("ascii"),
        )
        for relative in _PYTHON_SOURCE_PATHS:
            info = zipfile.ZipInfo(relative, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, records[relative].content)
    return output.getvalue()


def build_bootstrap_capsule(
    repository: Path,
    inherited_descriptor: int,
    *,
    after_first_pass: Callable[[], None] | None = None,
) -> BootstrapCapsule:
    """Bind all executable sources and derive the only executable authority."""
    repository = Path(os.path.abspath(os.fspath(repository)))
    records: dict[str, _HeldSource] = {}
    capsule_fd = authority_fd = -1
    try:
        for relative in BOOTSTRAP_SOURCE_PATHS:
            record = _open_source(repository, relative)
            try:
                records[relative] = record
            except BaseException as primary:
                cleanup_failed = False
                try:
                    record.close()
                except BaseException:
                    cleanup_failed = True
                finally:
                    closing, record.fd = record.fd, -1
                    if closing >= 0:
                        try:
                            os.close(closing)
                        except BaseException:
                            cleanup_failed = True
                    closing, record.parent_fd = record.parent_fd, -1
                    if closing >= 0:
                        try:
                            os.close(closing)
                        except BaseException:
                            cleanup_failed = True
                if cleanup_failed:
                    try:
                        _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
                    except BaseException:
                        pass
                raise
        inherited_content, inherited_status = _read_stable(inherited_descriptor)
        bootstrap = records["tools/gate01/kernel_bootstrap.py"]
        if (
            inherited_content != bootstrap.content
            or _status_tuple(inherited_status) != _status_tuple(bootstrap.status)
        ):
            raise RuntimeError("executing bootstrap differs from bound named source")
        for record in records.values():
            record.verify()
        if after_first_pass is not None:
            after_first_pass()
        for record in records.values():
            record.verify()

        capsule_value = _capsule_bytes(records)
        capsule_fd, capsule_sha256 = _seal_bytes(
            "openmythos-kernel-supervisor", capsule_value
        )
        authority_value = {
            "bootstrap_tcb": "launcher-held-descriptor-open",
            "capsule_sha256": capsule_sha256,
            "files": {
                relative: {
                    "mode": f"{stat.S_IMODE(record.status.st_mode):04o}",
                    "sha256": hashlib.sha256(record.content).hexdigest(),
                    "size": len(record.content),
                }
                for relative, record in sorted(records.items())
            },
            "ordered_paths": list(BOOTSTRAP_SOURCE_PATHS),
            "schema_version": 1,
        }
        authority_bytes = (
            json.dumps(authority_value, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        authority_fd, authority_sha256 = _seal_bytes(
            "openmythos-kernel-bootstrap-authority", authority_bytes
        )
        for record in records.values():
            record.verify()
        return BootstrapCapsule(
            capsule_fd,
            authority_fd,
            capsule_sha256,
            authority_sha256,
        )
    finally:
        primary = sys.exception()
        failures: BaseException | None = None
        while records:
            try:
                record = records.popitem()[1]
            except BaseException as error:
                if failures is None:
                    failures = error
                record = dict.popitem(records)[1]
            try:
                record.close()
            except BaseException as error:
                if failures is None:
                    failures = error
            finally:
                # A custom-close entry failure leaves this concrete record's
                # fields live; drain them before overwriting the local owner.
                closing, record.fd = record.fd, -1
                if closing >= 0:
                    try:
                        os.close(closing)
                    except BaseException as error:
                        if failures is None:
                            failures = error
                closing, record.parent_fd = record.parent_fd, -1
                if closing >= 0:
                    try:
                        os.close(closing)
                    except BaseException as error:
                        if failures is None:
                            failures = error
        if primary is not None or failures:
            first = capsule_fd
            second = authority_fd
            capsule_fd = authority_fd = -1
            while first >= 0 or second >= 0:
                if first >= 0:
                    descriptor, first = first, -1
                else:
                    descriptor, second = second, -1
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if failures is None:
                        failures = error
        if failures:
            if primary is None:
                raise RuntimeError("bootstrap source cleanup failed") from failures
            try:
                _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
            except BaseException:
                pass


def _install_inheritable(mapping: dict[int, int]) -> None:
    """Install both output roles from collision-free copies, or roll back.

    Sources remain owned by the caller. All transient copies are CLOEXEC above
    every source/target, including sparse maps, cycles and duplicate aliases.
    Untouched targets are never closed during partial setup rollback.
    """
    if not mapping or any(type(fd) is not int or fd < 3 for fd in (*mapping, *mapping.values())):
        raise ValueError("bootstrap descriptor mapping is invalid")
    floor = max(*mapping, *mapping.values()) + 1
    copies: dict[int, int] = {}
    saved: dict[int, tuple[int, bool] | None] = {}
    installed: list[int] = []
    transient: list[int] = []
    try:
        for source in sorted(set(mapping.values())):
            duplicate = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, floor)
            try:
                transient.append(duplicate)
            except BaseException as primary:
                closing, duplicate = duplicate, -1
                try:
                    os.close(closing)
                except BaseException:
                    try:
                        _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
                    except BaseException:
                        pass
                raise
            copies[source] = duplicate
        for target in mapping:
            try:
                inheritable = os.get_inheritable(target)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                saved[target] = None
            else:
                duplicate = fcntl.fcntl(target, fcntl.F_DUPFD_CLOEXEC, floor)
                try:
                    transient.append(duplicate)
                except BaseException as primary:
                    closing, duplicate = duplicate, -1
                    try:
                        os.close(closing)
                    except BaseException:
                        try:
                            _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
                        except BaseException:
                            pass
                    raise
                saved[target] = duplicate, inheritable
        for target, source in mapping.items():
            installed.append(target)
            os.dup2(copies[source], target, inheritable=False)
            os.set_inheritable(target, True)
    except BaseException as primary:
        restoration_failed = False
        while installed:
            try:
                target = installed.pop()
            except BaseException:
                restoration_failed = True
                target = list.pop(installed)
            try:
                previous = saved[target]
                if previous is None:
                    os.close(target)
                else:
                    os.dup2(previous[0], target, inheritable=previous[1])
            except BaseException:
                restoration_failed = True
        if restoration_failed:
            try:
                _add_cleanup_note(primary, "additional bootstrap role restoration failed")
            except BaseException:
                pass
        raise
    finally:
        primary = sys.exception()
        failure = None
        while transient:
            try:
                descriptor = transient.pop()
            except BaseException as error:
                if failure is None:
                    failure = error
                descriptor = list.pop(transient)
            try:
                os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            if primary is None:
                raise failure
            try:
                _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
            except BaseException:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap-fd", required=True, type=int)
    parser.add_argument("--repository", required=True)
    parser.add_argument("supervisor_arguments", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if arguments.bootstrap_fd != BOOTSTRAP_FD:
        raise RuntimeError("bootstrap descriptor role is not exact")
    supervisor_arguments = list(arguments.supervisor_arguments)
    if supervisor_arguments[:1] == ["--"]:
        supervisor_arguments.pop(0)
    if not supervisor_arguments:
        raise RuntimeError("supervisor command is absent")
    owned = {arguments.bootstrap_fd}
    capsule_identity = None
    authority_identity = None
    try:
        capsule = build_bootstrap_capsule(
            Path(arguments.repository), arguments.bootstrap_fd
        )
        try:
            owned.update((capsule.capsule_fd, capsule.authority_fd))
        except BaseException as primary:
            # A partial update may already own either source. Remove both
            # before their one close attempt; failed method dispatch must not
            # replace the primary or leave a stale numeric owner for finally.
            cleanup_failed = False
            try:
                owned.discard(capsule.capsule_fd)
            except BaseException:
                cleanup_failed = True
                set.discard(owned, capsule.capsule_fd)
            try:
                owned.discard(capsule.authority_fd)
            except BaseException:
                cleanup_failed = True
                set.discard(owned, capsule.authority_fd)
            first = capsule.capsule_fd
            second = capsule.authority_fd
            capsule.capsule_fd = capsule.authority_fd = -1
            while first >= 0 or second >= 0:
                if first >= 0:
                    descriptor, first = first, -1
                else:
                    descriptor, second = second, -1
                try:
                    os.close(descriptor)
                except BaseException:
                    cleanup_failed = True
            if cleanup_failed:
                try:
                    _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
                except BaseException:
                    pass
            raise
        mapping = {CAPSULE_FD: capsule.capsule_fd, AUTHORITY_FD: capsule.authority_fd}
        status = os.fstat(capsule.capsule_fd)
        capsule_identity = (status.st_dev, status.st_ino)
        status = os.fstat(capsule.authority_fd)
        authority_identity = (status.st_dev, status.st_ino)
        _install_inheritable(mapping)
        owned.update(mapping)
        capsule_identity = authority_identity = None
        for descriptor in sorted(owned - {CAPSULE_FD, AUTHORITY_FD}):
            owned.remove(descriptor)
            os.close(descriptor)
        os.execve(
            "/usr/bin/python3",
            [
                "/usr/bin/python3", "-I", "-S", "-B",
                f"/proc/self/fd/{CAPSULE_FD}",
                "--sealed-supervisor-entry",
                "--bootstrap-capsule-fd", str(CAPSULE_FD),
                "--bootstrap-authority-fd", str(AUTHORITY_FD),
                *supervisor_arguments,
            ],
            dict(os.environ),
        )
        raise AssertionError("execve returned")
    finally:
        # Installation can fail after creating a role. Only adopt aliases of
        # our own capsule, never a restored pre-existing caller descriptor.
        primary = sys.exception()
        identity_failed = False
        failure = None
        index = 0
        while index < 2:
            target = CAPSULE_FD if index == 0 else AUTHORITY_FD
            identity = capsule_identity if index == 0 else authority_identity
            index += 1
            if identity is None:
                continue
            try:
                status = os.fstat(target)
            except BaseException as error:
                if not isinstance(error, OSError) or error.errno != errno.EBADF:
                    identity_failed = True
                    if primary is not None:
                        try:
                            _add_cleanup_note(primary, "bootstrap role cleanup identity failed")
                        except BaseException:
                            pass
            else:
                if status.st_dev == identity[0] and status.st_ino == identity[1]:
                    try:
                        owned.discard(target)
                    except BaseException as error:
                        if failure is None:
                            failure = error
                        set.discard(owned, target)
                    try:
                        os.close(target)
                    except BaseException as error:
                        if failure is None:
                            failure = error
        while owned:
            try:
                descriptor = owned.pop()
            except BaseException as error:
                if failure is None:
                    failure = error
                descriptor = set.pop(owned)
            try:
                os.close(descriptor)
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            if primary is None:
                raise failure
            try:
                _add_cleanup_note(primary, "additional bootstrap descriptor cleanup failed")
            except BaseException:
                pass
        if identity_failed and primary is None:
            raise RuntimeError("bootstrap role cleanup identity failed")

if __name__ == "__main__":
    raise SystemExit(main())
