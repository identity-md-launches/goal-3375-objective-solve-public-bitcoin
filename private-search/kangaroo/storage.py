"""POSIX private storage. All state access is relative to an open directory FD."""

import fcntl
import hashlib
import json
import os
import stat
import sys
from .manifest import canonical

MAX_STATE_BYTES = 64 * 1024 * 1024
FILES = {"checkpoint.json", "dp.jsonl", "metrics.json", "run.lock", "launch.lock", "candidate.bin"}


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out
    def invalid_constant(_):
        raise ValueError("invalid JSON constant")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)


class PrivateDirectory:
    def __init__(self, path, checkout_root, create=True, lock=True):
        self.fd = self.lock_fd = None
        if (type(path) is not str or not os.path.isabs(path) or "\0" in path
                or path != os.path.normpath(path) or path.startswith("//") or path == "/"):
            raise ValueError("private directory must be an absolute canonical path")
        if checkout_root is not None:
            root = os.path.abspath(checkout_root)
            if os.path.commonpath((path, root)) == root:
                raise ValueError("production state must be outside checkout")
        self.path = path
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            components = path.split("/")[1:]
            for index, component in enumerate(components):
                if component in ("", ".", ".."):
                    raise ValueError("invalid private directory")
                try:
                    next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=directory)
                except FileNotFoundError:
                    if not create or index != len(components) - 1:
                        raise
                    os.mkdir(component, 0o700, dir_fd=directory)
                    os.fsync(directory)
                    next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=directory)
                os.close(directory)
                directory = next_fd
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("private directory owner or mode invalid")
            self.fd, directory = directory, None
            for name in os.listdir(self.fd):
                if name not in FILES and name not in {".checkpoint.json.pending", ".dp.jsonl.pending", ".metrics.json.pending"}:
                    raise ValueError("private directory contains unexpected entries")
                self._check_name(name)
            if lock:
                self.lock_fd = self.acquire_lock("run.lock")
        except BaseException:
            self.close()
            raise
        finally:
            if directory is not None:
                os.close(directory)

    @staticmethod
    def check_file(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("private file owner, mode, type or link count invalid")

    def _check_name(self, name, missing_ok=False):
        try:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise
        self.check_file(info)
        return info

    def open_file(self, name, flags, create=False):
        if name not in FILES:
            raise ValueError("invalid private file name")
        self._check_name(name, missing_ok=create)
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_CREAT if create else 0),
                     0o600, dir_fd=self.fd)
        try:
            self.check_file(os.fstat(fd))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def acquire_lock(self, name):
        if name not in ("run.lock", "launch.lock"):
            raise ValueError("invalid lock")
        fd = self.open_file(name, os.O_RDWR, create=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(self.fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def atomic_write(self, name, data):
        if name not in ("checkpoint.json", "dp.jsonl", "metrics.json") or type(data) is not bytes:
            raise ValueError("invalid atomic write")
        if len(data) > MAX_STATE_BYTES:
            raise ValueError("private state exceeds byte limit")
        self._check_name(name, missing_ok=True)
        pending = "." + name + ".pending"
        if self._check_name(pending, missing_ok=True) is not None:
            os.unlink(pending, dir_fd=self.fd)  # Previous interrupted write; checkpoint remains authoritative.
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            self.check_file(os.fstat(fd))
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("private write failed")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self._check_name(name, missing_ok=True)
        os.replace(pending, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def read(self, name):
        fd = self.open_file(name, os.O_RDONLY)
        try:
            if os.fstat(fd).st_size > MAX_STATE_BYTES:
                raise ValueError("private state exceeds byte limit")
            chunks, size = [], 0
            while True:
                data = os.read(fd, min(65536, MAX_STATE_BYTES + 1 - size))
                if not data:
                    return b"".join(chunks)
                chunks.append(data)
                size += len(data)
                if size > MAX_STATE_BYTES:
                    raise ValueError("private state exceeds byte limit")
        finally:
            os.close(fd)

    def save(self, engine, export=False):
        payload = engine.snapshot()
        checkpoint = {"schema": "kangaroo-checkpoint@1", "sha256": hashlib.sha256(canonical(payload)).hexdigest(),
                      "payload": payload}
        self.atomic_write("checkpoint.json", canonical(checkpoint) + b"\n")
        if export:
            self.atomic_write("dp.jsonl", b"".join(canonical(r) + b"\n" for r in engine.export_records()))

    def load(self):
        checkpoint = strict_json(self.read("checkpoint.json"))
        if (type(checkpoint) is not dict or set(checkpoint) != {"schema", "sha256", "payload"}
                or checkpoint["schema"] != "kangaroo-checkpoint@1"
                or checkpoint["sha256"] != hashlib.sha256(canonical(checkpoint["payload"])).hexdigest()):
            raise ValueError("checkpoint integrity failure")
        return checkpoint["payload"]

    def exists(self, name):
        if name not in FILES:
            raise ValueError("invalid private file name")
        return self._check_name(name, missing_ok=True) is not None

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class CandidateSink:
    """Only an inherited writable pipe or private-dir/candidate.bin is accepted.

    The caller owns the receiving process. Pipes are nonblocking so an absent or
    stuck receiver cannot turn a bounded search into an unbounded write.
    """

    def __init__(self, fd, directory):
        if type(fd) is not int or fd < 3:
            raise ValueError("private candidate FD required")
        info = os.fstat(fd)
        for standard in (0, 1, 2):
            try:
                other = os.fstat(standard)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (other.st_dev, other.st_ino):
                raise ValueError("candidate FD aliases standard IO")
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if flags & os.O_ACCMODE != os.O_WRONLY or flags & os.O_APPEND:
            raise ValueError("candidate FD must be write-only and non-append")
        self.regular = stat.S_ISREG(info.st_mode)
        if self.regular:
            if directory is None:
                raise ValueError("regular candidate sink requires private directory")
            directory.check_file(info)
            named = directory._check_name("candidate.bin")
            if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                    or info.st_size != 0 or os.lseek(fd, 0, os.SEEK_CUR) != 0):
                raise ValueError("candidate sink must be the empty private candidate file")
        elif stat.S_ISFIFO(info.st_mode):
            if sys.platform != "linux":
                raise ValueError("anonymous candidate pipe verification requires Linux")
            # On Linux anonymous pipes live on pipefs, unlike named FIFOs on a
            # filesystem. Compare with a fresh task-owned pipe, without /proc.
            probe_read, probe_write = os.pipe()
            try:
                if info.st_dev != os.fstat(probe_write).st_dev:
                    raise ValueError("named candidate FIFOs are not supported")
            finally:
                os.close(probe_read)
                os.close(probe_write)
            os.set_blocking(fd, False)
        else:
            raise ValueError("unsupported candidate sink")
        self.fd = fd

    def deliver(self, candidate):
        if type(candidate) is not bytes or len(candidate) != 32:
            raise ValueError("candidate must be 32 bytes")
        # One <= PIPE_BUF write, never formatted as text or copied into an error.
        if os.write(self.fd, candidate) != 32:
            raise OSError("candidate delivery incomplete")
        if self.regular:
            os.fsync(self.fd)
