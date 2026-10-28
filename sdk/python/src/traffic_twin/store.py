"""Local state of the source: enrollment (certificate, CA chain, pinned keys), private key,
signed policy cache, kill switch. Directory 0700, files 0600, atomic replace.

Trust (POSIX): the directory (and ``~/.traffic-twin``, the parent of the default one) is created 0700; a
pre-existing one owned by another user is refused (the state then lives in a private temporary directory) and a
group/world-accessible one owned by us is repaired to 0700 (refused when the repair fails). A state file is read
only when it is owned by the current user and not group/world-writable; otherwise it is treated as absent and
``on_untrusted`` is called (never its contents).

The key is created with mode 0600 from the first byte (``O_CREAT`` with the mode), never
written world-readable and then tightened.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from typing import Any, Callable, Optional

try:  # POSIX only; on Windows enrollment races are not serialized
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore


def default_state_dir(enroll_url: str, service_name: str) -> str:
    ident = hashlib.sha256((enroll_url + "\0" + service_name).encode("utf-8")).hexdigest()[:16]
    return os.path.join(os.path.expanduser("~"), ".traffic-twin", ident)


_POSIX = hasattr(os, "geteuid")


def _private_dir(path: str, create: bool = True) -> None:
    """Makes ``path`` a directory owned by us with mode 0700, or raises PermissionError."""
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    if not _POSIX:
        if not os.path.isdir(path):
            raise PermissionError(path)
        return
    st = os.stat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(path)
    if st.st_uid != os.geteuid():
        raise PermissionError("not owned by the current user: " + path)
    if st.st_mode & 0o077:
        os.chmod(path, 0o700)  # repair; failure refuses the directory
        if os.stat(path).st_mode & 0o077:
            raise PermissionError("cannot make private: " + path)


class StateStore:
    def __init__(self, directory: str, on_untrusted: Optional[Callable[[str], None]] = None) -> None:
        self.dir = directory
        self.ephemeral = False
        self._tmp_root: Optional[str] = None
        self.on_untrusted = on_untrusted

    def ensure(self) -> None:
        try:
            parent = os.path.dirname(self.dir)
            if os.path.basename(parent) == ".traffic-twin":  # the default layout: ~/.traffic-twin/<id>
                _private_dir(parent)
            if os.path.isdir(self.dir) or not os.path.lexists(self.dir):
                if not os.path.lexists(self.dir):
                    os.makedirs(self.dir, mode=0o700, exist_ok=True)
                _private_dir(self.dir, create=False)
            else:
                raise PermissionError(self.dir)
            if not os.access(self.dir, os.W_OK):
                raise PermissionError(self.dir)
        except OSError:
            # Unwritable location: keep the state in a private temporary directory. The
            # enrollment then does not survive a restart (documented).
            self._tmp_root = tempfile.mkdtemp(prefix="traffic-twin-")
            self.dir = self._tmp_root
            self.ephemeral = True

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def read_text(self, name: str) -> Optional[str]:
        try:
            fd = os.open(self.path(name), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return None
        try:
            if not self._trusted(fd, name):
                return None
            with os.fdopen(fd, "r", encoding="utf-8") as f:
                fd = -1
                return f.read()
        except (OSError, UnicodeDecodeError):
            return None
        finally:
            if fd >= 0:
                os.close(fd)

    def _trusted(self, fd: int, name: str) -> bool:
        if not _POSIX:
            return True
        st = os.fstat(fd)
        ok = stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022
        if ok and name == "client.key" and st.st_mode & 0o077:
            try:
                os.fchmod(fd, 0o600)  # the private key is ours: tighten rather than refuse
            except OSError:
                ok = False
        if not ok and self.on_untrusted is not None:
            try:
                self.on_untrusted("state_file_untrusted")
            except Exception:
                pass
        return ok

    def read_json(self, name: str) -> Optional[Any]:
        t = self.read_text(name)
        if t is None:
            return None
        try:
            return json.loads(t)
        except ValueError:
            return None

    def write_text(self, name: str, text: str) -> None:
        self.ensure()
        final = self.path(name)
        tmp = os.path.join(self.dir, ".%s.%d.tmp" % (name, os.getpid()))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, final)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def write_json(self, name: str, value: Any) -> None:
        self.write_text(name, json.dumps(value, separators=(",", ":")))

    def remove(self, name: str) -> None:
        try:
            os.unlink(self.path(name))
        except OSError:
            pass

    def lock(self) -> "_Lock":
        self.ensure()
        return _Lock(self.path(".lock"))

    def cleanup_ephemeral(self) -> None:
        if self._tmp_root:
            shutil.rmtree(self._tmp_root, ignore_errors=True)


class _Lock:
    """Inter-process lock around enrollment (several worker processes, one token)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd: Optional[int] = None

    def __enter__(self) -> "_Lock":
        try:
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            if fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError:
            self.fd = None
        return self

    def __exit__(self, *exc: object) -> None:
        if self.fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
