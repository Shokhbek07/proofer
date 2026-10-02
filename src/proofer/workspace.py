"""Read-only, path-jailed access to the repository under review.

The repository is untrusted input. Everything the agent learns about it goes
through this class, which can only read, and only inside the root.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "vendor", "dist", "build",
    "__pycache__", ".idea", ".next", "target", ".tox", ".mypy_cache",
}
MAX_FILE_BYTES = 400_000


class WorkspaceError(Exception):
    """A request the workspace refuses, with a message safe to show the model."""


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    text: str


class Workspace:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise WorkspaceError(f"{root} is not a directory")

    def resolve(self, rel: str) -> Path:
        """Map a model-supplied path to a real file inside the root, or refuse."""
        candidate = (self.root / rel).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise WorkspaceError(f"path escapes the repository: {rel}")
        return candidate

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def files(self, subdir: str = ".", glob: str | None = None) -> list[str]:
        base = self.resolve(subdir)
        if not base.is_dir():
            raise WorkspaceError(f"not a directory: {subdir}")
        out: list[str] = []
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                full = Path(dirpath) / name
                if full.is_symlink():
                    continue
                rel = self.rel(full)
                if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(name, glob)):
                    continue
                out.append(rel)
        return out

    def lines(self, rel: str) -> list[str]:
        path = self.resolve(rel)
        if not path.is_file():
            raise WorkspaceError(f"no such file: {rel}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise WorkspaceError(f"file too large to read: {rel}")
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            raise WorkspaceError(f"binary file: {rel}")
        return data.decode("utf-8", errors="replace").splitlines()

    def read(self, rel: str, start: int = 1, end: int | None = None) -> str:
        """Return lines start..end (1-based, inclusive) prefixed with line numbers."""
        lines = self.lines(rel)
        start = max(1, start)
        end = min(len(lines), end if end is not None else len(lines))
        if start > len(lines):
            raise WorkspaceError(f"{rel} has only {len(lines)} lines")
        width = len(str(end))
        return "\n".join(
            f"{n:>{width}}| {lines[n - 1]}" for n in range(start, end + 1)
        )

    def grep(
        self, pattern: str, glob: str | None = None, max_hits: int = 60
    ) -> list[Hit]:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise WorkspaceError(f"invalid regular expression: {exc}") from exc
        hits: list[Hit] = []
        for rel in self.files(glob=glob):
            try:
                lines = self.lines(rel)
            except WorkspaceError:
                continue
            for n, text in enumerate(lines, start=1):
                if rx.search(text):
                    hits.append(Hit(rel, n, text.strip()[:240]))
                    if len(hits) >= max_hits:
                        return hits
        return hits
