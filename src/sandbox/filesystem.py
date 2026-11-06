"""Sandboxed filesystem — constrained to temp directory."""
import os
from pathlib import Path


class SandboxedFilesystem:
    """Constrains all file operations to a temp directory."""

    def __init__(self, temp_dir: str) -> None:
        self.temp_dir = temp_dir

    def write(self, relative_path: str, content: str) -> str:
        """Write a file within the sandbox."""
        full_path = self._resolve(relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def read(self, relative_path: str) -> str:
        """Read a file within the sandbox."""
        full_path = self._resolve(relative_path)
        with open(full_path, "r") as f:
            return f.read()

    def list_files(self, relative_dir: str = ".") -> list[str]:
        """List files within the sandbox."""
        full_dir = self._resolve(relative_dir)
        if not os.path.isdir(full_dir):
            return []
        return os.listdir(full_dir)

    def _resolve(self, relative_path: str) -> str:
        """Resolve a relative path within the sandbox."""
        resolved = os.path.realpath(os.path.join(self.temp_dir, relative_path))
        base = os.path.realpath(self.temp_dir)
        try:
            inside = os.path.commonpath([resolved, base]) == base
        except ValueError:
            inside = False
        if not inside:
            raise SecurityError(f"Path traversal attempt: {relative_path}")
        return resolved


class SecurityError(Exception):
    pass
