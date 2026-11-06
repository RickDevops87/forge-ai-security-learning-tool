import pytest
from src.sandbox.filesystem import SandboxedFilesystem, SecurityError
import tempfile
import os


def test_filesystem_write_and_read():
    with tempfile.TemporaryDirectory() as tmpdir:
        fs = SandboxedFilesystem(tmpdir)
        path = fs.write("test.txt", "hello world")
        assert os.path.exists(path)
        content = fs.read("test.txt")
        assert content == "hello world"


def test_filesystem_path_traversal_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        fs = SandboxedFilesystem(tmpdir)
        with pytest.raises(SecurityError):
            fs.write("../../etc/passwd", "malicious")


def test_filesystem_sibling_prefix_escape_blocked():
    with tempfile.TemporaryDirectory() as parent:
        sandbox = os.path.join(parent, "lab")
        sibling = os.path.join(parent, "lab-escape")
        os.makedirs(sandbox)
        os.makedirs(sibling)
        with open(os.path.join(sibling, "secret.txt"), "w") as handle:
            handle.write("outside")
        fs = SandboxedFilesystem(sandbox)
        with pytest.raises(SecurityError):
            fs.read(os.path.join("..", "lab-escape", "secret.txt"))


def test_filesystem_list_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        fs = SandboxedFilesystem(tmpdir)
        fs.write("a.txt", "content a")
        fs.write("b.txt", "content b")
        files = fs.list_files(".")
        assert "a.txt" in files
        assert "b.txt" in files
