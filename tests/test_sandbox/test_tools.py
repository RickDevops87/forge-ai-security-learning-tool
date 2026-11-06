import os

import pytest

from src.sandbox.tools import MockToolRegistry


@pytest.mark.asyncio
async def test_fake_file_reader_blocks_parent_traversal(tmp_path):
    sandbox = tmp_path / "lab"
    sandbox.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must remain outside")
    registry = MockToolRegistry(str(sandbox))

    result = await registry.get("fake_file_reader").handler({"path": "../outside.txt"})

    assert result["error"] == "Path is outside the sandbox"
    assert "content" not in result


@pytest.mark.asyncio
async def test_fake_file_reader_reads_inside_sandbox(tmp_path):
    sandbox = tmp_path / "lab"
    sandbox.mkdir()
    (sandbox / "fixture.txt").write_text("synthetic fixture")
    registry = MockToolRegistry(str(sandbox))

    result = await registry.get("fake_file_reader").handler({"path": "fixture.txt"})

    assert result["content"] == "synthetic fixture"
