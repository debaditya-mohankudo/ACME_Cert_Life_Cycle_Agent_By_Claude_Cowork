"""
Tests for atomic file writing with fsync to prevent corruption.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from storage.atomic import atomic_write_text, atomic_write_bytes


@pytest.fixture
def tmp_dir():
    """Create and clean up a temporary directory."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


class TestAtomicWriteText:
    """Test atomic_write_text functionality."""

    def test_atomic_write_text_creates_file(self, tmp_dir):
        """Verify atomic_write_text creates a file with correct content."""
        path = tmp_dir / "test.txt"
        content = "hello world"

        atomic_write_text(path, content)

        assert path.exists()
        assert path.read_text() == content

    def test_atomic_write_text_overwrites_existing(self, tmp_dir):
        """Verify atomic_write_text overwrites existing files."""
        path = tmp_dir / "test.txt"
        path.write_text("old content")

        new_content = "new content"
        atomic_write_text(path, new_content)

        assert path.read_text() == new_content

    def test_atomic_write_text_no_temp_file_left(self, tmp_dir):
        """Verify no temporary files are left after successful write."""
        path = tmp_dir / "test.txt"
        atomic_write_text(path, "content")

        # Should only have the target file, no .tmp files
        files = list(tmp_dir.glob("*"))
        assert len(files) == 1
        assert files[0].name == "test.txt"

    def test_atomic_write_text_creates_parent_dirs(self, tmp_dir):
        """Verify atomic_write_text creates parent directories."""
        path = tmp_dir / "subdir" / "nested" / "test.txt"

        atomic_write_text(path, "content")

        assert path.exists()
        assert path.read_text() == "content"

    def test_atomic_write_text_cleans_up_temp_on_error(self, tmp_dir):
        """Verify temp files are cleaned up even on write error."""
        path = tmp_dir / "test.txt"

        # Try to write to a read-only directory (simulating error)
        os_mkdir = os.mkdir
        error_count = [0]

        def failing_mkdir(*args, **kwargs):
            error_count[0] += 1
            if error_count[0] == 1:  # Fail on the first mkdir inside atomic_write_text
                raise PermissionError("Simulated permission error")
            return os_mkdir(*args, **kwargs)

        # This will fail, but temp file should still be cleaned up
        with pytest.raises(PermissionError):
            # Create a read-only directory to trigger failure
            ro_dir = tmp_dir / "readonly"
            ro_dir.mkdir(mode=0o444)
            try:
                atomic_write_text(ro_dir / "test.txt", "content")
            finally:
                ro_dir.chmod(0o755)


class TestAtomicWriteBytes:
    """Test atomic_write_bytes functionality."""

    def test_atomic_write_bytes_creates_file(self, tmp_dir):
        """Verify atomic_write_bytes creates a file with correct content."""
        path = tmp_dir / "test.bin"
        content = b"hello world"

        atomic_write_bytes(path, content)

        assert path.exists()
        assert path.read_bytes() == content

    def test_atomic_write_bytes_overwrites_existing(self, tmp_dir):
        """Verify atomic_write_bytes overwrites existing files."""
        path = tmp_dir / "test.bin"
        path.write_bytes(b"old content")

        new_content = b"new content"
        atomic_write_bytes(path, new_content)

        assert path.read_bytes() == new_content

    def test_atomic_write_bytes_no_temp_file_left(self, tmp_dir):
        """Verify no temporary files are left after successful write."""
        path = tmp_dir / "test.bin"
        atomic_write_bytes(path, b"content")

        # Should only have the target file, no .tmp files
        files = list(tmp_dir.glob("*"))
        assert len(files) == 1
        assert files[0].name == "test.bin"

    def test_atomic_write_bytes_large_file(self, tmp_dir):
        """Verify atomic_write_bytes handles large files correctly."""
        path = tmp_dir / "large.bin"
        content = b"x" * (10 * 1024 * 1024)  # 10 MB

        atomic_write_bytes(path, content)

        assert path.read_bytes() == content
        assert path.stat().st_size == len(content)


class TestAtomicWriteIntegration:
    """Integration tests for atomic writes in realistic scenarios."""

    def test_pem_file_atomic_write_text(self, tmp_dir):
        """Simulate PEM file write (certificate or key)."""
        pem_content = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDfUhCwSyzexjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----"""

        path = tmp_dir / "cert.pem"
        atomic_write_text(path, pem_content)

        assert path.read_text() == pem_content
        # Verify no partial/corrupt temp files exist
        assert len(list(tmp_dir.glob(".*"))) == 0

    def test_multiple_atomic_writes_to_same_dir(self, tmp_dir):
        """Verify multiple atomic writes don't interfere."""
        files = []
        for i in range(5):
            path = tmp_dir / f"file{i}.txt"
            atomic_write_text(path, f"content {i}")
            files.append(path)

        # Verify all files exist with correct content
        for i, path in enumerate(files):
            assert path.read_text() == f"content {i}"

        # Verify no temp files left
        temp_files = list(tmp_dir.glob(".*.tmp"))
        assert len(temp_files) == 0

    def test_concurrent_writes_to_different_files(self, tmp_dir):
        """Verify concurrent writes don't create conflicting temp files."""
        import concurrent.futures

        def write_file(i):
            path = tmp_dir / f"concurrent{i}.txt"
            atomic_write_text(path, f"content {i}")
            return path

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(write_file, i) for i in range(10)]
            paths = [f.result() for f in futures]

        # Verify all files exist
        for i, path in enumerate(paths):
            assert path.read_text() == f"content {i}"

        # Verify no temp files left
        temp_files = list(tmp_dir.glob(".*.tmp"))
        assert len(temp_files) == 0
