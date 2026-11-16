import io
import pytest
import zipfile
from src.sandbox import (
    SandboxConfig,
    SandboxSecurityViolation,
    SandboxResourceExceeded,
    validate_archive_safety,
    run_sandboxed_scan,
)


def test_validate_archive_safety_valid():
    # Construct a valid, tiny docx-like zip archive
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types></Types>")
        zf.writestr("word/document.xml", b"<w:document></w:document>")

    # Should pass without exceptions
    validate_archive_safety(buf.getvalue())


def test_validate_archive_safety_zip_slip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", b"malicious traversal")

    with pytest.raises(SandboxSecurityViolation, match="Zip Slip"):
        validate_archive_safety(buf.getvalue())


def test_validate_archive_safety_file_size_exceeded():
    cfg = SandboxConfig(max_file_size_bytes=100)
    huge_bytes = b"A" * 200

    with pytest.raises(SandboxResourceExceeded, match="File size"):
        validate_archive_safety(huge_bytes, config=cfg)


def test_validate_archive_safety_too_many_entries():
    cfg = SandboxConfig(max_zip_entries=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("file1.txt", b"1")
        zf.writestr("file2.txt", b"2")
        zf.writestr("file3.txt", b"3")

    with pytest.raises(SandboxResourceExceeded, match="exceeding sandbox limit"):
        validate_archive_safety(buf.getvalue(), config=cfg)
