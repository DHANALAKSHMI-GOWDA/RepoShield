
import pytest

from backend.scanners.secret_scanner import (
    scan_text,
    scan_file,
    scan_directory
)


def test_detect_aws_access_key():
    content = "AWS_KEY = 'AKIA1234567890ABCDEF'"

    findings = scan_text(content)

    assert len(findings) == 1
    assert findings[0]["type"] == "AWS Access Key"
    assert findings[0]["severity"] == "HIGH"


def test_detect_github_token():
    content = "token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890'"

    findings = scan_text(content)

    assert any(
        finding["type"] == "GitHub Token"
        for finding in findings
    )


def test_detect_password():
    content = 'password = "mySecretPassword123"'

    findings = scan_text(content)

    assert any(
        finding["type"] == "Password"
        for finding in findings
    )


def test_safe_content_returns_no_findings():
    content = """
    name = "RepoShield"
    version = "1.0"
    debug = False
    """

    assert scan_text(content) == []


def test_multiple_secrets_are_detected():
    content = """
    password = "secret123"
    api_key = "abcdefghijklmnop123456"
    """

    findings = scan_text(content)

    assert len(findings) >= 2


def test_scan_file(tmp_path):
    file = tmp_path / "config.py"
    file.write_text(
        'password = "secret123"',
        encoding="utf-8"
    )

    findings = scan_file(file)

    assert len(findings) == 1
    assert findings[0]["file"] == str(file)
    assert findings[0]["line"] == 1


def test_scan_directory(tmp_path):
    file = tmp_path / "config.py"
    file.write_text(
        'password = "secret123"',
        encoding="utf-8"
    )

    result = scan_directory(tmp_path)

    assert result["status"] == "completed"
    assert result["total_findings"] == 1


def test_invalid_directory():
    result = scan_directory("nonexistent_directory")

    assert result["status"] == "error"
    assert result["findings"] == []
