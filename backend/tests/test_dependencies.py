
import json
import subprocess

from unittest.mock import patch, MagicMock

from backend.scanners.dependency_scanner import (
    scan_dependencies,
    get_vulnerability_severity
)


def mock_audit_output(vulnerabilities):
    return {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.19.0",
                "vulns": vulnerabilities
            }
        ],
        "fixes": []
    }


@patch("backend.scanners.dependency_scanner.subprocess.run")
@patch("backend.scanners.dependency_scanner.shutil.which")
def test_detect_vulnerable_dependency(mock_which, mock_run, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.19.0")

    mock_which.return_value = "/usr/bin/pip-audit"

    mock_run.return_value = MagicMock(
        stdout=json.dumps(
            mock_audit_output([
                {
                    "id": "CVE-2023-0001",
                    "description": "Test vulnerability",
                    "fix_versions": ["2.31.0"]
                }
            ])
        ),
        stderr="",
        returncode=1
    )

    result = scan_dependencies(requirements)

    assert result["status"] == "completed"
    assert result["total_findings"] == 1
    assert result["findings"][0]["package"] == "requests"
    assert result["findings"][0]["vulnerability_id"] == "CVE-2023-0001"


@patch("backend.scanners.dependency_scanner.subprocess.run")
@patch("backend.scanners.dependency_scanner.shutil.which")
def test_no_vulnerabilities(mock_which, mock_run, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0")

    mock_which.return_value = "/usr/bin/pip-audit"

    mock_run.return_value = MagicMock(
        stdout=json.dumps(mock_audit_output([])),
        stderr="",
        returncode=0
    )

    result = scan_dependencies(requirements)

    assert result["status"] == "completed"
    assert result["total_findings"] == 0
    assert result["findings"] == []


def test_missing_requirements_file():
    result = scan_dependencies("missing_requirements.txt")

    assert result["status"] == "error"
    assert result["findings"] == []


@patch("backend.scanners.dependency_scanner.shutil.which")
def test_pip_audit_not_installed(mock_which, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0")

    mock_which.return_value = None

    result = scan_dependencies(requirements)

    assert result["status"] == "error"
    assert "not installed" in result["message"]


@patch("backend.scanners.dependency_scanner.subprocess.run")
@patch("backend.scanners.dependency_scanner.shutil.which")
def test_dependency_scan_timeout(mock_which, mock_run, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0")

    mock_which.return_value = "/usr/bin/pip-audit"
    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd="pip-audit",
        timeout=180
    )

    result = scan_dependencies(requirements)

    assert result["status"] == "error"
    assert "timed out" in result["message"]


@patch("backend.scanners.dependency_scanner.subprocess.run")
@patch("backend.scanners.dependency_scanner.shutil.which")
def test_invalid_json_output(mock_which, mock_run, tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0")

    mock_which.return_value = "/usr/bin/pip-audit"

    mock_run.return_value = MagicMock(
        stdout="invalid json",
        stderr="",
        returncode=1
    )

    result = scan_dependencies(requirements)

    assert result["status"] == "error"
    assert "parse" in result["message"].lower()


@patch("backend.scanners.dependency_scanner.urlopen")
def test_database_specific_severity_fallback(mock_urlopen):
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = json.dumps({
        "id": "TEST-001",
        "severity": [],
        "database_specific": {
            "severity": "HIGH"
        }
    }).encode("utf-8")

    mock_urlopen.return_value = mock_response

    result = get_vulnerability_severity("TEST-001")

    assert result == "HIGH"


@patch("backend.scanners.dependency_scanner.urlopen")
def test_unknown_when_severity_unavailable(mock_urlopen):
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = json.dumps({
        "id": "TEST-002",
        "severity": [],
        "affected": [],
        "database_specific": {}
    }).encode("utf-8")

    mock_urlopen.return_value = mock_response

    result = get_vulnerability_severity("TEST-002")

    assert result == "UNKNOWN"


@patch("backend.scanners.dependency_scanner.urlopen")
def test_cvss_severity_lookup(mock_urlopen):
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = json.dumps({
        "id": "TEST-003",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        ]
    }).encode("utf-8")

    mock_urlopen.return_value = mock_response

    result = get_vulnerability_severity("TEST-003")

    assert result == "CRITICAL"

