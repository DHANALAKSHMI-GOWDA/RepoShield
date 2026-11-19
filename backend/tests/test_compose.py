
from backend.scanners.compose_scanner import scan_compose


def create_compose_file(tmp_path, content):
    file = tmp_path / "docker-compose.yml"
    file.write_text(content, encoding="utf-8")
    return file


def test_detect_compose_security_issues(tmp_path):
    file = create_compose_file(
        tmp_path,
        """
services:
  web:
    image: nginx:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    cap_add:
      - SYS_ADMIN
"""
    )

    result = scan_compose(file)

    assert result["status"] == "completed"
    assert result["total_findings"] == 5

    finding_types = [
        finding["type"] for finding in result["findings"]
    ]

    assert "Unpinned Docker Image" in finding_types
    assert "Privileged Container" in finding_types
    assert "Host Network Mode" in finding_types
    assert "Docker Socket Exposure" in finding_types
    assert "Dangerous Capability" in finding_types


def test_safe_compose_file(tmp_path):
    file = create_compose_file(
        tmp_path,
        """
services:
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
"""
    )

    result = scan_compose(file)

    assert result["status"] == "completed"
    assert result["total_findings"] == 0


def test_missing_compose_file(tmp_path):
    file = tmp_path / "missing-compose.yml"

    result = scan_compose(file)

    assert result["status"] == "error"
    assert result["findings"] == []


def test_invalid_yaml(tmp_path):
    file = create_compose_file(
        tmp_path,
        """
services:
  web: [
"""
    )

    result = scan_compose(file)

    assert result["status"] == "error"
    assert result["findings"] == []


def test_missing_services_section(tmp_path):
    file = create_compose_file(
        tmp_path,
        """
version: "3.9"
"""
    )

    result = scan_compose(file)

    assert result["status"] == "error"
    assert result["findings"] == []
