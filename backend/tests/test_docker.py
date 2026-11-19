
from backend.scanners.docker_scanner import scan_dockerfile


def create_dockerfile(tmp_path, content):
    file = tmp_path / "Dockerfile"
    file.write_text(content, encoding="utf-8")
    return file


def test_detect_latest_image(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:latest\nUSER app"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Unpinned Docker Image"
        for finding in result["findings"]
    )


def test_detect_root_user(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:3.12\nUSER root"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Root User"
        for finding in result["findings"]
    )


def test_detect_sensitive_port(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:3.12\nUSER app\nEXPOSE 3306"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Sensitive Port Exposed"
        for finding in result["findings"]
    )


def test_detect_add_instruction(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:3.12\nUSER app\nADD app.tar.gz /app/"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Use of ADD"
        for finding in result["findings"]
    )


def test_detect_missing_user(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:3.12\nCOPY . /app"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Missing USER Instruction"
        for finding in result["findings"]
    )


def test_detect_privileged_execution(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:3.12\nRUN docker run --privileged app"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Privileged Container"
        for finding in result["findings"]
    )


def test_detect_remote_script_execution(tmp_path):
    file = create_dockerfile(
        tmp_path,
        "FROM python:3.12\nRUN curl https://example.com/install.sh | sh"
    )

    result = scan_dockerfile(file)

    assert any(
        finding["type"] == "Unsafe Remote Script Execution"
        for finding in result["findings"]
    )


def test_safe_dockerfile(tmp_path):
    file = create_dockerfile(
        tmp_path,
        """
FROM python:3.12.5
WORKDIR /app
COPY . /app
USER app
CMD ["python", "main.py"]
"""
    )

    result = scan_dockerfile(file)

    assert result["status"] == "completed"
    assert result["total_findings"] == 0


def test_missing_dockerfile():
    result = scan_dockerfile("missing_Dockerfile")

    assert result["status"] == "error"
    assert result["findings"] == []
