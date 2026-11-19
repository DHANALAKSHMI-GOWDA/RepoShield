
from backend.scanners.workflow_scanner import (
    scan_workflow,
    scan_workflow_directory
)


def create_workflow(tmp_path, content):
    file = tmp_path / "test.yml"
    file.write_text(content, encoding="utf-8")
    return file


def test_detect_pull_request_target(tmp_path):
    file = create_workflow(
        tmp_path,
        """
on:
  pull_request_target:
    types: [opened]
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Dangerous Pull Request Trigger"
        for finding in result["findings"]
    )


def test_detect_unpinned_action(tmp_path):
    file = create_workflow(
        tmp_path,
        """
steps:
  - uses: actions/checkout@v4
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Unpinned GitHub Action"
        for finding in result["findings"]
    )


def test_accept_sha_pinned_action(tmp_path):
    sha = "a" * 40

    file = create_workflow(
        tmp_path,
        f"""
steps:
  - uses: actions/checkout@{sha}
"""
    )

    result = scan_workflow(file)

    assert not any(
        finding["type"] == "Unpinned GitHub Action"
        for finding in result["findings"]
    )


def test_detect_write_all_permissions(tmp_path):
    file = create_workflow(
        tmp_path,
        """
permissions:
  write-all
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Excessive Permissions"
        for finding in result["findings"]
    )


def test_detect_write_permission(tmp_path):
    file = create_workflow(
        tmp_path,
        """
permissions:
  contents: write
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Write Permission"
        for finding in result["findings"]
    )


def test_detect_persistent_credentials(tmp_path):
    file = create_workflow(
        tmp_path,
        """
steps:
  - uses: actions/checkout@v4
    with:
      persist-credentials: true
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Persistent Git Credentials"
        for finding in result["findings"]
    )


def test_detect_secret_reference(tmp_path):
    file = create_workflow(
        tmp_path,
        """
steps:
  - name: Deploy
    run: echo "${{ secrets.API_KEY }}"
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Potential Secret Exposure"
        for finding in result["findings"]
    )


def test_detect_remote_script_execution(tmp_path):
    file = create_workflow(
        tmp_path,
        """
steps:
  - name: Install
    run: curl https://example.com/install.sh | bash
"""
    )

    result = scan_workflow(file)

    assert any(
        finding["type"] == "Unsafe Script Execution"
        for finding in result["findings"]
    )


def test_safe_workflow(tmp_path):
    sha = "a" * 40

    file = create_workflow(
        tmp_path,
        f"""
name: Safe Workflow

permissions:
  contents: read

jobs:
  build:
    steps:
      - uses: actions/checkout@{sha}
        with:
          persist-credentials: false
      - run: echo "Build successful"
"""
    )

    result = scan_workflow(file)

    assert result["status"] == "completed"
    assert result["total_findings"] == 0


def test_missing_workflow():
    result = scan_workflow("missing.yml")

    assert result["status"] == "error"
    assert result["findings"] == []


def test_scan_workflow_directory(tmp_path):
    file1 = tmp_path / "first.yml"
    file2 = tmp_path / "second.yaml"

    file1.write_text(
        "on:\n  pull_request_target:\n",
        encoding="utf-8"
    )

    file2.write_text(
        "permissions:\n  write-all\n",
        encoding="utf-8"
    )

    result = scan_workflow_directory(tmp_path)

    assert result["status"] == "completed"
    assert result["total_findings"] == 2


def test_invalid_workflow_directory():
    result = scan_workflow_directory("missing_workflows")

    assert result["status"] == "error"
    assert result["findings"] == []
