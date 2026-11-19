
import logging
import os
from pathlib import Path

from backend.scanners.secret_scanner import scan_directory
from backend.scanners.dependency_scanner import scan_dependencies
from backend.scanners.docker_scanner import scan_dockerfile
from backend.scanners.compose_scanner import scan_compose
from backend.scanners.workflow_scanner import scan_workflow_directory

logger = logging.getLogger(__name__)

IGNORED_DIRS = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".idea"
}


def get_repository_files(root):
    """Find repository files while skipping unnecessary directories."""

    root = Path(root)

    for current, dirs, files in os.walk(root):
        dirs[:] = [
            directory for directory in dirs
            if directory not in IGNORED_DIRS
        ]

        for filename in files:
            yield Path(current) / filename


def run_all_scanners(root: Path):
    """
    Run all available scanners on an extracted repository.

    Returns findings, scanner errors and skipped scanners separately.
    """

    root = Path(root).resolve()

    all_findings = []
    scanner_errors = []
    skipped_scanners = []

    if not root.is_dir():
        return {
            "findings": [],
            "scanner_errors": [{
                "scanner": "Coordinator",
                "error": "Invalid repository directory"
            }],
            "skipped_scanners": []
        }

    def process_result(scanner_name, result, source=None):

        if not isinstance(result, dict):
            raise TypeError("Scanner must return a dictionary")

        if result.get("status") != "completed":
            scanner_errors.append({
                "scanner": scanner_name,
                "error": result.get("message", "Scanner did not complete")
            })
            return

        findings = result.get("findings", [])

        if not isinstance(findings, list):
            raise TypeError("Scanner findings must be a list")

        for finding in findings:

            if not isinstance(finding, dict):
                raise TypeError("Each finding must be a dictionary")

            finding.setdefault("scanner", scanner_name)

            if source:
                finding.setdefault("file", str(source))

            all_findings.append(finding)

    # 1. Secret Scanner
    try:
        result = scan_directory(root)
        process_result("Secret Scanner", result)

    except Exception as error:
        logger.exception("Secret Scanner failed")
        scanner_errors.append({
            "scanner": "Secret Scanner",
            "error": str(error)
        })

    # Find relevant repository files once
    try:
        repository_files = list(get_repository_files(root))
    except Exception as error:
        logger.exception("Repository file discovery failed")
        scanner_errors.append({
            "scanner": "File Discovery",
            "error": str(error)
        })
        repository_files = []

    # 2. Dependency Scanner
    requirement_files = [
        path for path in repository_files
        if path.name.lower().startswith("requirements")
        and path.suffix.lower() == ".txt"
    ]

    if not requirement_files:
        skipped_scanners.append("Dependency Scanner")

    for requirements_file in requirement_files:
        try:
            result = scan_dependencies(requirements_file)
            process_result(
                "Dependency Scanner",
                result,
                requirements_file
            )

        except Exception as error:
            logger.exception("Dependency Scanner failed")
            scanner_errors.append({
                "scanner": "Dependency Scanner",
                "file": str(requirements_file),
                "error": str(error)
            })

    # 3. Docker Scanner
    dockerfiles = [
        path for path in repository_files
        if path.name.lower() == "dockerfile"
        or path.name.lower().startswith("dockerfile.")
    ]

    if not dockerfiles:
        skipped_scanners.append("Docker Scanner")

    for dockerfile in dockerfiles:
        try:
            result = scan_dockerfile(dockerfile)
            process_result(
                "Docker Scanner",
                result,
                dockerfile
            )

        except Exception as error:
            logger.exception("Docker Scanner failed")
            scanner_errors.append({
                "scanner": "Docker Scanner",
                "file": str(dockerfile),
                "error": str(error)
            })

    # 4. Docker Compose Scanner
    compose_files = [
        path for path in repository_files
        if (
            path.name.lower() in {
                "compose.yml",
                "compose.yaml",
                "docker-compose.yml",
                "docker-compose.yaml"
            }
            or path.name.lower().startswith("compose.")
            or path.name.lower().startswith("docker-compose.")
        )
        and path.suffix.lower() in {".yml", ".yaml"}
    ]

    if not compose_files:
        skipped_scanners.append("Compose Scanner")

    for compose_file in compose_files:
        try:
            result = scan_compose(compose_file)
            process_result(
                "Compose Scanner",
                result,
                compose_file
            )

        except Exception as error:
            logger.exception("Compose Scanner failed")
            scanner_errors.append({
                "scanner": "Compose Scanner",
                "file": str(compose_file),
                "error": str(error)
            })

    # 5. GitHub Workflow Scanner
    workflow_dirs = {
        path.parent
        for path in repository_files
        if path.suffix.lower() in {".yml", ".yaml"}
        and path.parent.name == "workflows"
        and path.parent.parent.name == ".github"
    }

    if not workflow_dirs:
        skipped_scanners.append("Workflow Scanner")

    for workflow_dir in sorted(workflow_dirs):
        try:
            result = scan_workflow_directory(workflow_dir)
            process_result(
                "Workflow Scanner",
                result
            )

        except Exception as error:
            logger.exception("Workflow Scanner failed")
            scanner_errors.append({
                "scanner": "Workflow Scanner",
                "directory": str(workflow_dir),
                "error": str(error)
            })

    return {
        "findings": all_findings,
        "scanner_errors": scanner_errors,
        "skipped_scanners": skipped_scanners
    }


def calculate_security_score(findings):
    """
    Calculate a security score between 0 and 100.
    Higher severity findings reduce the score.
    """

    deductions = {
        "Critical": 20,
        "High": 10,
        "Medium": 5,
        "Low": 2
    }

    score = 100

    for finding in findings:
        severity = finding.get("severity", "").capitalize()
        score -= deductions.get(severity, 0)

    return max(0, min(100, score))
