
import re
from pathlib import Path


SECRET_PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
    "Generic API Key": r"""(?i)(?:api_key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
    "Password": r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]""",
    "Secret Key": r"""(?i)(?:secret_key|client_secret)\s*[:=]\s*['"][^'"]{8,}['"]""",
    "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic Token": r"""(?i)(?:access_token|auth_token)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{16,}['"]"""
}

# Files and directories that should not be scanned.
IGNORED_DIRS = {
    ".git", "venv", ".venv", "__pycache__",
    "node_modules", ".idea", ".pytest_cache"
}

IGNORED_EXTENSIONS = {
    ".pyc", ".png", ".jpg", ".jpeg", ".gif",
    ".pdf", ".exe", ".dll", ".zip"
}


def scan_text(content, filename="<memory>"):
    """Scan text content for possible hardcoded secrets."""

    findings = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():

            if re.search(pattern, line):
                findings.append({
                    "type": secret_type,
                    "severity": "HIGH",
                    "file": str(filename),
                    "line": line_number,
                    "description": f"Possible {secret_type.lower()} detected."
                })

    return findings


def scan_file(file_path):
    """Scan an individual file."""

    path = Path(file_path)

    if not path.is_file():
        return []

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
        return scan_text(content, str(path))

    except OSError:
        return []


def scan_directory(directory):
    """Recursively scan a directory for secrets."""

    root = Path(directory)
    findings = []

    if not root.is_dir():
        return {
            "scanner": "secret_scanner",
            "status": "error",
            "findings": [],
            "message": "Invalid directory."
        }

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        if any(part in IGNORED_DIRS for part in file_path.parts):
            continue

        if file_path.suffix.lower() in IGNORED_EXTENSIONS:
            continue

        findings.extend(scan_file(file_path))

    return {
        "scanner": "secret_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }
