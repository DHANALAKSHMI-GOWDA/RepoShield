
import re
from pathlib import Path


def scan_workflow(file_path):
    """Scan GitHub Actions workflows for security misconfigurations."""

    path = Path(file_path)

    if not path.is_file():
        return {
            "scanner": "workflow_scanner",
            "status": "error",
            "findings": [],
            "message": "Workflow file not found."
        }

    findings = []

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except OSError as error:
        return {
            "scanner": "workflow_scanner",
            "status": "error",
            "findings": [],
            "message": str(error)
        }

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        # Detect pull_request_target.
        if re.search(r"pull_request_target\s*:", stripped):
            findings.append({
                "type": "Dangerous Pull Request Trigger",
                "severity": "HIGH",
                "line": line_number,
                "description": "pull_request_target can expose privileged workflow context to untrusted pull requests."
            })

        # Detect unpinned third-party actions.
        action_match = re.search(
            r"uses:\s*([^\s#]+)",
            stripped
        )

        if action_match:
            action = action_match.group(1)

            if "@" in action:
                version = action.rsplit("@", 1)[1]

                if not re.fullmatch(r"[a-fA-F0-9]{40}", version):
                    findings.append({
                        "type": "Unpinned GitHub Action",
                        "severity": "MEDIUM",
                        "line": line_number,
                        "description": f"Action '{action}' is not pinned to a full commit SHA."
                    })

        # Detect excessive write permissions.
        if re.search(r"^\s*write-all\s*$", stripped):
            findings.append({
                "type": "Excessive Permissions",
                "severity": "HIGH",
                "line": line_number,
                "description": "Workflow grants write access to all available permissions."
            })

        if re.search(
            r"^\s*(contents|packages|actions|pull-requests|issues):\s*write\s*$",
            line
        ):
            findings.append({
                "type": "Write Permission",
                "severity": "MEDIUM",
                "line": line_number,
                "description": "Workflow grants write permissions. Check whether they are necessary."
            })

        # Detect persistent checkout credentials.
        if re.search(
            r"persist-credentials\s*:\s*true",
            stripped,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Persistent Git Credentials",
                "severity": "MEDIUM",
                "line": line_number,
                "description": "Checkout credentials remain configured in the local Git repository."
            })

        # Detect possible secret exposure in shell commands.
        if "run:" in stripped and re.search(
            r"\$\{\{\s*secrets\.",
            stripped
        ):
            findings.append({
                "type": "Potential Secret Exposure",
                "severity": "HIGH",
                "line": line_number,
                "description": "A GitHub secret is referenced directly in a shell command. Review quoting and injection risks."
            })

        # Detect remote script execution.
        if "run:" in stripped and re.search(
            r"curl\s+.*\|\s*(?:sh|bash)",
            stripped,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Unsafe Script Execution",
                "severity": "HIGH",
                "line": line_number,
                "description": "A remote script is piped directly into a shell."
            })

    return {
        "scanner": "workflow_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }


def scan_workflow_directory(directory):
    """Scan all YAML workflow files in a directory."""

    root = Path(directory)
    findings = []

    if not root.is_dir():
        return {
            "scanner": "workflow_scanner",
            "status": "error",
            "findings": [],
            "message": "Invalid workflow directory."
        }

    for file_path in root.rglob("*"):

        if file_path.is_file() and file_path.suffix.lower() in {
            ".yml", ".yaml"
        }:
            result = scan_workflow(file_path)

            findings.extend(result.get("findings", []))

    return {
        "scanner": "workflow_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }
