
import json
import subprocess
import shutil
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from cvss import CVSS2, CVSS3, CVSS4


def get_vulnerability_severity(vulnerability_id):
    """
    Retrieve vulnerability severity from OSV.
    Uses CVSS vectors first, then recognized database-specific labels.
    """

    url = f"https://api.osv.dev/v1/vulns/{vulnerability_id}"

    try:
        request = Request(
            url,
            headers={"Accept": "application/json"}
        )

        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        def normalize_severity(value):
            if not isinstance(value, str):
                return None

            value = value.strip().upper()

            if value == "MODERATE":
                value = "MEDIUM"

            if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                return value

            return None

        def get_cvss_severity(severity_list):
            for severity_info in severity_list:
                vector = severity_info.get("score", "")
                severity_type = severity_info.get("type", "")

                try:
                    if severity_type == "CVSS_V4":
                        return normalize_severity(
                            CVSS4(vector).severities()[0]
                        )

                    elif severity_type == "CVSS_V3":
                        return normalize_severity(
                            CVSS3(vector).severities()[0]
                        )

                    elif severity_type == "CVSS_V2":
                        return normalize_severity(
                            CVSS2(vector).severities()[0]
                        )

                except (ValueError, IndexError):
                    continue

            return None

        # First: top-level CVSS severity
        severity = get_cvss_severity(data.get("severity", []))

        if severity:
            return severity

        # Second: affected-package CVSS severity
        for affected in data.get("affected", []):
            severity = get_cvss_severity(
                affected.get("severity", [])
            )

            if severity:
                return severity

        # Third: recognized database-specific severity
        database_severity = data.get(
            "database_specific", {}
        ).get("severity")

        severity = normalize_severity(database_severity)

        if severity:
            return severity

        return "UNKNOWN"

    except (HTTPError, URLError, TimeoutError, OSError,
            json.JSONDecodeError, ValueError):
        return "UNKNOWN"


def scan_dependencies(requirements_file):
    """
    Scan Python dependencies using pip-audit.
    """

    requirements = Path(requirements_file)

    if not requirements.is_file():
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "Requirements file not found."
        }

    if shutil.which("pip-audit") is None:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "pip-audit is not installed. Run: pip install pip-audit"
        }

    try:
        result = subprocess.run(
            [
                "pip-audit",
                "--requirement", str(requirements),
                "--format", "json"
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        if not result.stdout.strip():
            return {
                "scanner": "dependency_scanner",
                "status": "error",
                "findings": [],
                "message": result.stderr.strip() or
                           "pip-audit returned no output."
            }

        data = json.loads(result.stdout)
        findings = []
        seen = set()

        for dependency in data.get("dependencies", []):

            for vulnerability in dependency.get("vulns", []):

                package = dependency.get("name")
                version = dependency.get("version")
                vulnerability_id = vulnerability.get("id")

                # Avoid duplicate vulnerability records.
                unique_key = (
                    package,
                    version,
                    vulnerability_id
                )

                if unique_key in seen:
                    continue

                seen.add(unique_key)

                findings.append({
                    "package": package,
                    "installed_version": version,
                    "vulnerability_id": vulnerability_id,
                    "severity": get_vulnerability_severity(vulnerability_id),
                    "description": vulnerability.get("description", ""),
                    "fixed_versions": vulnerability.get("fix_versions", [])
                })

        return {
            "scanner": "dependency_scanner",
            "status": "completed",
            "total_findings": len(findings),
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "Dependency scan timed out."
        }

    except json.JSONDecodeError:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "Unable to parse pip-audit output."
        }

    except OSError as error:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": str(error)
        }
