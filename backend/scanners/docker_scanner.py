
import re
from pathlib import Path


def scan_dockerfile(file_path):
    """Scan a Dockerfile for common security issues."""

    path = Path(file_path)

    def error_result(message):
        return {
            "scanner": "docker_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": message
        }

    if not path.is_file():
        return error_result("Dockerfile not found.")

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except OSError as error:
        return error_result(str(error))

    findings = []
    has_user = False

    def add_finding(issue, severity, line_number, description):
        findings.append({
            "type": issue,
            "severity": severity,
            "line": line_number,
            "description": description
        })

    # Join Dockerfile continuation lines.
    logical_lines = []
    current_line = ""
    start_line = 0

    for number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()

        if not stripped:
            continue

        if stripped.startswith("#") and not current_line:
            continue

        if not current_line:
            start_line = number

        if stripped.endswith("\\"):
            current_line += " " + stripped[:-1]
            continue

        current_line += " " + stripped
        logical_lines.append((start_line, current_line.strip()))
        current_line = ""

    if current_line:
        logical_lines.append((start_line, current_line.strip()))

    for line_number, line in logical_lines:

        upper = line.upper()

        # 1. Check FROM image references.
        if upper.startswith("FROM "):
            parts = line.split()
            image_index = 1

            if len(parts) > 1 and parts[1].upper() == "--PLATFORM":
                image_index = 3
            elif len(parts) > 1 and parts[1].upper().startswith("--PLATFORM="):
                image_index = 2

            if image_index >= len(parts):
                continue

            image = parts[image_index]

            if image.lower() == "scratch" or image.startswith("$"):
                continue

            image_without_digest = image.split("@")[0]
            image_name = image_without_digest.rsplit("/", 1)[-1]

            if ":" not in image_name:
                add_finding(
                    "Unpinned Docker Image",
                    "MEDIUM",
                    line_number,
                    "Use a specific image version or digest instead of an untagged image."
                )

            elif image_name.endswith(":latest"):
                add_finding(
                    "Unpinned Docker Image",
                    "MEDIUM",
                    line_number,
                    "Avoid the latest tag. Pin the image to a specific version or digest."
                )

        # 2. Check USER instruction.
        if upper == "USER" or upper.startswith("USER "):
            parts = line.split(maxsplit=1)

            if len(parts) < 2 or not parts[1].strip():
                add_finding(
                    "Invalid USER Instruction",
                    "HIGH",
                    line_number,
                    "Specify a valid non-root user."
                )
            else:
                has_user = True
                user = parts[1].split(":")[0].strip().lower()

                if user in ("root", "0"):
                    add_finding(
                        "Root User",
                        "HIGH",
                        line_number,
                        "Container explicitly runs as root."
                    )

        # 3. Check ADD instruction.
        if upper.startswith("ADD "):
            add_finding(
                "Use of ADD",
                "LOW",
                line_number,
                "Prefer COPY unless archive extraction or URL functionality is required."
            )

        # 4. Check sensitive exposed ports.
        if upper.startswith("EXPOSE "):
            ports = re.findall(r"\b\d+\b", line)

            sensitive_ports = {
                "22", "2375", "2376", "3306",
                "5432", "6379", "27017"
            }

            for port in set(ports):
                if port in sensitive_ports:
                    add_finding(
                        "Sensitive Port Exposed",
                        "MEDIUM",
                        line_number,
                        f"Potentially sensitive port {port} is exposed."
                    )

        # 5. Check privileged container execution.
        if "--privileged" in line.lower():
            add_finding(
                "Privileged Container",
                "HIGH",
                line_number,
                "Privileged container execution detected."
            )

        # 6. Check hardcoded secrets in ENV and ARG.
        if upper.startswith(("ENV ", "ARG ")):
            secret_pattern = (
                r"\b(PASSWORD|PASSWD|SECRET|API_KEY|"
                r"ACCESS_KEY|TOKEN)\b(?:=|\s+)([^\s]+)"
            )

            match = re.search(secret_pattern, line, re.IGNORECASE)

            if match:
                value = match.group(2).strip("\"'")

                if value and value not in ("$VAR", "${VAR}"):
                    add_finding(
                        "Possible Hardcoded Secret",
                        "HIGH",
                        line_number,
                        "Possible hardcoded secret in ENV or ARG. Use secure secret management."
                    )

        # 7. Check HEALTHCHECK NONE.
        if re.match(r"HEALTHCHECK\s+NONE\b", upper):
            add_finding(
                "Healthcheck Disabled",
                "LOW",
                line_number,
                "HEALTHCHECK NONE disables container health monitoring."
            )

        # 8. Check unsafe remote script execution.
        if re.search(r"\b(curl|wget)\b", line, re.IGNORECASE):
            if re.search(r"\|\s*(?:sh|bash)\b", line, re.IGNORECASE):
                add_finding(
                    "Unsafe Remote Script Execution",
                    "HIGH",
                    line_number,
                    "Remote script is piped directly into a shell."
                )

    # 9. Check whether a non-root USER is specified.
    if not has_user:
        add_finding(
            "Missing USER Instruction",
            "MEDIUM",
            None,
            "No USER instruction found. Review whether the container should run as a non-root user."
        )

    return {
        "scanner": "docker_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }
