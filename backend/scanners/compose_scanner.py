
from pathlib import Path

import yaml


def scan_compose(file_path):
    """Scan a Docker Compose file for common security issues."""

    path = Path(file_path)

    if not path.is_file():
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Docker Compose file not found."
        }

    findings = []

    try:
        with path.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

    except yaml.YAMLError as error:
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": f"Invalid YAML: {error}"
        }

    except OSError as error:
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": str(error)
        }

    if not isinstance(config, dict):
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Invalid Compose configuration."
        }

    services = config.get("services")

    if not isinstance(services, dict) or not services:
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "No valid services section found."
        }

    def add_finding(service, issue, severity, description):
        findings.append({
            "type": issue,
            "severity": severity,
            "line": None,
            "description": f"Service '{service}': {description}"
        })

    for service_name, service in services.items():

        if not isinstance(service, dict):
            continue

        # Check privileged mode.
        if service.get("privileged") is True:
            add_finding(
                service_name,
                "Privileged Container",
                "HIGH",
                "Privileged mode is enabled. Avoid granting unrestricted host access."
            )

        # Check host networking.
        if service.get("network_mode") == "host":
            add_finding(
                service_name,
                "Host Network Mode",
                "HIGH",
                "Host networking is enabled. Use an isolated network where possible."
            )

        # Check Docker socket exposure.
        volumes = service.get("volumes", [])

        if isinstance(volumes, list):
            for volume in volumes:
                if isinstance(volume, str) and "docker.sock" in volume:
                    add_finding(
                        service_name,
                        "Docker Socket Exposure",
                        "HIGH",
                        "The Docker socket is mounted into the container."
                    )

                elif isinstance(volume, dict):
                    source = volume.get("source", "")
                    if "docker.sock" in str(source):
                        add_finding(
                            service_name,
                            "Docker Socket Exposure",
                            "HIGH",
                            "The Docker socket is mounted into the container."
                        )

        # Check dangerous capabilities.
        capabilities = service.get("cap_add", [])

        if isinstance(capabilities, list):
            dangerous_capabilities = {
                str(cap).upper() for cap in capabilities
            }

            if "SYS_ADMIN" in dangerous_capabilities:
                add_finding(
                    service_name,
                    "Dangerous Capability",
                    "HIGH",
                    "SYS_ADMIN capability is added to the container."
                )

        # Check image tags.
        image = service.get("image")

        if isinstance(image, str):
            image_name = image.rsplit("@", 1)[0]

            if ":" not in image_name.rsplit("/", 1)[-1]:
                add_finding(
                    service_name,
                    "Unpinned Docker Image",
                    "MEDIUM",
                    "The image has no explicit version tag."
                )

            elif image_name.endswith(":latest"):
                add_finding(
                    service_name,
                    "Unpinned Docker Image",
                    "MEDIUM",
                    "The image uses the latest tag. Specify a fixed version."
                )

    return {
        "scanner": "compose_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }
