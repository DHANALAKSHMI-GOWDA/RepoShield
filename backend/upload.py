
import io
import logging
import shutil
import stat
import tempfile
import zipfile

from pathlib import Path, PurePosixPath

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.coordinator import (
    run_all_scanners,
    calculate_security_score
)
from backend.database import save_scan

router = APIRouter()

logger = logging.getLogger(__name__)

# Upload and extraction limits
MAX_UPLOAD_SIZE = 20 * 1024 * 1024       # 20 MB
MAX_EXTRACTED_SIZE = 100 * 1024 * 1024   # 100 MB
MAX_FILES = 2000


def safe_extract(zip_file, destination):
    """
    Extract ZIP contents without allowing path traversal,
    symbolic links, encrypted files or excessive extraction.
    """

    destination = Path(destination).resolve()
    extracted_size = 0
    seen_paths = set()
    file_count = 0

    for member in zip_file.infolist():

        name = member.filename

        # Reject suspicious path formats
        if not name or "\\" in name:
            raise ValueError("Unsafe file path in ZIP archive")

        path = PurePosixPath(name)

        if path.is_absolute() or ".." in path.parts:
            raise ValueError("ZIP contains an unsafe path")

        if path.parts and ":" in path.parts[0]:
            raise ValueError("ZIP contains an unsafe drive path")

        if name in seen_paths:
            raise ValueError("ZIP contains duplicate file paths")

        seen_paths.add(name)

        # Reject symbolic links
        mode = member.external_attr >> 16

        if stat.S_ISLNK(mode):
            raise ValueError("Symbolic links are not allowed")

        # Reject encrypted files
        if member.flag_bits & 0x1:
            raise ValueError("Encrypted ZIP files are not supported")

        target = destination.joinpath(*path.parts).resolve()

        if not target.is_relative_to(destination):
            raise ValueError("ZIP path escapes extraction directory")

        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        file_count += 1

        if file_count > MAX_FILES:
            raise ValueError("ZIP contains too many files")

        extracted_size += member.file_size

        if extracted_size > MAX_EXTRACTED_SIZE:
            raise ValueError("Extracted files exceed the size limit")

        target.parent.mkdir(parents=True, exist_ok=True)

        with zip_file.open(member) as source:
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)


@router.post("/scan")
async def scan_repository(file: UploadFile = File(...)):

    # Check filename
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a ZIP file"
        )

    # Read with an upload size limit
    contents = await file.read(MAX_UPLOAD_SIZE + 1)
    await file.close()

    if len(contents) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Upload exceeds the 20 MB limit"
        )

    # Validate ZIP format
    if not zipfile.is_zipfile(io.BytesIO(contents)):
        raise HTTPException(
            status_code=400,
            detail="Invalid or corrupted ZIP file"
        )

    repository_name = Path(file.filename).stem

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as archive:

            with tempfile.TemporaryDirectory(
                prefix="reposhield_"
            ) as temp_dir:

                extracted_path = Path(temp_dir)

                safe_extract(archive, extracted_path)

                # Run all available scanners
                result = run_all_scanners(extracted_path)

                findings = result["findings"]
                scanner_errors = result["scanner_errors"]
                skipped_scanners = result["skipped_scanners"]

                # Do not present an incomplete scan as a clean scan
                if scanner_errors:
                    return {
                        "status": "partial",
                        "message": "Some scanners could not complete",
                        "repository": repository_name,
                        "security_score": None,
                        "total_findings": len(findings),
                        "findings": findings,
                        "scanner_errors": scanner_errors,
                        "skipped_scanners": skipped_scanners,
                        "scan_id": None
                    }

                score = calculate_security_score(findings)

                scan_id = save_scan(
                    repository_name,
                    score,
                    findings
                )

                return {
                    "status": "completed",
                    "message": "Repository scan completed successfully",
                    "repository": repository_name,
                    "security_score": score,
                    "total_findings": len(findings),
                    "findings": findings,
                    "scanner_errors": [],
                    "skipped_scanners": skipped_scanners,
                    "scan_id": scan_id 
                }

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=400,
            detail="Invalid ZIP archive"
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        logger.exception("Repository scanning failed")

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during scanning"
        )
