"""
Archive Handler & Extraction Security Module for AttackLens SAST

Handles safe extraction of uploaded source-code ZIP files:
- Strict Zip Slip / Path Traversal prevention
- Safe temporary workspace creation and isolation
- Resource limits (ZIP size, uncompressed total size, max file count, single file size limit)
- Protection against symlink escapes, absolute paths, and compression bombs
"""

import os
import shutil
import tempfile
import zipfile
from typing import Dict, Any, Tuple, Optional


# Configurable default safety limits
DEFAULT_MAX_ZIP_SIZE = 500 * 1024 * 1024        # 500 MB
DEFAULT_MAX_EXTRACTED_SIZE = 1024 * 1024 * 1024  # 1 GB
DEFAULT_MAX_FILES_COUNT = 20000                  # 20,000 files
DEFAULT_MAX_SINGLE_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
DEFAULT_MAX_SOURCE_ANALYSIS_SIZE = 10 * 1024 * 1024  # 10 MB


class ArchiveSecurityError(Exception):
    """Custom exception raised when an archive violates security limits or contains malicious patterns."""
    pass


class SafeArchiveWorkspace:
    """
    Manages an isolated temporary workspace for extracting and analyzing an uploaded project archive.
    Ensures safe extraction and deterministic cleanup.
    """

    def __init__(
        self,
        max_zip_size: int = DEFAULT_MAX_ZIP_SIZE,
        max_extracted_size: int = DEFAULT_MAX_EXTRACTED_SIZE,
        max_files_count: int = DEFAULT_MAX_FILES_COUNT,
        max_single_file_size: int = DEFAULT_MAX_SINGLE_FILE_SIZE,
    ):
        self.max_zip_size = max_zip_size
        self.max_extracted_size = max_extracted_size
        self.max_files_count = max_files_count
        self.max_single_file_size = max_single_file_size
        self.temp_dir: Optional[str] = None
        self.extracted_path: Optional[str] = None

    def __enter__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="attacklens_sast_")
        self.extracted_path = os.path.join(self.temp_dir, "workspace")
        os.makedirs(self.extracted_path, exist_ok=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Deterministically remove temporary directories."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass
            self.temp_dir = None
            self.extracted_path = None

    def extract_zip(self, zip_file_or_path) -> Dict[str, Any]:
        """
        Safely extracts an archive to the workspace with rigorous security checks:
        - Validates zip integrity
        - Checks total file count and uncompressed sizes before/during extraction
        - Prevents directory traversal / Zip Slip
        - Resolves and normalizes paths strictly within self.extracted_path

        Returns extraction metadata or raises ArchiveSecurityError.
        """
        if not self.extracted_path:
            raise ArchiveSecurityError("Workspace not initialized.")

        try:
            if isinstance(zip_file_or_path, str):
                if not os.path.exists(zip_file_or_path):
                    raise ArchiveSecurityError(f"Archive file not found: {zip_file_or_path}")
                zip_size = os.path.getsize(zip_file_or_path)
                if zip_size > self.max_zip_size:
                    raise ArchiveSecurityError(
                        f"Archive size ({zip_size / (1024*1024):.1f} MB) exceeds maximum allowed limit ({self.max_zip_size / (1024*1024):.1f} MB)"
                    )
                zf = zipfile.ZipFile(zip_file_or_path, "r")
            else:
                # File-like object (e.g. Django UploadedFile)
                if hasattr(zip_file_or_path, "size") and zip_file_or_path.size > self.max_zip_size:
                    raise ArchiveSecurityError(
                        f"Uploaded file size ({zip_file_or_path.size / (1024*1024):.1f} MB) exceeds maximum limit ({self.max_zip_size / (1024*1024):.1f} MB)"
                    )
                zf = zipfile.ZipFile(zip_file_or_path, "r")
        except zipfile.BadZipFile as e:
            raise ArchiveSecurityError(f"Invalid or corrupted ZIP archive: {str(e)}")
        except Exception as e:
            if isinstance(e, ArchiveSecurityError):
                raise
            raise ArchiveSecurityError(f"Failed to open archive: {str(e)}")

        with zf:
            infolist = zf.infolist()
            if not infolist:
                raise ArchiveSecurityError("The uploaded ZIP archive is empty.")

            if len(infolist) > self.max_files_count:
                raise ArchiveSecurityError(
                    f"Archive contains {len(infolist)} files, exceeding maximum limit of {self.max_files_count} files"
                )

            total_extracted_size = 0
            extracted_files_count = 0
            skipped_files = []
            canonical_workspace = os.path.realpath(self.extracted_path)

            for member in infolist:
                # Check for single file uncompressed size
                if member.file_size > self.max_single_file_size:
                    skipped_files.append({
                        "file": member.filename,
                        "reason": f"File size ({member.file_size / (1024*1024):.1f} MB) exceeds limit ({self.max_single_file_size / (1024*1024):.1f} MB)"
                    })
                    continue

                total_extracted_size += member.file_size
                if total_extracted_size > self.max_extracted_size:
                    raise ArchiveSecurityError(
                        f"Total uncompressed size exceeds maximum allowed limit of {self.max_extracted_size / (1024*1024):.1f} MB"
                    )

                # Normalize member path to prevent Zip Slip (path traversal / absolute paths / escape)
                raw_filename = member.filename.replace("\\", "/")
                # Strip drive letters (e.g. C:) and leading slashes
                if len(raw_filename) > 1 and raw_filename[1] == ":":
                    raw_filename = raw_filename[2:]
                clean_filename = os.path.normpath(raw_filename.lstrip("/"))

                # Strict traversal check
                parts = clean_filename.split(os.sep)
                if ".." in parts or clean_filename.startswith(".."):
                    raise ArchiveSecurityError(
                        f"Zip Slip / Path traversal pattern detected in archive member: '{member.filename}'"
                    )

                target_path = os.path.normpath(os.path.join(canonical_workspace, clean_filename))
                target_real = os.path.realpath(target_path)

                # Enforce containment inside workspace
                if not (target_real == canonical_workspace or target_real.startswith(canonical_workspace + os.sep)):
                    raise ArchiveSecurityError(
                        f"Attempted directory traversal outside workspace for file: '{member.filename}'"
                    )

                # Directories
                if member.is_dir() or raw_filename.endswith("/"):
                    os.makedirs(target_real, exist_ok=True)
                    continue

                # Ensure parent dir exists
                os.makedirs(os.path.dirname(target_real), exist_ok=True)

                # Check if it's a symlink attempt (external attributes for unix symlinks)
                # UNIX mode bits: S_IFLNK = 0o120000
                is_symlink = (member.external_attr >> 16) & 0o120000 == 0o120000
                if is_symlink:
                    # Do not create symlinks from untrusted archives
                    skipped_files.append({
                        "file": member.filename,
                        "reason": "Symbolic links are disallowed for security"
                    })
                    continue

                # Safely write file data
                with zf.open(member) as source_handle, open(target_real, "wb") as target_handle:
                    shutil.copyfileobj(source_handle, target_handle, length=64 * 1024)

                extracted_files_count += 1

            return {
                "workspace_path": self.extracted_path,
                "total_files": len(infolist),
                "extracted_files": extracted_files_count,
                "total_uncompressed_bytes": total_extracted_size,
                "skipped_files": skipped_files
            }
