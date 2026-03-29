"""Chain-of-custody evidence hashing and manifest management.

Provides SHA-256 based integrity verification for evidence artifacts,
supporting cross-platform forensic evidence handling with integrity guarantees.
"""

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class EvidenceManifest(BaseModel):
    """Evidence integrity manifest with cryptographic hashes.

    Tracks all evidence artifacts with SHA-256 hashes and timestamps
    for chain-of-custody compliance.
    """

    scan_id: str = Field(..., description="Unique scan identifier")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Manifest creation timestamp (UTC)",
    )
    artifacts: dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of artifact names to their SHA-256 hashes",
    )
    manifest_hash: str = Field(
        default="", description="SHA-256 hash of the manifest itself"
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}
        use_enum_values = True


class EvidenceHasher:
    """Cryptographic hasher for evidence integrity verification.

    Uses SHA-256 for reliable, secure hashing of text, files, and
    structured data. Supports manifests for batch integrity verification.

    Example:
        >>> hasher = EvidenceHasher()
        >>> text_hash = hasher.hash_string("evidence data")
        >>> file_hash = hasher.hash_file(Path("scan_results.json"))
        >>> dict_hash = hasher.hash_dict({"key": "value"})
        >>> manifest = hasher.create_manifest({
        ...     "text": text_hash,
        ...     "file": file_hash,
        ...     "dict": dict_hash
        ... })
        >>> is_valid = hasher.verify_manifest(manifest)
    """

    ALGORITHM = "sha256"

    def hash_string(self, data: str) -> str:
        """Compute SHA-256 hash of text data.

        Args:
            data: String data to hash

        Returns:
            Hexadecimal hash value (64 characters)

        Raises:
            TypeError: If data is not a string
        """
        if not isinstance(data, str):
            raise TypeError(f"Expected str, got {type(data).__name__}")

        return sha256(data.encode("utf-8")).hexdigest()

    def hash_file(self, filepath: Path) -> str:
        """Compute SHA-256 hash of a file.

        Uses streaming to handle large files efficiently without
        loading entire file into memory.

        Args:
            filepath: Path to file to hash

        Returns:
            Hexadecimal hash value (64 characters)

        Raises:
            FileNotFoundError: If file does not exist
            IsADirectoryError: If filepath is a directory
            PermissionError: If file cannot be read
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        if filepath.is_dir():
            raise IsADirectoryError(f"Expected file, got directory: {filepath}")

        hasher = sha256()
        chunk_size = 65536  # 64 KB chunks

        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
        except PermissionError as e:
            raise PermissionError(f"Cannot read file: {filepath}") from e

        return hasher.hexdigest()

    def hash_dict(self, data: dict) -> str:
        """Compute SHA-256 hash of a dictionary.

        Serializes dict with sorted keys for deterministic hashing.
        Handles nested structures and typical JSON-serializable types.

        Args:
            data: Dictionary to hash

        Returns:
            Hexadecimal hash value (64 characters)

        Raises:
            TypeError: If data is not a dict
            ValueError: If dict contains non-serializable objects
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        try:
            json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as e:
            raise ValueError(f"Dict contains non-serializable objects: {e}") from e

        return self.hash_string(json_str)

    def create_manifest(
        self, scan_id: str, artifacts: dict[str, str]
    ) -> EvidenceManifest:
        """Create a manifest of all evidence artifacts with hashes.

        Generates a manifest containing all artifact hashes and creates
        a hash of the manifest itself for complete chain-of-custody.

        Args:
            scan_id: Unique scan identifier
            artifacts: Mapping of artifact names to their hashes

        Returns:
            EvidenceManifest with all artifacts and manifest_hash populated

        Raises:
            ValueError: If scan_id is empty or artifacts is empty
        """
        if not scan_id or not scan_id.strip():
            raise ValueError("scan_id cannot be empty")

        if not artifacts:
            raise ValueError("artifacts cannot be empty")

        # Create manifest without manifest_hash
        manifest = EvidenceManifest(scan_id=scan_id, artifacts=artifacts)

        # Compute hash of the manifest content (before adding the hash itself)
        manifest_dict = {
            "scan_id": manifest.scan_id,
            "created_at": manifest.created_at.isoformat(),
            "artifacts": manifest.artifacts,
        }
        manifest.manifest_hash = self.hash_dict(manifest_dict)

        return manifest

    def verify_manifest(self, manifest: EvidenceManifest) -> bool:
        """Verify the integrity of a manifest.

        Recomputes the manifest hash and compares with stored value
        to detect any tampering or corruption.

        Args:
            manifest: EvidenceManifest to verify

        Returns:
            True if manifest integrity verified, False otherwise

        Raises:
            ValueError: If manifest is missing required fields
        """
        if not manifest.scan_id:
            raise ValueError("Manifest missing scan_id")

        if not manifest.artifacts:
            raise ValueError("Manifest missing artifacts")

        if not manifest.manifest_hash:
            raise ValueError("Manifest missing manifest_hash")

        # Recreate the manifest dict for hashing
        manifest_dict = {
            "scan_id": manifest.scan_id,
            "created_at": manifest.created_at.isoformat(),
            "artifacts": manifest.artifacts,
        }

        computed_hash = self.hash_dict(manifest_dict)
        return computed_hash == manifest.manifest_hash
