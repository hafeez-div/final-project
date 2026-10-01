"""
MetadataExtractor: reads technical and EXIF metadata from preserved read-only evidence files.

FORENSIC RULES:
  - NEVER modifies original or preserved evidence files.
  - NEVER invents missing metadata fields — absent fields are reported as None.
  - Metadata results are derived analysis, NOT original evidence.
  - Never claim extracted metadata proves authenticity, ownership, or authorship.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.metadata.models import MetadataResult
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore


# EXIF tag IDs to human-readable keys (subset of standard EXIF tags via Pillow)
EXIF_TAGS_OF_INTEREST = {
    271: "Make",
    272: "Model",
    305: "Software",
    306: "DateTime",
    36867: "DateTimeOriginal",
    36868: "DateTimeDigitized",
    33434: "ExposureTime",
    33437: "FNumber",
    34855: "ISOSpeedRatings",
    37386: "FocalLength",
    37385: "Flash",
}

GPS_TAG_ID = 34853  # GPSInfo IFD pointer tag


class MetadataExtractor:
    """
    Reads technical file properties and EXIF data from preserved evidence.
    Results are stored under the existing JSONStore without touching evidence files.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.evidence_manager = EvidenceManager(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rational_to_str(value) -> str:
        """Convert a Pillow IFDRational or tuple fraction to human-readable string."""
        try:
            if hasattr(value, "numerator") and hasattr(value, "denominator"):
                return f"{value.numerator}/{value.denominator}"
            if isinstance(value, tuple) and len(value) == 2:
                return f"{value[0]}/{value[1]}"
            return str(value)
        except Exception:
            return str(value)

    @staticmethod
    def _dms_to_decimal(dms_tuple, ref: str) -> str:
        """
        Convert GPS degrees/minutes/seconds tuple to decimal degrees string.
        Never raises — returns raw string fallback if conversion fails.
        """
        try:
            degrees = float(dms_tuple[0])
            minutes = float(dms_tuple[1])
            seconds = float(dms_tuple[2])
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            if ref in ("S", "W"):
                decimal = -decimal
            return f"{decimal:.6f}"
        except Exception:
            return str(dms_tuple)

    def _extract_gps(self, gps_info: dict) -> tuple:
        """
        Extract latitude, longitude, and altitude from GPSInfo dict.
        Returns (lat_str, lon_str, alt_str), each None if unavailable.
        """
        lat = lon = alt = None
        try:
            if 2 in gps_info and 1 in gps_info:
                lat = self._dms_to_decimal(gps_info[2], str(gps_info[1]))
            if 4 in gps_info and 3 in gps_info:
                lon = self._dms_to_decimal(gps_info[4], str(gps_info[3]))
            if 6 in gps_info:
                alt = self._rational_to_str(gps_info[6]) + " m"
        except Exception:
            pass
        return lat, lon, alt

    def _parse_exif(self, img) -> dict:
        """
        Parse EXIF data from an open Pillow image.
        Returns a dict of extracted fields; absent fields are omitted (will become None in model).
        """
        result = {}
        try:
            raw_exif = img.getexif()
            if not raw_exif:
                return result

            result["exif_present"] = True

            for tag_id, field_name in EXIF_TAGS_OF_INTEREST.items():
                value = raw_exif.get(tag_id)
                if value is None:
                    continue
                # Convert rational numbers
                if hasattr(value, "numerator"):
                    result[field_name] = self._rational_to_str(value)
                elif isinstance(value, bytes):
                    try:
                        result[field_name] = value.decode("utf-8", errors="replace").strip()
                    except Exception:
                        result[field_name] = repr(value)
                else:
                    result[field_name] = str(value).strip()

            # GPS
            gps_raw = raw_exif.get_ifd(GPS_TAG_ID)
            if gps_raw:
                lat, lon, alt = self._extract_gps(gps_raw)
                if lat is not None:
                    result["gps_latitude"] = lat
                if lon is not None:
                    result["gps_longitude"] = lon
                if alt is not None:
                    result["gps_altitude"] = alt

        except Exception:
            pass

        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, evidence_id: str) -> MetadataResult:
        """
        Extract metadata from a preserved evidence file identified by evidence_id.

        IMPORTANT:
          - Opens preserved vault copy in read-only mode (rb).
          - Never writes to or modifies any evidence file.
          - Missing fields are reported as None — never fabricated.
        """
        from PIL import Image, UnidentifiedImageError  # local import to keep module lightweight

        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Resolve evidence record
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' not found.")

        preserved_path = Path(evidence.stored_path)
        if not preserved_path.exists():
            raise FileNotFoundError(
                f"Preserved evidence file not found on disk: {preserved_path}"
            )

        # Base result scaffolding
        base = dict(
            evidence_id=evidence_id,
            case_id=evidence.case_id,
            extraction_timestamp=timestamp,
            filename=evidence.original_filename,
            mime_type=evidence.mime_type,
            file_size_bytes=evidence.file_size,
            extraction_status="OK",
        )

        try:
            # 2. Open read-only — Pillow does not modify source file
            with open(preserved_path, "rb") as fh:
                img = Image.open(fh)
                img.load()  # load pixel data so we can close file handle safely

            base["file_format"] = img.format or None
            if img.format and hasattr(Image, "MIME") and img.format in Image.MIME:
                base["mime_type"] = Image.MIME[img.format]
            base["width_px"] = img.width
            base["height_px"] = img.height
            base["color_mode"] = img.mode

            # 3. EXIF extraction
            exif_data = self._parse_exif(img)
            base["exif_present"] = exif_data.pop("exif_present", False)

            # Map EXIF fields to model fields
            base["camera_make"] = exif_data.get("Make")
            base["camera_model"] = exif_data.get("Model")
            base["software"] = exif_data.get("Software")
            base["datetime_original"] = exif_data.get("DateTimeOriginal")
            base["datetime_digitized"] = exif_data.get("DateTimeDigitized")
            base["datetime_modified"] = exif_data.get("DateTime")
            base["exposure_time"] = exif_data.get("ExposureTime")
            base["f_number"] = exif_data.get("FNumber")
            iso = exif_data.get("ISOSpeedRatings")
            base["iso_speed"] = int(iso) if iso is not None else None
            base["focal_length"] = exif_data.get("FocalLength")
            base["flash"] = exif_data.get("Flash")
            base["gps_latitude"] = exif_data.get("gps_latitude")
            base["gps_longitude"] = exif_data.get("gps_longitude")
            base["gps_altitude"] = exif_data.get("gps_altitude")

        except UnidentifiedImageError:
            # Non-image format (e.g. PDF, TXT) — report basic fields only
            base["extraction_status"] = "OK"
            base["exif_present"] = False
        except Exception as exc:
            base["extraction_status"] = "ERROR"
            base["extraction_error"] = str(exc)
            base["exif_present"] = False

        result = MetadataResult(**base)

        # 4. Persist metadata result under existing store
        self.store.save_metadata(result.to_dict())

        # 5. Audit log
        self.audit_logger.log_event(
            action="METADATA_EXTRACTED",
            details={
                "evidence_id": evidence_id,
                "case_id": evidence.case_id,
                "status": result.extraction_status,
                "exif_present": result.exif_present,
                "file_format": result.file_format,
            },
            actor="DigitalShield Metadata Engine"
        )

        return result

    def get_metadata(self, evidence_id: str) -> Optional[MetadataResult]:
        """Retrieve previously stored metadata result for an evidence ID."""
        data = self.store.get_metadata(evidence_id)
        if data:
            return MetadataResult.from_dict(data)
        return None
