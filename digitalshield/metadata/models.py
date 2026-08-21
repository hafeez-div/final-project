"""
Data model for extracted metadata results from forensic evidence files.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class MetadataResult(BaseModel):
    """
    Represents all extracted technical and EXIF metadata from a single evidence file.
    This is derived analysis data — it is NOT the original evidence.
    All fields absent in the source file are reported as None, never fabricated.
    """

    # --- Identity ---
    evidence_id: str = Field(description="Associated Evidence ID")
    case_id: str = Field(description="Associated Case ID")
    extraction_timestamp: str = Field(description="UTC ISO 8601 timestamp of when extraction was performed")

    # --- Basic File Properties ---
    filename: Optional[str] = Field(default=None, description="Original filename at ingestion time")
    file_format: Optional[str] = Field(default=None, description="File format (e.g. JPEG, PNG, GIF)")
    mime_type: Optional[str] = Field(default=None, description="MIME type (e.g. image/jpeg)")
    file_size_bytes: Optional[int] = Field(default=None, description="File size in bytes")

    # --- Image Dimensions & Mode ---
    width_px: Optional[int] = Field(default=None, description="Image width in pixels")
    height_px: Optional[int] = Field(default=None, description="Image height in pixels")
    color_mode: Optional[str] = Field(default=None, description="Color mode (e.g. RGB, RGBA, L, CMYK)")

    # --- Camera / Device EXIF ---
    camera_make: Optional[str] = Field(default=None, description="Camera manufacturer (EXIF Make tag)")
    camera_model: Optional[str] = Field(default=None, description="Camera model (EXIF Model tag)")
    software: Optional[str] = Field(default=None, description="Software used (EXIF Software tag)")
    datetime_original: Optional[str] = Field(default=None, description="Original capture date/time (EXIF DateTimeOriginal)")
    datetime_digitized: Optional[str] = Field(default=None, description="Digitization date/time (EXIF DateTimeDigitized)")
    datetime_modified: Optional[str] = Field(default=None, description="Modification date/time (EXIF DateTime)")

    # --- Camera Settings ---
    exposure_time: Optional[str] = Field(default=None, description="Exposure time (EXIF ExposureTime)")
    f_number: Optional[str] = Field(default=None, description="Aperture f-number (EXIF FNumber)")
    iso_speed: Optional[int] = Field(default=None, description="ISO speed rating (EXIF ISOSpeedRatings)")
    focal_length: Optional[str] = Field(default=None, description="Focal length in mm (EXIF FocalLength)")
    flash: Optional[str] = Field(default=None, description="Flash mode (EXIF Flash)")

    # --- GPS ---
    gps_latitude: Optional[str] = Field(default=None, description="GPS latitude (if embedded in EXIF)")
    gps_longitude: Optional[str] = Field(default=None, description="GPS longitude (if embedded in EXIF)")
    gps_altitude: Optional[str] = Field(default=None, description="GPS altitude (if embedded in EXIF)")

    # --- Status ---
    exif_present: bool = Field(default=False, description="Whether EXIF data was found in this file")
    extraction_status: str = Field(default="OK", description="Extraction status: OK or ERROR")
    extraction_error: Optional[str] = Field(default=None, description="Error message if extraction failed")

    def to_dict(self) -> dict:
        """Convert MetadataResult to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "MetadataResult":
        """Construct MetadataResult from dictionary."""
        return cls(**data)
