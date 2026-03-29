"""
Phone and voicemail intake module for Chharcop.

Accepts scam reports via:
- Forwarded SMS (received as email via an SMS gateway)
- Voicemail audio files (attached to emails or uploaded directly)

Processing pipeline:
1. Parse phone numbers from text content
2. Reverse lookup the number (via PhoneInfoga or similar)
3. Transcribe voicemail audio via OpenAI Whisper (if available)
4. Extract scam indicators from transcription
5. Auto-create investigation cases

Configuration (environment variables)::

    CHHARCOP_WHISPER_MODEL  — Whisper model size (default: base)
    OPENAI_API_KEY          — For Whisper API (optional, local model used by default)
"""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx
from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PhoneCase(BaseModel):
    """An investigation case originating from a phone/SMS/voicemail report."""

    case_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    intake_source: str = "phone"
    phone_number: str
    raw_text: str = ""
    voicemail_path: Optional[str] = None
    transcription: Optional[str] = None
    scam_indicators: list[str] = Field(default_factory=list)
    reverse_lookup: dict[str, Any] = Field(default_factory=dict)
    status: str = "queued"
    scan_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    notes: str = ""


class ReversePhoneLookup(BaseModel):
    """Result of a reverse phone number lookup."""

    number: str
    carrier: Optional[str] = None
    line_type: Optional[str] = None  # mobile, landline, voip
    country: Optional[str] = None
    region: Optional[str] = None
    is_voip: bool = False
    reported_scam: bool = False
    scam_report_count: int = 0
    lookup_source: str = ""
    queried_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Scam indicator keywords
# ---------------------------------------------------------------------------

_SCAM_KEYWORDS: list[str] = [
    "social security",
    "irs",
    "internal revenue",
    "warrant",
    "arrest",
    "lawsuit",
    "suspended",
    "amazon",
    "prize",
    "winner",
    "gift card",
    "wire transfer",
    "crypto",
    "bitcoin",
    "refund",
    "account compromised",
    "verify your",
    "limited time",
    "act now",
    "call immediately",
    "do not hang up",
    "legal action",
    "federal agent",
    "bank fraud",
    "overdraft",
]

# Phone number extraction pattern
_PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?"
    r"\(?([0-9]{3})\)?"
    r"[-.\s]?"
    r"([0-9]{3})"
    r"[-.\s]?"
    r"([0-9]{4})",
)

# Audio file extensions supported by Whisper
_AUDIO_EXTENSIONS: set[str] = {".mp3", ".mp4", ".wav", ".m4a", ".ogg", ".flac", ".webm"}


# ---------------------------------------------------------------------------
# PhoneIntake
# ---------------------------------------------------------------------------


class PhoneIntake:
    """
    Processes forwarded SMS texts and voicemail audio files to create
    phone-scam investigation cases.

    Usage::

        intake = PhoneIntake()

        # From a forwarded SMS text
        case = await intake.process_text(
            text="Your account is suspended. Call 1-800-FAKE-IRS now.",
            source="sms_forward"
        )

        # From a voicemail audio file
        case = await intake.process_voicemail(Path("voicemail.mp3"))
    """

    def __init__(
        self,
        db_path: Path | None = None,
        whisper_model: str | None = None,
        voicemail_dir: Path | None = None,
    ) -> None:
        self.db_path = db_path or Path("intake.db")
        self.whisper_model = whisper_model or os.getenv("CHHARCOP_WHISPER_MODEL", "base")
        self.voicemail_dir = voicemail_dir or Path("voicemails")
        self.voicemail_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS phone_cases (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id         TEXT    NOT NULL UNIQUE,
                    intake_source   TEXT    NOT NULL DEFAULT 'phone',
                    phone_number    TEXT    NOT NULL,
                    raw_text        TEXT    NOT NULL DEFAULT '',
                    voicemail_path  TEXT,
                    transcription   TEXT,
                    scam_indicators TEXT    NOT NULL DEFAULT '[]',
                    reverse_lookup  TEXT    NOT NULL DEFAULT '{}',
                    status          TEXT    NOT NULL DEFAULT 'queued',
                    scan_id         TEXT,
                    created_at      TEXT    NOT NULL,
                    completed_at    TEXT,
                    notes           TEXT    NOT NULL DEFAULT ''
                )
                """
            )
            con.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def process_text(
        self, text: str, source: str = "sms_forward"
    ) -> list[PhoneCase]:
        """
        Extract phone numbers from *text* and create an investigation case
        for each unique number found.

        Args:
            text: Raw SMS or email body text.
            source: Intake channel label (e.g. ``"sms_forward"``).

        Returns:
            List of created :class:`PhoneCase` objects.
        """
        phones = self._extract_phones(text)
        if not phones:
            logger.debug("No phone numbers found in text")
            return []

        cases: list[PhoneCase] = []
        for phone in phones:
            indicators = self._detect_scam_indicators(text)
            lookup = await self.reverse_lookup(phone)

            case = PhoneCase(
                intake_source=source,
                phone_number=phone,
                raw_text=text[:2000],  # truncate very long texts
                scam_indicators=indicators,
                reverse_lookup=lookup.model_dump(mode="json"),
                notes=f"Extracted from {source} text",
            )
            self._save_case(case)
            cases.append(case)
            logger.info("Phone case {} created for {}", case.case_id, phone)

        return cases

    async def process_voicemail(
        self, audio_path: Path, phone_number: str = "", source: str = "voicemail"
    ) -> Optional[PhoneCase]:
        """
        Transcribe a voicemail audio file and create an investigation case.

        Args:
            audio_path: Path to the audio file.
            phone_number: Known caller number (may be empty).
            source: Intake channel label.

        Returns:
            Created :class:`PhoneCase`, or ``None`` if processing failed.
        """
        if audio_path.suffix.lower() not in _AUDIO_EXTENSIONS:
            logger.warning("Unsupported audio format: {}", audio_path.suffix)
            return None

        # Copy to voicemails dir for archiving
        dest = self.voicemail_dir / audio_path.name
        if not dest.exists():
            import shutil
            shutil.copy2(audio_path, dest)

        transcription = await self.transcribe_audio(dest)
        if not transcription:
            transcription = ""

        phones = [phone_number] if phone_number else self._extract_phones(transcription)
        primary_phone = phones[0] if phones else "unknown"
        indicators = self._detect_scam_indicators(transcription)

        lookup = ReversePhoneLookup(number=primary_phone)
        if primary_phone != "unknown":
            lookup = await self.reverse_lookup(primary_phone)

        case = PhoneCase(
            intake_source=source,
            phone_number=primary_phone,
            voicemail_path=str(dest),
            transcription=transcription,
            scam_indicators=indicators,
            reverse_lookup=lookup.model_dump(mode="json"),
            notes=f"Voicemail: {audio_path.name}",
        )
        self._save_case(case)
        logger.info("Voicemail case {} created for {}", case.case_id, primary_phone)
        return case

    async def transcribe_audio(self, audio_path: Path) -> str:
        """
        Transcribe an audio file using Whisper.

        Tries local ``whisper`` library first; falls back to OpenAI Whisper API
        if ``OPENAI_API_KEY`` is set.

        Returns the transcription text, or empty string on failure.
        """
        # Try local Whisper
        try:
            import whisper  # type: ignore[import]

            model = await asyncio.get_event_loop().run_in_executor(
                None, whisper.load_model, self.whisper_model
            )
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: model.transcribe(str(audio_path))
            )
            text: str = result.get("text", "").strip()
            logger.info("Whisper transcription complete ({} chars)", len(text))
            return text
        except ImportError:
            logger.debug("Local whisper not installed, trying OpenAI API")
        except Exception as exc:
            logger.warning("Local Whisper failed: {}", exc)

        # Try OpenAI Whisper API
        api_key = os.getenv("OPENAI_API_KEY", "")
        if api_key:
            return await self._transcribe_openai(audio_path, api_key)

        logger.warning(
            "No transcription available. Install whisper: pip install openai-whisper"
        )
        return ""

    async def reverse_lookup(self, phone: str) -> ReversePhoneLookup:
        """
        Perform a reverse phone number lookup.

        Queries the free numverify / abstract phone validation API.
        Falls back gracefully if no API key is configured.

        Args:
            phone: Phone number string (digits only or formatted).

        Returns:
            :class:`ReversePhoneLookup` with whatever data was obtainable.
        """
        # Normalise to digits only
        digits = re.sub(r"\D", "", phone)

        # Try AbstractAPI (free tier, no key required for basic lookups)
        api_key = os.getenv("CHHARCOP_PHONE_API_KEY", "")
        if not api_key:
            # Return minimal result without lookup
            return ReversePhoneLookup(
                number=digits,
                lookup_source="none (no API key configured)",
            )

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://phonevalidation.abstractapi.com/v1/",
                    params={"api_key": api_key, "phone": digits},
                )
                data = resp.json()
                carrier = data.get("carrier", {})
                location = data.get("location", {})
                return ReversePhoneLookup(
                    number=digits,
                    carrier=carrier.get("name"),
                    line_type=carrier.get("type"),
                    country=data.get("country", {}).get("name"),
                    region=location,
                    is_voip=carrier.get("type", "").lower() == "voip",
                    lookup_source="abstractapi",
                )
        except Exception as exc:
            logger.warning("Phone lookup failed for {}: {}", phone, exc)
            return ReversePhoneLookup(number=digits, lookup_source="failed")

    def list_cases(self, status: str | None = None) -> list[PhoneCase]:
        """Return phone intake cases, optionally filtered by status."""
        sql = (
            "SELECT case_id, intake_source, phone_number, raw_text, voicemail_path, "
            "transcription, scam_indicators, reverse_lookup, status, scan_id, "
            "created_at, completed_at, notes FROM phone_cases"
        )
        params: list = []
        if status:
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY id DESC"
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(sql, params).fetchall()
        return [self._row_to_case(r) for r in rows]

    def status_snapshot(self) -> dict[str, Any]:
        """Return phone intake stats for chharcop-status.json."""
        with sqlite3.connect(self.db_path) as con:
            total = con.execute(
                "SELECT COUNT(*) FROM phone_cases"
            ).fetchone()[0]
            auto_inv = con.execute(
                "SELECT COUNT(*) FROM phone_cases WHERE status != 'queued'"
            ).fetchone()[0]
            pending = con.execute(
                "SELECT COUNT(*) FROM phone_cases WHERE status='queued'"
            ).fetchone()[0]
        return {
            "total_received": total,
            "auto_investigated": auto_inv,
            "pending": pending,
        }

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_phones(text: str) -> list[str]:
        """Extract unique phone numbers from text."""
        matches = _PHONE_RE.findall(text)
        return sorted(set("".join(m) for m in matches))

    @staticmethod
    def _detect_scam_indicators(text: str) -> list[str]:
        """Return list of scam keywords found in text (case-insensitive)."""
        text_lower = text.lower()
        return [kw for kw in _SCAM_KEYWORDS if kw in text_lower]

    # ------------------------------------------------------------------
    # OpenAI Whisper API fallback
    # ------------------------------------------------------------------

    @staticmethod
    async def _transcribe_openai(audio_path: Path, api_key: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                with audio_path.open("rb") as f:
                    resp = await client.post(
                        "https://api.openai.com/v1/audio/transcriptions",
                        headers={"Authorization": f"Bearer {api_key}"},
                        data={"model": "whisper-1"},
                        files={"file": (audio_path.name, f, "audio/mpeg")},
                    )
                    resp.raise_for_status()
                    return resp.json().get("text", "")
        except Exception as exc:
            logger.warning("OpenAI transcription failed: {}", exc)
            return ""

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _save_case(self, case: PhoneCase) -> None:
        import json

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT OR IGNORE INTO phone_cases "
                "(case_id, intake_source, phone_number, raw_text, voicemail_path, "
                "transcription, scam_indicators, reverse_lookup, status, scan_id, created_at, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case.case_id,
                    case.intake_source,
                    case.phone_number,
                    case.raw_text,
                    case.voicemail_path,
                    case.transcription,
                    json.dumps(case.scam_indicators),
                    json.dumps(case.reverse_lookup),
                    case.status,
                    case.scan_id,
                    case.created_at.isoformat(),
                    case.notes,
                ),
            )
            con.commit()

    @staticmethod
    def _row_to_case(row: tuple) -> PhoneCase:
        import json

        (
            case_id, intake_source, phone_number, raw_text, voicemail_path,
            transcription, scam_indicators_json, reverse_lookup_json, status,
            scan_id, created_at, completed_at, notes,
        ) = row
        return PhoneCase(
            case_id=case_id,
            intake_source=intake_source,
            phone_number=phone_number,
            raw_text=raw_text or "",
            voicemail_path=voicemail_path,
            transcription=transcription,
            scam_indicators=json.loads(scam_indicators_json or "[]"),
            reverse_lookup=json.loads(reverse_lookup_json or "{}"),
            status=status,
            scan_id=scan_id,
            created_at=datetime.fromisoformat(created_at),
            completed_at=datetime.fromisoformat(completed_at) if completed_at else None,
            notes=notes or "",
        )
