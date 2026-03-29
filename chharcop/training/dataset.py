"""
Training dataset manager for Chharcop.

Maintains curated lists of known-scam and known-legitimate sites with
ground-truth labels. Supports ingestion from external sources such as
ScamAdviser, VirusTotal, and manual curation.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class SiteEntry(BaseModel):
    """A single labelled site in the training dataset."""

    url: str = Field(..., description="Canonical URL (scheme + domain)")
    label: Literal["scam", "legit"] = Field(..., description="Ground-truth classification")
    source: str = Field(default="manual", description="Where the label came from")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in the label (1.0 = verified, lower = heuristic)",
    )
    added_at: datetime = Field(default_factory=datetime.utcnow)
    notes: str = Field(default="", description="Free-text notes about the site")
    active: bool = Field(default=True, description="Whether to include in training runs")


# ---------------------------------------------------------------------------
# Dataset manager
# ---------------------------------------------------------------------------


class TrainingDataset:
    """
    Manages the SQLite-backed training dataset.

    All site records are stored in ``training_results.db`` (same DB used by
    the Trainer) so that foreign-key relationships can be maintained.

    Usage::

        ds = TrainingDataset(db_path=Path("training_results.db"))
        ds.add_site("https://lookups.io", label="scam", source="manual")
        scam_sites = ds.get_scam_sites()
    """

    # Default seed data — sites whose classification is well-established
    _SEED_SCAMS: list[dict] = [
        {
            "url": "https://lookups.io",
            "source": "manual",
            "confidence": 1.0,
            "notes": "Confirmed scam reverse-lookup / people-finder monetisation site",
        },
        {
            "url": "https://whitepages.com",
            "source": "manual",
            "confidence": 0.8,
            "notes": "Aggressive data-broker practices; included as borderline scam for calibration",
        },
        {
            "url": "https://beenverified.com",
            "source": "manual",
            "confidence": 0.75,
            "notes": "Paid people-search with dark-pattern subscription flows",
        },
    ]

    _SEED_LEGIT: list[dict] = [
        {"url": "https://google.com", "source": "manual", "confidence": 1.0, "notes": ""},
        {"url": "https://github.com", "source": "manual", "confidence": 1.0, "notes": ""},
        {"url": "https://wikipedia.org", "source": "manual", "confidence": 1.0, "notes": ""},
        {"url": "https://bbc.com", "source": "manual", "confidence": 1.0, "notes": ""},
        {"url": "https://microsoft.com", "source": "manual", "confidence": 1.0, "notes": ""},
    ]

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init_db()
        self._seed()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create the sites table if it does not exist."""
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS training_sites (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    url         TEXT    NOT NULL UNIQUE,
                    label       TEXT    NOT NULL CHECK(label IN ('scam', 'legit')),
                    source      TEXT    NOT NULL DEFAULT 'manual',
                    confidence  REAL    NOT NULL DEFAULT 1.0,
                    added_at    TEXT    NOT NULL,
                    notes       TEXT    NOT NULL DEFAULT '',
                    active      INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            con.commit()

    def _seed(self) -> None:
        """Insert seed sites if the table is empty."""
        with sqlite3.connect(self.db_path) as con:
            count = con.execute("SELECT COUNT(*) FROM training_sites").fetchone()[0]
            if count > 0:
                return

        for entry in self._SEED_SCAMS:
            self.add_site(entry["url"], label="scam", **{k: v for k, v in entry.items() if k != "url"})
        for entry in self._SEED_LEGIT:
            self.add_site(entry["url"], label="legit", **{k: v for k, v in entry.items() if k != "url"})

        logger.info("Training dataset seeded with {} sites", len(self._SEED_SCAMS) + len(self._SEED_LEGIT))

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_site(
        self,
        url: str,
        *,
        label: Literal["scam", "legit"],
        source: str = "manual",
        confidence: float = 1.0,
        notes: str = "",
        active: bool = True,
    ) -> bool:
        """
        Add a site to the dataset.

        Returns True if inserted, False if the URL already exists.
        """
        entry = SiteEntry(
            url=url,
            label=label,
            source=source,
            confidence=confidence,
            notes=notes,
            active=active,
        )
        try:
            with sqlite3.connect(self.db_path) as con:
                con.execute(
                    "INSERT INTO training_sites (url, label, source, confidence, added_at, notes, active) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.url,
                        entry.label,
                        entry.source,
                        entry.confidence,
                        entry.added_at.isoformat(),
                        entry.notes,
                        int(entry.active),
                    ),
                )
                con.commit()
            logger.debug("Added {} site: {}", label, url)
            return True
        except sqlite3.IntegrityError:
            logger.debug("Site already in dataset: {}", url)
            return False

    def ingest_from_json(self, path: Path) -> int:
        """
        Bulk-ingest sites from a JSON file.

        Expected format::

            [{"url": "...", "label": "scam", "source": "...", "confidence": 0.9}, ...]

        Returns the number of new sites added.
        """
        data: list[dict] = json.loads(path.read_text(encoding="utf-8"))
        added = 0
        for item in data:
            url = item.get("url", "").strip()
            label = item.get("label", "")
            if not url or label not in ("scam", "legit"):
                logger.warning("Skipping malformed entry: {}", item)
                continue
            if self.add_site(
                url,
                label=label,  # type: ignore[arg-type]
                source=item.get("source", "import"),
                confidence=float(item.get("confidence", 0.9)),
                notes=item.get("notes", ""),
            ):
                added += 1
        logger.info("Ingested {} new sites from {}", added, path)
        return added

    def ingest_from_virustotal(self, urls: list[str], label: Literal["scam", "legit"]) -> int:
        """
        Mark a batch of URLs as scam/legit sourced from VirusTotal.

        The caller is responsible for performing the VT lookups; this method
        only stores the results.
        """
        added = 0
        for url in urls:
            if self.add_site(url, label=label, source="virustotal", confidence=0.9):
                added += 1
        return added

    def ingest_from_scamadviser(self, entries: list[dict]) -> int:
        """
        Ingest entries sourced from ScamAdviser.

        Each entry should have keys: ``url``, ``score`` (0-100, lower = scammer).
        Sites with score < 40 are labelled scam, ≥ 70 legit, 40-69 are skipped.
        """
        added = 0
        for item in entries:
            url = item.get("url", "").strip()
            score = int(item.get("score", 50))
            if not url:
                continue
            if score < 40:
                label: Literal["scam", "legit"] = "scam"
                conf = round(1.0 - score / 100, 2)
            elif score >= 70:
                label = "legit"
                conf = round(score / 100, 2)
            else:
                continue  # grey area — skip
            if self.add_site(url, label=label, source="scamadviser", confidence=conf):
                added += 1
        return added

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_scam_sites(self, active_only: bool = True) -> list[SiteEntry]:
        """Return all scam-labelled sites."""
        return self._query("scam", active_only)

    def get_legit_sites(self, active_only: bool = True) -> list[SiteEntry]:
        """Return all legit-labelled sites."""
        return self._query("legit", active_only)

    def get_all_sites(self, active_only: bool = True) -> list[SiteEntry]:
        """Return all sites regardless of label."""
        sql = "SELECT url, label, source, confidence, added_at, notes, active FROM training_sites"
        params: list = []
        if active_only:
            sql += " WHERE active = 1"
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(sql, params).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def total_count(self) -> dict[str, int]:
        """Return a dict with counts by label."""
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(
                "SELECT label, COUNT(*) FROM training_sites WHERE active=1 GROUP BY label"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _query(self, label: str, active_only: bool) -> list[SiteEntry]:
        sql = "SELECT url, label, source, confidence, added_at, notes, active FROM training_sites WHERE label=?"
        params: list = [label]
        if active_only:
            sql += " AND active=1"
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(sql, params).fetchall()
        return [self._row_to_entry(r) for r in rows]

    @staticmethod
    def _row_to_entry(row: tuple) -> SiteEntry:
        url, label, source, confidence, added_at, notes, active = row
        return SiteEntry(
            url=url,
            label=label,  # type: ignore[arg-type]
            source=source,
            confidence=confidence,
            added_at=datetime.fromisoformat(added_at),
            notes=notes or "",
            active=bool(active),
        )
