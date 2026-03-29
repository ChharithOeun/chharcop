"""
Reporting form structure checker for Chharcop.

Periodically fetches each agency's reporting page, extracts form field names,
and compares them against the stored template.  If the form has changed an
alert is emitted so the pre-fill templates can be updated.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from bs4 import BeautifulSoup
from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FormSnapshot(BaseModel):
    """A scrape of a form's field structure at a specific point in time."""

    agency: str
    form_url: str
    field_names: list[str] = Field(default_factory=list)
    scraped_at: datetime = Field(default_factory=datetime.utcnow)
    checksum: str = ""  # SHA-256 of sorted field_names


class FormDiff(BaseModel):
    """Difference between a stored template and the live form."""

    agency: str
    form_url: str
    added_fields: list[str] = Field(default_factory=list)
    removed_fields: list[str] = Field(default_factory=list)
    template_version: str = ""
    checked_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def has_changes(self) -> bool:
        return bool(self.added_fields or self.removed_fields)


# ---------------------------------------------------------------------------
# FormChecker
# ---------------------------------------------------------------------------


class FormChecker:
    """
    Scrapes agency form pages and compares their field structure against
    stored templates.

    Usage::

        checker = FormChecker(templates_dir=Path("report_templates"))
        diffs = await checker.check_all()
        for diff in diffs:
            if diff.has_changes:
                print(f"{diff.agency}: form changed!")
    """

    # Timeout for HTTP requests in seconds
    REQUEST_TIMEOUT: float = 20.0

    # Known form URLs per agency (mirrors auto_submit.py _AGENCY_TEMPLATES)
    FORM_URLS: dict[str, str] = {
        "ftc": "https://reportfraud.ftc.gov/",
        "fbi_ic3": "https://www.ic3.gov/complaint/default.aspx",
        "google_safe_browsing": "https://safebrowsing.google.com/safebrowsing/report_phish/",
        "apwg_ecx": "https://ecx.apwg.org/",
    }

    def __init__(
        self,
        templates_dir: Path | None = None,
        db_path: Path | None = None,
    ) -> None:
        self.templates_dir = templates_dir or Path("report_templates")
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path or Path("reports.db")
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS form_checks (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    agency          TEXT    NOT NULL,
                    form_url        TEXT    NOT NULL,
                    field_names_json TEXT   NOT NULL,
                    checksum        TEXT    NOT NULL,
                    has_changes     INTEGER NOT NULL DEFAULT 0,
                    added_fields    TEXT    NOT NULL DEFAULT '[]',
                    removed_fields  TEXT    NOT NULL DEFAULT '[]',
                    checked_at      TEXT    NOT NULL
                )
                """
            )
            con.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_all(self) -> list[FormDiff]:
        """Check all known agency forms. Returns a list of diff results."""
        results: list[FormDiff] = []
        async with httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "Chharcop/0.2 FormChecker (research tool)"},
        ) as client:
            for agency, url in self.FORM_URLS.items():
                diff = await self._check_one(agency, url, client)
                results.append(diff)
                self._persist(diff)
        return results

    async def check_agency(self, agency: str) -> FormDiff:
        """Check a single agency form."""
        url = self.FORM_URLS.get(agency)
        if not url:
            raise ValueError(f"Unknown agency: {agency}")
        async with httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            diff = await self._check_one(agency, url, client)
        self._persist(diff)
        return diff

    def history(self, agency: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent form-check results from DB."""
        sql = (
            "SELECT agency, form_url, field_names_json, checksum, has_changes, "
            "added_fields, removed_fields, checked_at FROM form_checks"
        )
        params: list = []
        if agency:
            sql += " WHERE agency=?"
            params.append(agency)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(sql, params).fetchall()
        return [
            {
                "agency": r[0],
                "form_url": r[1],
                "field_names": json.loads(r[2]),
                "checksum": r[3],
                "has_changes": bool(r[4]),
                "added_fields": json.loads(r[5]),
                "removed_fields": json.loads(r[6]),
                "checked_at": r[7],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _check_one(
        self, agency: str, url: str, client: httpx.AsyncClient
    ) -> FormDiff:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            live_fields = self._extract_fields(resp.text)
        except Exception as exc:
            logger.warning("Could not fetch {} form: {}", agency, exc)
            live_fields = []

        template_fields = self._load_template_fields(agency)
        template_version = self._load_template_version(agency)

        added = sorted(set(live_fields) - set(template_fields))
        removed = sorted(set(template_fields) - set(live_fields))

        diff = FormDiff(
            agency=agency,
            form_url=url,
            added_fields=added,
            removed_fields=removed,
            template_version=template_version,
        )

        if diff.has_changes:
            logger.warning(
                "Form change detected for {}: +{} fields, -{} fields",
                agency,
                len(added),
                len(removed),
            )
        else:
            logger.debug("Form unchanged for {}", agency)

        return diff

    @staticmethod
    def _extract_fields(html: str) -> list[str]:
        """Extract all form input/select/textarea names from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        names: list[str] = []
        for tag in soup.find_all(["input", "select", "textarea"]):
            name = tag.get("name") or tag.get("id") or ""
            name = name.strip()
            if name and name not in names:
                names.append(name)
        return sorted(names)

    def _load_template_fields(self, agency: str) -> list[str]:
        path = self.templates_dir / f"{agency}.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data.get("field_names", [])
        except Exception:
            return []

    def _load_template_version(self, agency: str) -> str:
        path = self.templates_dir / f"{agency}.json"
        if not path.exists():
            return ""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data.get("version", "")
        except Exception:
            return ""

    def update_template(self, agency: str, live_snapshot: FormSnapshot) -> None:
        """
        Update the stored template to match the current live form.

        Call this after verifying that the form change is intentional and the
        pre-fill logic has been updated accordingly.
        """
        path = self.templates_dir / f"{agency}.json"
        data: dict[str, Any] = {}
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        data["field_names"] = live_snapshot.field_names
        data["version"] = live_snapshot.scraped_at.isoformat()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Updated template for {} to version {}", agency, data["version"])

    def _persist(self, diff: FormDiff) -> None:
        with sqlite3.connect(self.db_path) as con:
            # We don't store the live field list separately; derive from diff
            live_fields: list[str] = []
            try:
                path = self.templates_dir / f"{diff.agency}.json"
                if path.exists():
                    stored = json.loads(path.read_text(encoding="utf-8")).get("field_names", [])
                    # Reconstruct live = stored - removed + added
                    live_fields = sorted(
                        (set(stored) - set(diff.removed_fields)) | set(diff.added_fields)
                    )
            except Exception:
                pass

            import hashlib
            checksum = hashlib.sha256(json.dumps(live_fields).encode()).hexdigest()[:16]

            con.execute(
                "INSERT INTO form_checks "
                "(agency, form_url, field_names_json, checksum, has_changes, added_fields, removed_fields, checked_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    diff.agency,
                    diff.form_url,
                    json.dumps(live_fields),
                    checksum,
                    int(diff.has_changes),
                    json.dumps(diff.added_fields),
                    json.dumps(diff.removed_fields),
                    diff.checked_at.isoformat(),
                ),
            )
            con.commit()
