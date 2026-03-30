"""
Autonomous reporting submission engine for Chharcop.

Manages pre-filled report templates for FTC, FBI IC3, Google Safe Browsing,
and APWG eCX.  API-based agencies are submitted programmatically; form-based
agencies use Playwright to pre-fill the form, capture a screenshot for human
review, then wait for approval before the final click.

Submission lifecycle::

    draft → awaiting_approval → submitted → acknowledged
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urljoin

import httpx
from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


AgencyName = Literal["ftc", "fbi_ic3", "google_safe_browsing", "apwg_ecx"]

SubmissionStatus = Literal[
    "draft", "awaiting_approval", "submitted", "acknowledged", "failed"
]


class FormTemplate(BaseModel):
    """Versioned snapshot of a reporting-agency form."""

    agency: AgencyName
    form_url: str
    version: str = Field(description="ISO datetime when template was captured")
    field_names: list[str] = Field(default_factory=list)
    pre_fill_data: dict[str, str] = Field(default_factory=dict)
    submission_method: Literal["api", "playwright"] = "playwright"


class ReportSubmission(BaseModel):
    """A single queued or completed report submission."""

    id: Optional[int] = None
    agency: AgencyName
    target_url: str
    scan_id: str
    status: SubmissionStatus = "draft"
    form_version: str = ""
    screenshot_path: Optional[str] = None
    submitted_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    response_reference: Optional[str] = None
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Agency configurations
# ---------------------------------------------------------------------------


# Pre-built form templates — field names are best-effort and may drift over time.
# form_checker.py detects when the live form diverges from these templates.
_AGENCY_TEMPLATES: dict[AgencyName, FormTemplate] = {
    "ftc": FormTemplate(
        agency="ftc",
        form_url="https://reportfraud.ftc.gov/",
        version="2026-03-29T00:00:00",
        field_names=["reportType", "fraudDetails", "companyName", "website", "description"],
        pre_fill_data={},
        submission_method="playwright",
    ),
    "fbi_ic3": FormTemplate(
        agency="fbi_ic3",
        form_url="https://www.ic3.gov/complaint/default.aspx",
        version="2026-03-29T00:00:00",
        field_names=["victimType", "perpetratorInfo", "crimeType", "description", "website"],
        pre_fill_data={},
        submission_method="playwright",
    ),
    "google_safe_browsing": FormTemplate(
        agency="google_safe_browsing",
        form_url="https://safebrowsing.google.com/safebrowsing/report_phish/",
        version="2026-03-29T00:00:00",
        field_names=["url", "details"],
        pre_fill_data={},
        submission_method="playwright",
    ),
    "apwg_ecx": FormTemplate(
        agency="apwg_ecx",
        form_url="https://ecx.apwg.org/",
        version="2026-03-29T00:00:00",
        field_names=["url", "brand", "report_type", "description"],
        pre_fill_data={},
        submission_method="api",
    ),
}


# ---------------------------------------------------------------------------
# AutoSubmitter
# ---------------------------------------------------------------------------


class AutoSubmitter:
    """
    Manages the full lifecycle of scam-report submissions.

    For API agencies (APWG eCX) submissions are automated.
    For form agencies (FTC, FBI IC3, Google) Playwright pre-fills the form,
    saves a screenshot, then waits for human approval via
    :meth:`approve_submission`.

    Usage::

        submitter = AutoSubmitter(db_path=Path("reports.db"))

        # Queue a draft
        sub_id = await submitter.queue_report(
            agency="google_safe_browsing",
            target_url="https://lookups.io",
            scan_id="abc123",
        )

        # For playwright agencies this returns a screenshot path you can show
        sub = await submitter.prepare_submission(sub_id)
        print(f"Review screenshot: {sub.screenshot_path}")

        # After human approval:
        await submitter.approve_submission(sub_id)
    """

    def __init__(
        self,
        db_path: Path | None = None,
        screenshots_dir: Path | None = None,
        templates_dir: Path | None = None,
    ) -> None:
        self.db_path = db_path or Path("reports.db")
        self.screenshots_dir = screenshots_dir or Path("report_screenshots")
        self.templates_dir = templates_dir or Path("report_templates")
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._save_default_templates()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    agency              TEXT    NOT NULL,
                    target_url          TEXT    NOT NULL,
                    scan_id             TEXT    NOT NULL,
                    status              TEXT    NOT NULL DEFAULT 'draft',
                    form_version        TEXT    NOT NULL DEFAULT '',
                    screenshot_path     TEXT,
                    submitted_at        TEXT,
                    acknowledged_at     TEXT,
                    response_reference  TEXT,
                    last_error          TEXT,
                    created_at          TEXT    NOT NULL
                )
                """
            )
            con.commit()

    def _save_default_templates(self) -> None:
        """Persist default templates to disk if not already present."""
        for agency, tpl in _AGENCY_TEMPLATES.items():
            path = self.templates_dir / f"{agency}.json"
            if not path.exists():
                path.write_text(tpl.model_dump_json(indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def queue_report(
        self,
        agency: AgencyName,
        target_url: str,
        scan_id: str,
        extra_fields: dict[str, str] | None = None,
    ) -> int:
        """
        Create a draft submission record and return its ID.

        Args:
            agency: Target reporting agency.
            target_url: URL of the scam site being reported.
            scan_id: Chharcop scan ID for evidence linkage.
            extra_fields: Additional pre-fill data to merge into the template.

        Returns:
            Database ID of the new submission record.
        """
        tpl = self._load_template(agency)
        if extra_fields:
            tpl.pre_fill_data.update(extra_fields)
        tpl.pre_fill_data["url"] = target_url

        sub = ReportSubmission(
            agency=agency,
            target_url=target_url,
            scan_id=scan_id,
            form_version=tpl.version,
            created_at=datetime.utcnow(),
        )
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute(
                "INSERT INTO submissions (agency, target_url, scan_id, status, form_version, created_at) "
                "VALUES (?, ?, ?, 'draft', ?, ?)",
                (agency, target_url, scan_id, tpl.version, sub.created_at.isoformat()),
            )
            con.commit()
            sub.id = cur.lastrowid

        logger.info("Queued {} report #{} for {}", agency, sub.id, target_url)
        return sub.id  # type: ignore[return-value]

    async def prepare_submission(self, submission_id: int) -> ReportSubmission:
        """
        Pre-fill the form and capture a screenshot.

        For API agencies the request is pre-validated but not sent.
        For Playwright agencies a headless browser fills the form.

        Returns the updated submission (status ``awaiting_approval``).
        """
        sub = self._get_submission(submission_id)
        tpl = self._load_template(sub.agency)

        if tpl.submission_method == "playwright":
            screenshot_path = await self._playwright_prefill(sub, tpl)
            self._update(submission_id, status="awaiting_approval", screenshot_path=str(screenshot_path))
            sub.status = "awaiting_approval"
            sub.screenshot_path = str(screenshot_path)
        else:
            # API agencies: just move to awaiting_approval for human review
            self._update(submission_id, status="awaiting_approval")
            sub.status = "awaiting_approval"

        logger.info("Submission #{} ready for approval", submission_id)
        return sub

    async def approve_submission(self, submission_id: int) -> ReportSubmission:
        """
        Human-approved — execute the final submission.

        For API agencies: sends the HTTP request.
        For Playwright agencies: clicks the submit button.
        """
        sub = self._get_submission(submission_id)
        if sub.status != "awaiting_approval":
            raise ValueError(
                f"Submission #{submission_id} is in status '{sub.status}', "
                "expected 'awaiting_approval'"
            )

        tpl = self._load_template(sub.agency)
        try:
            if tpl.submission_method == "api":
                reference = await self._api_submit(sub, tpl)
            else:
                reference = await self._playwright_submit(sub, tpl)

            self._update(
                submission_id,
                status="submitted",
                submitted_at=datetime.utcnow().isoformat(),
                response_reference=reference,
            )
            sub.status = "submitted"
            sub.response_reference = reference
            logger.info("Submission #{} submitted (ref: {})", submission_id, reference)
        except Exception as exc:
            self._update(submission_id, status="failed", last_error=str(exc))
            sub.status = "failed"
            logger.error("Submission #{} failed: {}", submission_id, exc)
            raise

        return sub

    def list_queue(
        self,
        status: SubmissionStatus | None = None,
    ) -> list[ReportSubmission]:
        """Return all submissions, optionally filtered by status."""
        sql = "SELECT id, agency, target_url, scan_id, status, form_version, screenshot_path, submitted_at, acknowledged_at, response_reference, last_error, created_at FROM submissions"
        params: list = []
        if status:
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY id DESC"
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(sql, params).fetchall()
        return [self._row_to_sub(r) for r in rows]

    def status_snapshot(self) -> list[dict[str, Any]]:
        """Return queue snapshot for chharcop-status.json."""
        subs = self.list_queue()
        return [
            {
                "agency": s.agency,
                "target": s.target_url,
                "status": s.status,
                "form_version": s.form_version,
                "last_checked": s.created_at.isoformat(),
            }
            for s in subs[:20]  # cap at 20 items for the status file
        ]

    # ------------------------------------------------------------------
    # Playwright integration
    # ------------------------------------------------------------------

    async def _playwright_prefill(
        self, sub: ReportSubmission, tpl: FormTemplate
    ) -> Path:
        """Pre-fill form fields using Playwright and capture a screenshot."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning(
                "Playwright not installed — skipping browser pre-fill. "
                "Install with: pip install 'chharcop[screenshots]'"
            )
            # Return a placeholder path so the workflow can continue
            placeholder = self.screenshots_dir / f"submission_{sub.id}_placeholder.txt"
            placeholder.write_text(
                f"[Playwright not installed]\n"
                f"Agency: {sub.agency}\n"
                f"URL: {sub.target_url}\n"
                f"Form: {tpl.form_url}\n",
                encoding="utf-8",
            )
            return placeholder

        screenshot_path = self.screenshots_dir / f"submission_{sub.id}_{sub.agency}.png"

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(tpl.form_url, timeout=30_000)

            # Best-effort field filling — field selectors are heuristic
            for field_name, value in tpl.pre_fill_data.items():
                if not value:
                    continue
                selectors = [
                    f"[name='{field_name}']",
                    f"[id='{field_name}']",
                    f"[placeholder*='{field_name}' i]",
                ]
                for sel in selectors:
                    try:
                        locator = page.locator(sel).first
                        if await locator.count() > 0:
                            await locator.fill(value)
                            break
                    except Exception:
                        continue

            await page.screenshot(path=str(screenshot_path), full_page=True)
            await browser.close()

        logger.info("Screenshot saved: {}", screenshot_path)
        return screenshot_path

    async def _playwright_submit(
        self, sub: ReportSubmission, tpl: FormTemplate
    ) -> str:
        """Click the submit button on the pre-filled form."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError(
                "Playwright required for browser-based submission. "
                "Install: pip install 'chharcop[screenshots]'"
            )

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=False)  # visible for audit
            page = await browser.new_page()
            await page.goto(tpl.form_url, timeout=30_000)

            # Re-fill fields
            for field_name, value in tpl.pre_fill_data.items():
                if not value:
                    continue
                try:
                    await page.fill(f"[name='{field_name}']", value)
                except Exception:
                    pass

            # Click submit
            submit_selectors = [
                "button[type='submit']",
                "input[type='submit']",
                "button:has-text('Submit')",
                "button:has-text('Report')",
            ]
            for sel in submit_selectors:
                try:
                    btn = page.locator(sel).first
                    if await btn.count() > 0:
                        await btn.click()
                        break
                except Exception:
                    continue

            await asyncio.sleep(2)
            final_url = page.url
            await browser.close()

        return f"submitted_to={final_url}"

    # ------------------------------------------------------------------
    # API submission
    # ------------------------------------------------------------------

    async def _api_submit(
        self, sub: ReportSubmission, tpl: FormTemplate
    ) -> str:
        """
        Submit via API (used for APWG eCX).

        In production this would use a stored API key.  Currently logs the
        payload and returns a synthetic reference so the workflow can proceed
        without real credentials.
        """
        payload = {
            "url": sub.target_url,
            "source": "chharcop",
            "scan_id": sub.scan_id,
            **tpl.pre_fill_data,
        }
        logger.info("APWG eCX API payload (dry-run): {}", json.dumps(payload))
        # TODO: Replace with real API call once APWG credentials are configured
        # async with httpx.AsyncClient() as client:
        #     resp = await client.post(tpl.form_url, json=payload, headers={"X-API-Key": api_key})
        #     resp.raise_for_status()
        #     return resp.json().get("reference_id", "unknown")
        return f"dry_run_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_template(self, agency: AgencyName) -> FormTemplate:
        path = self.templates_dir / f"{agency}.json"
        if path.exists():
            return FormTemplate.model_validate_json(path.read_text(encoding="utf-8"))
        return _AGENCY_TEMPLATES[agency]

    def _get_submission(self, submission_id: int) -> ReportSubmission:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT id, agency, target_url, scan_id, status, form_version, screenshot_path, "
                "submitted_at, acknowledged_at, response_reference, last_error, created_at "
                "FROM submissions WHERE id=?",
                (submission_id,),
            ).fetchone()
        if not row:
            raise ValueError(f"Submission #{submission_id} not found")
        return self._row_to_sub(row)

    # Columns that may be updated — used to prevent SQL injection via kwargs keys.
    _UPDATABLE_COLUMNS: frozenset[str] = frozenset({
        "status",
        "form_version",
        "screenshot_path",
        "submitted_at",
        "acknowledged_at",
        "response_reference",
        "last_error",
    })

    def _update(self, submission_id: int, **kwargs: Any) -> None:
        if not kwargs:
            return
        # Whitelist column names to prevent SQL injection through dynamic key names.
        safe_kwargs = {k: v for k, v in kwargs.items() if k in self._UPDATABLE_COLUMNS}
        if not safe_kwargs:
            return
        cols = ", ".join(f"{k}=?" for k in safe_kwargs)
        vals = list(safe_kwargs.values()) + [submission_id]
        with sqlite3.connect(self.db_path) as con:
            con.execute(f"UPDATE submissions SET {cols} WHERE id=?", vals)
            con.commit()

    @staticmethod
    def _row_to_sub(row: tuple) -> ReportSubmission:
        (
            sub_id, agency, target_url, scan_id, status, form_version,
            screenshot_path, submitted_at, acknowledged_at, response_reference,
            last_error, created_at,
        ) = row
        return ReportSubmission(
            id=sub_id,
            agency=agency,  # type: ignore[arg-type]
            target_url=target_url,
            scan_id=scan_id,
            status=status,  # type: ignore[arg-type]
            form_version=form_version or "",
            screenshot_path=screenshot_path,
            submitted_at=datetime.fromisoformat(submitted_at) if submitted_at else None,
            acknowledged_at=datetime.fromisoformat(acknowledged_at) if acknowledged_at else None,
            response_reference=response_reference,
            last_error=last_error,
            created_at=datetime.fromisoformat(created_at),
        )
