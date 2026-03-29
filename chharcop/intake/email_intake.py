"""
Email intake module for Chharcop.

Monitors an IMAP inbox (e.g. via ProtonMail Bridge) for forwarded scam emails,
parses them to extract URLs, phone numbers, and sender domains, then
auto-creates investigation cases that Chharcop's core scanner can act on.

Configuration (environment variables)::

    CHHARCOP_IMAP_HOST      — IMAP server hostname (default: 127.0.0.1 for ProtonMail Bridge)
    CHHARCOP_IMAP_PORT      — IMAP port (default: 1143 for ProtonMail Bridge)
    CHHARCOP_IMAP_USER      — Email address / username
    CHHARCOP_IMAP_PASSWORD  — Password / Bridge token
    CHHARCOP_IMAP_FOLDER    — Mailbox folder to monitor (default: INBOX)
"""

from __future__ import annotations

import asyncio
import email
import email.header
import imaplib
import os
import re
import sqlite3
import uuid
from datetime import datetime
from email.message import Message
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ParsedEmail(BaseModel):
    """Structured representation of a parsed scam-forward email."""

    message_id: str
    from_address: str
    subject: str
    body_text: str
    received_at: datetime
    urls: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    sender_domains: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)  # filenames


class InvestigationCase(BaseModel):
    """An auto-created investigation case derived from an email."""

    case_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    intake_source: str = "email"
    type: str = "web"  # web | phone | domain
    target: str = ""
    status: str = "queued"  # queued | in_progress | completed | failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    scan_id: Optional[str] = None
    source_message_id: str = ""
    forwarder_email: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    notes: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regex patterns
_URL_RE = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?"        # optional country code
    r"\(?([0-9]{3})\)?"        # area code
    r"[-.\s]?"
    r"([0-9]{3})"
    r"[-.\s]?"
    r"([0-9]{4})",
)


def _extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    return sorted(set(_URL_RE.findall(text)))


def _extract_phones(text: str) -> list[str]:
    """Extract US/international phone numbers from text."""
    matches = _PHONE_RE.findall(text)
    return sorted({"".join(m) for m in matches})


def _extract_domains(email_body: str, from_address: str) -> list[str]:
    """Extract unique sender domains from email metadata and body."""
    domains: set[str] = set()

    # From address domain
    if "@" in from_address:
        domains.add(from_address.split("@")[-1].lower().strip(">"))

    # Domains from embedded URLs
    for url in _extract_urls(email_body):
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc.lower())
        except Exception:
            pass

    return sorted(domains)


def _decode_header_value(value: str | bytes | None) -> str:
    """Decode potentially encoded email header values."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        decoded_parts = email.header.decode_header(value.decode(errors="replace"))
    else:
        decoded_parts = email.header.decode_header(value)
    parts: list[str] = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            parts.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(str(part))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# EmailIntake
# ---------------------------------------------------------------------------


class EmailIntake:
    """
    Monitors an IMAP mailbox and converts scam-forward emails into
    investigation cases.

    Usage::

        intake = EmailIntake()
        await intake.poll()           # one-shot poll
        await intake.monitor(interval=60)  # continuous polling
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        folder: str | None = None,
        db_path: Path | None = None,
        auto_reply: bool = True,
    ) -> None:
        self.host = host or os.getenv("CHHARCOP_IMAP_HOST", "127.0.0.1")
        self.port = port or int(os.getenv("CHHARCOP_IMAP_PORT", "1143"))
        self.username = username or os.getenv("CHHARCOP_IMAP_USER", "")
        self.password = password or os.getenv("CHHARCOP_IMAP_PASSWORD", "")
        self.folder = folder or os.getenv("CHHARCOP_IMAP_FOLDER", "INBOX")
        self.db_path = db_path or Path("intake.db")
        self.auto_reply = auto_reply
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS email_messages (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id      TEXT    NOT NULL UNIQUE,
                    from_address    TEXT    NOT NULL,
                    subject         TEXT    NOT NULL,
                    received_at     TEXT    NOT NULL,
                    urls_json       TEXT    NOT NULL DEFAULT '[]',
                    phones_json     TEXT    NOT NULL DEFAULT '[]',
                    domains_json    TEXT    NOT NULL DEFAULT '[]',
                    processed       INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_cases (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id         TEXT    NOT NULL UNIQUE,
                    intake_source   TEXT    NOT NULL DEFAULT 'email',
                    type            TEXT    NOT NULL,
                    target          TEXT    NOT NULL,
                    status          TEXT    NOT NULL DEFAULT 'queued',
                    started_at      TEXT,
                    completed_at    TEXT,
                    scan_id         TEXT,
                    source_msg_id   TEXT,
                    forwarder       TEXT,
                    created_at      TEXT    NOT NULL,
                    notes           TEXT    NOT NULL DEFAULT ''
                )
                """
            )
            con.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def poll(self) -> list[InvestigationCase]:
        """
        Connect to IMAP, fetch unread messages, create investigation cases.

        Returns the list of new cases created in this poll.
        """
        if not self.username or not self.password:
            logger.warning("IMAP credentials not configured — skipping email poll")
            return []

        new_cases: list[InvestigationCase] = []
        try:
            messages = await asyncio.get_event_loop().run_in_executor(
                None, self._fetch_unread
            )
        except Exception as exc:
            logger.error("IMAP poll failed: {}", exc)
            return []

        for parsed in messages:
            if self._already_processed(parsed.message_id):
                continue
            cases = self._create_cases_from_email(parsed)
            new_cases.extend(cases)
            self._mark_processed(parsed)
            if self.auto_reply:
                await self._send_acknowledgement(parsed, cases)

        logger.info("Email poll: {} new messages, {} cases created", len(messages), len(new_cases))
        return new_cases

    async def monitor(self, interval: int = 60) -> None:
        """
        Continuously poll the inbox at the given interval (seconds).

        This coroutine runs indefinitely; cancel it to stop monitoring.
        """
        logger.info("Email monitor started (interval={}s)", interval)
        while True:
            await self.poll()
            await asyncio.sleep(interval)

    def list_cases(self, status: str | None = None) -> list[InvestigationCase]:
        """Return all investigation cases, optionally filtered by status."""
        sql = (
            "SELECT case_id, intake_source, type, target, status, started_at, "
            "completed_at, scan_id, source_msg_id, forwarder, created_at, notes "
            "FROM investigation_cases"
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
        """Return email intake stats for chharcop-status.json."""
        with sqlite3.connect(self.db_path) as con:
            total = con.execute(
                "SELECT COUNT(*) FROM email_messages"
            ).fetchone()[0]
            auto_inv = con.execute(
                "SELECT COUNT(*) FROM investigation_cases WHERE intake_source='email'"
            ).fetchone()[0]
            pending = con.execute(
                "SELECT COUNT(*) FROM investigation_cases WHERE intake_source='email' AND status='queued'"
            ).fetchone()[0]
            recent_rows = con.execute(
                "SELECT forwarder, notes, created_at, case_id FROM investigation_cases "
                "WHERE intake_source='email' ORDER BY id DESC LIMIT 5"
            ).fetchall()

        return {
            "total_received": total,
            "auto_investigated": auto_inv,
            "pending": pending,
            "recent_messages": [
                {
                    "from": r[0],
                    "subject": r[1][:80] if r[1] else "",
                    "timestamp": r[2],
                    "investigation_id": r[3],
                }
                for r in recent_rows
            ],
        }

    # ------------------------------------------------------------------
    # IMAP helpers
    # ------------------------------------------------------------------

    def _fetch_unread(self) -> list[ParsedEmail]:
        """Synchronous IMAP fetch (run in executor)."""
        results: list[ParsedEmail] = []
        try:
            mail = imaplib.IMAP4(self.host, self.port)
            mail.login(self.username, self.password)
            mail.select(self.folder)
            _, data = mail.search(None, "UNSEEN")
            ids = data[0].split() if data[0] else []
            for uid in ids:
                _, msg_data = mail.fetch(uid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]  # type: ignore[index]
                if isinstance(raw, bytes):
                    parsed = self._parse_raw_email(raw)
                    if parsed:
                        results.append(parsed)
            mail.logout()
        except Exception as exc:
            logger.error("IMAP fetch error: {}", exc)
        return results

    @staticmethod
    def _parse_raw_email(raw: bytes) -> Optional[ParsedEmail]:
        """Parse a raw RFC 822 message into a :class:`ParsedEmail`."""
        try:
            msg: Message = email.message_from_bytes(raw)
            from_addr = _decode_header_value(msg.get("From", ""))
            subject = _decode_header_value(msg.get("Subject", "(no subject)"))
            msg_id = msg.get("Message-ID", str(uuid.uuid4()))
            date_str = msg.get("Date", "")
            try:
                from email.utils import parsedate_to_datetime
                received_at = parsedate_to_datetime(date_str)
                received_at = received_at.replace(tzinfo=None)
            except Exception:
                received_at = datetime.utcnow()

            # Extract plain text body
            body = ""
            attachments: list[str] = []
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    cd = str(part.get("Content-Disposition", ""))
                    if "attachment" in cd:
                        filename = part.get_filename()
                        if filename:
                            attachments.append(filename)
                    elif ct == "text/plain":
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes):
                            body += payload.decode(errors="replace")
            else:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    body = payload.decode(errors="replace")

            return ParsedEmail(
                message_id=msg_id,
                from_address=from_addr,
                subject=subject,
                body_text=body,
                received_at=received_at,
                urls=_extract_urls(body),
                phone_numbers=_extract_phones(body),
                sender_domains=_extract_domains(body, from_addr),
                attachments=attachments,
            )
        except Exception as exc:
            logger.warning("Could not parse email: {}", exc)
            return None

    # ------------------------------------------------------------------
    # Case creation
    # ------------------------------------------------------------------

    def _create_cases_from_email(self, parsed: ParsedEmail) -> list[InvestigationCase]:
        """Create one investigation case per extracted target."""
        cases: list[InvestigationCase] = []

        # One case per URL
        for url in parsed.urls[:10]:  # cap at 10 to prevent spam
            case = InvestigationCase(
                intake_source="email",
                type="web",
                target=url,
                source_message_id=parsed.message_id,
                forwarder_email=parsed.from_address,
                notes=f"Extracted from email: {parsed.subject[:80]}",
            )
            self._save_case(case)
            cases.append(case)

        # One case per phone number
        for phone in parsed.phone_numbers[:5]:
            case = InvestigationCase(
                intake_source="email",
                type="phone",
                target=phone,
                source_message_id=parsed.message_id,
                forwarder_email=parsed.from_address,
                notes=f"Phone extracted from email: {parsed.subject[:80]}",
            )
            self._save_case(case)
            cases.append(case)

        # One case per suspicious domain (excluding known good domains)
        _SKIP_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "protonmail.com"}
        for domain in parsed.sender_domains:
            if domain in _SKIP_DOMAINS:
                continue
            case = InvestigationCase(
                intake_source="email",
                type="domain",
                target=f"https://{domain}",
                source_message_id=parsed.message_id,
                forwarder_email=parsed.from_address,
                notes=f"Sender domain from email: {parsed.subject[:80]}",
            )
            self._save_case(case)
            cases.append(case)

        return cases

    def _save_case(self, case: InvestigationCase) -> None:
        import json

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT OR IGNORE INTO investigation_cases "
                "(case_id, intake_source, type, target, status, source_msg_id, forwarder, created_at, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case.case_id,
                    case.intake_source,
                    case.type,
                    case.target,
                    case.status,
                    case.source_message_id,
                    case.forwarder_email,
                    case.created_at.isoformat(),
                    case.notes,
                ),
            )
            con.commit()

    def _mark_processed(self, parsed: ParsedEmail) -> None:
        import json

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT OR REPLACE INTO email_messages "
                "(message_id, from_address, subject, received_at, urls_json, phones_json, domains_json, processed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    parsed.message_id,
                    parsed.from_address,
                    parsed.subject,
                    parsed.received_at.isoformat(),
                    json.dumps(parsed.urls),
                    json.dumps(parsed.phone_numbers),
                    json.dumps(parsed.sender_domains),
                ),
            )
            con.commit()

    def _already_processed(self, message_id: str) -> bool:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT processed FROM email_messages WHERE message_id=?", (message_id,)
            ).fetchone()
        return bool(row and row[0])

    async def _send_acknowledgement(
        self, parsed: ParsedEmail, cases: list[InvestigationCase]
    ) -> None:
        """
        Send an acknowledgement reply to the forwarder.

        Uses smtplib via the same Bridge connection.  Silently skips if SMTP
        is not configured or the reply fails.
        """
        smtp_host = os.getenv("CHHARCOP_SMTP_HOST", "")
        smtp_port = int(os.getenv("CHHARCOP_SMTP_PORT", "1025"))
        if not smtp_host or not self.username:
            return

        try:
            import smtplib
            from email.mime.text import MIMEText

            body = (
                f"Hi,\n\n"
                f"Thank you for forwarding this to Chharcop.\n\n"
                f"We've created {len(cases)} investigation case(s) from your email.\n\n"
                f"Case IDs: {', '.join(c.case_id for c in cases)}\n\n"
                f"You'll receive a follow-up when the investigation is complete.\n\n"
                f"— Chharcop Auto-Investigator"
            )
            msg_out = MIMEText(body, "plain")
            msg_out["Subject"] = f"Re: {parsed.subject}"
            msg_out["From"] = self.username
            msg_out["To"] = parsed.from_address

            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: smtplib.SMTP(smtp_host, smtp_port).sendmail(
                    self.username, [parsed.from_address], msg_out.as_string()
                ),
            )
            logger.debug("Acknowledgement sent to {}", parsed.from_address)
        except Exception as exc:
            logger.debug("Could not send acknowledgement: {}", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_case(row: tuple) -> InvestigationCase:
        (
            case_id, intake_source, itype, target, status,
            started_at, completed_at, scan_id, source_msg_id,
            forwarder, created_at, notes,
        ) = row
        return InvestigationCase(
            case_id=case_id,
            intake_source=intake_source,
            type=itype,
            target=target,
            status=status,
            started_at=datetime.fromisoformat(started_at) if started_at else None,
            completed_at=datetime.fromisoformat(completed_at) if completed_at else None,
            scan_id=scan_id,
            source_message_id=source_msg_id or "",
            forwarder_email=forwarder or "",
            created_at=datetime.fromisoformat(created_at),
            notes=notes or "",
        )
