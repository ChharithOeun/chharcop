"""
Core training engine for Chharcop.

Runs Chharcop's web scanner against labelled training sites, compares the
predicted risk level to the ground-truth label, accumulates accuracy metrics,
and persists everything to SQLite.  Results are also exported to
``chharcop-status.json`` so the dashboard always shows fresh numbers.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from loguru import logger
from pydantic import BaseModel, Field

from chharcop.training.dataset import SiteEntry, TrainingDataset
from chharcop.training.metrics import AccuracyMetrics, ConfusionMatrix


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TrainingRun(BaseModel):
    """Record of a single complete training run."""

    id: Optional[int] = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    sites_tested: int = 0
    sites_skipped: int = 0
    overall_accuracy: float = 0.0
    overall_f1: float = 0.0
    overall_precision: float = 0.0
    overall_recall: float = 0.0
    status: str = "running"  # running | completed | failed


class SitePrediction(BaseModel):
    """Prediction result for a single site in a training run."""

    run_id: int
    url: str
    ground_truth: str
    predicted: str        # "scam" or "legit"
    risk_score: float
    risk_level: str
    duration_ms: float
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class Trainer:
    """
    Automated training loop.

    Iterates the dataset, calls Chharcop's scanner on each site, determines
    whether the risk assessment matches the ground truth, and persists all
    results.

    A site is considered *predicted scam* when its ``risk_score >= threshold``
    (default 0.3, mapping to HIGH or CRITICAL).

    Usage::

        trainer = Trainer(
            db_path=Path("training_results.db"),
            status_json=Path("chharcop-status.json"),
        )
        run = await trainer.run_once()
        print(f"Accuracy: {run.overall_accuracy:.1%}")
    """

    # Risk-score threshold above which a site is classified as a scam prediction
    DEFAULT_SCAM_THRESHOLD: float = 0.3

    # Maximum concurrent scans to avoid hammering target sites
    MAX_CONCURRENT: int = 3

    def __init__(
        self,
        db_path: Path | None = None,
        status_json: Path | None = None,
        scam_threshold: float = DEFAULT_SCAM_THRESHOLD,
    ) -> None:
        self.db_path = db_path or Path("training_results.db")
        self.status_json = status_json or Path("chharcop-status.json")
        self.scam_threshold = scam_threshold

        self.dataset = TrainingDataset(db_path=self.db_path)
        self.metrics_engine = AccuracyMetrics(db_path=self.db_path)
        self._init_db()

    # ------------------------------------------------------------------
    # DB initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS training_runs (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at      TEXT    NOT NULL,
                    finished_at     TEXT,
                    sites_tested    INTEGER NOT NULL DEFAULT 0,
                    sites_skipped   INTEGER NOT NULL DEFAULT 0,
                    overall_accuracy REAL   NOT NULL DEFAULT 0.0,
                    overall_f1      REAL    NOT NULL DEFAULT 0.0,
                    overall_precision REAL  NOT NULL DEFAULT 0.0,
                    overall_recall  REAL    NOT NULL DEFAULT 0.0,
                    status          TEXT    NOT NULL DEFAULT 'running'
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS site_predictions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id      INTEGER NOT NULL,
                    url         TEXT    NOT NULL,
                    ground_truth TEXT   NOT NULL,
                    predicted   TEXT    NOT NULL,
                    risk_score  REAL    NOT NULL,
                    risk_level  TEXT    NOT NULL,
                    duration_ms REAL    NOT NULL,
                    error       TEXT,
                    FOREIGN KEY (run_id) REFERENCES training_runs(id)
                )
                """
            )
            con.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_once(self, module_filter: str | None = None) -> TrainingRun:
        """
        Execute one full training pass over the active dataset.

        Args:
            module_filter: If ``"web"``, only test web sites.  If ``"gaming"``,
                only gaming-related entries.  ``None`` means all sites.

        Returns:
            A completed :class:`TrainingRun` with accuracy metrics populated.
        """
        run = self._create_run()
        sites = self.dataset.get_all_sites(active_only=True)
        if not sites:
            logger.warning("Training dataset is empty — nothing to test")
            return self._finish_run(run, [], [])

        logger.info("Starting training run #{} — {} sites", run.id, len(sites))

        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        tasks = [self._evaluate_site(site, run.id, semaphore) for site in sites]
        predictions: list[SitePrediction] = await asyncio.gather(*tasks)

        valid = [p for p in predictions if p.error is None]
        skipped = len(predictions) - len(valid)

        # Compute confusion matrix
        cm_data = [{"ground_truth": p.ground_truth, "predicted": p.predicted} for p in valid]
        overall_cm = self.metrics_engine.build_confusion_matrix(cm_data)

        # Web-only subset (all current sites are web-based)
        self.metrics_engine.record(run.id, "overall", overall_cm)
        self.metrics_engine.record(run.id, "web", overall_cm)

        run = self._finish_run(run, valid, predictions, overall_cm, skipped)
        self.metrics_engine.export_to_json(self.status_json)
        logger.info(
            "Training run #{} done. Accuracy={:.1%} F1={:.3f} ({}/{} sites)",
            run.id,
            run.overall_accuracy,
            run.overall_f1,
            len(valid),
            len(sites),
        )
        return run

    def run_once_sync(self, module_filter: str | None = None) -> TrainingRun:
        """Synchronous wrapper around :meth:`run_once`."""
        return asyncio.run(self.run_once(module_filter))

    def history(self, limit: int = 10) -> list[TrainingRun]:
        """Return the *limit* most recent training runs."""
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(
                "SELECT id, started_at, finished_at, sites_tested, sites_skipped, "
                "overall_accuracy, overall_f1, overall_precision, overall_recall, status "
                "FROM training_runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_run(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _evaluate_site(
        self,
        site: SiteEntry,
        run_id: int,
        semaphore: asyncio.Semaphore,
    ) -> SitePrediction:
        """Scan a single site and return the prediction."""
        # Import here to avoid circular imports
        from chharcop.core import Chharcop

        async with semaphore:
            t0 = asyncio.get_event_loop().time()
            try:
                engine = Chharcop()
                result = await engine.scan_website(site.url)
                result.calculate_risk_score()
                duration_ms = (asyncio.get_event_loop().time() - t0) * 1000

                predicted = "scam" if result.risk_score >= self.scam_threshold else "legit"
                pred = SitePrediction(
                    run_id=run_id,
                    url=site.url,
                    ground_truth=site.label,
                    predicted=predicted,
                    risk_score=result.risk_score,
                    risk_level=str(result.risk_level),
                    duration_ms=round(duration_ms, 1),
                )
            except Exception as exc:
                duration_ms = (asyncio.get_event_loop().time() - t0) * 1000
                logger.warning("Error scanning {}: {}", site.url, exc)
                pred = SitePrediction(
                    run_id=run_id,
                    url=site.url,
                    ground_truth=site.label,
                    predicted="legit",  # conservative default on error
                    risk_score=0.0,
                    risk_level="unknown",
                    duration_ms=round(duration_ms, 1),
                    error=str(exc),
                )
            self._save_prediction(pred)
            return pred

    def _create_run(self) -> TrainingRun:
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute(
                "INSERT INTO training_runs (started_at, status) VALUES (?, 'running')",
                (datetime.utcnow().isoformat(),),
            )
            con.commit()
            run_id = cur.lastrowid
        return TrainingRun(
            id=run_id,
            started_at=datetime.utcnow(),
            status="running",
        )

    def _finish_run(
        self,
        run: TrainingRun,
        valid: list[SitePrediction],
        all_preds: list[SitePrediction],
        cm: ConfusionMatrix | None = None,
        skipped: int = 0,
    ) -> TrainingRun:
        now = datetime.utcnow()
        if cm is None:
            cm = ConfusionMatrix()

        run.finished_at = now
        run.sites_tested = len(valid)
        run.sites_skipped = skipped
        run.overall_accuracy = round(cm.accuracy, 4)
        run.overall_f1 = round(cm.f1, 4)
        run.overall_precision = round(cm.precision, 4)
        run.overall_recall = round(cm.recall, 4)
        run.status = "completed"

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "UPDATE training_runs SET finished_at=?, sites_tested=?, sites_skipped=?, "
                "overall_accuracy=?, overall_f1=?, overall_precision=?, overall_recall=?, "
                "status=? WHERE id=?",
                (
                    now.isoformat(),
                    run.sites_tested,
                    run.sites_skipped,
                    run.overall_accuracy,
                    run.overall_f1,
                    run.overall_precision,
                    run.overall_recall,
                    run.status,
                    run.id,
                ),
            )
            con.commit()
        return run

    def _save_prediction(self, pred: SitePrediction) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO site_predictions "
                "(run_id, url, ground_truth, predicted, risk_score, risk_level, duration_ms, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pred.run_id,
                    pred.url,
                    pred.ground_truth,
                    pred.predicted,
                    pred.risk_score,
                    pred.risk_level,
                    pred.duration_ms,
                    pred.error,
                ),
            )
            con.commit()

    @staticmethod
    def _row_to_run(row: tuple) -> TrainingRun:
        (
            run_id, started_at, finished_at, sites_tested, sites_skipped,
            accuracy, f1, precision, recall, status,
        ) = row
        return TrainingRun(
            id=run_id,
            started_at=datetime.fromisoformat(started_at),
            finished_at=datetime.fromisoformat(finished_at) if finished_at else None,
            sites_tested=sites_tested,
            sites_skipped=sites_skipped,
            overall_accuracy=accuracy,
            overall_f1=f1,
            overall_precision=precision,
            overall_recall=recall,
            status=status,
        )

    # ------------------------------------------------------------------
    # Status snapshot
    # ------------------------------------------------------------------

    def status_snapshot(self) -> dict[str, Any]:
        """Return a dict suitable for embedding in chharcop-status.json."""
        runs = self.history(limit=1)
        last = runs[0] if runs else None
        trend = self.metrics_engine.trend("overall", limit=10)
        return {
            "accuracy": last.overall_accuracy if last else None,
            "precision": last.overall_precision if last else None,
            "recall": last.overall_recall if last else None,
            "f1": last.overall_f1 if last else None,
            "total_runs": len(self.history(limit=1000)),
            "last_run": last.finished_at.isoformat() if last and last.finished_at else None,
            "trend": [
                {"run_id": p.run_id, "timestamp": p.run_timestamp.isoformat(), "accuracy": p.accuracy}
                for p in trend
            ],
        }
