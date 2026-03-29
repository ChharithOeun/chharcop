"""
Accuracy tracking and metrics for Chharcop training runs.

Computes standard classification metrics (precision, recall, F1, confusion
matrix) per-module and overall, and exports them to JSON for the status
dashboard.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ConfusionMatrix(BaseModel):
    """Binary confusion-matrix counts."""

    true_positives: int = 0   # scam correctly flagged as scam
    false_positives: int = 0  # legit incorrectly flagged as scam
    true_negatives: int = 0   # legit correctly cleared
    false_negatives: int = 0  # scam incorrectly cleared

    @property
    def total(self) -> int:
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "total": self.total,
        }


class ModuleMetrics(BaseModel):
    """Per-module accuracy breakdown."""

    module: str = Field(..., description="Module name (e.g. 'web', 'gaming', 'overall')")
    confusion: ConfusionMatrix = Field(default_factory=ConfusionMatrix)
    run_id: int = Field(..., description="FK to training run")
    computed_at: datetime = Field(default_factory=datetime.utcnow)


class TrendPoint(BaseModel):
    """Single point in the accuracy trend series."""

    run_id: int
    run_timestamp: datetime
    accuracy: float
    f1: float
    precision: float
    recall: float


class AccuracyMetrics:
    """
    Computes and aggregates accuracy metrics across training runs.

    Usage::

        metrics = AccuracyMetrics(db_path=Path("training_results.db"))

        # After a training run produces predictions:
        cm = metrics.build_confusion_matrix(predictions)
        metrics.record(run_id=1, module="web", confusion=cm)

        # Export for dashboard:
        metrics.export_to_json(Path("chharcop-status.json"))
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # DB initialisation
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        import sqlite3

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS training_metrics (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id      INTEGER NOT NULL,
                    module      TEXT    NOT NULL,
                    tp          INTEGER NOT NULL DEFAULT 0,
                    fp          INTEGER NOT NULL DEFAULT 0,
                    tn          INTEGER NOT NULL DEFAULT 0,
                    fn          INTEGER NOT NULL DEFAULT 0,
                    computed_at TEXT    NOT NULL
                )
                """
            )
            con.commit()

    # ------------------------------------------------------------------
    # Core calculations
    # ------------------------------------------------------------------

    @staticmethod
    def build_confusion_matrix(
        predictions: list[dict[str, Any]],
    ) -> ConfusionMatrix:
        """
        Build a confusion matrix from a list of prediction dicts.

        Each prediction dict must have:
        - ``ground_truth``: ``"scam"`` or ``"legit"``
        - ``predicted``: ``"scam"`` or ``"legit"``
        """
        cm = ConfusionMatrix()
        for p in predictions:
            gt = p["ground_truth"]
            pred = p["predicted"]
            if gt == "scam" and pred == "scam":
                cm.true_positives += 1
            elif gt == "legit" and pred == "scam":
                cm.false_positives += 1
            elif gt == "legit" and pred == "legit":
                cm.true_negatives += 1
            else:  # gt == "scam" and pred == "legit"
                cm.false_negatives += 1
        return cm

    def record(self, run_id: int, module: str, confusion: ConfusionMatrix) -> None:
        """Persist metrics for a completed training run module."""
        import sqlite3

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO training_metrics (run_id, module, tp, fp, tn, fn, computed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    module,
                    confusion.true_positives,
                    confusion.false_positives,
                    confusion.true_negatives,
                    confusion.false_negatives,
                    datetime.utcnow().isoformat(),
                ),
            )
            con.commit()
        logger.debug("Recorded metrics for run_id={} module={}", run_id, module)

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def latest_metrics(self, module: str = "overall") -> ConfusionMatrix | None:
        """Return the confusion matrix for the most recent run of a given module."""
        import sqlite3

        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT tp, fp, tn, fn FROM training_metrics "
                "WHERE module=? ORDER BY id DESC LIMIT 1",
                (module,),
            ).fetchone()
        if not row:
            return None
        tp, fp, tn, fn = row
        return ConfusionMatrix(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
        )

    def trend(self, module: str = "overall", limit: int = 20) -> list[TrendPoint]:
        """
        Return the last *limit* accuracy data-points for a module.

        Requires a join with the training_runs table created by Trainer.
        """
        import sqlite3

        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(
                """
                SELECT m.run_id, r.started_at, m.tp, m.fp, m.tn, m.fn
                FROM training_metrics m
                JOIN training_runs r ON r.id = m.run_id
                WHERE m.module = ?
                ORDER BY m.run_id DESC
                LIMIT ?
                """,
                (module, limit),
            ).fetchall()

        points: list[TrendPoint] = []
        for run_id, started_at, tp, fp, tn, fn in reversed(rows):
            cm = ConfusionMatrix(
                true_positives=tp,
                false_positives=fp,
                true_negatives=tn,
                false_negatives=fn,
            )
            points.append(
                TrendPoint(
                    run_id=run_id,
                    run_timestamp=datetime.fromisoformat(started_at),
                    accuracy=round(cm.accuracy, 4),
                    f1=round(cm.f1, 4),
                    precision=round(cm.precision, 4),
                    recall=round(cm.recall, 4),
                )
            )
        return points

    def calibration_report(
        self, predictions: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Analyse risk-score calibration.

        For each risk-score bucket (0-0.2, 0.2-0.4, …, 0.8-1.0) compute what
        fraction of sites in that bucket were actually scams.

        Args:
            predictions: list of dicts with keys ``ground_truth``, ``risk_score``.

        Returns:
            Dict mapping bucket label to fraction_scam.
        """
        buckets: dict[str, list[str]] = {
            "0.0-0.2": [],
            "0.2-0.4": [],
            "0.4-0.6": [],
            "0.6-0.8": [],
            "0.8-1.0": [],
        }
        for p in predictions:
            score: float = p.get("risk_score", 0.0)
            gt: str = p.get("ground_truth", "legit")
            if score < 0.2:
                buckets["0.0-0.2"].append(gt)
            elif score < 0.4:
                buckets["0.2-0.4"].append(gt)
            elif score < 0.6:
                buckets["0.4-0.6"].append(gt)
            elif score < 0.8:
                buckets["0.6-0.8"].append(gt)
            else:
                buckets["0.8-1.0"].append(gt)

        result: dict[str, Any] = {}
        for bucket, labels in buckets.items():
            if not labels:
                result[bucket] = None
            else:
                frac = sum(1 for l in labels if l == "scam") / len(labels)
                result[bucket] = round(frac, 4)
        return result

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_to_json(self, status_path: Path) -> dict[str, Any]:
        """
        Merge training metrics into ``chharcop-status.json``.

        Creates the file if it does not exist.  Returns the metrics dict
        that was written.
        """
        overall = self.latest_metrics("overall")
        web = self.latest_metrics("web")
        gaming = self.latest_metrics("gaming")
        trend_points = self.trend("overall")

        metrics_payload: dict[str, Any] = {
            "accuracy": round(overall.accuracy, 4) if overall else None,
            "precision": round(overall.precision, 4) if overall else None,
            "recall": round(overall.recall, 4) if overall else None,
            "f1": round(overall.f1, 4) if overall else None,
            "false_positive_rate": round(overall.false_positive_rate, 4) if overall else None,
            "total_runs": len(trend_points),
            "last_run": trend_points[-1].run_timestamp.isoformat() if trend_points else None,
            "trend": [
                {
                    "run_id": p.run_id,
                    "timestamp": p.run_timestamp.isoformat(),
                    "accuracy": p.accuracy,
                    "f1": p.f1,
                }
                for p in trend_points
            ],
            "per_module": {
                "web": web.to_dict() if web else None,
                "gaming": gaming.to_dict() if gaming else None,
                "overall": overall.to_dict() if overall else None,
            },
        }

        # Read / create status file
        if status_path.exists():
            try:
                status: dict[str, Any] = json.loads(status_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                status = {}
        else:
            status = {}

        status["training_metrics"] = metrics_payload
        status_path.write_text(json.dumps(status, indent=2, default=str), encoding="utf-8")
        logger.info("Exported training metrics to {}", status_path)
        return metrics_payload
