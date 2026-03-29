"""
Chharcop auto-training module.

Continuously evaluates Chharcop's detection accuracy against known scam and
legitimate sites, tracks improvement over time, and exports metrics for
the status dashboard.
"""

from chharcop.training.dataset import TrainingDataset
from chharcop.training.metrics import AccuracyMetrics
from chharcop.training.trainer import TrainingRun, Trainer

__all__ = ["Trainer", "TrainingRun", "TrainingDataset", "AccuracyMetrics"]
