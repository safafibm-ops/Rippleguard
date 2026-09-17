"""Ranking-quality metrics used by the validation harness."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.evaluation.validate import (average_precision, precision_at_k,
                                     recall_at_k, roc_auc)


def test_roc_auc_perfect_and_inverted():
    assert roc_auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) == 1.0
    assert roc_auc([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]) == 0.0


def test_roc_auc_is_half_for_ties():
    assert roc_auc([0.5, 0.5, 0.5, 0.5], [1, 1, 0, 0]) == 0.5


def test_roc_auc_none_without_both_classes():
    assert roc_auc([0.4, 0.6], [1, 1]) is None


def test_precision_and_recall_at_k():
    scores, labels = [0.9, 0.8, 0.7, 0.1], [1, 0, 1, 0]
    assert precision_at_k(scores, labels, 2) == 0.5
    assert recall_at_k(scores, labels, 3) == 1.0


def test_average_precision():
    assert average_precision([0.9, 0.8, 0.7], [1, 1, 0]) == 1.0
