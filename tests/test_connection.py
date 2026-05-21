"""
tests/test_connection.py
------------------------
Smoke tests for DatabaseConnection and dataclass models.
"""

import os
import tempfile
import pytest
from pathlib import Path

from database.connection import DatabaseConnection
from database.models import (
    HarmCategory,
    AttackVector,
    SafetyClassification,
    PolicyCoverage,
    GoldSetEntry,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """Return a fresh DatabaseConnection backed by a temp file."""
    db_path = tmp_path / "test.db"
    with DatabaseConnection(db_path) as db:
        yield db


# ── Connection tests ──────────────────────────────────────────────────────────

def test_schema_applied_on_new_db(tmp_path):
    """A freshly created DB must have all 8 tables."""
    db_path = tmp_path / "fresh.db"
    expected_tables = {
        "harm_categories", "attack_vectors", "policy_rules",
        "prompts", "model_responses", "safety_classifications",
        "policy_coverage", "gold_set",
    }
    with DatabaseConnection(db_path) as db:
        rows = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        found = {r["name"] for r in rows}
    assert expected_tables.issubset(found)


def test_foreign_keys_enforced(tmp_path):
    """Inserting a prompt with a non-existent attack_vector_id must fail."""
    import sqlite3
    db_path = tmp_path / "fk.db"
    with pytest.raises(sqlite3.IntegrityError):
        with DatabaseConnection(db_path) as db:
            db.execute(
                "INSERT INTO prompts (attack_vector_id, text, is_base) VALUES (?, ?, ?)",
                (9999, "should fail", 1),
            )


def test_insert_and_fetch_harm_category(tmp_db):
    tmp_db.execute(
        "INSERT INTO harm_categories (name, severity_level) VALUES (?, ?)",
        ("test_cat", "HIGH"),
    )
    row = tmp_db.fetchone(
        "SELECT * FROM harm_categories WHERE name = ?", ("test_cat",)
    )
    assert row is not None
    assert row["severity_level"] == "HIGH"


def test_context_manager_commits(tmp_path):
    """Data written inside the context manager must persist after close."""
    db_path = tmp_path / "persist.db"
    with DatabaseConnection(db_path) as db:
        db.execute(
            "INSERT INTO harm_categories (name, severity_level) VALUES (?, ?)",
            ("persist_test", "LOW"),
        )
    with DatabaseConnection(db_path) as db:
        row = db.fetchone(
            "SELECT * FROM harm_categories WHERE name = ?", ("persist_test",)
        )
    assert row is not None


# ── Model validation tests ────────────────────────────────────────────────────

def test_harm_category_invalid_severity():
    cat = HarmCategory(name="x", severity_level="EXTREME")
    with pytest.raises(ValueError, match="severity_level"):
        cat.validate()


def test_safety_classification_confidence_out_of_range():
    sc = SafetyClassification(prompt_id=1, classification="SAFE", confidence=1.5)
    with pytest.raises(ValueError, match="confidence"):
        sc.validate()


def test_safety_classification_invalid_label():
    sc = SafetyClassification(prompt_id=1, classification="MAYBE", confidence=0.5)
    with pytest.raises(ValueError, match="classification"):
        sc.validate()


def test_policy_coverage_invalid_status():
    pc = PolicyCoverage(attack_vector_id=1, coverage_status="UNKNOWN")
    with pytest.raises(ValueError, match="coverage_status"):
        pc.validate()


def test_gold_set_invalid_confidence_level():
    gs = GoldSetEntry(
        prompt_id=1,
        expected_classification="SAFE",
        confidence_level="EXTREME",
    )
    with pytest.raises(ValueError, match="confidence_level"):
        gs.validate()
