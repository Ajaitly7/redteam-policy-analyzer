"""
database/models.py
------------------
Python dataclasses mirroring every table in schema.sql.
These are plain data containers — no ORM magic.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class HarmCategory:
    name: str
    severity_level: str           # LOW | MEDIUM | HIGH | CRITICAL
    description: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None

    # Allowed severity levels for quick validation
    SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def validate(self) -> None:
        if self.severity_level not in self.SEVERITY_LEVELS:
            raise ValueError(
                f"severity_level must be one of {self.SEVERITY_LEVELS}, "
                f"got '{self.severity_level}'"
            )


@dataclass
class AttackVector:
    harm_category_id: int
    name: str
    description: Optional[str] = None
    framing_type: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None


@dataclass
class PolicyRule:
    rule_text: str
    harm_category_id: Optional[int] = None
    domain: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None


@dataclass
class Prompt:
    text: str
    attack_vector_id: Optional[int] = None
    is_base: bool = True
    parent_prompt_id: Optional[int] = None
    variation_type: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None


@dataclass
class ModelResponse:
    prompt_id: int
    response_text: Optional[str] = None
    model_name: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None


@dataclass
class SafetyClassification:
    prompt_id: int
    classification: str           # SAFE | UNSAFE | AMBIGUOUS
    confidence: float             # 0.0 – 1.0
    classifier_type: str = "heuristic"
    model_response_id: Optional[int] = None
    reasoning: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None

    LABELS = ("SAFE", "UNSAFE", "AMBIGUOUS")

    def validate(self) -> None:
        if self.classification not in self.LABELS:
            raise ValueError(
                f"classification must be one of {self.LABELS}, "
                f"got '{self.classification}'"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )


@dataclass
class PolicyCoverage:
    attack_vector_id: int
    coverage_status: str          # COVERED | PARTIAL | GAP
    policy_rule_id: Optional[int] = None
    notes: Optional[str] = None
    id: Optional[int] = None
    updated_at: Optional[datetime] = None

    STATUSES = ("COVERED", "PARTIAL", "GAP")

    def validate(self) -> None:
        if self.coverage_status not in self.STATUSES:
            raise ValueError(
                f"coverage_status must be one of {self.STATUSES}, "
                f"got '{self.coverage_status}'"
            )


@dataclass
class GoldSetEntry:
    prompt_id: int
    expected_classification: str  # SAFE | UNSAFE | AMBIGUOUS
    confidence_level: str         # HIGH | MEDIUM | LOW
    labeler_notes: Optional[str] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None

    CONFIDENCE_LEVELS = ("HIGH", "MEDIUM", "LOW")

    def validate(self) -> None:
        if self.expected_classification not in SafetyClassification.LABELS:
            raise ValueError(
                f"expected_classification must be one of "
                f"{SafetyClassification.LABELS}"
            )
        if self.confidence_level not in self.CONFIDENCE_LEVELS:
            raise ValueError(
                f"confidence_level must be one of {self.CONFIDENCE_LEVELS}"
            )
