"""
WinShield+ risk policy.

Provides transparent vulnerability risk scoring used by both training and
runtime prioritisation.

The policy score is the primary explainable ranking signal. Machine learning
models can learn and support this policy, but the policy remains visible and
auditable.
"""

from __future__ import annotations

from typing import Any

import pandas as pd


# ------------------------------------------------------------
# POLICY CONSTANTS
# ------------------------------------------------------------

HIGH_PRIORITY_THRESHOLD = 9.0
MEDIUM_PRIORITY_THRESHOLD = 6.0

MAX_PATCH_AGE_BONUS = 2.0
PATCH_AGE_DIVISOR_DAYS = 90


# ------------------------------------------------------------
# VALUE HELPERS
# ------------------------------------------------------------

def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float without raising runtime errors."""

    try:
        if pd.isna(value):
            return default

        return float(value)

    except (TypeError, ValueError):
        return default


def safe_string(value: Any) -> str:
    """Convert a value to a stripped string."""

    if pd.isna(value):
        return ""

    return str(value).strip()


def exploitation_detected(value: Any) -> bool:
    """Return True if MSRC exploitation metadata indicates active exploitation."""

    return "Exploited:Yes" in safe_string(value)


# ------------------------------------------------------------
# RISK DRIVER HELPERS
# ------------------------------------------------------------

def get_patch_age_bonus(patch_age_days: Any) -> float:
    """Return a capped patch age bonus."""

    age_days = max(safe_float(patch_age_days), 0.0)

    return min(age_days / PATCH_AGE_DIVISOR_DAYS, MAX_PATCH_AGE_BONUS)


def get_impact_bonus(row: pd.Series) -> float:
    """Return a bonus when confidentiality, integrity, or availability impact is high."""

    impact_fields = [
        safe_string(row.get("confidentiality_impact")).upper(),
        safe_string(row.get("integrity_impact")).upper(),
        safe_string(row.get("availability_impact")).upper(),
    ]

    if "H" in impact_fields:
        return 0.5

    return 0.0


def get_policy_drivers(row: pd.Series) -> list[str]:
    """Return human-readable drivers behind the policy score."""

    drivers: list[str] = []

    cvss_score = safe_float(row.get("cvss_score"))

    if cvss_score >= 9.0:
        drivers.append("critical CVSS")
    elif cvss_score >= 7.0:
        drivers.append("high CVSS")

    if exploitation_detected(row.get("exploitation")):
        drivers.append("exploitation signal")

    if safe_string(row.get("attack_vector")).upper() == "N":
        drivers.append("network attack vector")

    if safe_string(row.get("privileges_required")).upper() == "N":
        drivers.append("no privileges required")

    if safe_string(row.get("user_interaction")).upper() == "N":
        drivers.append("no user interaction")

    if get_impact_bonus(row) > 0:
        drivers.append("high impact")

    if get_patch_age_bonus(row.get("patch_age_days")) >= 1.0:
        drivers.append("patch age exposure")

    if not drivers:
        drivers.append("baseline CVSS exposure")

    return drivers


# ------------------------------------------------------------
# POLICY SCORING
# ------------------------------------------------------------

def calculate_policy_risk(row: pd.Series) -> float:
    """
    Calculate transparent policy risk for one vulnerability row.

    Base score:
        CVSS score

    Additive policy factors:
        +2.0 if exploitation is detected
        +1.0 if attack vector is network
        +0.5 if no privileges are required
        +0.5 if no user interaction is required
        +0.5 if any CIA impact is high
        +patch age bonus capped at 2.0
    """

    score = safe_float(row.get("cvss_score"))

    if exploitation_detected(row.get("exploitation")):
        score += 2.0

    if safe_string(row.get("attack_vector")).upper() == "N":
        score += 1.0

    if safe_string(row.get("privileges_required")).upper() == "N":
        score += 0.5

    if safe_string(row.get("user_interaction")).upper() == "N":
        score += 0.5

    score += get_impact_bonus(row)
    score += get_patch_age_bonus(row.get("patch_age_days"))

    return round(score, 2)


def assign_priority_label(policy_risk: float) -> str:
    """Assign a priority label from a policy risk score."""

    if policy_risk >= HIGH_PRIORITY_THRESHOLD:
        return "High"

    if policy_risk >= MEDIUM_PRIORITY_THRESHOLD:
        return "Medium"

    return "Low"


def apply_risk_policy(dataframe: pd.DataFrame) -> pd.DataFrame:
    """
    Apply risk policy columns to a vulnerability dataframe.

    Adds:
        policy_risk
        policy_priority
        policy_drivers
        top_driver
    """

    output = dataframe.copy()

    output["policy_risk"] = output.apply(calculate_policy_risk, axis=1)
    output["policy_priority"] = output["policy_risk"].apply(assign_priority_label)
    output["policy_drivers"] = output.apply(get_policy_drivers, axis=1)
    output["top_driver"] = output["policy_drivers"].apply(
        lambda drivers: drivers[0] if drivers else "baseline CVSS exposure"
    )

    return output