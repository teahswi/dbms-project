"""
CyberShield Risk Scoring Engine
Implements the transparent, explainable formula:
priority = min(100, (CVSS * 10) * asset_criticality_weight * exploit_multiplier * (1 - control_effectiveness))
"""
from typing import Dict, Any, Tuple
from app.constants import AssetCriticality, Severity

ASSET_WEIGHTS = {
    AssetCriticality.TIER_1: 1.30, # Critical (Prod Core)
    AssetCriticality.TIER_2: 1.15, # High (Prod Edge)
    AssetCriticality.TIER_3: 1.00, # Medium (Internal)
    AssetCriticality.TIER_4: 0.85, # Low (Staging/Dev)
    AssetCriticality.TIER_5: 0.70  # Informational (Sandbox)
}

EXPLOIT_MULTIPLIERS = {
    True: 1.25,   # Weaponized / Active Exploit Available
    False: 1.00   # No known public exploit
}

SLA_DAYS = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 14,
    Severity.MEDIUM: 30,
    Severity.LOW: 90
}

def calculate_priority_score(
    cvss_score: float,
    asset_criticality: int,
    exploit_available: bool = False,
    control_effectiveness: float = 0.0
) -> Tuple[float, str, Dict[str, Any]]:
    """
    Computes normalized 0-100 priority score and returns breakdown inputs.
    """
    cvss = max(0.0, min(10.0, float(cvss_score)))
    base_val = cvss * 10.0
    crit_weight = ASSET_WEIGHTS.get(int(asset_criticality), 1.0)
    exploit_mult = EXPLOIT_MULTIPLIERS.get(bool(exploit_available), 1.0)
    eff = max(0.0, min(0.5, float(control_effectiveness))) # Mitigating factor up to 50%
    control_factor = 1.0 - eff

    raw_score = base_val * crit_weight * exploit_mult * control_factor
    normalized_score = round(min(100.0, max(0.0, raw_score)), 1)

    if normalized_score >= 80.0:
        bucket = Severity.CRITICAL
    elif normalized_score >= 60.0:
        bucket = Severity.HIGH
    elif normalized_score >= 35.0:
        bucket = Severity.MEDIUM
    else:
        bucket = Severity.LOW

    breakdown = {
        "cvss_score": cvss,
        "base_val": base_val,
        "asset_criticality": asset_criticality,
        "asset_criticality_weight": crit_weight,
        "exploit_available": exploit_available,
        "exploit_multiplier": exploit_mult,
        "control_effectiveness": eff,
        "control_factor": control_factor,
        "raw_score": raw_score,
        "normalized_score": normalized_score,
        "severity_bucket": bucket,
        "formula": "priority = min(100, (CVSS * 10) * asset_weight * exploit_mult * (1 - control_eff))"
    }

    return normalized_score, bucket, breakdown
