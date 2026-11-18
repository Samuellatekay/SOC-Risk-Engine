from .config import settings
from .models import RiskInput, RiskResult

BUSINESS_VALUE_SCORES = {"core": 1.0, "support": 0.6, "test": 0.2}
DATA_SENSITIVITY_SCORES = {
    "top_secret": 1.0,
    "confidential": 0.75,
    "internal": 0.5,
    "public": 0.25,
}
ATTACK_STAGE_SCORES = {
    "malware": 0.9,
    "intrusion_detection": 0.9,
    "threat": 0.9,
    "web": 0.7,
    "authentication": 0.7,
    "network": 0.5,
    "file": 0.5,
    "security": 0.5,
    "configuration": 0.5,
}
AHP_WEIGHTS = {
    "stage": 0.31,
    "feasibility": 0.22,
    "intel": 0.18,
    "target": 0.16,
    "persistence": 0.07,
    "env": 0.06,
}

def get_risk_level(score: float) -> str:
    """Classify the final 0-100 score: <40 low, <60 medium, <80 high, otherwise critical."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def build_risk_result(score: float, breakdown: dict[str, float]) -> RiskResult:
    """Apply the global environment multiplier, cap at 100, then classify the final score.

    Note: This global multiplier is a *deployment-level* tuning knob (e.g. to raise
    overall alerting sensitivity across the whole SOC). It is applied on top of the
    per-request `c_env` factor computed inside the AHP strategy, which reflects the
    specific request's own environment context. The two serve different purposes and
    are intentionally stacked.
    """
    multiplier = settings.risk_environment_multiplier
    final_score = round(max(0, min(100, score * multiplier)), 2)
    return RiskResult(
        score=final_score,
        level=get_risk_level(final_score),
        breakdown={**breakdown, "global_multiplier": multiplier},
    )


# --- STRATEGY 1: LINEAR ---
def calculate_linear(data: RiskInput) -> RiskResult:
    W_A, W_S, W_O, W_T = 0.30, 0.25, 0.20, 0.25
    max_raw = 5*W_A + 5*W_S + 1*W_O + 5*W_T  # Hasil: 4.2
    scale = 100 / max_raw  # FIX: Agar skor maksimal tepat 100

    raw = (data.asset.criticality * W_A) + \
          (data.event.severity * W_S) + \
          (data.event.outcome * W_O) + \
          (data.threat.base_weight * W_T)

    score = round(raw * scale, 2)
    return build_risk_result(
        score,
        {
            "asset": round(data.asset.criticality / 5, 3),
            "severity": round(data.event.severity / 5, 3),
            "outcome": float(data.event.outcome),
            "threat": round(data.threat.base_weight / 5, 3),
            "raw": raw,
        },
    )

# --- STRATEGY 2: AHP 2026 ---
def calculate_ahp_2026(data: RiskInput) -> RiskResult:
    """Calculate the weighted AHP score; the global multiplier is applied afterward."""
    # 1. Target Criticality (asset business value + data sensitivity + numeric criticality)
    c_target = (
        BUSINESS_VALUE_SCORES[data.asset.business_value]
        + DATA_SENSITIVITY_SCORES[data.asset.data_sensitivity]
        + (data.asset.criticality / 5.0)
    ) / 3

    # 2. Attack Stage Hazard (event category blended with event severity and
    #    threat base weight so every severity signal influences the score)
    c_stage = (
        ATTACK_STAGE_SCORES[data.event.category]
        + (data.event.severity / 5.0)
        + (data.threat.base_weight / 5.0)
    ) / 3

    # 3. Intel Match
    intel_score = 0.0
    if data.threat.ioc_match:
        intel_score += 0.5
    if (
        data.threat.reputation_score is not None
        and data.threat.reputation_score >= 80
    ):
        intel_score += 0.5
    c_intel = intel_score

    # 4. Feasibility (domain age)
    # FIX: Newly Registered Domains (NRD) are a known high-risk indicator in SOC.
    # Domain < 30 days  -> high risk (1.0)
    # Domain 30-180 days -> moderate risk (0.7)
    # Domain > 180 days  -> established/trusted (0.3)
    #    Unknown domain age (None) is treated as NEUTRAL (0.5), not maximum risk.
    feas = 0.5
    if data.threat.domain_age_days is not None:
        if data.threat.domain_age_days < 30:
            feas = 1.0
        elif data.threat.domain_age_days < 180:
            feas = 0.7
        else:
            feas = 0.3
    c_feas = feas

    # 5. Persistence
    c_persist = min(1.0, data.threat.repeat_count / 50.0)

    # 6. Environment (per-request context; see build_risk_result note above)
    c_env = min(
        1.0,
        max(
            0.0,
            (
                data.environment.external_multiplier
                + data.environment.internal_multiplier
            )
            / 4.0,
        ),
    )

    weights = AHP_WEIGHTS
    rb = 100 * (
        (weights["target"] * c_target)
        + (weights["stage"] * c_stage)
        + (weights["intel"] * c_intel)
        + (weights["feasibility"] * c_feas)
        + (weights["persistence"] * c_persist)
        + (weights["env"] * c_env)
    )

    # 7. Outcome adjustment
    # FIX: If the event was blocked (outcome=0), the realized risk is lower.
    # Reduce the raw AHP score by 30% to reflect successful mitigation.
    outcome_factor = 1.0 if data.event.outcome == 1 else 0.7
    adjusted_rb = rb * outcome_factor

    score = round(max(0, min(100, adjusted_rb)), 2)

    return build_risk_result(
        score,
        {
            "target": round(c_target, 3),
            "stage": round(c_stage, 3),
            "intel": round(c_intel, 3),
            "feas": round(c_feas, 3),
            "persist": round(c_persist, 3),
            "env": round(c_env, 3),
            "outcome_factor": outcome_factor,
        },
    )
