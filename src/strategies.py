from .config import settings
from .graph_integrity import validate_graph
from .models import GraphValidationResult, RiskInput, RiskResult

BUSINESS_VALUE_SCORES = {"core": 1.0, "support": 0.6, "test": 0.2}
DATA_SENSITIVITY_SCORES = {
    "top_secret": 1.0,
    "confidential": 0.75,
    "internal": 0.5,
    "public": 0.25,
}
ATTACK_SURFACE_SCORES = {
    "internet": 1.0,
    "dmz": 0.8,
    "internal": 0.6,
    "isolated": 0.2,
}
ATTACK_PHASE_FALLBACKS = {
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
VULNERABILITY_SCORES = {"existing": 1.0, "possible": 0.5, "none": 0.0}
EXPLOITABILITY_SCORES = {
    "public_exploit": 1.0,
    "vulnerability_only": 0.7,
    "none": 0.3,
}
PATH_REACHABILITY_SCORES = {
    "direct": 1.0,
    "hop": 0.8,
    "isolated": 0.1,
    "unknown": 0.5,
}
LATERAL_MOVEMENT_SCORES = {
    "jump_server": 1.0,
    "key_segment": 1.0,
    "endpoint": 0.7,
    "unknown": 0.7,
}

# Criterion weights from the paper's AHP judgment matrix (Table 5).
AHP_WEIGHTS = {
    "target": 0.16,
    "stage": 0.31,
    "intel": 0.18,
    "feasibility": 0.22,
    "persistence": 0.07,
    "env": 0.06,
}

TARGET_SUBWEIGHTS = {
    "business_value": 0.40,
    "data_sensitivity": 0.30,
    "attack_surface": 0.30,
}
STAGE_SUBWEIGHTS = {"phase_hazard": 0.70, "policy_weight": 0.30}
INTEL_SUBWEIGHTS = {
    "ioc_confidence": 0.30,
    "vulnerability": 0.20,
    "apt_association": 0.40,
    "freshness": 0.10,
}
FEASIBILITY_SUBWEIGHTS = {
    "exploitability": 0.50,
    "path_reachability": 0.30,
    "protection_bypass": 0.20,
}
PERSISTENCE_SUBWEIGHTS = {
    "alert_correlation": 0.40,
    "kill_chain_progression": 0.40,
    "lateral_movement": 0.20,
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


def get_environment_multipliers(data: RiskInput) -> tuple[float, float]:
    external = data.environment.external_multiplier
    internal = data.environment.internal_multiplier
    return (
        settings.risk_external_multiplier if external is None else external,
        settings.risk_internal_multiplier if internal is None else internal,
    )


def validate_input_graph(data: RiskInput) -> GraphValidationResult:
    return validate_graph(
        data.graph,
        asset_criticality=data.asset.criticality,
        attack_stage_evidence=(
            data.event.phase_hazard is not None and data.event.phase_hazard > 0
        ),
        kill_chain_progression=data.threat.kill_chain_progression,
    )


def build_risk_result(
    score: float,
    breakdown: dict[str, float],
    external_multiplier: float,
    internal_multiplier: float,
    graph_validation: GraphValidationResult,
) -> RiskResult:
    """Apply the paper's external and internal multipliers before classifying the score."""
    final_multiplier = external_multiplier * internal_multiplier
    final_score = round(max(0, min(100, score * final_multiplier)), 2)
    return RiskResult(
        score=final_score,
        level=get_risk_level(final_score),
        breakdown={
            **breakdown,
            "base_score": round(score, 2),
            "external_multiplier": external_multiplier,
            "internal_multiplier": internal_multiplier,
            "final_multiplier": final_multiplier,
        },
        graph_validation=graph_validation,
    )


def calculate_linear(data: RiskInput) -> RiskResult:
    weight_asset, weight_severity, weight_outcome, weight_threat = (
        0.30,
        0.25,
        0.20,
        0.25,
    )
    max_raw = 5 * weight_asset + 5 * weight_severity + weight_outcome + 5 * weight_threat
    raw = (
        data.asset.criticality * weight_asset
        + data.event.severity * weight_severity
        + data.event.outcome * weight_outcome
        + data.threat.base_weight * weight_threat
    )
    score = round(raw * (100 / max_raw), 2)
    external_multiplier, internal_multiplier = get_environment_multipliers(data)
    return build_risk_result(
        score,
        {"raw": raw},
        external_multiplier,
        internal_multiplier,
        validate_input_graph(data),
    )


def calculate_ahp_2026(data: RiskInput) -> RiskResult:
    """Calculate the six-criterion AHP model using the paper's 17 sub-indicators."""
    asset = data.asset
    event = data.event
    threat = data.threat
    external_multiplier, internal_multiplier = get_environment_multipliers(data)
    graph_validation = validate_input_graph(data)

    target_business_value = BUSINESS_VALUE_SCORES[asset.business_value]
    target_data_sensitivity = DATA_SENSITIVITY_SCORES[asset.data_sensitivity]
    target_attack_surface = ATTACK_SURFACE_SCORES[asset.attack_surface_exposure]
    c_target = (
        TARGET_SUBWEIGHTS["business_value"] * target_business_value
        + TARGET_SUBWEIGHTS["data_sensitivity"] * target_data_sensitivity
        + TARGET_SUBWEIGHTS["attack_surface"] * target_attack_surface
    )

    phase_hazard = (
        event.phase_hazard
        if event.phase_hazard is not None
        else ATTACK_PHASE_FALLBACKS[event.category]
    )
    stage_policy_weight = (
        event.stage_policy_weight if event.stage_policy_weight is not None else 0.5
    )
    c_stage = (
        STAGE_SUBWEIGHTS["phase_hazard"] * phase_hazard
        + STAGE_SUBWEIGHTS["policy_weight"] * stage_policy_weight
    )

    if threat.ioc_confidence is not None:
        ioc_confidence = threat.ioc_confidence
    elif data.graph is not None:
        ioc_confidence = graph_validation.ioc_confidence or 0.0
    elif threat.reputation_score is not None:
        ioc_confidence = threat.reputation_score / 100
    else:
        ioc_confidence = 1.0 if threat.ioc_match else 0.0

    vulnerability_score = (
        1.0
        if graph_validation.exploitable_vulnerability
        else VULNERABILITY_SCORES[threat.vulnerability_existence]
    )
    apt_association = max(
        threat.apt_association,
        1.0 if graph_validation.apt_association else 0.0,
    )
    intelligence_freshness = threat.intelligence_freshness
    c_intel = (
        INTEL_SUBWEIGHTS["ioc_confidence"] * ioc_confidence
        + INTEL_SUBWEIGHTS["vulnerability"] * vulnerability_score
        + INTEL_SUBWEIGHTS["apt_association"] * apt_association
        + INTEL_SUBWEIGHTS["freshness"] * intelligence_freshness
    )

    exploitability = (
        1.0
        if graph_validation.exploitable_vulnerability
        else EXPLOITABILITY_SCORES[threat.exploitability]
    )
    path_reachability = PATH_REACHABILITY_SCORES[threat.path_reachability]
    protection_bypass = 1.0 if threat.protection_bypass_evidence else 0.8
    c_feasibility = (
        FEASIBILITY_SUBWEIGHTS["exploitability"] * exploitability
        + FEASIBILITY_SUBWEIGHTS["path_reachability"] * path_reachability
        + FEASIBILITY_SUBWEIGHTS["protection_bypass"] * protection_bypass
    )

    alert_correlation = min(1.0, 0.5 + 0.1 * threat.repeat_count)
    kill_chain_progression = (
        1.0
        if threat.kill_chain_progression or graph_validation.kill_chain_progression
        else 0.5
    )
    lateral_movement = LATERAL_MOVEMENT_SCORES[threat.lateral_movement_potential]
    c_persistence = (
        PERSISTENCE_SUBWEIGHTS["alert_correlation"] * alert_correlation
        + PERSISTENCE_SUBWEIGHTS["kill_chain_progression"] * kill_chain_progression
        + PERSISTENCE_SUBWEIGHTS["lateral_movement"] * lateral_movement
    )

    # Table 4 gives no sub-weights for these two indicators, so use an equal average.
    external_environment = min(1.0, max(0.0, (external_multiplier - 1.0) / 0.2))
    internal_environment = min(1.0, max(0.0, (internal_multiplier - 1.0) / 0.1))
    c_environment = (external_environment + internal_environment) / 2

    criteria = {
        "target": c_target,
        "stage": c_stage,
        "intel": c_intel,
        "feasibility": c_feasibility,
        "persistence": c_persistence,
        "env": c_environment,
    }
    base_score = 100 * sum(
        AHP_WEIGHTS[key] * criteria[key] for key in AHP_WEIGHTS
    )

    breakdown = {
        "target": round(c_target, 3),
        "stage": round(c_stage, 3),
        "intel": round(c_intel, 3),
        "feas": round(c_feasibility, 3),
        "persist": round(c_persistence, 3),
        "env": round(c_environment, 3),
        "target_business_value": target_business_value,
        "target_data_sensitivity": target_data_sensitivity,
        "target_attack_surface": target_attack_surface,
        "phase_hazard": round(phase_hazard, 3),
        "stage_policy_weight": round(stage_policy_weight, 3),
        "ioc_confidence": round(ioc_confidence, 3),
        "vulnerability_existence": vulnerability_score,
        "apt_association": round(apt_association, 3),
        "intelligence_freshness": round(intelligence_freshness, 3),
        "exploitability": exploitability,
        "path_reachability": path_reachability,
        "protection_bypass": protection_bypass,
        "alert_correlation": round(alert_correlation, 3),
        "kill_chain_progression": kill_chain_progression,
        "lateral_movement": lateral_movement,
        "external_environment": round(external_environment, 3),
        "internal_environment": round(internal_environment, 3),
    }
    return build_risk_result(
        base_score,
        breakdown,
        external_multiplier,
        internal_multiplier,
        graph_validation,
    )
