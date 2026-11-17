from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

BusinessValue = Literal["core", "support", "test"]
DataSensitivity = Literal["top_secret", "confidential", "internal", "public"]
AttackSurfaceExposure = Literal["internet", "dmz", "internal", "isolated"]
EventCategory = Literal[
    "malware",
    "intrusion_detection",
    "threat",
    "web",
    "authentication",
    "network",
    "file",
    "security",
    "configuration",
]
VulnerabilityExistence = Literal["existing", "possible", "none"]
Exploitability = Literal["public_exploit", "vulnerability_only", "none"]
PathReachability = Literal["direct", "hop", "isolated", "unknown"]
LateralMovementPotential = Literal[
    "jump_server", "key_segment", "endpoint", "unknown"
]
RiskStrategy = Literal["linear", "ahp_2026"]


class AssetContext(BaseModel):
    criticality: float = Field(3.0, ge=1, le=5, allow_inf_nan=False)
    business_value: BusinessValue = "support"
    data_sensitivity: DataSensitivity = "internal"
    attack_surface_exposure: AttackSurfaceExposure = "internal"


class EventContext(BaseModel):
    severity: float = Field(1.0, ge=1, le=5, allow_inf_nan=False)
    outcome: int = Field(1, ge=0, le=1)  # 0=blocked, 1=success/alert
    category: EventCategory = "network"
    phase_hazard: Optional[float] = Field(
        default=None, ge=0, le=1, allow_inf_nan=False
    )
    stage_policy_weight: Optional[float] = Field(
        default=None, ge=0, le=1, allow_inf_nan=False
    )


class ThreatContext(BaseModel):
    base_weight: float = Field(2.0, ge=1, le=5, allow_inf_nan=False)
    ioc_match: bool = False
    reputation_score: Optional[float] = Field(
        default=None, ge=0, le=100, allow_inf_nan=False
    )
    domain_age_days: Optional[int] = Field(default=None, ge=0)
    repeat_count: int = Field(default=0, ge=0)
    ioc_confidence: Optional[float] = Field(
        default=None, ge=0, le=1, allow_inf_nan=False
    )
    vulnerability_existence: VulnerabilityExistence = "none"
    apt_association: float = Field(0.0, ge=0, le=1, allow_inf_nan=False)
    intelligence_freshness: float = Field(0.0, ge=0, le=1, allow_inf_nan=False)
    exploitability: Exploitability = "none"
    path_reachability: PathReachability = "unknown"
    protection_bypass_evidence: bool = False
    kill_chain_progression: bool = False
    lateral_movement_potential: LateralMovementPotential = "unknown"


class EnvironmentContext(BaseModel):
    external_multiplier: Optional[float] = Field(
        default=None, ge=1, allow_inf_nan=False
    )
    internal_multiplier: Optional[float] = Field(
        default=None, ge=1, allow_inf_nan=False
    )


class RiskInput(BaseModel):
    asset: AssetContext = Field(default_factory=AssetContext)
    event: EventContext = Field(default_factory=EventContext)
    threat: ThreatContext = Field(default_factory=ThreatContext)
    environment: EnvironmentContext = Field(default_factory=EnvironmentContext)
    graph: Optional[dict[str, Any]] = None
    strategy: Optional[RiskStrategy] = None


class GraphValidationResult(BaseModel):
    status: Literal["not_provided", "valid", "partial", "invalid"] = "not_provided"
    gate_decision: Literal["retain", "fallback"] = "fallback"
    snapshot_id: Optional[str] = None
    validated_nodes: int = 0
    validated_edges: int = 0
    quarantined_facts: int = 0
    confirmed_ioc: bool = False
    ioc_confidence: Optional[float] = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    exploitable_vulnerability: bool = False
    apt_association: bool = False
    attack_stage_evidence: bool = False
    kill_chain_progression: bool = False
    evidence: list[str] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)


class RiskResult(BaseModel):
    score: float
    level: str  # low, medium, high, critical
    breakdown: dict[str, float]
    graph_validation: GraphValidationResult = Field(default_factory=GraphValidationResult)
