from typing import Literal, Optional

from pydantic import BaseModel, Field

BusinessValue = Literal["core", "support", "test"]
DataSensitivity = Literal["top_secret", "confidential", "internal", "public"]
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
RiskStrategy = Literal["linear", "ahp_2026"]


class AssetContext(BaseModel):
    criticality: float = Field(3.0, ge=1, le=5, allow_inf_nan=False)
    business_value: BusinessValue = "support"
    data_sensitivity: DataSensitivity = "internal"


class EventContext(BaseModel):
    severity: float = Field(1.0, ge=1, le=5, allow_inf_nan=False)
    outcome: int = Field(1, ge=0, le=1)  # 0=blocked, 1=success/alert
    category: EventCategory = "network"


class ThreatContext(BaseModel):
    base_weight: float = Field(2.0, ge=1, le=5, allow_inf_nan=False)
    ioc_match: bool = False
    reputation_score: Optional[float] = Field(
        default=None, ge=0, le=100, allow_inf_nan=False
    )
    domain_age_days: Optional[int] = Field(default=None, ge=0)
    repeat_count: int = Field(default=0, ge=0)


class EnvironmentContext(BaseModel):
    external_multiplier: float = Field(1.0, ge=0, allow_inf_nan=False)
    internal_multiplier: float = Field(1.0, ge=0, allow_inf_nan=False)


class RiskInput(BaseModel):
    asset: AssetContext = Field(default_factory=AssetContext)
    event: EventContext = Field(default_factory=EventContext)
    threat: ThreatContext = Field(default_factory=ThreatContext)
    environment: EnvironmentContext = Field(default_factory=EnvironmentContext)
    strategy: Optional[RiskStrategy] = None


class RiskResult(BaseModel):
    score: float
    level: str  # low, medium, high, critical
    breakdown: dict[str, float]
