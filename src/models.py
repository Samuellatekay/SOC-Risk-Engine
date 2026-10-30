from pydantic import BaseModel, Field
from typing import Optional, Literal

class AssetContext(BaseModel):
    criticality: float = Field(3.0, ge=1, le=5)
    business_value: str = "support"  # core, support, test
    data_sensitivity: str = "internal" # top_secret, confidential, internal, public

class EventContext(BaseModel):
    severity: float = Field(1.0, ge=1, le=5)
    outcome: int = Field(1, ge=0, le=1)  # 0=blocked, 1=success/alert
    category: str = "network"

class ThreatContext(BaseModel):
    base_weight: float = Field(2.0, ge=1, le=5)
    ioc_match: bool = False
    reputation_score: Optional[float] = None  # 0-100
    domain_age_days: Optional[int] = None
    repeat_count: int = 0

class EnvironmentContext(BaseModel):
    external_multiplier: float = 1.0
    internal_multiplier: float = 1.0

class RiskInput(BaseModel):
    asset: AssetContext = AssetContext()
    event: EventContext = EventContext()
    threat: ThreatContext = ThreatContext()
    environment: EnvironmentContext = EnvironmentContext()
    strategy: Literal["linear", "ahp_2026"] = "linear"

class RiskResult(BaseModel):
    score: float
    level: str  # low, medium, high, critical
    breakdown: dict