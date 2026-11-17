from pydantic import Field
from pydantic_settings import BaseSettings

from .models import RiskStrategy


class Settings(BaseSettings):
    risk_strategy: RiskStrategy = "linear"
    risk_external_multiplier: float = Field(1.0, ge=1, allow_inf_nan=False)
    risk_internal_multiplier: float = Field(1.0, ge=1, allow_inf_nan=False)
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 2
    log_level: str = "info"

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()