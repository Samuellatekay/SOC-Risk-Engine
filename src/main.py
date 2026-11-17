from fastapi import FastAPI
from .config import settings
from .models import RiskInput, RiskResult, RiskStrategy
from .strategies import calculate_linear, calculate_ahp_2026


app = FastAPI(title="SOC Risk Score Engine", version="1.0.0")

STRATEGIES = {
    "linear": calculate_linear,
    "ahp_2026": calculate_ahp_2026,
}


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "strategy": settings.risk_strategy,
        "environment_multiplier": settings.risk_environment_multiplier,
    }


@app.post("/calculate", response_model=RiskResult)
def calculate_risk(payload: RiskInput):
    strategy_name: RiskStrategy = payload.strategy or settings.risk_strategy
    return STRATEGIES[strategy_name](payload)
