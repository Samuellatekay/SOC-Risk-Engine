from fastapi import FastAPI, HTTPException
from src.config import settings
from src.models import RiskInput, RiskResult
from src.strategies import calculate_linear, calculate_ahp_2026

app = FastAPI(title="SOC Risk Score Engine", version="1.0.0")

STRATEGIES = {
    "linear": calculate_linear,
    "ahp_2026": calculate_ahp_2026,
}

@app.get("/health")
def health_check():
    return {"status": "healthy", "strategy": settings.risk_strategy}

@app.post("/calculate", response_model=RiskResult)
def calculate_risk(payload: RiskInput):
    strategy_name = payload.strategy or settings.risk_strategy
    strategy_fn = STRATEGIES.get(strategy_name)
    
    if not strategy_fn:
        raise HTTPException(status_code=400, detail=f"Strategi '{strategy_name}' tidak didukung.")
    
    try:
        return strategy_fn(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))