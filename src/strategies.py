from .models import RiskInput, RiskResult

def get_risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"

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
    return RiskResult(score=score, level=get_risk_level(score), breakdown={"raw": raw})

# --- STRATEGY 2: AHP 2026 ---
def calculate_ahp_2026(data: RiskInput) -> RiskResult:
    W = {
        "stage": 0.31, 
        "feasibility": 0.22, 
        "intel": 0.18, 
        "target": 0.16, 
        "persistence": 0.07, 
        "env": 0.06
    }
    
    # 1. Target Criticality
    bv_map = {"core": 1.0, "support": 0.6, "test": 0.2}
    ds_map = {"top_secret": 1.0, "confidential": 0.75, "internal": 0.5, "public": 0.25}
    c_target = (
        bv_map.get(data.asset.business_value, 0.6) + 
        ds_map.get(data.asset.data_sensitivity, 0.5)
    ) / 2
    
    # 2. Attack Stage Hazard
    stage_map = {
        "malware": 0.9, "intrusion_detection": 0.9, "threat": 0.9, 
        "web": 0.7, "authentication": 0.7, "network": 0.5, "file": 0.5
    }
    c_stage = stage_map.get(data.event.category, 0.5)
    
    # 3. Intel Match
    intel_score = 0.0
    if data.threat.ioc_match:
        intel_score += 0.5
    if data.threat.reputation_score and data.threat.reputation_score >= 80:
        intel_score += 0.5
    c_intel = intel_score
    
    # 4. Feasibility
    feas = 1.0
    if data.threat.domain_age_days:
        if data.threat.domain_age_days < 30:
            feas = 0.3
        elif data.threat.domain_age_days < 180:
            feas = 0.7
        else:
            feas = 1.0
    c_feas = feas
    
    # 5. Persistence
    c_persist = min(1.0, data.threat.repeat_count / 50.0)
    
    # 6. Environment
    c_env = (
        data.environment.external_multiplier + 
        data.environment.internal_multiplier
    ) / 2

    # Hitung Rb (Persamaan 9)
    Rb = 100 * (
        (W["target"] * c_target) + 
        (W["stage"] * c_stage) + 
        (W["intel"] * c_intel) +
        (W["feasibility"] * c_feas) + 
        (W["persistence"] * c_persist) + 
        (W["env"] * c_env)
    )
    
    # Hitung Skor Final (Persamaan 10)
    score = round(min(100, Rb), 2)
    
    return RiskResult(
        score=score, 
        level=get_risk_level(score), 
        breakdown={
            "target": round(c_target, 3), 
            "stage": round(c_stage, 3), 
            "intel": round(c_intel, 3), 
            "feas": round(c_feas, 3), 
            "persist": round(c_persist, 3), 
            "env": round(c_env, 3)
        }
    )