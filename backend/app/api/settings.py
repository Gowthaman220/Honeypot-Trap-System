import json
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.models.configuration import SystemConfiguration
from app.detection.engine import detection_engine
from app.api.deps import get_current_admin

router = APIRouter(prefix="/settings", tags=["Settings"])


class RuleToggleRequest(BaseModel):
    enabled: bool


class RiskWeightsUpdateRequest(BaseModel):
    repeated_attempts: int
    multi_service: int
    high_frequency: int
    suspicious_pattern: int
    known_indicator: int


@router.get("")
def get_settings(db: Session = Depends(get_db), current_admin = Depends(get_current_admin)):
    """Retrieve system settings, detection rules, and risk scoring configuration."""
    rules = detection_engine.get_all_rules()

    # Read config from DB
    weights_cfg = db.query(SystemConfiguration).filter(SystemConfiguration.key == "risk_weights").first()
    weights = json.loads(weights_cfg.value_json) if weights_cfg else {
        "repeated_attempts": settings.RISK_WEIGHT_REPEATED_ATTEMPTS,
        "multi_service": settings.RISK_WEIGHT_MULTI_SERVICE,
        "high_frequency": settings.RISK_WEIGHT_HIGH_FREQUENCY,
        "suspicious_pattern": settings.RISK_WEIGHT_SUSPICIOUS_PATTERN,
        "known_indicator": settings.RISK_WEIGHT_KNOWN_INDICATOR
    }

    return {
        "app_name": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "detection_rules": rules,
        "risk_weights": weights,
        "honeypot_ports": {
            "ssh": settings.SSH_HONEYPOT_PORT,
            "http": settings.HTTP_HONEYPOT_PORT,
            "ftp": settings.FTP_HONEYPOT_PORT,
            "tcp": settings.TCP_HONEYPOT_PORT
        }
    }


@router.put("/rules/{rule_id}")
def toggle_rule(rule_id: str, payload: RuleToggleRequest, current_admin = Depends(get_current_admin)):
    """Toggle a detection rule active/inactive."""
    success = detection_engine.set_rule_enabled(rule_id.upper(), payload.enabled)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule ID not found")
    return {"message": f"Rule {rule_id.upper()} enabled set to {payload.enabled}"}


@router.put("/weights")
def update_weights(payload: RiskWeightsUpdateRequest, db: Session = Depends(get_db), current_admin = Depends(get_current_admin)):
    """Update heuristic risk scoring factor weights."""
    cfg = db.query(SystemConfiguration).filter(SystemConfiguration.key == "risk_weights").first()
    new_weights = payload.dict()
    if not cfg:
        cfg = SystemConfiguration(key="risk_weights", value_json=json.dumps(new_weights), description="Heuristic risk weights")
        db.add(cfg)
    else:
        cfg.value_json = json.dumps(new_weights)

    # Sync runtime settings
    settings.RISK_WEIGHT_REPEATED_ATTEMPTS = payload.repeated_attempts
    settings.RISK_WEIGHT_MULTI_SERVICE = payload.multi_service
    settings.RISK_WEIGHT_HIGH_FREQUENCY = payload.high_frequency
    settings.RISK_WEIGHT_SUSPICIOUS_PATTERN = payload.suspicious_pattern
    settings.RISK_WEIGHT_KNOWN_INDICATOR = payload.known_indicator

    db.commit()
    return {"message": "Risk scoring weights updated successfully", "weights": new_weights}
