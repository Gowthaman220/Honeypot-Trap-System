from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.core.database import get_db
from app.models.detection import Detection
from app.schemas.detection import DetectionResponse
from app.api.deps import get_current_user

router = APIRouter(prefix="/detections", tags=["Detections"])


@router.get("", response_model=List[DetectionResponse])
def get_detections(
    rule_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """List threat detections filtered by rule, severity, or source IP."""
    query = db.query(Detection)

    if rule_id:
        query = query.filter(Detection.rule_id == rule_id.upper())
    if severity:
        query = query.filter(Detection.severity == severity.upper())
    if source_ip:
        query = query.filter(Detection.source_ip == source_ip)

    return query.order_by(desc(Detection.detection_timestamp)).limit(limit).all()


@router.get("/{detection_id}", response_model=DetectionResponse)
def get_detection(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retrieve details of a single detection entry."""
    detection = db.query(Detection).filter(Detection.id == detection_id).first()
    if not detection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")
    return detection
