from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.honeypot_service import HoneypotService
from app.schemas.honeypot import HoneypotServiceResponse, ServiceActionRequest
from app.api.deps import get_current_user, get_current_admin
from app.honeypot.manager import honeypot_manager

router = APIRouter(prefix="/honeypots", tags=["Honeypot Services"])


@router.get("", response_model=List[HoneypotServiceResponse])
def get_honeypot_services(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """Retrieve all honeypot services, ports, and operational statuses."""
    # Sync with runtime manager status
    services = db.query(HoneypotService).all()
    statuses = {s["name"]: s["is_running"] for s in honeypot_manager.get_service_statuses()}
    for s in services:
        if s.name in statuses:
            s.status = "running" if statuses[s.name] else "stopped"
    db.commit()
    return services


@router.post("/{service_id}/start")
async def start_service(service_id: int, db: Session = Depends(get_db), current_admin = Depends(get_current_admin)):
    """Start an individual honeypot service listener."""
    svc = db.query(HoneypotService).filter(HoneypotService.id == service_id).first()
    if not svc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    success = await honeypot_manager.start_service(svc.name)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to start service")

    db.refresh(svc)
    return {"message": f"Service {svc.name} started successfully", "status": svc.status}


@router.post("/{service_id}/stop")
async def stop_service(service_id: int, db: Session = Depends(get_db), current_admin = Depends(get_current_admin)):
    """Stop an individual honeypot service listener."""
    svc = db.query(HoneypotService).filter(HoneypotService.id == service_id).first()
    if not svc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    success = await honeypot_manager.stop_service(svc.name)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to stop service")

    db.refresh(svc)
    return {"message": f"Service {svc.name} stopped successfully", "status": svc.status}
