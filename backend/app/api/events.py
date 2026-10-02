from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from app.core.database import get_db
from app.models.event import Event
from app.models.detection import Detection
from app.schemas.event import EventResponse, EventDetailResponse, PaginatedEventsResponse
from app.api.deps import get_current_user

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=PaginatedEventsResponse)
def get_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retrieve paginated, filtered, and searchable honeypot telemetry events."""
    query = db.query(Event)

    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            or_(
                Event.source_ip.ilike(search_filter),
                Event.service.ilike(search_filter),
                Event.event_type.ilike(search_filter),
                Event.raw_payload.ilike(search_filter)
            )
        )

    if severity:
        query = query.filter(Event.severity == severity.upper())

    if service:
        query = query.filter(Event.service.ilike(f"%{service}%"))

    if event_type:
        query = query.filter(Event.event_type == event_type.upper())

    if source_ip:
        query = query.filter(Event.source_ip == source_ip)

    total = query.count()
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    items = query.order_by(desc(Event.timestamp)).offset(offset).limit(page_size).all()

    return PaginatedEventsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/{event_id}", response_model=EventDetailResponse)
def get_event_detail(
    event_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retrieve in-depth details of a specific event including triggered threat detections."""
    event = db.query(Event).filter(Event.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    detections = db.query(Detection).filter(Detection.event_id == event.event_id).all()

    return EventDetailResponse(
        id=event.id,
        event_id=event.event_id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        protocol=event.protocol,
        service=event.service,
        event_type=event.event_type,
        severity=event.severity,
        risk_score=event.risk_score,
        session_id=event.session_id,
        metadata_json=event.metadata_json,
        raw_payload=event.raw_payload,
        created_at=event.created_at,
        detections=detections
    )
