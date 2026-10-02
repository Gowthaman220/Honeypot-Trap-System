from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.events import router as events_router
from app.api.detections import router as detections_router
from app.api.alerts import router as alerts_router
from app.api.honeypots import router as honeypots_router
from app.api.reports import router as reports_router
from app.api.settings import router as settings_router

__all__ = [
    "auth_router",
    "dashboard_router",
    "events_router",
    "detections_router",
    "alerts_router",
    "honeypots_router",
    "reports_router",
    "settings_router"
]
