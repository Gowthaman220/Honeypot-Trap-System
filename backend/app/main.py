from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.init_db import init_db
from app.core.logger import logger
from app.honeypot.manager import honeypot_manager
from app.services.websocket_manager import ws_manager
from app.api import (
    auth_router,
    dashboard_router,
    events_router,
    detections_router,
    alerts_router,
    honeypots_router,
    reports_router,
    settings_router
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    logger.info("Initializing Honeypot Trap System backend...")
    init_db()
    try:
        await honeypot_manager.start_all()
        logger.info("Honeypot services successfully initialized.")
    except Exception as e:
        logger.error(f"Error starting honeypot services on startup: {e}")

    yield

    # Shutdown sequence
    logger.info("Shutting down honeypot services...")
    try:
        await honeypot_manager.stop_all()
    except Exception as e:
        logger.error(f"Error stopping honeypots on shutdown: {e}")
    logger.info("Honeypot Trap System stopped.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Defensive Cybersecurity Honeypot Trap System - Real-time Threat Intelligence and Monitoring",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(detections_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(honeypots_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(settings_router, prefix="/api")


@app.get("/api/health")
def health_check():
    """Health status check endpoint."""
    return {
        "status": "healthy",
        "system": settings.APP_NAME,
        "environment": settings.ENVIRONMENT
    }


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """Real-time event stream WebSocket endpoint for the SOC dashboard."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and accept incoming pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket client error: {e}")
        ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
