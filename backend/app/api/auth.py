from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import verify_password, create_access_token
from app.models.user import User
from app.schemas.auth import Token, LoginRequest, UserResponse
from app.api.deps import get_current_user
from app.core.logger import logger

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
async def login(request: Request, db: Session = Depends(get_db)):
    """Authenticate user with username/password (supports JSON or Form data) and return JWT."""
    username = None
    password = None

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            username = body.get("username")
            password = body.get("password")
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            username = form.get("username")
            password = form.get("password")
        except Exception:
            pass

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required"
        )

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        logger.warning(f"Failed login attempt for username: {username}")
        
        # Record security event for failed login attempt
        client_ip = request.client.host if request.client else "127.0.0.1"
        client_port = request.client.port if request.client else None
        try:
            from app.schemas.event import RawEventInput
            from app.services.event_processor import event_processor
            event_processor.process_raw_event(
                RawEventInput(
                    source_ip=client_ip,
                    source_port=client_port,
                    destination_port=8000,
                    protocol="TCP",
                    service="SOC Dashboard",
                    event_type="FAILED_LOGIN",
                    metadata={
                        "attempted_user": username,
                        "auth_mechanism": "web_console_login",
                        "status": "rejected"
                    },
                    raw_payload=f"POST /api/auth/login - Failed authentication attempt for user '{username}'"
                ),
                db
            )
        except Exception as ex:
            logger.error(f"Error recording failed login event: {ex}")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account is disabled")

    token = create_access_token(subject=user.username)
    logger.info(f"Successful login for user: {user.username} ({user.role})")
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role
    }


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    """Handles logout notification."""
    logger.info(f"User logged out: {current_user.username}")
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    """Returns details for currently logged-in user."""
    return current_user
