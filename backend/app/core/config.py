import os
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Honeypot Trap System"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    SECRET_KEY: str = "honey-secret-key-change-in-production-super-safe-32chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    
    # Database
    DATABASE_URL: str = "sqlite:///./honeypot.db"
    
    # Initial Admin
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "adminpassword123"
    
    # Honeypot Ports & Controls
    SSH_HONEYPOT_ENABLED: bool = True
    SSH_HONEYPOT_PORT: int = 2222
    
    HTTP_HONEYPOT_ENABLED: bool = True
    HTTP_HONEYPOT_PORT: int = 8080
    
    FTP_HONEYPOT_ENABLED: bool = True
    FTP_HONEYPOT_PORT: int = 2121
    
    TCP_HONEYPOT_ENABLED: bool = True
    TCP_HONEYPOT_PORT: int = 9999
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ]
    
    # Risk scoring heuristics
    RISK_WEIGHT_REPEATED_ATTEMPTS: int = 10
    RISK_WEIGHT_MULTI_SERVICE: int = 20
    RISK_WEIGHT_HIGH_FREQUENCY: int = 20
    RISK_WEIGHT_SUSPICIOUS_PATTERN: int = 20
    RISK_WEIGHT_KNOWN_INDICATOR: int = 30
    
    # Notification settings
    ALERT_EMAIL_ENABLED: bool = False
    ALERT_WEBHOOK_ENABLED: bool = False
    ALERT_WEBHOOK_URL: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
