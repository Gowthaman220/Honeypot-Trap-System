import pytest
import os
import sys

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure test settings
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-purpose-32char"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app.core.database import Base, get_db
from app.core.config import settings
from app.core.security import hash_password, create_access_token
from app.models.user import User
from app.models.honeypot_service import HoneypotService
from app.main import app

# In-memory SQLite engine for fast, isolated tests
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    db = TestingSessionLocal()
    # Create test admin
    test_user = User(
        username="admin",
        hashed_password=hash_password("adminpassword123"),
        role="admin",
        is_active=True
    )
    db.add(test_user)

    # Create default honeypot service records
    services = [
        HoneypotService(name="SSH Honeypot", service_type="SSH", port=2222, protocol="TCP", status="running", enabled=True),
        HoneypotService(name="HTTP Honeypot", service_type="HTTP", port=8080, protocol="TCP", status="running", enabled=True),
        HoneypotService(name="FTP Honeypot", service_type="FTP", port=2121, protocol="TCP", status="running", enabled=True),
        HoneypotService(name="Generic TCP Listener", service_type="TCP", port=9999, protocol="TCP", status="running", enabled=True),
    ]
    for s in services:
        db.add(s)
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture
def db_session():
    connection = TEST_ENGINE.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    token = create_access_token(subject="admin")
    return {"Authorization": f"Bearer {token}"}
