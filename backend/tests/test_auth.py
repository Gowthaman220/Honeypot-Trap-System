from app.core.security import hash_password, verify_password, create_access_token, decode_access_token


def test_password_hashing():
    raw = "SuperSecretPassword!123"
    hashed = hash_password(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_lifecycle():
    token = create_access_token("admin_test_user")
    assert isinstance(token, str)
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "admin_test_user"


def test_login_success(client):
    response = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "adminpassword123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["username"] == "admin"


def test_login_invalid_credentials(client):
    response = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "incorrect_password"}
    )
    assert response.status_code == 401
    assert "detail" in response.json()


def test_protected_route_unauthorized(client):
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 401


def test_protected_route_authorized(client, auth_headers):
    response = client.get("/api/dashboard/summary", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
