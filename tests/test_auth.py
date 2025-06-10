import pytest
from fastapi.testclient import TestClient
from app.utils.jwt import create_access_token, decode_access_token


class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_login_success(self, client: TestClient, test_user):
        """Test successful login"""
        response = client.post(
            "/auth/login",
            data={"username": test_user.email, "password": "testpassword123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        
        # Verify token is valid
        token_payload = decode_access_token(data["access_token"])
        assert token_payload is not None
        assert token_payload["sub"] == str(test_user.id)
    
    def test_login_invalid_email(self, client: TestClient):
        """Test login with invalid email"""
        response = client.post(
            "/auth/login",
            data={"username": "nonexistent@example.com", "password": "password"}
        )
        assert response.status_code == 400
        assert "Incorrect username or password" in response.json()["detail"]
    
    def test_login_invalid_password(self, client: TestClient, test_user):
        """Test login with invalid password"""
        response = client.post(
            "/auth/login",
            data={"username": test_user.email, "password": "wrongpassword"}
        )
        assert response.status_code == 400
        assert "Incorrect username or password" in response.json()["detail"]
    
    def test_whoami_authenticated(self, client: TestClient, auth_headers):
        """Test whoami endpoint with valid token"""
        response = client.get("/auth/whoami", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert "email" in data
        assert "is_active" in data
    
    def test_whoami_unauthenticated(self, client: TestClient):
        """Test whoami endpoint without token"""
        response = client.get("/auth/whoami")
        assert response.status_code == 401
    
    def test_whoami_invalid_token(self, client: TestClient):
        """Test whoami endpoint with invalid token"""
        response = client.get(
            "/auth/whoami",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
    
    def test_refresh_token(self, client: TestClient, auth_headers):
        """Test token refresh"""
        response = client.post("/auth/refresh", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_logout(self, client: TestClient):
        """Test logout endpoint"""
        response = client.post("/auth/logout")
        assert response.status_code == 200
        assert "msg" in response.json()


class TestJWTUtils:
    """Test JWT utility functions"""
    
    def test_create_and_decode_access_token(self):
        """Test creating and decoding access token"""
        payload = {"sub": "user123", "roles": ["admin"]}
        token = create_access_token(payload, roles=["admin"])
        
        decoded = decode_access_token(token)
        assert decoded is not None
        assert decoded["sub"] == "user123"
        assert decoded["roles"] == ["admin"]
        assert "exp" in decoded
    
    def test_decode_invalid_token(self):
        """Test decoding invalid token"""
        invalid_token = "invalid.token.here"
        decoded = decode_access_token(invalid_token)
        assert decoded is None
    
    def test_create_access_token_with_roles(self):
        """Test creating access token with roles"""
        payload = {"sub": "user123"}
        roles = ["admin", "user"]
        token = create_access_token(payload, roles=roles)
        
        decoded = decode_access_token(token)
        assert decoded["roles"] == roles
    
    def test_create_access_token_without_roles(self):
        """Test creating access token without roles"""
        payload = {"sub": "user123"}
        token = create_access_token(payload)
        
        decoded = decode_access_token(token)
        assert decoded["roles"] == []