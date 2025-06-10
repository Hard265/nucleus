import pytest
from fastapi.testclient import TestClient
from app.models import User


class TestUserEndpoints:
    """Test user-related endpoints"""
    
    def test_create_user_success(self, client: TestClient):
        """Test successful user creation"""
        user_data = {
            "email": "newuser@example.com",
            "password": "securepassword123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == user_data["email"]
        assert "id" in data
        assert data["is_active"] is True
        assert "password" not in data  # Password should not be returned
    
    def test_create_user_duplicate_email(self, client: TestClient, test_user):
        """Test creating user with duplicate email"""
        user_data = {
            "email": test_user.email,
            "password": "anotherpassword123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]
    
    def test_create_user_invalid_email(self, client: TestClient):
        """Test creating user with invalid email"""
        user_data = {
            "email": "invalid-email",
            "password": "securepassword123"
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 422  # Validation error
    
    def test_create_user_weak_password(self, client: TestClient):
        """Test creating user with weak password"""
        user_data = {
            "email": "newuser@example.com",
            "password": "123"  # Too short
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 422
    
    def test_create_user_numeric_password(self, client: TestClient):
        """Test creating user with entirely numeric password"""
        user_data = {
            "email": "newuser@example.com",
            "password": "12345678"  # Entirely numeric
        }
        response = client.post("/users/", json=user_data)
        assert response.status_code == 422
    
    def test_get_user_success(self, client: TestClient, test_user):
        """Test getting user by ID"""
        response = client.get(f"/users/{test_user.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_user.id)
        assert data["email"] == test_user.email
        assert "password" not in data
    
    def test_get_user_not_found(self, client: TestClient):
        """Test getting non-existent user"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = client.get(f"/users/{fake_id}")
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]
    
    def test_get_user_invalid_uuid(self, client: TestClient):
        """Test getting user with invalid UUID"""
        response = client.get("/users/invalid-uuid")
        assert response.status_code == 422  # Validation error


class TestUserModel:
    """Test User model functionality"""
    
    def test_user_creation(self, db_session):
        """Test creating a user in the database"""
        user = User(
            email="model_test@example.com",
            password_hash="hashed_password",
            is_active=True
        )
        db_session.add(user)
        db_session.commit()
        
        # Verify user was created
        saved_user = db_session.query(User).filter_by(email="model_test@example.com").first()
        assert saved_user is not None
        assert saved_user.email == "model_test@example.com"
        assert saved_user.is_active is True
        assert saved_user.id is not None
        assert saved_user.created_at is not None
    
    def test_user_email_uniqueness(self, db_session):
        """Test that user emails must be unique"""
        # Create first user
        user1 = User(
            email="unique@example.com",
            password_hash="password1"
        )
        db_session.add(user1)
        db_session.commit()
        
        # Try to create second user with same email
        user2 = User(
            email="unique@example.com",
            password_hash="password2"
        )
        db_session.add(user2)
        
        with pytest.raises(Exception):  # Should raise IntegrityError
            db_session.commit()
    
    def test_user_default_values(self, db_session):
        """Test user model default values"""
        user = User(
            email="defaults@example.com",
            password_hash="password"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        
        assert user.is_active is True  # Default value
        assert user.created_at is not None
        assert user.id is not None