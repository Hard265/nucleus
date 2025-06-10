import pytest
from sqlalchemy.exc import IntegrityError
from app.models import User, Role, Permission, UserRole, ScopeEnum
from app.utils.security import hash_password


class TestUserModel:
    """Test User model"""
    
    def test_create_user(self, db_session):
        """Test creating a user"""
        user = User(
            email="test@example.com",
            password_hash=hash_password("password"),
            is_active=True
        )
        db_session.add(user)
        db_session.commit()
        
        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.created_at is not None
    
    def test_user_email_unique_constraint(self, db_session):
        """Test that user email must be unique"""
        user1 = User(
            email="duplicate@example.com",
            password_hash=hash_password("password1")
        )
        user2 = User(
            email="duplicate@example.com",
            password_hash=hash_password("password2")
        )
        
        db_session.add(user1)
        db_session.commit()
        
        db_session.add(user2)
        with pytest.raises(IntegrityError):
            db_session.commit()
    
    def test_user_default_active_status(self, db_session):
        """Test user default active status"""
        user = User(
            email="default@example.com",
            password_hash=hash_password("password")
        )
        db_session.add(user)
        db_session.commit()
        
        assert user.is_active is True
    
    def test_user_roles_relationship(self, db_session):
        """Test user-roles relationship"""
        user = User(
            email="user_roles@example.com",
            password_hash=hash_password("password")
        )
        db_session.add(user)
        db_session.flush()
        
        role = Role(name="test_role", scope=ScopeEnum.global_scope)
        db_session.add(role)
        db_session.flush()
        
        user_role = UserRole(
            user_id=user.id,
            role_id=role.id,
            scope_id=user.id
        )
        db_session.add(user_role)
        db_session.commit()
        
        db_session.refresh(user)
        assert len(user.roles) == 1
        assert user.roles[0].role.name == "test_role"


class TestRoleModel:
    """Test Role model"""
    
    def test_create_role(self, db_session):
        """Test creating a role"""
        role = Role(
            name="admin",
            scope=ScopeEnum.global_scope
        )
        db_session.add(role)
        db_session.commit()
        
        assert role.id is not None
        assert role.name == "admin"
        assert role.scope == ScopeEnum.global_scope
    
    def test_role_name_unique_constraint(self, db_session):
        """Test that role name must be unique"""
        role1 = Role(name="duplicate_role", scope=ScopeEnum.global_scope)
        role2 = Role(name="duplicate_role", scope=ScopeEnum.app_scope)
        
        db_session.add(role1)
        db_session.commit()
        
        db_session.add(role2)
        with pytest.raises(IntegrityError):
            db_session.commit()
    
    def test_role_scope_enum(self, db_session):
        """Test role scope enum values"""
        # Test all valid scope values
        scopes = [ScopeEnum.global_scope, ScopeEnum.app_scope, ScopeEnum.resource_scope]
        
        for i, scope in enumerate(scopes):
            role = Role(name=f"role_{i}", scope=scope)
            db_session.add(role)
        
        db_session.commit()
        
        roles = db_session.query(Role).all()
        assert len(roles) >= 3
    
    def test_role_permissions_relationship(self, db_session):
        """Test role-permissions many-to-many relationship"""
        role = Role(name="test_role_perms", scope=ScopeEnum.global_scope)
        permission = Permission(action="read:users")
        
        db_session.add(role)
        db_session.ad