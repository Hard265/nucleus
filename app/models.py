import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, DateTime,
    Enum, ForeignKey, Table, UUID,
    UniqueConstraint
)
from sqlalchemy.orm import relationship
from app.database import Base

# Enum for role scopes
class ScopeEnum(str, enum.Enum):
    global_scope = "global"
    app_scope = "app"
    resource_scope = "resource"

class Resource(Base):
    __tablename__ = "resources"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)  # e.g., "Report.pdf", "User Profile"
    type = Column(String, nullable=False)  # e.g., "file", "app", "user"

    # Unique constraint to prevent duplicate resources with same name and type
    __table_args__ = (UniqueConstraint('name', 'type', name='uq_resource_name_type'),)

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, onupdate=datetime.now(timezone.utc))
    last_login_at = Column(DateTime, nullable=True)
    
    roles = relationship("UserRole", back_populates="user")

class Role(Base):
    __tablename__ = "roles"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    scope = Column(Enum(ScopeEnum), nullable=False)
    
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action = Column(String, nullable=False)  # e.g., "read", "write"
    resource_type = Column(String, nullable=True)  # e.g., "file", "user"; null for broad permissions
    resource_id = Column(UUID(as_uuid=True), ForeignKey("resources.id"), nullable=True, index=True)  # Specific resource, if applicable
    
    resource = relationship("Resource")  # Relationship to access Resource.type if needed
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")

# Association table for many-to-many between Role and Permission
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE")),
    Column("permission_id", UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"))
)

# Link table for user-role (with a scope id)
class UserRole(Base):
    __tablename__ = "user_roles"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("resources.id"), nullable=True, index=True)  # Nullable for global roles

    user = relationship("User", back_populates="roles")
    role = relationship("Role")

class Session(Base):
    __tablename__ = "sessions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    user_agent = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    last_accessed = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))