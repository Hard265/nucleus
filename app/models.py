import uuid
import enum
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, DateTime,
    Enum, ForeignKey, Table
)
from sqlalchemy.dialects.postgresql import UUID  # Use this if you target PostgreSQL
from sqlalchemy.orm import relationship
from app.database import Base

# Enum for role scopes
class ScopeEnum(str, enum.Enum):
    global_scope = "global"
    app_scope = "app"
    resource_scope = "resource"

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=True)
    password_hash = Column(String)
    mnemonic_hash = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    roles = relationship("UserRole", back_populates="user")

class Role(Base):
    __tablename__ = "roles"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True)
    scope = Column(Enum(ScopeEnum))
    
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")
    
class Permission(Base):
    __tablename__ = "permissions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action = Column(String)  # e.g. "read:file", "edit:user"
    resource_id = Column(UUID, nullable=True)
    
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")

# Association table for many-to-many between Role and Permission
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id")),
    Column("permission_id", UUID(as_uuid=True), ForeignKey("permissions.id"))
)

# Link table for user-role (with a scope id)
class UserRole(Base):
    __tablename__ = "user_roles"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True)
    scope_id = Column(UUID, nullable=False)
    
    user = relationship("User", back_populates="roles")
    role = relationship("Role")

class Session(Base):
    __tablename__ = "sessions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    user_agent = Column(String)
    expires_at = Column(DateTime)
