from datetime import datetime, timezone
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import strawberry
from typing import Annotated, List, Optional, Sequence
from uuid import UUID
from fastapi import Depends, Request
from strawberry.fastapi import GraphQLRouter
from sqlalchemy.orm import Session
from app.models import User, Role, UserRole, Permission, ScopeEnum
from app.dependencies.auth import get_user_from_token
from app.database import get_db
from app.schemas import UserCreate
from app.utils.security import pwd_context
from app.utils.jwt import create_access_token, create_refresh_token, decode_access_token
from app.utils.helpers import get_current_user


scope_type = Annotated[ScopeEnum, strawberry.enum(ScopeEnum)]

# enums
ScopeEnumStrawberry = strawberry.enum(ScopeEnum)

# types
@strawberry.type
class LoginResponse:
    access_token: str
    refresh_token: str

@strawberry.type
class RoleType:
    id: UUID
    name: str
    scope: scope_type

@strawberry.type
class UserRoleType:
    role: RoleType
    scope_id: UUID

@strawberry.type
class UserType:
    id: UUID
    email: str
    is_active: bool

    @strawberry.field
    def roles(self, info) -> List[UserRoleType]:
        db: Session = next(get_db())
        user = db.query(User).filter_by(id=self.id).first()
        if not user:
            raise Exception("User not found")

        return [
            UserRoleType(role=ur.role, scope_id=ur.scope_id)
            for ur in user.roles
        ]

@strawberry.type
class PermissionType:
    id: UUID
    action: str
    resource_id: Optional[UUID]


# inputs
@strawberry.input
class UserInput:
    email: str
    password: str

@strawberry.input
class LoginInput:
    email: str
    password: str

@strawberry.input
class RoleInput:
    name: str
    scope: scope_type

@strawberry.input
class PermissionInput:
    action: str
    resource_id: Optional[UUID] = None

@strawberry.input
class RolePermissionLinkInput:
    role_id: UUID
    permission_id: UUID

@strawberry.input
class AssignRoleInput:
    user_id: UUID
    role_id: UUID
    scope_id: UUID


# Query
@strawberry.type
class Query:
    @strawberry.field
    def users(self, info) -> Sequence[UserType]:
        db: Session = next(get_db())
        return db.query(User).all()

    @strawberry.field
    def get_user(self, info, id: UUID) -> Optional[UserType]:
        db: Session = next(get_db())
        return db.query(User).filter(User.id == id).first()

    @strawberry.field
    def me(self, info) -> UserType:
        user_id = get_current_user(info)
        db: Session = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()
        return user



# Mutation
@strawberry.type
class Mutation:
    @strawberry.mutation
    def create_user(self, info, input: UserInput) -> UserType:
        try:
            data = UserCreate(**input.__dict__)
        except ValidationError as e:
            raise Exception(e.json())

        db: Session = next(get_db())
        try:
            user = User(
                email=data.email,
                password_hash=data.password,
                created_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            return user
        except IntegrityError:
            db.rollback()
            raise Exception("User with this email already exist")
        except SQLAlchemyError:
            db.rollback()
            raise Exception("Internal server error")
    
    @strawberry.mutation
    def login(self, info, input: LoginInput) -> LoginResponse:
        db: Session = next(get_db())
        user = db.query(User).filter(User.email == input.email).first()
        if not user or not pwd_context.verify(input.password, user.password_hash):
            raise Exception("Invalid credentials")
        
        roles = [r.role.name for r in user.roles]  # or include scope_id if needed
        payload = {"sub": str(user.id)}
        return LoginResponse(
            access_token=create_access_token(payload, roles),
            refresh_token=create_refresh_token(payload)
        )
    
    @strawberry.mutation
    def refresh_token(self, info, refresh_token: str) -> LoginResponse:
        payload = decode_access_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise Exception("Invalid refresh token")

        new_payload = {"sub": payload["sub"]}
        return LoginResponse(
            access_token=create_access_token(new_payload),
            refresh_token=create_refresh_token(new_payload)
        )

    @strawberry.mutation
    def create_role(self, info, input: RoleInput) -> RoleType:
        db: Session = next(get_db())
        role = Role(name=input.name, scope=ScopeEnum(input.scope))
        db.add(role)
        db.commit()
        db.refresh(role)
        return role

    @strawberry.mutation
    def create_permission(self, info, input: PermissionInput) -> PermissionType:
        db: Session = next(get_db())
        perm = Permission(action=input.action, resource_id=input.resource_id)
        db.add(perm)
        db.commit()
        db.refresh(perm)
        return perm

    @strawberry.mutation
    def link_permission_to_role(self, info, input: RolePermissionLinkInput) -> bool:
        db: Session = next(get_db())
        role = db.query(Role).filter_by(id=input.role_id).first()
        perm = db.query(Permission).filter_by(id=input.permission_id).first()

        if not role or not perm:
            raise Exception("Role or Permission not found")

        role.permissions.append(perm)
        db.commit()
        return True


    @strawberry.mutation
    def assign_role_to_user(self, info, input: AssignRoleInput) -> bool:
        db: Session = next(get_db())

        # Ensure user and role exist
        user = db.query(User).filter_by(id=input.user_id).first()
        role = db.query(Role).filter_by(id=input.role_id).first()
        if not user or not role:
            raise Exception("User or Role not found")

        # Prevent duplicate assignment
        exists = db.query(UserRole).filter_by(
            user_id=input.user_id,
            role_id=input.role_id,
            scope_id=input.scope_id
        ).first()
        if exists:
            raise Exception("User already has this role in the given scope")

        user_role = UserRole(
            user_id=input.user_id,
            role_id=input.role_id,
            scope_id=input.scope_id
        )
        db.add(user_role)
        db.commit()
        return True


async def get_context(
    request: Request,
    user=Depends(get_user_from_token)
):
    return {
        "request": request,
        "user": user
    }

schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_app = GraphQLRouter(
    schema,
    context_getter=get_context
)

