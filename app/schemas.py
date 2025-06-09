import re
from typing import Any
from pydantic import BaseModel, EmailStr, field_validator
from uuid import UUID
from datetime import datetime
from enum import Enum
from app.utils.security import hash_password

class UserCreate(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value) -> str: 
        if len(value) < 8:
            raise ValueError("This password is too short. It must contain at least 8 characters.")

        if re.fullmatch(r"\d+", value) is not None:
            raise ValueError("This password is entirely numeric.")
        return value

    def model_post_init(self, context: Any, /) -> None:
        self.password = hash_password(self.password)


class UserOut(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True


class ScopeEnum(str, Enum):
    global_scope = "global"
    app_scope = "app"
    resource_scope = "resource"

class RoleCreate(BaseModel):
    name: str
    scope: ScopeEnum
