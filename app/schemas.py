from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional
from enum import Enum

class UserCreate(BaseModel):
    email: Optional[EmailStr] = None
    password: str

class UserOut(BaseModel):
    id: UUID
    email: Optional[EmailStr]
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
