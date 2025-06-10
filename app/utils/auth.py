# app/utils/auth.py - Consolidated authentication
import os
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from strawberry.types import Info
from sqlalchemy.orm import Session
from app.utils.jwt import decode_access_token
from app.models import User
from app.database import get_db

def extract_token_from_request(request: Request) -> Optional[str]:
    """Extract JWT token from Authorization header"""
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.removeprefix("Bearer ").strip()
    return None

def get_user_payload_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT token and return payload"""
    if not token:
        return None
    return decode_access_token(token)

def get_current_user_payload(request: Request) -> Optional[Dict[str, Any]]:
    """Get current user payload from request (for FastAPI dependencies)"""
    token = extract_token_from_request(request)
    return get_user_payload_from_token(token)

def get_current_user_payload_graphql(info: Info) -> Dict[str, Any]:
    """Get current user payload from GraphQL context"""
    request = info.context["request"]
    token = extract_token_from_request(request)
    payload = get_user_payload_from_token(token)
    
    if not payload or "sub" not in payload:
        raise Exception("Authentication required")
    
    return payload

def get_current_user_from_db(token: str, db: Session) -> User:
    """Get current user object from database (for REST endpoints)"""
    payload = get_user_payload_from_token(token)
    
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user