from typing import Optional, Dict, Any
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.auth.core import AuthCore, AuthenticationError
from app.database import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user_payload(request: Request) -> Optional[Dict[str, Any]]:
    """FastAPI dependency to get current user payload (optional)"""
    auth_header = request.headers.get("authorization", "")
    token = AuthCore.extract_token(auth_header)
    if not token:
        return None
    return AuthCore.get_payload_from_token(token)

def require_auth_payload(request: Request) -> Dict[str, Any]:
    """FastAPI dependency to require authentication (payload only)"""
    auth_header = request.headers.get("authorization", "")
    token = AuthCore.extract_token(auth_header)
    if not token:
        return None
    payload = AuthCore.get_payload_from_token(token)
    
    try:
        return AuthCore.validate_payload(payload)
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> User:
    """FastAPI dependency to get current user object from database"""
    payload = AuthCore.get_payload_from_token(token)
    
    try:
        validated_payload = AuthCore.validate_payload(payload)
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.id == validated_payload["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user

def get_optional_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """FastAPI dependency to get current user if authenticated, None otherwise"""
    payload = get_current_user_payload(request)
    if not payload or "sub" not in payload:
        return None
    
    return db.query(User).filter(User.id == payload["sub"]).first()

