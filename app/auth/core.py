from typing import Optional, Dict, Any, Union
from fastapi import Request, HTTPException, status, Depends
from strawberry.types import Info
from sqlalchemy.orm import Session
from app.utils.jwt import decode_access_token
from app.models import User
from app.database import get_db

class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    def __init__(self, message: str = "Authentication required"):
        self.message = message
        super().__init__(self.message)

class AuthCore:
    """Core authentication functionality"""
    
    @staticmethod
    def extract_token(auth_header: str) -> Optional[str]:
        """Extract JWT token from Authorization header"""
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        return auth_header.removeprefix("Bearer ").strip()
    
    @staticmethod
    def get_payload_from_token(token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT token and return payload"""
        if not token:
            return None
        return decode_access_token(token)
    
    @staticmethod
    def validate_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate payload and raise exception if invalid"""
        if not payload or "sub" not in payload:
            raise AuthenticationError("Invalid or expired token")
        return payload

