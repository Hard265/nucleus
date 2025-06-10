from strawberry.types import Info
from app.auth.core import AuthCore, AuthenticationError

def get_current_user_payload_graphql(info: Info) -> Dict[str, Any]:
    """GraphQL helper to get current user payload (required)"""
    request = info.context["request"]
    auth_header = request.headers.get("authorization", "")
    token = AuthCore.extract_token(auth_header)
    payload = AuthCore.get_payload_from_token(token)
    
    return AuthCore.validate_payload(payload)

def get_optional_user_payload_graphql(info: Info) -> Optional[Dict[str, Any]]:
    """GraphQL helper to get current user payload (optional)"""
    try:
        return get_current_user_payload_graphql(info)
    except AuthenticationError:
        return None

def get_current_user_graphql(info: Info) -> User:
    """GraphQL helper to get current user object from database"""
    from app.database import get_db
    
    payload = get_current_user_payload_graphql(info)
    db = next(get_db())
    
    try:
        user = db.query(User).filter(User.id == payload["sub"]).first()
        if not user:
            raise AuthenticationError("User not found")
        return user
    finally:
        db.close()
