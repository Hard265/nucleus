from functools import wraps
from strawberry.types import Info
from app.auth.graphql import get_current_user_payload_graphql, get_optional_user_payload_graphql

def require_auth(resolver):
    """GraphQL decorator to require authentication"""
    @wraps(resolver)
    def wrapper(*args, info: Info, **kwargs):
        user_payload = get_current_user_payload_graphql(info)
        # Add user payload to context for use in resolver
        info.context["current_user"] = user_payload
        return resolver(*args, info=info, **kwargs)
    return wrapper

def require_role(role: str):
    """GraphQL decorator to require specific role"""
    def decorator(resolver):
        @wraps(resolver)
        def wrapper(*args, info: Info, **kwargs):
            user_payload = get_current_user_payload_graphql(info)
            user_roles = user_payload.get("roles", [])
            
            if role not in user_roles:
                raise AuthenticationError("Insufficient permissions")
            
            info.context["current_user"] = user_payload
            return resolver(*args, info=info, **kwargs)
        return wrapper
    return decorator

def optional_auth(resolver):
    """GraphQL decorator for optional authentication"""
    @wraps(resolver)
    def wrapper(*args, info: Info, **kwargs):
        user_payload = get_optional_user_payload_graphql(info)
        info.context["current_user"] = user_payload
        return resolver(*args, info=info, **kwargs)
    return wrapper
