from functools import wraps
from strawberry.types import Info

def require_login(resolver):
    @wraps(resolver)
    def wrapper(*args, info: Info, **kwargs):
        user = info.context.get("user")
        if not user:
            raise Exception("Authentication required")
        return resolver(*args, info=info, **kwargs)
    return wrapper

def require_role(role: str):
    def decorator(resolver):
        @wraps(resolver)
        def wrapper(*args, info: Info, **kwargs):
            user = info.context.get("user")
            if not user or role not in user.get("roles", []):
                raise Exception("Insufficient permissions")
            return resolver(*args, info=info, **kwargs)
        return wrapper
    return decorator

