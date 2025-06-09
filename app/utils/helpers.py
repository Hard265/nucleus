from strawberry.types import Info
from app.utils.jwt import decode_access_token

def get_current_user(info: Info):
    auth = info.context["request"].headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        raise Exception("Missing or invalid token")
    token = auth.removeprefix("Bearer ")
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise Exception("Token invalid or expired")
    return payload

