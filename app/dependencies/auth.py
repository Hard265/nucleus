from fastapi import Request, HTTPException, status, Depends
from app.utils.jwt import decode_access_token

def get_user_from_token(request: Request):
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth.removeprefix("Bearer ").strip()
        payload = decode_access_token(token)
        if payload and "sub" in payload:
            return payload  # user payload: {sub, roles, etc.}
    return None
