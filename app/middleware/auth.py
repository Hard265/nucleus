from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.utils.jwt import decode_access_token

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        payload = decode_access_token(token)
        request.state.user = payload if payload else None
        return await call_next(request)
