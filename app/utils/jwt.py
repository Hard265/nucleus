import os
from typing import Self
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from jose import JWTError, jwt
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment.")

def create_access_token(data: dict, roles: list[str] = []):
    to_encode = data.copy()
    to_encode.update({"roles": roles})
    expire = datetime.now(timezone.utc)  + (timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY not set in environment.")
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    expire = datetime.now(timezone.utc)  + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    data.update({"exp": expire, "type": "refresh"})
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY not set in environment.")
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        if not SECRET_KEY:
            raise RuntimeError("SECRET_KEY not set in environment.")
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
