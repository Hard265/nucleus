from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import jwt

from app import models, schemas, auth
from app.database import SessionLocal, get_db
from app.auth.dependencies import get_current_user

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # This example assumes login by email (or mnemonic) as the username.
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = auth.create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
def logout():
    # In JWT stateless auth, "logout" is typically handled client side (delete the token)
    return {"msg": "Logged out. Invalidate the token client side."}

@router.post("/refresh")
def refresh_token(current_user: models.User = Depends(get_current_user)):
    # You may also issue a new token based on a refresh token mechanism
    new_token = auth.create_access_token(data={"sub": str(current_user.id)})
    return {"access_token": new_token, "token_type": "bearer"}

@router.get("/whoami")
def whoami(current_user: models.User = Depends(get_current_user)):
    return {"id": str(current_user.id), "email": current_user.email, "is_active": current_user.is_active}
