from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas

router = APIRouter()

@router.get("/")
def list_roles(db: Session = Depends(get_db)):
    roles = db.query(models.Role).all()
    return roles

@router.post("/")
def create_role(role: schemas.RoleCreate, db: Session = Depends(get_db)):
    db_role = models.Role(name=role.name, scope=role.scope)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role

# Additional endpoints for handling permissions (e.g. POST /roles/{id}/permissions) go here.
