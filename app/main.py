from fastapi import FastAPI
from app.routers import auth as auth_router, users as users_router, roles as roles_router
from app.database import engine, Base

# Create all tables (for development; consider using Alembic in production)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Nucleus API", description="A GraphQL Hybrid API with JWT-based auth")

app.include_router(auth_router.router, prefix="/auth", tags=["Auth"])
app.include_router(users_router.router, prefix="/users", tags=["Users"])
app.include_router(roles_router.router, prefix="/roles", tags=["Roles"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
