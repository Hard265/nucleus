from fastapi import FastAPI
from app.routers import auth as auth_router, users as users_router, roles as roles_router
from app.database import engine, Base
from app.graphql.schema import graphql_app
from dotenv import load_dotenv

load_dotenv()

# Create all tables (for development; consider using Alembic in production)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Nucleus API", 
    description="IAM"
)

app.include_router(auth_router.router, prefix="/auth", tags=["Auth"])
app.include_router(users_router.router, prefix="/users", tags=["Users"])
app.include_router(roles_router.router, prefix="/roles", tags=["Roles"])
app.include_router(graphql_app, prefix="/graphql", tags=["GraphQL"])

# Health check route
@app.get("/")
def health_check():
    return {"status": "running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
