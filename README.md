# Nucleus - Identity and Access Management (IAM) System

**Nucleus** is a modular, secure, and extensible Identity and Access Management (IAM) backend system designed to handle user authentication, authorization, and access control for distributed applications.

## 🔐 Core Features

- JWT-based authentication system
- Role-Based Access Control (RBAC)
- RESTful and GraphQL APIs
- Secure password hashing and validation
- Middleware and dependency-based access control
- Modular structure for maintainability and scalability

## 🚀 Tech Stack

- **Framework:** FastAPI (asynchronous Python backend)
- **ORM:** SQLAlchemy + Alembic (for migrations)
- **Auth:** JWT (JSON Web Tokens)
- **Database:** PostgreSQL (or SQLite for development)
- **API:** REST + GraphQL

## 📁 Project Structure

app/ ├── auth.py                # Authentication logic ├── database.py            # DB connection/session ├── models.py              # SQLAlchemy models ├── schemas.py             # Pydantic schemas ├── routers/               # REST API routes ├── graphql/schema.py      # GraphQL schema ├── middleware/            # Request-level auth enforcement ├── utils/                 # JWT, security, helpers └── main.py                # Entry point

## 🛠️ Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/Hard265/nucleus.git
   cd nucleus

2. Create and activate virtual environment

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


3. Install dependencies

pip install -r requirements.txt


4. Configure environment Create a .env file or set environment variables:

DATABASE_URL=postgresql://user:pass@localhost/nucleus_db
JWT_SECRET_KEY=your_secret_key
JWT_ALGORITHM=HS256


5. Run database migrations

alembic upgrade head


6. Start the application

uvicorn app.main:app --reload



🧪 Example API Usage

REST:

curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}'

GraphQL: Access at: http://localhost:8000/graphql


✅ To-Do

Add email verification & password reset

Implement OAuth2 support

Add admin dashboard UI

Containerize with Docker

Integrate CI/CD


📄 License

Licensed under MIT. See <a href="./LICENSE">LICENSE</a> file.
