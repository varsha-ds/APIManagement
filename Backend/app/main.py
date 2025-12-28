"""
API Access & Management Platform
================================

A backend-first API Gateway and Developer Platform built with FastAPI.

Tech Stack:
- FastAPI
- Postgres
- SQLAlchemy
- Alembic

Features:
- Multi-auth: JWT, API Keys, OAuth2 Client Credentials
- RBAC + Scope-based authorization
- API Product lifecycle management
- Subscription approval workflow
- Rate limiting and audit logging
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from pathlib import Path
import os
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import SessionLocal  # from your database.py
# If you want: from app.database import engine

# Import routers (Postgres-migrated routes)
from app.routes.auth_routes import router as auth_router
from app.routes.org_routes import router as org_router
from app.routes.api_routes import router as api_router
from app.routes.key_routes import router as key_router
from app.routes.subscription_routes import router as subscription_router
from app.routes.oauth_routes import router as oauth_router
from app.routes.admin_routes import router as admin_router

# If your audit logger needs initialization, keep it;
# best is to make audit_log write using DI session instead.
from app.middleware.audit_log import audit_logger

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def db_healthcheck() -> None:
    """Simple DB connectivity check."""
    db: Session = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    Notes:
    - With SQLAlchemy sync engine, we don't hold a global DB connection on app.state.
    - We optionally run a startup health check.
    - Migrations are handled by Alembic (run separately).
    """
    # Startup
    try:
        db_healthcheck()
        logger.info("Connected to Postgres successfully")
    except Exception as e:
        logger.error(f"Database connection failed: {e}", exc_info=True)
        raise RuntimeError("Database connection failed") from e

    # Optional: if your audit logger needs setup, wire it to SessionLocal
    # Recommended: audit_logger should use DI session instead, but if you keep a global:
    audit_logger.set_session_factory(SessionLocal)

    logger.info("API Access & Management Platform started")
    yield
    # Shutdown
    logger.info("Platform shutdown complete")


app = FastAPI(
    title="API Access & Management Platform",
    description="""
## Overview

A production-style backend platform for managing API access and governance.

### Features

- **Multi-Auth Support**: JWT tokens, API Keys, OAuth2 Client Credentials
- **RBAC + Scopes**: Role-based access control with fine-grained scope permissions
- **API Lifecycle**: Draft → Published → Deprecated workflow
- **Subscription Workflow**: Request → Pending → Approved/Denied
- **Rate Limiting**: Per-client rate limiting with configurable limits
- **Audit Logging**: Complete audit trail for all operations

### Authentication Methods

1. **User JWT**: For management operations
2. **API Key**: For machine-to-machine API access (`X-API-Key`)
3. **OAuth2**: Client credentials flow (`/api/oauth/token`)
""",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth_router, prefix="/api")
app.include_router(org_router, prefix="/api")
app.include_router(api_router, prefix="/api")
app.include_router(key_router, prefix="/api")
app.include_router(subscription_router, prefix="/api")
app.include_router(oauth_router, prefix="/api")
app.include_router(admin_router, prefix="/api")

# Health
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "API Access & Management Platform",
        "version": "1.0.0",
    }

# Root
@app.get("/api")
def root():
    return {
        "name": "API Access & Management Platform",
        "version": "1.0.0",
        "documentation": {
            "swagger": "/api/docs",
            "redoc": "/api/redoc",
            "openapi": "/api/openapi.json",
        },
        "endpoints": {
            "auth": "/api/auth",
            "organizations": "/api/organizations",
            "apis": "/api/apis",
            "clients": "/api/clients",
            "subscriptions": "/api/subscriptions",
            "oauth": "/api/oauth",
            "admin": "/api/admin",
        },
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": True, "status_code": exc.status_code, "detail": exc.detail},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": True, "status_code": 500, "detail": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.server:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8001)), reload=True)
