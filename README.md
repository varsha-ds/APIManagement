
# API Access & Management Platform

A production-style backend-first API Gateway and Developer Platform built with FastAPI.

## High-Level Overview
This project provides an internal API management platform for organizations to define, publish, and govern APIs. It supports API product/version lifecycle control, scoped access via subscriptions, and client credentials for secure access. The platform enforces role-based permissions across orgs, includes audit logging and rate limiting, and serves as the control plane that drives gateway behavior.


## Overview

This platform provides comprehensive API access management with:

- **Multi-Authentication**: JWT tokens, API Keys, OAuth2 Client Credentials
- **RBAC + Scopes**: Role-based access control with fine-grained scope permissions
- **API Lifecycle**: Draft → Published → Deprecated workflow
- **Subscription Workflow**: Request → Pending → Approved/Denied flow
- **Rate Limiting**: Per-client rate limiting with configurable limits
- **Audit Logging**: Complete audit trail for all operations

## Commands

```bash
# Create venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r Backend/requirements.txt

# Alembic migrations (from Backend/)
alembic revision --autogenerate -m "init"
alembic upgrade head
alembic downgrade -1

# Run server (from Backend/)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```


## Platform Bootstrap Design

- The platform enforces a one-time initialization step
- Until setup is completed:
  - User registration is disabled
  - Only `/api/admin/setup` is accessible
- This guarantees a trusted root administrator

########


## Actors & Roles

| Role | Capabilities |
|------|--------------|
| **Platform Admin**  | Global visibility, manage all orgs/users/APIs, revoke any credential |
| **Org Admin**       | Manage organization APIs, approve subscriptions, manage org users |
| **Developer**       | Create APIs, manage app clients, request API access |
| **App Client**      | Machine identity for API access (cannot manage itself) |



## API Key Lifecycle

1. **Creation**: Generate new key → Store hash → Return plaintext once
2. **Usage**: Validate key → Check subscription → Apply rate limits
3. **Rotation**: Revoke old key → Generate new key → Update clients
4. **Revocation**: Immediate invalidation → Audit log


## Subscription Workflow

```
Consumer → Request Access → [Pending] → Producer Reviews
                                      ↓
                              Approve (grant scopes) OR Deny
                                      ↓
                              [Approved] → API Access Enabled
```

**Default Deny**: Only explicitly granted scopes are allowed.

## Rate Limiting

- Per-subscription rate limits (configurable on approval)
- Default: 100 requests/minute
- In-memory sliding window algorithm
- Rate limit info in response headers

## Audit Logging

All operations are logged with:
- Actor (who)
- Action (what)
- Resource (on what)
- Decision (allowed/denied)
- Reason (if denied)
- Timestamp
- IP Address

## Quick Start

### 1. Initial Setup
### 2. Login
### 3. Create Organization
### 4. Create API Product
### 5. Create Version & Publish
### 6. Create App Client
### 7. Request Subscription
### 8. Approve Subscription
### 9. Get OAuth Token
## API Endpoints


## Security Features

- Password hashing with bcrypt
- JWT with expiration, issuer, audience claims
- Refresh token rotation
- API key hashing (SHA-256)
- Immediate credential revocation
- Request validation
- Rate limiting on auth endpoints
- Audit logging for all operations

## Tech Stack

- **Backend**: FastAPI (Python)
- **Database**: MongoDB
- **Auth**: JWT + bcrypt + OAuth2
- **Rate Limiting**: In-memory (production: use Redis)

## Documentation

- Swagger UI: `/api/docs`
- ReDoc: `/api/redoc`
- OpenAPI Spec: `/api/openapi.json`
