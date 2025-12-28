"""Admin schemas."""

from pydantic import BaseModel, EmailStr


class SetupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str
