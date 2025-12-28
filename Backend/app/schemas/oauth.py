from pydantic import BaseModel
from typing import Optional


class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: Optional[str] = None
