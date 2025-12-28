import os
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple, List

try:
    from app.config import settings
except Exception:  
    settings = None

import bcrypt
import jwt


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val



JWT_SECRET = os.environ.get("JWT_SECRET") or (settings.secret_key if settings else None)
if not JWT_SECRET:
    # Fail fast: prevents silent token invalidation across restarts/pods
    raise RuntimeError("JWT_SECRET or SECRET_KEY must be set (do not default-generate it).")

JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM") or (settings.algorithm if settings else "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    or (settings.access_token_expire_minutes if settings else "30")
)
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
OAUTH_TOKEN_EXPIRE_SECONDS = int(os.environ.get("OAUTH_TOKEN_EXPIRE_SECONDS", "900"))  # 15 minutes

# ---- API Key Configuration ----
API_KEY_PREFIX_LENGTH = int(os.environ.get("API_KEY_PREFIX_LENGTH", "8"))
API_KEY_BYTES = int(os.environ.get("API_KEY_BYTES", "32"))  # bytes of entropy, not string length

# Secret used to hash API keys / client secrets safely (HMAC).
API_KEY_HASH_SECRET = os.environ.get("API_KEY_HASH_SECRET", JWT_SECRET)


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    now = _utc_now()
    exp = now + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = dict(data)
    payload.update({"exp": exp, "iat": now, "type": "access"})
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token."""
    now = _utc_now()
    exp = now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    payload = dict(data)
    payload.update({"exp": exp, "iat": now, "type": "refresh"})
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_oauth_token(client_id: str, scopes: List[str], expires_in: int = OAUTH_TOKEN_EXPIRE_SECONDS) -> str:
    """Create OAuth2 access token for client credentials flow."""
    now = _utc_now()
    exp = now + timedelta(seconds=expires_in)
    payload = {
        "sub": client_id,
        "scopes": scopes,
        "exp": exp,
        "iat": now,
        "type": "oauth_client",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate JWT token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def _hmac_sha256_hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_api_key() -> Tuple[str, str, str]:
    """
    Generate a new API key.
    Returns: (full_key, prefix, key_hash)
    - full_key: shown once to user
    - prefix: for identification (first N chars)
    - key_hash: stored in database (HMAC-based)
    """
    full_key = secrets.token_urlsafe(API_KEY_BYTES)
    prefix = full_key[:API_KEY_PREFIX_LENGTH]
    key_hash = _hmac_sha256_hex(API_KEY_HASH_SECRET, full_key)
    return full_key, prefix, key_hash


def hash_api_key(api_key: str) -> str:
    """Hash an API key for comparison (HMAC-based)."""
    return _hmac_sha256_hex(API_KEY_HASH_SECRET, api_key)


def generate_client_secret() -> Tuple[str, str]:
    """
    Generate OAuth client secret.
    Returns: (secret, hashed_secret)
    """
    secret = secrets.token_urlsafe(32)
    hashed = _hmac_sha256_hex(API_KEY_HASH_SECRET, secret)
    return secret, hashed


def hash_client_secret(secret: str) -> str:
    """Hash client secret for comparison (HMAC-based)."""
    return _hmac_sha256_hex(API_KEY_HASH_SECRET, secret)


def verify_client_secret(secret: str, stored_hash: str) -> bool:
    """Verify client secret against stored hash (constant-time)."""
    if not secret or not stored_hash:
        return False
    computed = _hmac_sha256_hex(API_KEY_HASH_SECRET, secret)
    return hmac.compare_digest(computed, stored_hash)
