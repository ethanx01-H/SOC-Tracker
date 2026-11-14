"""Authentication, password hashing, and RBAC utilities."""

import logging
import hmac
import re
import secrets
from hashlib import pbkdf2_hmac, sha256
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from .config import SECRET_KEY, SESSION_TTL_SECONDS
from .dependencies import get_db
from .models import User

logger = logging.getLogger("sentriq.auth")

signer = URLSafeTimedSerializer(SECRET_KEY, salt="sentriq")


def session_stamp(user: User) -> str:
    """Tie sessions to the current password hash without exposing that hash in cookies."""
    return hmac.new(SECRET_KEY.encode(), user.password_hash.encode(), sha256).hexdigest()


def hash_password(password: str, salt: str | None = None) -> str:
    """Hash password with PBKDF2-SHA256 (240k iterations)."""
    salt = salt or secrets.token_hex(16)
    digest = pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash using timing-safe comparison."""
    try:
        _, salt, digest = stored_hash.split("$", 2)
    except ValueError:
        return False
    return secrets.compare_digest(hash_password(password, salt), f"pbkdf2_sha256${salt}${digest}")


def validate_password_strength(password: str) -> str | None:
    """Validate password meets complexity requirements. Returns error message or None."""
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include a number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include a symbol."
    return None


def current_user(request: Request, db: Session) -> User | None:
    """Get current user from session cookie, or None if not authenticated."""
    raw = request.cookies.get("session")
    if not raw:
        return None
    try:
        data = signer.loads(raw, max_age=SESSION_TTL_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    user = db.get(User, data.get("user_id"))
    if not user or not user.is_active:
        # A deactivated account loses its existing sessions on the next request.
        return None
    if not hmac.compare_digest(data.get("session_stamp", ""), session_stamp(user)):
        return None
    return user


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency that requires authentication. Redirects to login if not authenticated."""
    user = current_user(request, db)
    if user:
        if user.must_change_password and request.url.path != "/account/password/":
            raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/account/password/"})
        return user
    raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login/"})


def user_role(user: User) -> str:
    """Get effective role (L3 for admins)."""
    return "L3" if user.is_admin else user.role


def can_create_alert(user: User) -> bool:
    return user_role(user) in {"L1", "L2", "L3"}


def can_edit_alert(user: User, alert) -> bool:
    role = user_role(user)
    return role in {"L2", "L3"} or (role == "L1" and alert.status != "Closed")


def can_delete_alert(user: User) -> bool:
    return user_role(user) == "L3"


def can_manage_users(user: User) -> bool:
    return user_role(user) == "L3"


def can_escalate_alert(user: User) -> bool:
    return user_role(user) in {"L1", "L2"}


def can_assign_alert(user: User) -> bool:
    return user_role(user) in {"L2", "L3"}


def assignable_roles_for(user: User) -> list[str]:
    """Get list of roles this user can assign alerts to."""
    role = user_role(user)
    if role == "L3":
        return ["L1", "L2"]
    if role == "L2":
        return ["L1"]
    return []


UserDep = Annotated[User, Depends(require_user)]
