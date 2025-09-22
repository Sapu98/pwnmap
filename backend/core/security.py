import logging

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from backend.core.settings import settings

bearer_scheme = HTTPBearer(auto_error=False)

def require_admin(authorization: str = Header(None)):
    if not authorization:
        logging.info("auth: missing Authorization header")
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.startswith("Bearer "):
        logging.info("auth: bad schema: %s", authorization.split()[0] if authorization else None)
        raise HTTPException(status_code=401, detail="Use Bearer token")

    token = authorization.split(None, 1)[1]
    if token != settings.auth_token:
        logging.info("auth: invalid token")
        raise HTTPException(status_code=403, detail="Invalid token")

    return True
