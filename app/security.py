from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .keycloak import KeycloakClient, KeycloakError


bearer_scheme = HTTPBearer(scheme_name="BearerAuth")
optional_bearer_scheme = HTTPBearer(scheme_name="BearerAuth", auto_error=False)
keycloak = KeycloakClient()


def current_keycloak_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    try:
        return keycloak.user_info(credentials.credentials)
    except KeycloakError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def optional_keycloak_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_bearer_scheme),
) -> dict | None:
    if not credentials:
        return None
    try:
        return keycloak.user_info(credentials.credentials)
    except KeycloakError:
        return None
