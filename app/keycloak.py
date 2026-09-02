import os
import secrets
import time
from typing import Any

import httpx


class KeycloakError(RuntimeError):
    """Raised when a Keycloak operation cannot be completed."""


class KeycloakClient:
    """Small, synchronous Keycloak REST client used by the FastAPI application."""

    def __init__(self) -> None:
        self.base_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
        self.realm = os.getenv("KEYCLOAK_REALM", "studypro")
        self.admin_realm = os.getenv("KEYCLOAK_ADMIN_REALM", "master")
        self.admin_username = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
        self.admin_password = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "change-this-password")
        self.client_id = os.getenv("KEYCLOAK_CLIENT_ID", "studypro-api")
        self.client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
        self.timeout = float(os.getenv("KEYCLOAK_TIMEOUT", "15"))

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            return httpx.request(method, url, timeout=self.timeout, **kwargs)
        except httpx.HTTPError as exc:
            raise KeycloakError(f"Keycloak is unavailable: {exc}") from exc

    def wait_until_ready(self, attempts: int = 3, delay: float = 0.5) -> None:
        last_error: Exception | None = None
        for _ in range(attempts):
            try:
                response = self._request("GET", f"{self.base_url}/health/ready")
                if response.status_code == 200:
                    return
                last_error = KeycloakError(
                    f"Keycloak readiness returned HTTP {response.status_code}"
                )
            except KeycloakError as exc:
                last_error = exc
            time.sleep(delay)
        raise KeycloakError(f"Keycloak did not become ready: {last_error}")

    def admin_token(self) -> str:
        response = self._request(
            "POST",
            f"{self.base_url}/realms/{self.admin_realm}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_username,
                "password": self.admin_password,
            },
        )
        if response.status_code != 200:
            raise KeycloakError(
                f"Could not obtain Keycloak admin token (HTTP {response.status_code})"
            )
        try:
            return response.json()["access_token"]
        except (KeyError, ValueError) as exc:
            raise KeycloakError("Keycloak admin token response was invalid") from exc

    def admin_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token()}"}

    def ensure_realm(self) -> None:
        headers = self.admin_headers()
        response = self._request(
            "GET", f"{self.base_url}/admin/realms/{self.realm}", headers=headers
        )
        if response.status_code == 200:
            return
        if response.status_code != 404:
            raise KeycloakError(f"Could not inspect realm: {response.text}")

        response = self._request(
            "POST",
            f"{self.base_url}/admin/realms",
            headers={**headers, "Content-Type": "application/json"},
            json={
                "realm": self.realm,
                "enabled": True,
                "registrationAllowed": False,
                "resetPasswordAllowed": True,
                "rememberMe": True,
                "loginWithEmailAllowed": True,
                "duplicateEmailsAllowed": False,
                "accessTokenLifespan": 1800,
                "ssoSessionIdleTimeout": 1800,
                "ssoSessionMaxLifespan": 86400,
            },
        )
        if response.status_code not in (201, 204):
            raise KeycloakError(f"Could not create realm: {response.text}")

    def ensure_client(self) -> None:
        headers = self.admin_headers()
        response = self._request(
            "GET",
            f"{self.base_url}/admin/realms/{self.realm}/clients",
            headers=headers,
            params={"clientId": self.client_id},
        )
        if response.status_code != 200:
            raise KeycloakError(f"Could not inspect client: {response.text}")

        clients = response.json()
        if clients:
            client = clients[0]
            client_uuid = client["id"]
            secret_response = self._request(
                "GET",
                f"{self.base_url}/admin/realms/{self.realm}/clients/{client_uuid}/client-secret",
                headers=headers,
            )
            if secret_response.status_code == 200:
                value = secret_response.json().get("value")
                if value:
                    self.client_secret = value
            if not self.client_secret:
                raise KeycloakError(
                    "StudyPro client exists but its client secret could not be read"
                )
            return

        secret = self.client_secret or secrets.token_urlsafe(32)
        payload = {
            "clientId": self.client_id,
            "name": "StudyPro Python API",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": secret,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "fullScopeAllowed": True,
        }
        response = self._request(
            "POST",
            f"{self.base_url}/admin/realms/{self.realm}/clients",
            headers={**headers, "Content-Type": "application/json"},
            json=payload,
        )
        if response.status_code not in (201, 204):
            raise KeycloakError(f"Could not create StudyPro client: {response.text}")
        self.client_secret = secret

    def ensure_plan_groups(self, plans: list[str]) -> None:
        headers = self.admin_headers()
        response = self._request(
            "GET", f"{self.base_url}/admin/realms/{self.realm}/groups", headers=headers
        )
        if response.status_code != 200:
            raise KeycloakError(f"Could not inspect groups: {response.text}")

        names = {g.get("name") for g in response.json()}
        for plan in plans:
            name = f"plan:{plan.lower()}"
            if name in names:
                continue
            response = self._request(
                "POST",
                f"{self.base_url}/admin/realms/{self.realm}/groups",
                headers={**headers, "Content-Type": "application/json"},
                json={"name": name},
            )
            if response.status_code not in (201, 204):
                raise KeycloakError(f"Could not create group {name}: {response.text}")
            names.add(name)

    def bootstrap(self, plan_names: list[str] | None = None) -> None:
        self.wait_until_ready()
        self.ensure_realm()
        self.ensure_client()
        if plan_names:
            self.ensure_plan_groups(plan_names)

    def create_user(self, name: str, email: str, password: str) -> dict[str, Any]:
        username = email.lower().strip()
        headers = self.admin_headers()
        response = self._request(
            "POST",
            f"{self.base_url}/admin/realms/{self.realm}/users",
            headers={**headers, "Content-Type": "application/json"},
            json={
                "username": username,
                "email": username,
                "firstName": name.strip(),
                "lastName": "User",
                "enabled": True,
                "emailVerified": True,
                "requiredActions": [],
                "credentials": [
                    {"type": "password", "value": password, "temporary": False}
                ],
            },
        )
        if response.status_code == 409:
            raise KeycloakError("Email already registered")
        if response.status_code not in (201, 204):
            raise KeycloakError(f"Could not create Keycloak user: {response.text}")

        lookup = self._request(
            "GET",
            f"{self.base_url}/admin/realms/{self.realm}/users",
            headers=headers,
            params={"username": username, "exact": "true"},
        )
        if lookup.status_code != 200 or not lookup.json():
            raise KeycloakError("User was created but could not be retrieved")
        return lookup.json()[0]

    def login(self, email: str, password: str) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": email.lower().strip(),
                "password": password,
                "scope": "openid profile email",
            },
        )
        if response.status_code != 200:
            raise KeycloakError("Invalid email or password")
        try:
            return response.json()
        except ValueError as exc:
            raise KeycloakError("Invalid token response from Keycloak") from exc

    def user_info(self, access_token: str) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise KeycloakError("Invalid or expired Keycloak token")
        return response.json()

    def user_sessions(self, user_id: str) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/sessions",
            headers=self.admin_headers(),
        )
        if response.status_code != 200:
            raise KeycloakError(f"Could not retrieve sessions: {response.text}")
        return response.json()

    def revoke_session(self, session_id: str) -> None:
        response = self._request(
            "DELETE",
            f"{self.base_url}/admin/realms/{self.realm}/sessions/{session_id}",
            headers=self.admin_headers(),
        )
        if response.status_code not in (204, 404):
            raise KeycloakError(f"Could not revoke session: {response.text}")

    def revoke_user_session(self, user_id: str, session_id: str) -> None:
        """Revoke only a session after verifying it belongs to the user."""
        sessions = self.user_sessions(user_id)
        if not any(s.get("id") == session_id for s in sessions):
            raise KeycloakError("Active session not found or does not belong to you")
        self.revoke_session(session_id)

    def assign_user_to_plan(self, user_id: str, plan_name: str) -> None:
        headers = self.admin_headers()
        groups = self._request(
            "GET", f"{self.base_url}/admin/realms/{self.realm}/groups", headers=headers
        )
        if groups.status_code != 200:
            raise KeycloakError(f"Could not inspect groups: {groups.text}")
        target = f"plan:{plan_name.lower()}"
        group = next((g for g in groups.json() if g.get("name") == target), None)
        if not group:
            self.ensure_plan_groups([plan_name])
            groups = self._request(
                "GET", f"{self.base_url}/admin/realms/{self.realm}/groups",
                headers=headers,
            )
            group = next((g for g in groups.json() if g.get("name") == target), None)
        if not group:
            raise KeycloakError(f"Plan group not found: {target}")
        response = self._request(
            "PUT",
            f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/groups/{group['id']}",
            headers=headers,
        )
        if response.status_code not in (204, 200):
            raise KeycloakError(f"Could not assign plan group: {response.text}")

    def remove_user_from_plan_groups(self, user_id: str) -> None:
        headers = self.admin_headers()
        response = self._request(
            "GET",
            f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/groups",
            headers=headers,
        )
        if response.status_code != 200:
            raise KeycloakError(f"Could not inspect user's groups: {response.text}")
        for group in response.json():
            if str(group.get("name", "")).startswith("plan:"):
                self._request(
                    "DELETE",
                    f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/groups/{group['id']}",
                    headers=headers,
                )
