"""Unit-Tests für Authentifizierung und Autorisierung.

Testet JWT-Erstellung, Dekodierung, Passwort-Hashing, RBAC-Prüfung
und MFA-Session-Token.
"""

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from src.shared.auth import (
    ALGORITHM,
    ROLES,
    SECRET_KEY,
    create_access_token,
    decode_token,
    hash_password,
    role_has_permission,
    verify_password,
)


# --- Passwort-Hashing ---

class TestPasswordHashing:
    """Tests für bcrypt-basiertes Passwort-Hashing."""

    def test_hash_and_verify_correct_password(self):
        """Korrektes Passwort wird erfolgreich verifiziert."""
        password = "SicheresPasswort123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed)

    def test_verify_wrong_password_fails(self):
        """Falsches Passwort wird abgelehnt."""
        hashed = hash_password("richtig")
        assert not verify_password("falsch", hashed)

    def test_hash_is_not_plaintext(self):
        """Hash darf nicht dem Klartext-Passwort entsprechen."""
        password = "TestPasswort"
        hashed = hash_password(password)
        assert hashed != password

    def test_different_hashes_for_same_password(self):
        """Gleiche Passwörter erzeugen verschiedene Hashes (Salt)."""
        password = "SicheresPasswort123!"
        hash_a = hash_password(password)
        hash_b = hash_password(password)
        assert hash_a != hash_b

    def test_unicode_password(self):
        """Passwörter mit Umlauten werden korrekt gehasht."""
        password = "Überp@sswörd!42"
        hashed = hash_password(password)
        assert verify_password(password, hashed)


# --- JWT Token ---

class TestJWTToken:
    """Tests für JWT-basierte Access-Tokens."""

    def test_create_token_returns_tuple(self):
        """create_access_token gibt (token, jti) Tupel zurück."""
        token, jti = create_access_token("user-1", "test@example.com", "analyst")
        assert isinstance(token, str)
        assert isinstance(jti, str)
        assert len(jti) == 32  # uuid4().hex = 32 hex chars

    def test_token_contains_claims(self):
        """Token enthält alle erwarteten Claims."""
        token, _ = create_access_token("user-1", "test@example.com", "analyst", "org-1")
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == "user-1"
        assert decoded["email"] == "test@example.com"
        assert decoded["role"] == "analyst"
        assert decoded["org_id"] == "org-1"
        assert "jti" in decoded
        assert "exp" in decoded
        assert "iat" in decoded

    def test_token_decode_valid(self):
        """Gültiger Token wird korrekt dekodiert."""
        token, jti = create_access_token("user-1", "admin@example.com", "org_admin")
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["jti"] == jti

    def test_expired_token_returns_none(self):
        """Abgelaufener Token gibt None zurück."""
        payload = {
            "sub": "user-1",
            "email": "expired@example.com",
            "role": "analyst",
            "jti": "test-jti",
            "exp": datetime.now(UTC) - timedelta(hours=1),
            "iat": datetime.now(UTC) - timedelta(hours=2),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        assert decode_token(token) is None

    def test_forged_token_returns_none(self):
        """Token mit falschem Secret gibt None zurück."""
        payload = {
            "sub": "user-1",
            "email": "forged@example.com",
            "role": "system_admin",
            "jti": "forged-jti",
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC),
        }
        token = jwt.encode(payload, "falsches-secret", algorithm=ALGORITHM)
        assert decode_token(token) is None

    def test_malformed_token_returns_none(self):
        """Ungültiger Token-String gibt None zurück."""
        assert decode_token("kein.gültiger.token") is None
        assert decode_token("") is None

    def test_default_org_id(self):
        """Ohne explizite org_id wird default-org gesetzt."""
        token, _ = create_access_token("user-1", "test@example.com", "analyst")
        decoded = decode_token(token)
        assert decoded["org_id"] == "default-org"


# --- RBAC ---

class TestRBAC:
    """Tests für rollenbasierte Zugriffskontrolle."""

    def test_system_admin_has_all_permissions(self):
        """System-Admin hat Zugriff auf alle Rollen-Level."""
        for role in ROLES:
            assert role_has_permission("system_admin", role)

    def test_viewer_only_has_own_permission(self):
        """Viewer hat nur Zugriff auf Viewer-Level."""
        assert role_has_permission("viewer", "viewer")
        assert not role_has_permission("viewer", "analyst")
        assert not role_has_permission("viewer", "security_lead")
        assert not role_has_permission("viewer", "org_admin")
        assert not role_has_permission("viewer", "system_admin")

    def test_analyst_permissions(self):
        """Analyst hat Zugriff auf Analyst und Viewer."""
        assert role_has_permission("analyst", "viewer")
        assert role_has_permission("analyst", "analyst")
        assert not role_has_permission("analyst", "security_lead")

    def test_security_lead_permissions(self):
        """Security-Lead hat Zugriff bis Security-Lead."""
        assert role_has_permission("security_lead", "viewer")
        assert role_has_permission("security_lead", "analyst")
        assert role_has_permission("security_lead", "security_lead")
        assert not role_has_permission("security_lead", "org_admin")

    def test_unknown_role_denied(self):
        """Unbekannte Rollen werden abgelehnt."""
        assert not role_has_permission("unbekannt", "viewer")

    def test_role_hierarchy_values(self):
        """Rollen-Hierarchie hat korrekte Reihenfolge."""
        assert ROLES["viewer"] < ROLES["analyst"]
        assert ROLES["analyst"] < ROLES["security_lead"]
        assert ROLES["security_lead"] < ROLES["org_admin"]
        assert ROLES["org_admin"] < ROLES["system_admin"]
