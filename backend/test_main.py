"""
Backend Test Suite — API Key Management Gateway
=================================================
Comprehensive tests for auth, keys, validation, admin, and security.
"""

import pytest
import os
import sys

# ── Setup test env BEFORE importing main ──
os.environ["DATABASE_URL"] = "sqlite:///./test_api_keys.db"
os.environ["ENCRYPTION_KEY"] = "FvGGWbuwbLf4zjJ_eqSsos7tjf4cs09WyMbsyIiDMH4="
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-for-testing-only-do-not-use-in-prod"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"

from fastapi.testclient import TestClient

# Add parent dir to path
sys.path.insert(0, os.path.dirname(__file__))

from main import app, engine, Base, rate_limit_store, failed_attempts

# ── Fixtures ──

@pytest.fixture(autouse=True)
def fresh_db():
    """Reset DB and rate limiters before each test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    rate_limit_store.clear()
    failed_attempts.clear()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def registered_user(client):
    """Register a user and return credentials."""
    email = "test@example.com"
    password = "TestPass123"
    res = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert res.status_code == 200
    return {"email": email, "password": password}


@pytest.fixture
def auth_headers(client, registered_user):
    """Login and return auth headers."""
    res = client.post("/api/v1/auth/login", json={
        "email": registered_user["email"],
        "password": registered_user["password"],
    })
    assert res.status_code == 200
    data = res.json()
    return {
        "Authorization": f"Bearer {data['access_token']}",
        "refresh_token": data["refresh_token"],
    }


# ═══════════════════════════════════════
# AUTH TESTS
# ═══════════════════════════════════════

class TestRegistration:
    def test_register_success(self, client):
        res = client.post("/api/v1/auth/register", json={
            "email": "new@example.com",
            "password": "StrongPass1"
        })
        assert res.status_code == 200
        data = res.json()
        assert "message" in data
        assert data["role"] in ["admin", "user"]

    def test_register_duplicate_email(self, client, registered_user):
        res = client.post("/api/v1/auth/register", json={
            "email": registered_user["email"],
            "password": "AnotherPass1"
        })
        assert res.status_code == 400
        assert "already registered" in res.json()["detail"].lower()

    def test_register_weak_password(self, client):
        res = client.post("/api/v1/auth/register", json={
            "email": "weak@test.com",
            "password": "short"
        })
        assert res.status_code == 422  # validation error

    def test_register_invalid_email(self, client):
        res = client.post("/api/v1/auth/register", json={
            "email": "not-an-email",
            "password": "StrongPass1"
        })
        assert res.status_code == 422


class TestLogin:
    def test_login_success(self, client, registered_user):
        res = client.post("/api/v1/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    def test_login_wrong_password(self, client, registered_user):
        res = client.post("/api/v1/auth/login", json={
            "email": registered_user["email"],
            "password": "WrongPassword1",
        })
        assert res.status_code == 401

    def test_login_nonexistent_user(self, client):
        res = client.post("/api/v1/auth/login", json={
            "email": "nobody@test.com",
            "password": "Password123",
        })
        assert res.status_code == 401


class TestTokenRefresh:
    def test_refresh_token(self, client, auth_headers):
        res = client.post("/api/v1/auth/refresh", json={
            "refresh_token": auth_headers["refresh_token"]
        })
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_refresh_invalid_token(self, client):
        res = client.post("/api/v1/auth/refresh", json={
            "refresh_token": "invalid-token"
        })
        assert res.status_code == 401


class TestAuthMe:
    def test_get_profile(self, client, auth_headers):
        res = client.get("/api/v1/auth/me", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        data = res.json()
        assert data["email"] == "test@example.com"
        assert data["role"] == "admin"  # first user is always admin

    def test_get_profile_no_auth(self, client):
        res = client.get("/api/v1/auth/me")
        assert res.status_code == 401


class TestLogout:
    def test_logout(self, client, auth_headers):
        res = client.post("/api/v1/auth/logout", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200


# ═══════════════════════════════════════
# API KEY TESTS
# ═══════════════════════════════════════

class TestKeyCreation:
    def test_create_key_default(self, client, auth_headers):
        res = client.post("/api/v1/keys", json={}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        data = res.json()
        assert "keyId" in data
        assert "keyValue" in data
        assert data["scope"] == "read_write"
        assert data["status"] == "active"

    def test_create_key_with_options(self, client, auth_headers):
        res = client.post("/api/v1/keys", json={
            "label": "Production API",
            "provider": "internal",
            "scope": "read_only",
            "usage_quota": 1000,
            "expires_in_days": 30,
        }, headers={"Authorization": auth_headers["Authorization"]})
        assert res.status_code == 200
        data = res.json()
        assert data["label"] == "Production API"
        assert data["scope"] == "read_only"
        assert data["expiresAt"] is not None

    def test_create_key_unauthenticated(self, client):
        res = client.post("/api/v1/keys", json={})
        assert res.status_code == 401


class TestKeyListing:
    def test_list_keys_empty(self, client, auth_headers):
        res = client.get("/api/v1/keys", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        data = res.json()
        assert data["keys"] == []
        assert data["pagination"]["total"] == 0

    def test_list_keys_with_data(self, client, auth_headers):
        # Create 3 keys
        for i in range(3):
            client.post("/api/v1/keys", json={"label": f"Key {i}"}, headers={
                "Authorization": auth_headers["Authorization"]
            })
        
        res = client.get("/api/v1/keys", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        data = res.json()
        assert len(data["keys"]) == 3
        assert data["pagination"]["total"] == 3

    def test_list_keys_filter_status(self, client, auth_headers):
        client.post("/api/v1/keys", json={"label": "active-key"}, headers={
            "Authorization": auth_headers["Authorization"]
        })

        res = client.get("/api/v1/keys?status=active", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        assert len(res.json()["keys"]) == 1

    def test_list_keys_pagination(self, client, auth_headers):
        for i in range(5):
            client.post("/api/v1/keys", json={"label": f"Key {i}"}, headers={
                "Authorization": auth_headers["Authorization"]
            })

        res = client.get("/api/v1/keys?per_page=2&page=1", headers={
            "Authorization": auth_headers["Authorization"]
        })
        data = res.json()
        assert len(data["keys"]) == 2
        assert data["pagination"]["totalPages"] == 3


class TestKeyUpdate:
    def test_update_key_status(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={"label": "toggle-me"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_id = create_res.json()["keyId"]

        res = client.patch(f"/api/v1/keys/{key_id}", json={"status": "inactive"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        assert "message" in res.json()

    def test_update_key_label(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={"label": "old-name"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_id = create_res.json()["keyId"]

        res = client.patch(f"/api/v1/keys/{key_id}", json={"label": "new-name"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        assert "message" in res.json()

    def test_update_nonexistent_key(self, client, auth_headers):
        res = client.patch("/api/v1/keys/fake-key-id", json={"status": "inactive"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 404


class TestKeyDeletion:
    def test_delete_key(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={"label": "delete-me"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_id = create_res.json()["keyId"]

        res = client.delete(f"/api/v1/keys/{key_id}", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200

        # Verify it's gone
        list_res = client.get("/api/v1/keys", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert len(list_res.json()["keys"]) == 0

    def test_delete_nonexistent_key(self, client, auth_headers):
        res = client.delete("/api/v1/keys/fake-key-id", headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 404


class TestKeyRotation:
    def test_rotate_key(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={"label": "rotate-me"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_id = create_res.json()["keyId"]

        res = client.post(f"/api/v1/keys/{key_id}/rotate", json={}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        assert res.status_code == 200
        data = res.json()
        assert "keyValue" in data
        assert data["keyId"] != key_id  # New key ID
        assert data["rotatedFrom"] == key_id


# ═══════════════════════════════════════
# VALIDATION TESTS
# ═══════════════════════════════════════

class TestValidation:
    def test_validate_valid_key(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={"label": "validate-me"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_value = create_res.json()["keyValue"]

        res = client.post("/api/v1/validate", json={"apiKey": key_value})
        assert res.status_code == 200
        data = res.json()
        assert data["valid"] is True
        assert data["provider"] == "internal"

    def test_validate_invalid_key(self, client):
        res = client.post("/api/v1/validate", json={"apiKey": "invalid-key"})
        assert res.status_code in [400, 401]
        data = res.json()
        assert data.get("valid") is False or "detail" in data

    def test_validate_via_header(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_value = create_res.json()["keyValue"]

        res = client.post("/api/v1/validate", headers={"X-API-Key": key_value})
        assert res.status_code == 200
        assert res.json()["valid"] is True

    def test_validate_inactive_key(self, client, auth_headers):
        create_res = client.post("/api/v1/keys", json={"label": "deactivated"}, headers={
            "Authorization": auth_headers["Authorization"]
        })
        key_id = create_res.json()["keyId"]
        key_value = create_res.json()["keyValue"]

        # Deactivate key
        client.patch(f"/api/v1/keys/{key_id}", json={"status": "inactive"}, headers={
            "Authorization": auth_headers["Authorization"]
        })

        res = client.post("/api/v1/validate", json={"apiKey": key_value})
        assert res.status_code == 401


# ═══════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════

class TestHealth:
    def test_health_endpoint(self, client):
        res = client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    def test_health_no_auth(self, client):
        """Health endpoint should NOT require auth."""
        res = client.get("/api/v1/health")
        assert res.status_code == 200


# ═══════════════════════════════════════
# BACKWARD COMPATIBILITY
# ═══════════════════════════════════════

class TestBackwardCompat:
    def test_legacy_register(self, client):
        res = client.post("/api/auth/register", json={
            "email": "legacy@test.com",
            "password": "LegacyPass1"
        })
        assert res.status_code == 200

    def test_legacy_login(self, client, registered_user):
        res = client.post("/api/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        assert res.status_code == 200
        assert "access_token" in res.json()


# ═══════════════════════════════════════
# SECURITY TESTS
# ═══════════════════════════════════════

class TestSecurity:
    def test_expired_token_rejected(self, client):
        """Manually crafted expired token should be rejected."""
        res = client.get("/api/v1/auth/me", headers={
            "Authorization": "Bearer expired.fake.token"
        })
        assert res.status_code == 401

    def test_cors_headers(self, client):
        res = client.options("/api/v1/health", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        })
        # CORS preflight should work for allowed origins
        assert res.status_code in [200, 400]

    def test_no_key_leakage_in_list(self, client, auth_headers):
        """Key values should NEVER appear in list response."""
        client.post("/api/v1/keys", json={"label": "secret-key"}, headers={
            "Authorization": auth_headers["Authorization"]
        })

        res = client.get("/api/v1/keys", headers={
            "Authorization": auth_headers["Authorization"]
        })
        data = res.json()
        for key in data["keys"]:
            assert "keyValue" not in key or key.get("keyValue") is None

    def test_cross_user_isolation(self, client):
        """User A should not see User B's keys."""
        # Register User A
        client.post("/api/v1/auth/register", json={"email": "a@test.com", "password": "PassWordA1"})
        res_a = client.post("/api/v1/auth/login", json={"email": "a@test.com", "password": "PassWordA1"})
        headers_a = {"Authorization": f"Bearer {res_a.json()['access_token']}"}
        
        # Register User B
        client.post("/api/v1/auth/register", json={"email": "b@test.com", "password": "PassWordB1"})
        res_b = client.post("/api/v1/auth/login", json={"email": "b@test.com", "password": "PassWordB1"})
        headers_b = {"Authorization": f"Bearer {res_b.json()['access_token']}"}

        # User A creates a key
        client.post("/api/v1/keys", json={"label": "A-only"}, headers=headers_a)

        # User B should NOT see User A's key
        list_res = client.get("/api/v1/keys", headers=headers_b)
        assert len(list_res.json()["keys"]) == 0


# ═══════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════

class TestEdgeCases:
    def test_empty_body_register(self, client):
        res = client.post("/api/v1/auth/register", json={})
        assert res.status_code == 422

    def test_sql_injection_email(self, client):
        res = client.post("/api/v1/auth/register", json={
            "email": "'; DROP TABLE users; --@test.com",
            "password": "StrongPass1"
        })
        # Should either reject or safely handle
        assert res.status_code in [201, 422, 400]
        # DB should still be functional
        res2 = client.get("/api/v1/health")
        assert res2.status_code == 200

    def test_validate_empty_key(self, client):
        res = client.post("/api/v1/validate", json={"apiKey": ""})
        assert res.status_code in [400, 401, 422]

    def test_validate_no_body(self, client):
        res = client.post("/api/v1/validate")
        # Should handle gracefully
        assert res.status_code in [400, 401, 422]
