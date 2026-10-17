"""
Pytest Fixtures and Test Configuration for CyberShield
Provides isolated testing clients, database fixtures, and persona authorization tokens.
"""
import pytest
import os
import sys

# Ensure backend directory is in python search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from app.repositories.factory import reset_repository_for_testing
from app.seeds.seed_data import _seed_sql, _seed_mongo


@pytest.fixture(scope="session")
def app():
    # Use SQLite memory or isolated test database
    os.environ["DB_BACKEND"] = "sqlite"
    os.environ["SQLITE_PATH"] = ":memory:"
    os.environ["ENABLE_DEV_FALLBACK"] = "false"

    test_config = {
        "TESTING": True,
        "JWT_SECRET_KEY": "test-jwt-secret-key-32bytes-long",
        "SECRET_KEY": "test-secret-key"
    }

    app = create_app(test_config=test_config)
    with app.app_context():
        repo = reset_repository_for_testing("sqlite")
        _seed_sql(repo)

    return app

@pytest.fixture
def client(app):
    return app.test_client()

def get_auth_token(client, email, password="Nexora@2026"):
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    data = res.get_json()
    if data and data.get("status") == "success":
        return data["data"]["access_token"]
    return None

@pytest.fixture
def auth_headers_analyst(client):
    token = get_auth_token(client, "analyst@nexora.test")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_infra(client):
    token = get_auth_token(client, "infra@nexora.test")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_auditor(client):
    token = get_auth_token(client, "auditor@nexora.test")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_manager(client):
    token = get_auth_token(client, "manager@nexora.test")
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_admin(client):
    token = get_auth_token(client, "admin@nexora.test")
    return {"Authorization": f"Bearer {token}"}
