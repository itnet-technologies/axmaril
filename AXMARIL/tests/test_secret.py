import pytest
from tests.config import create_app
import uuid


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _create_secret(client, headers, code):
    data = {
        "exp_time": "string",
        "name": "test azumaril",
        "secret": {
            "password": "String1#"
        },
        "safe_id": "string",
        "secret_type": "other",
        "app_type": "string"
    }
    response = client.post("/secret/create", json=data, headers=headers, follow_redirects=True)
    assert response.status_code == code


def _get_all_secret(client, headers, code):
    response = client.get("/secret/all", headers=headers, follow_redirects=True)
    assert response.status_code == code


def _get_secret_types(client, headers, code):
    response = client.get("/secret/types", headers=headers, follow_redirects=True)
    assert response.status_code == code