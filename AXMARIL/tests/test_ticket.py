import pytest
from tests.config import create_app
import uuid


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _create_ticket(client, headers, code):
    data = {
        "title": f"{str(uuid.uuid4())}_New ticket",
        "description": "Description of ticket",
        "type": "Test type",
        "files": (open("results/report.html", "rb"),)
    }
    response = client.post("/ticket/create", data=data, headers=headers, follow_redirects=True)
    assert response.status_code == code


def _get_ticket_stories(client, headers, code):
    response = client.get("/ticket/stories", headers=headers, follow_redirects=True)
    assert response.status_code == code
