import pytest
from tests.config import create_app, generate_random_email
from pymongo import MongoClient

server = MongoClient(host="0.0.0.0", port=27017)
db = server["db002"]
dbtoken = db["tokens"]
users = db["users"]

@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _create_account(client, user_type, firstname, lastname, email, password, tel, managerID, businessCategory, Dfa, code):
    data = {
        "user_type": user_type,
        "firstname": firstname,
        "lastname": lastname,
        "email": email,
        "password": password,
        "tel": tel,
        "managerID": managerID,
        "businessCategory": businessCategory,
        "2fa": Dfa
    }
    response = client.post("/auth/register", json=data, follow_redirects=True)
    assert response.status_code == code


def _activate_user_account(client, email, code):
    user = users.find_one({"email": email})
    token = dbtoken.find_one({"type" : "activation", "user_uid" : user["uid"]})
    data = {"uid": user["uid"], "activation_code" : str(token["activation_code"])}
    assert user is not None
    response = client.put(f"/auth/activation", json=data, follow_redirects=True)
    assert response.status_code == code


def _login_user(client, uid, password, code):
    data = {"uid": uid, "password": password}
    response = client.post("/auth/login", json=data, follow_redirects=True)
    assert response.status_code == code


def _forgotpassword(client, uid, code):
    data = {"uid": uid}
    response = client.post("/auth/forgot/password", json=data, follow_redirects=True)
    assert response.status_code == code


def _resetpassword(client, email, code):
    user = users.find_one({"email": email})
    token = dbtoken.find_one({"user_uid": user["uid"], "type":"password_reset"})
    data = {"code": token["code"], "newPassword": "String3#"}
    response = client.put(f"/auth/change/resetpassword", json=data, follow_redirects=True)
    assert response.status_code == code


random_mail = generate_random_email()

def test_register_user(client):
    _create_account(client, "user", "User", "Test", random_mail, "String1#", "", "", "", "", 200)
    _login_user(client, random_mail, "String1#", 400)


def test_activation_account(client):
    _activate_user_account(client, random_mail, 200)
    _login_user(client, random_mail, "String1#", 200)


@pytest.fixture
def current_user(client):
    data = {"uid": random_mail, "password": "String1#"}
    response = client.post("/auth/login", json=data, follow_redirects=True)
    assert response.status_code == 200
    token = response.json.get("token")
    assert token is not None
    return token

"""
def test_change_password(client, current_user):
    fuser = users.find_one({"email": random_mail})
    headers = {"Authorization": f"Bearer {current_user}"}
    data = {"uid": fuser["uid"], "oldPassword": "String1#", "newPassword": "String2#"}
    response = client.post("/auth/change/password", json=data, headers=headers, follow_redirects=True)
    assert response.status_code == 200
    _login_user(client, random_mail, "String2#", 200)
"""


def test_forgot_password(client):
    _forgotpassword(client, random_mail, 200)
    _resetpassword(client, random_mail, 200)
    _login_user(client, random_mail, "String3#", 200)


@pytest.fixture
def auth_token(client):
    data = {"uid": random_mail, "password": "String3#"}
    response = client.post("/auth/login", json=data, follow_redirects=True)
    assert response.status_code == 200
    token = response.json.get("token")
    assert token is not None
    return token


#########################
#       TICKET TEST     #
#########################

"""
def test_create_ticket(client, auth_token):
    from tests.test_ticket import _create_ticket
    headers = {"Authorization": f"Bearer {auth_token}"}
    _create_ticket(client, headers, 200)
"""

def test_get_ticket_stories(client, auth_token):
    from tests.test_ticket import _get_ticket_stories
    headers = {"Authorization": f"Bearer {auth_token}"}
    _get_ticket_stories(client, headers, 200)


#########################
#       SECRET TEST     #
#########################
"""
def test_create_secret(client, auth_token):
    from tests.test_secret import _create_secret
    headers = {"Authorization": f"Bearer {auth_token}"}
    _create_secret(client, headers, 200)
"""

def test_get_all_secret(client, auth_token):
    from tests.test_secret import _get_all_secret
    headers = {"Authorization": f"Bearer {auth_token}"}
    _get_all_secret(client, headers, 200)


def test_get_secret_types(client, auth_token):
    from tests.test_secret import _get_secret_types
    headers = {"Authorization": f"Bearer {auth_token}"}
    _get_secret_types(client, headers, 200)


    