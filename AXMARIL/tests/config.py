from flask import Flask
from modules.ldapauth import LDAP_REQUEST
from modules.tickets.routes import TICKET_REQUEST
from modules.secret import SHARE_REQUEST
import string
import random


def create_app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(LDAP_REQUEST, url_prefix="/auth")
    app.register_blueprint(TICKET_REQUEST, url_prefix="/ticket")
    app.register_blueprint(SHARE_REQUEST, url_prefix="/secret")
    return app


def generate_random_email(prefix="user", domain="e.com", length=8):
    random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    email = f"{prefix}{random_chars}@{domain}"
    return email