# modules/guacamole_auth.py
# Logique métier uniquement - pas de routes

import os
import json
import requests
import logging
from datetime import datetime, timedelta
from typing import Tuple, Optional

# ---------------------------------------------------
# Logging
# ---------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------
# Chargement config
# ---------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE_PATH = os.path.join(BASE_DIR, 'static', 'config.json')

with open(CONFIG_FILE_PATH, 'r') as f:
    config_data = json.load(f)

GUACAMOLE_API_URL = config_data.get("GUACAMOLE_URL", "http://127.0.0.1:8080")

# ---------------------------------------------------
# Fonctions utilitaires backend UNIQUEMENT
# ---------------------------------------------------


def guacamole_api_url(endpoint: str) -> str:
    """Construit l'URL de l'API Guacamole"""
    return f"{GUACAMOLE_API_URL}/guacamole/api{endpoint}"


def login_backend(username: str, password: str) -> Tuple[bool, dict]:
    """
    Authentifie un utilisateur Guacamole et retourne token + expiration
    """
    url = guacamole_api_url("/tokens")
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(
            url, data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            token_data = response.json()
            auth_token = token_data.get('authToken')
            expires = token_data.get('expires') or 86400
            logger.info(f"Utilisateur '{username}' connecté avec succès")
            return True, {"authToken": auth_token, "expires_in": expires}
        else:
            logger.warning(
                f"Échec login '{username}' ({response.status_code}): {response.text}")
            return False, {"error": response.text, "status_code": response.status_code}
    except requests.ConnectionError:
        logger.error("Impossible de se connecter au serveur Guacamole")
        return False, {"error": "Impossible de se connecter au serveur Guacamole"}
    except Exception as e:
        logger.error(f"Erreur interne login Guacamole: {e}")
        return False, {"error": str(e)}


def logout_backend(token: str) -> Tuple[bool, dict]:
    """
    Déconnecte un utilisateur Guacamole en invalidant son token
    """
    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    url = guacamole_api_url("/tokens")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.delete(url, headers=headers, timeout=10)
        if response.status_code == 204:
            logger.info("Déconnexion réussie")
            return True, {"message": "Déconnexion réussie"}
        else:
            logger.warning(
                f"Échec déconnexion ({response.status_code}): {response.text}")
            return False, {"error": response.text, "status_code": response.status_code}
    except requests.ConnectionError:
        logger.error("Impossible de se connecter au serveur Guacamole")
        return False, {"error": "Impossible de se connecter au serveur Guacamole"}
    except Exception as e:
        logger.error(f"Erreur interne logout Guacamole: {e}")
        return False, {"error": str(e)}


def check_user_exists(email: str, admin_token: str) -> Tuple[bool, dict]:
    """
    Vérifie si un utilisateur existe dans Guacamole par email
    """
    url = guacamole_api_url("/session/data/mysql/users")
    headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            users = response.json()
            user_exists = email in users
            logger.info(
                f"Vérification utilisateur '{email}': {'existe' if user_exists else 'inexistant'}")
            return user_exists, {"exists": user_exists, "users": users}
        else:
            logger.error(
                f"Erreur vérification utilisateur ({response.status_code}): {response.text}")
            return False, {"error": response.text, "status_code": response.status_code}
    except Exception as e:
        logger.error(f"Erreur interne vérification utilisateur: {e}")
        return False, {"error": str(e)}


def create_guacamole_user(user_info: dict, password: str, admin_token: str) -> Tuple[bool, dict]:
    """
    Crée un nouvel utilisateur dans Guacamole
    """
    url = guacamole_api_url("/session/data/mysql/users")
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "username": user_info.get('email'),
        "password": password,
        "attributes": {
            "disabled": "",
            "expired": "",
            "access-window-start": "",
            "access-window-end": "",
            "valid-from": "",
            "valid-until": "",
            "timezone": ""
        }
    }

    try:
        response = requests.post(
            url, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            logger.info(
                f"Utilisateur '{user_info.get('email')}' créé avec succès")
            return True, {"message": "Utilisateur créé", "username": user_info.get('email')}
        else:
            logger.error(
                f"Erreur création utilisateur ({response.status_code}): {response.text}")
            return False, {"error": response.text, "status_code": response.status_code}
    except Exception as e:
        logger.error(f"Erreur interne création utilisateur: {e}")
        return False, {"error": str(e)}


def generate_random_password(length: int = 12) -> str:
    """
    Génère un mot de passe aléatoire pour Guacamole
    """
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def get_admin_token() -> Tuple[bool, str]:
    """
    Récupère un token admin pour les opérations administratives
    """
    admin_user = config_data.get("GUACAMOLE_ADMIN_USER", "guacadmin")
    admin_password = config_data.get("GUACAMOLE_ADMIN_PASSWORD", "guacadmin")

    success, result = login_backend(admin_user, admin_password)
    if success:
        return True, result.get('authToken')
    else:
        return False, result.get('error', 'Erreur authentification admin')
