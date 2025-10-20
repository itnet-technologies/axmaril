import json
import os
import requests
import traceback
import urllib.parse
from builtins import Exception
from bson import ObjectId
from werkzeug.utils import secure_filename

from .guacamole_model import GuacamoleModel
from .guacamole_schema import GuacamoleSchema
from ...utils.helpers import generate_guac_base64, save_icon_file, generate_ssh_password
from ...utils.custom_exception import ApplicationNotFoundException
from api.v2.utils.helpers import config_data
import requests
import json
import logging
# la fonction pour mdp aléatoire
from ...utils.helpers import generate_ssh_password
logger = logging.getLogger(__name__)


class GuacamoleService:

    guacadmin_token = None

    def __init__(self):
        # Charger config si nécessaire
        try:
            with open("config.json", "r") as f:
                cfg = json.load(f)
                config_data.update(cfg)
        except FileNotFoundError:
            print("config.json introuvable, utiliser config_data existant")

        self.guacamole_model = GuacamoleModel()
        self.guacamole_schema = GuacamoleSchema()

    def _guac_api(self, path: str) -> str:
        """Construire l'URL de l'API Guacamole"""
        base = config_data['GUACAMOLE_URL'].rstrip(
            '/')  # http://62.161.252.154:8080
        if not path.startswith('/'):
            path = '/' + path
        return f"{base}/guacamole/api{path}"
    
    def get_admin_token(self):
        base = config_data['GUACAMOLE_URL'].rstrip('/')
        url = f"{base}/guacamole/api/tokens"

        payload = {
            "username": config_data["GUACAMOLE_ADMIN_USER"],
            "password": config_data["GUACAMOLE_ADMIN_PASSWORD"],
            "dataSource": config_data.get("GUACAMOLE_DATASOURCE", "mysql"),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        resp = requests.post(url, data=payload, headers=headers, timeout=10)
        if resp.status_code != 200:
            # message d’erreur lisible si 403/401
            raise RuntimeError(f"Guacamole admin login failed ({resp.status_code}): {resp.text[:500]}")
        data = resp.json()
        token = data.get("authToken")
        if not token:
            raise RuntimeError(f"Guacamole admin login response missing token: {data}")
        return token
    
    def get_user_token(self, guac):
        """Obtenir le token pour un utilisateur spécifique"""
        url = self._guac_api('/tokens')  # CORRIGÉ: plus de /api/ au début
        payload = {"username": guac["username"], "password": guac["password"]}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            return response.json().get('authToken')
        return None

    def create_user(self, secret):
        token = self.get_admin_token()
        headers = {"Guacamole-Token": token, "Content-Type": "application/json"}
        datasource = config_data.get("GUACAMOLE_DATASOURCE", "mysql")
        url = self._guac_api(f'/session/data/{datasource}/users')

        payload = {
            "username": secret["username"],
            "password": secret["password"],
            "attributes": secret.get("attributes", {})
        }

        response = requests.post(url, headers=headers, json=payload)
        if response.status_code not in [200, 201]:
            return {"error": "Impossible de créer l'utilisateur", "details": response.text}, response.status_code

        return {"message": "Utilisateur créé"}, 201

    def create_rdp_connexion(self, data):
        """Créer une connexion RDP dans Guacamole"""
        token = self.get_admin_token()  # CORRIGÉ: utiliser self.get_admin_token()
        headers = {"Guacamole-Token": token,
                   "Content-Type": "application/json"}
        datasource = config_data.get("GUACAMOLE_DATASOURCE", "mysql")

        # CORRIGÉ: plus de /api/ au début
        url = self._guac_api(f'/session/data/{datasource}/connections')
        payload = {
            "parentIdentifier": "ROOT",
            "name": data["secret_name"],
            "protocol": "rdp",
            "parameters": data["secret"],
            "attributes": {
                "max-connections": data["secret"].get("max_connections", "5"),
                "max-connections-per-user": data["secret"].get("max_connections_per_user", "1")
            }
        }

        response = requests.post(url, headers=headers, json=payload)
        if response.status_code not in [200, 201]:
            return 500, {"error": "Échec de la création RDP", "details": response.text}

        connection_id = response.json().get("identifier")
        if not connection_id:
            return 500, {"error": "Connexion créée mais pas d'identifiant"}

        perm_url = self._guac_api(
            f'/session/data/{datasource}/connectionGroups/ROOT/permissions')
        perm_payload = [{
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": f"READ:{config_data['GUACAMOLE_DEFAULT_GROUP']}"
        }]
        requests.patch(perm_url, headers=headers, json=perm_payload)

        return 201, {"message": "Connexion RDP créée", "connection_id": connection_id}

    def create_ssh_connexion(self, data):
        """Créer une connexion SSH dans Guacamole"""
        token = self.get_admin_token()  # CORRIGÉ: utiliser self.get_admin_token()
        headers = {"Guacamole-Token": token,
                   "Content-Type": "application/json"}
        datasource = config_data.get("GUACAMOLE_DATASOURCE", "mysql")
        # CORRIGÉ: plus de /api/ au début
        ssh_url = self._guac_api(f'/session/data/{datasource}/connections')

        payload = {
            "parentIdentifier": "ROOT",
            "name": data["secret_name"],
            "protocol": "ssh",
            "parameters": data["secret"],
            "attributes": {
                "max-connections": data["secret"].get("max_connections", "5"),
                "max-connections-per-user": data["secret"].get("max_connections_per_user", "1")
            }
        }

        response = requests.post(ssh_url, headers=headers, json=payload)
        if response.status_code not in [200, 201]:
            return 500, {"error": "Échec de la création de la connexion SSH", "details": response.text}

        connection_id = response.json().get("identifier")
        if not connection_id:
            return 500, {"error": "Connexion SSH créée mais aucun identifiant retourné"}

        permission_url = self._guac_api(
            f'/session/data/{datasource}/connectionGroups/ROOT/permissions')
        permission_payload = [
            {
                "op": "add",
                "path": f"/connectionPermissions/{connection_id}",
                "value": f"READ:{config_data['GUACAMOLE_DEFAULT_GROUP']}"
            }
        ]
        requests.patch(permission_url, headers=headers,
                       json=permission_payload)

        return 201, {"message": "Connexion SSH créée et permissions attribuées au groupe par défaut", "connection_id": connection_id}

    def create_user_and_assign_secret(self, secret_data):
        """
        Crée un utilisateur Guacamole et une connexion SSH/RDP,
        et renvoie l'URL de connexion avec token utilisateur.
        """
        try:
            email = secret_data.get("owner_email")
            if not email:
                return {"error": "Adresse email requise"}, 400

            username = email.split("@")[0]
            password = generate_ssh_password()

            # Créer utilisateur si inexistant
            if not self.guacamole_model.find_user_by_username(username):
                user_payload = {
                    "username": username,
                    "password": password,
                    "attributes": {"email": email}
                }

                # Créer dans Guacamole via API REST
                status_resp = self.create_user(user_payload)
                if status_resp[1] != 201:
                    return {"error": "Impossible de créer l'utilisateur Guacamole", "details": status_resp}, status_resp[1]

                # AJOUT : Enregistrer dans MongoDB pour synchronisation
                mongo_user_data = {
                    "username": username,
                    "email": email,
                    "guac_password": password,  # Stocké pour référence
                    "owner_uid": secret_data.get("owner_uid"),
                    "groups": ["guac_user"],  # Groupe par défaut
                    "active": True
                }

                try:
                    self.guacamole_model.create_guacamole_user(mongo_user_data)
                    print(f"Utilisateur {username} enregistré dans MongoDB")
                except Exception as e:
                    print(
                        f"Erreur enregistrement MongoDB pour {username}: {e}")
                    # On continue même si l'enregistrement MongoDB échoue

            # Déterminer type de connexion
            secret_type = secret_data.get('type')
            if not secret_type:
                port = secret_data.get('secret', {}).get('port')
                if str(port) == '22':
                    secret_type = 'ssh'
                elif str(port) == '3389':
                    secret_type = 'rdp'
                else:
                    return {"error": "Type de connexion inconnu (ssh ou rdp)"}, 400

            # Créer la connexion
            if secret_type == 'ssh':
                status, resp = self.create_ssh_connexion(secret_data)
            else:
                status, resp = self.create_rdp_connexion(secret_data)

            if status not in [200, 201]:
                return resp, status

            connection_id = resp.get('connection_id')
            if not connection_id:
                return {"error": "Impossible de récupérer l'identifiant de connexion"}, 500

            # Token utilisateur
            user_token = self.get_user_token(
                {"username": username, "password": password})
            if not user_token:
                return {"error": "Impossible d'obtenir le token utilisateur Guacamole"}, 500

            connection_url = f"{config_data['GUACAMOLE_URL'].rstrip('/')}/guacamole/#/client/{connection_id}?token={user_token}"

            return {
                "connection_url": connection_url,
                "username": username,
                "password": password,
                "connection_id": connection_id
            }, 201

        except Exception as e:
            import traceback
            traceback_str = traceback.format_exc()
            print(traceback_str)
            return {"error": "Erreur interne lors de la création", "details": str(e)}, 500

    def auto_create_connection_from_secret(self, secret_data, user_data=None):
        try:
            guac_secret_data = secret_data.copy()

            # Gestion robuste de user_data qui peut être None
            if user_data is not None:
                email = user_data.get('email') or user_data.get(
                    'mail') or secret_data.get('owner_email')
                uid = user_data.get('uid') or user_data.get(
                    'cn') or secret_data.get('owner_uid')
            else:
                # Si user_data est None, utiliser seulement secret_data
                email = secret_data.get('owner_email')
                uid = secret_data.get('owner_uid')
                print(
                    "WARNING: user_data est None, utilisation de secret_data uniquement")

            if not email:
                return False, {"error": "L'adresse email du propriétaire est requise mais non trouvée"}
            if not uid:
                return False, {"error": "L'UID du propriétaire est requis mais non trouvé"}

            guac_secret_data['owner_email'] = email
            guac_secret_data['owner_uid'] = uid

            if 'secret_name' not in guac_secret_data and 'name' in secret_data:
                guac_secret_data['secret_name'] = secret_data['name']

            if 'type' not in guac_secret_data:
                port = guac_secret_data.get('secret', {}).get('port', '')
                if str(port) == '22':
                    guac_secret_data['type'] = 'ssh'
                elif str(port) == '3389':
                    guac_secret_data['type'] = 'rdp'
                else:
                    return False, {"error": "Impossible de déterminer le type de connexion (ssh ou rdp)"}

            result, status_code = self.create_user_and_assign_secret(
                guac_secret_data)
            if status_code in [200, 201]:
                return True, result
            else:
                return False, result

        except Exception as e:
            traceback_str = traceback.format_exc()
            print(
                f"Erreur dans auto_create_connection_from_secret: {traceback_str}")
            return False, {"error": f"Erreur lors de la création de la connexion Guacamole: {str(e)}"}

    # Fonctions CRUD Guacamole
    def create_guacamole(self, data, app_icon):
        existing = self.guacamole_model.find_by_name(data['app_name'])
        if existing['data']:
            raise ApplicationNotFoundException(
                'Application with the same name already exists')

        if app_icon:
            filename = secure_filename(app_icon.filename)
            icon_dir = 'static/app_icons'
            new_filename = f"{str(ObjectId())}_{filename}"
            save_icon_file(icon_dir, app_icon, new_filename)
            icon_path = os.path.join(icon_dir, new_filename)
            data['app_icon_path'] = '/' + icon_path

        self.guacamole_model.create_guacamole(data)

    def update_guacamole(self, app_id, data, app_icon):
        existing = self.guacamole_model.find_by_id(app_id)
        if not existing:
            raise ApplicationNotFoundException('Application not found')

        if app_icon:
            icon_path = existing['app_icon_path'].lstrip('/')
            if os.path.exists(icon_path):
                os.remove(icon_path)

            filename = secure_filename(app_icon.filename)
            icon_dir = 'static/app_icons'
            new_filename = f"{str(ObjectId())}_{filename}"
            save_icon_file(icon_dir, app_icon, new_filename)

            icon_path = os.path.join(icon_dir, new_filename)
            app_icon.save(icon_path)
            data['app_icon_path'] = '/' + icon_path

        self.guacamole_model.update_guacamole(app_id, data)

    def find_guacamole_by_id(self, app_id):
        existing = self.guacamole_model.find_by_id(app_id)
        if not existing:
            raise ApplicationNotFoundException('Application not found')
        return existing

    def find_guacamole_by_type(self, app_type):
        existing = self.guacamole_model.find_by_type(app_type)
        if not existing:
            raise ApplicationNotFoundException('Application not found')
        return existing

    def find_guacamole_by_name(self, app_name, page, per_page):
        return self.guacamole_model.find_by_name_with_paginate(app_name, page, per_page)

    def find_all_guacamoles(self, page, per_page):
        return self.guacamole_model.find_all_with_paginate(page, per_page)

    def delete_guacamole(self, app_id):
        existing = self.guacamole_model.find_by_id(app_id)
        if not existing:
            raise ApplicationNotFoundException('Application not found')
        self.guacamole_model.delete_guacamole(app_id)
    def add_user_to_default_group(self, username: str, admin_token: str) -> bool:
        """
        Ajoute un utilisateur Guacamole au groupe par défaut (ex: guac-user).
        """
        try:
            group = config_data.get("GUACAMOLE_DEFAULT_GROUP", "guac-user")
            guac_url = config_data.get("GUACAMOLE_URL")

            if not guac_url or not group:
                logger.error("GUACAMOLE_URL ou GUACAMOLE_DEFAULT_GROUP manquant dans config.json")
                return False

            patch_url = f"{guac_url}/guacamole/api/session/data/mysql/userGroups/{group}/memberUsers"
            headers = {
                "Guacamole-Token": admin_token,
                "Content-Type": "application/json"
            }
            patch_payload = [{"op": "add", "path": "/", "value": username}]

            resp = requests.patch(patch_url, headers=headers, json=patch_payload)
            if resp.status_code in (200, 204):
                logger.info(f"Utilisateur {username} ajouté au groupe {group}")
                return True
            else:
                logger.warning(f"Échec ajout {username} au groupe {group}: {resp.text}")
                return False

        except Exception as e:
            logger.error(f"Erreur add_user_to_default_group: {e}")
            return False
        
    def get_connexion_url(self, connexion_id: str) -> str:
        """URL directe via token admin."""
        admin_token = self.get_admin_token()
        base = config_data['GUACAMOLE_URL'].rstrip('/')
        # format standard : /guacamole/#/client/<id>?token=<token>
        return f"{base}/guacamole/#/client/{connexion_id}?token={admin_token}"

class WorkflowService:
    """
    Workflow robuste :
     - Vérifie/crée utilisateur Guacamole (via GuacamoleService)
     - Vérifie/crée connexion SSH/RDP
     - Récupère token utilisateur Guacamole
     - Puis crée le secret dans Azumaril (MongoDB) seulement si tout a fonctionné
    """

    def __init__(self):
        self.guac_url = config_data['GUACAMOLE_URL'].rstrip('/')
        self.axmaril_url = config_data['AXMARIL_API_URL'].rstrip('/')
        self.guac_admin_user = config_data['GUACAMOLE_ADMIN_USERNAME']
        self.guac_admin_pass = config_data['GUACAMOLE_ADMIN_PASSWORD']
        self.guac_service = GuacamoleService()

    # ---------- Helpers Guacamole ----------
    def get_guac_admin_token(self) -> str:
        """Récupère token admin Guacamole (lève exception si échec)."""
        url = f"{self.guac_url}/guacamole/api/tokens"
        payload = {"username": self.guac_admin_user,
                   "password": self.guac_admin_pass}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = requests.post(url, data=payload, headers=headers)
        try:
            resp.raise_for_status()
        except Exception as e:
            logger.error(
                "Echec récupération token admin Guacamole: %s - %s", resp.status_code, resp.text)
            raise
        return resp.json().get('authToken')
 
    def ensure_guac_user(self, username: str, email: str, admin_token: str) -> str:
        """
        Vérifie si l'utilisateur Guacamole existe. S'il n'existe pas, le crée.
        Dans tous les cas, (ré)initialise un mot de passe aléatoire et ajoute l'utilisateur
        au groupe par défaut (GUACAMOLE_DEFAULT_GROUP). Retourne le mot de passe.
        """
        headers = {
            "Guacamole-Token": admin_token,
            "Content-Type": "application/json"
        }
        datasource = config_data.get("GUACAMOLE_DATASOURCE", "mysql")
        group = config_data.get("GUACAMOLE_DEFAULT_GROUP", "guac-user")

        base = f"{self.guac_url}/guacamole/api"

        # 1) GET user
        get_user_url = f"{base}/session/data/{datasource}/users/{username}"
        r = requests.get(get_user_url, headers=headers)

        # Nouveau mot de passe pour obtenir un token côté user
        new_password = generate_ssh_password()

        if r.status_code == 404:
            # 2) CREATE user
            create_user_url = f"{base}/session/data/{datasource}/users"
            payload = {
                "username": username,
                "password": new_password,
                "attributes": {"guac-email-address": email or ""}
            }
            cr = requests.post(create_user_url, headers=headers, json=payload)
            if cr.status_code not in (200, 201):
                raise RuntimeError(f"Guacamole: création user échouée: {cr.status_code} {cr.text}")
        elif r.status_code == 200:
            # 3) RESET password
            patch_user_url = f"{base}/session/data/{datasource}/users/{username}"
            patch_payload = {
                "password": new_password,
                "attributes": r.json().get("attributes", {"guac-email-address": email or ""})
            }
            pr = requests.put(patch_user_url, headers=headers, json=patch_payload)
            if pr.status_code not in (200, 204):
                raise RuntimeError(f"Guacamole: reset password échoué: {pr.status_code} {pr.text}")
        else:
            raise RuntimeError(f"Guacamole: lecture user échouée: {r.status_code} {r.text}")

        # 4) Ajout au groupe par défaut (idempotent)
        try:
            patch_url = f"{base}/session/data/{datasource}/userGroups/{group}/memberUsers"
            patch_payload = [{"op": "add", "path": "/", "value": username}]
            grp = requests.patch(patch_url, headers=headers, json=patch_payload)
            if grp.status_code not in (200, 204):
                logger.warning(f"[Guacamole] Ajout {username} au groupe {group} a échoué: {grp.status_code} {grp.text}")
        except Exception as e:
            logger.warning(f"[Guacamole] Ajout au groupe: {e}")

        return new_password

    def ensure_connection(self, secret_info: dict, owner_uid: str, owner_email: str, admin_token: str) -> str:
        """
        Vérifie si la connexion existe (par nom) et retourne connection_id.
        Si non, crée la connexion (ssh ou rdp) via GuacamoleService.
        """
        conn_name = secret_info.get('name') or f"conn_{owner_uid}"
        # optional: normaliser le nom si nécessaire
        try:
            existing = self.guac_service.guacamole_model.find_connection_by_name(
                conn_name)
        except Exception as e:
            logger.exception(
                "Erreur interrogation mirror pour connection %s: %s", conn_name, e)
            existing = None

        if existing:
            logger.debug("Connexion existante trouvée: %s -> %s",
                         conn_name, existing.get('identifier'))
            return existing.get('identifier')

        # déterminer type
        port = secret_info.get('port') or secret_info.get(
            'secret', {}).get('port')
        protocol = secret_info.get('type')
        if not protocol:
            if str(port) == '22':
                protocol = 'ssh'
            elif str(port) == '3389':
                protocol = 'rdp'
            else:
                raise Exception(
                    "Impossible de déterminer le protocole (ssh/rdp) depuis le secret")

        payload = {
            "secret_name": conn_name,
            "secret": secret_info,
            "owner_email": owner_email,
            "owner_uid": owner_uid
        }

        try:
            if protocol == 'ssh':
                status, resp = self.guac_service.create_ssh_connexion(payload)
            else:
                status, resp = self.guac_service.create_rdp_connexion(payload)
        except Exception as e:
            logger.exception(
                "Erreur appel création connexion Guacamole: %s", e)
            raise

        if status not in (200, 201):
            logger.error("Création connexion Guacamole échouée: %s", resp)
            raise Exception(f"Erreur création connexion Guacamole: {resp}")

        connection_id = resp.get('connection_id')
        if not connection_id:
            logger.error(
                "Aucun connection_id retourné par Guacamole: %s", resp)
            raise Exception(
                "Identifiant de connexion non retourné par Guacamole")

        logger.info("Connexion Guacamole créée: %s -> %s",
                    conn_name, connection_id)
        return connection_id

    # ---------- Azumaril (MongoDB) ----------

    def create_secret_in_axmaril(self, axmaril_token: str, secret_payload: dict) -> dict:
        """
        Crée un secret dans Azumaril avec la structure API v2 corrigée
        """
        # CORRECTION : Utiliser v2 au lieu de v1
        url = f"{self.axmaril_url}/api/v2/secrets"
        headers = {"Authorization": f"Bearer {axmaril_token}",
                   "Content-Type": "application/json"}

        # CORRECTION : Structure de données basée sur l'analyse des erreurs API
        corrected_payload = {
            "safe_id": secret_payload.get("safe_id"),
            "secret_type": secret_payload.get("secret_type", "other"),
            "app_type": secret_payload.get("app_type") or "other",
            "secret_name": secret_payload.get("secret_name") or secret_payload.get("name"),
            "secret": secret_payload.get("secret"),
        }


        # Vérifications
        if not corrected_payload["safe_id"]:
            raise ValueError("safe_id est requis pour créer un secret")
        if not corrected_payload["secret_name"]:
            raise ValueError("secret_name est requis pour créer un secret")

        try:
            resp = requests.post(url, headers=headers,
                                 json=corrected_payload, verify=False)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            logger.error("Echec création secret Azumaril: %s",
                         resp.text if hasattr(e, 'response') else str(e))
            if hasattr(e, 'response') and e.response.status_code == 401:
                raise Exception(
                    "Token Azumaril expiré ou invalide. Reconnectez-vous.")
            raise

        # ---------- Main workflow ----------
    def run_full_workflow(self, axmaril_token: str, secret_info: dict, owner_email: str, owner_uid: str, safe_id: str, user_credentials: dict = None) -> dict:
        """
        Workflow complet :
        1) Crée utilisateur Guacamole si inexistant
        2) Crée connexion SSH/RDP si inexistante
        3) Récupère token utilisateur Guacamole
        4) Crée le secret dans Azumaril v2
        """
        if not all([axmaril_token, secret_info, owner_email, owner_uid, safe_id]):
            raise ValueError(
                "axmaril_token, secret_info, owner_email, owner_uid et safe_id sont requis")

        try:
            # --- 1) Token admin Guacamole ---
            admin_token = self.get_guac_admin_token()

            # --- 2) Créer/utilisateur Guacamole ---
            username = owner_email.split('@')[0]
            guac_password = self.ensure_guac_user(
                username, owner_email, admin_token)

            # --- 3) Créer connexion SSH/RDP ---
            connection_id = self.ensure_connection(
                secret_info, owner_uid, owner_email, admin_token)

            # --- 4) Token utilisateur Guacamole pour URL ---
            user_token = self.guac_service.get_user_token(
                {"username": username, "password": guac_password})
            if not user_token:
                raise Exception(
                    f"Impossible d'obtenir le token utilisateur Guacamole pour {username}")
           
            guac_connection_url = f"{self.guac_url}/guacamole/#/client/{connection_id}?token={user_token}"


            # --- 5) Préparer payload Azumaril v2 ---
            port = secret_info.get("port") or secret_info.get(
                "secret", {}).get("port")
            secret_type = secret_info.get("type")
            if not secret_type:
                if str(port) == '22':
                    secret_type = 'ssh'
                elif str(port) == '3389':
                    secret_type = 'rdp'
                else:
                    secret_type = 'other'

            axmaril_payload = {
                "safe_id": safe_id,
                "secret_type": "ssh" if (secret_info.get("port")==22) else "other",
                "app_type": "ssh",
                "secret_name": secret_info.get("name"),
                "secret": {
                    "hostname": secret_info["hostname"],
                    "port": secret_info["port"],
                    "username": secret_info["username"],
                    "password": secret_info["password"]
                }
            }

            

            # --- 6) Créer secret dans Azumaril (avec retry token expiré) ---
            axmaril_resp = self.create_secret_in_axmaril_with_retry(
              axmaril_token, axmaril_payload, user_credentials)

            return {
                "guac_connection_url": guac_connection_url,
                "guac_username": username,
                "guac_password": guac_password,
                "connection_id": connection_id,
                "axmaril_secret_creation": axmaril_resp
            }

        except Exception as e:
            logger.exception("Echec run_full_workflow: %s", e)
            raise

    def get_fresh_axmaril_token(self, uid: str, password: str) -> str:
        """
        Obtient un nouveau token Azumaril en cas d'expiration.
        ⚠️ Utilise v1 pour l'auth (fonctionne sur ton serveur actuel).
        """
        url = f"{self.axmaril_url}/api/v1/auth/login"  # <-- v1 ici
        payload = {
            "uid": uid,
            "password": password,
            "2FA": "No",
            "code": ""  # facultatif, à adapter si nécessaire
        }
        headers = {"Content-Type": "application/json"}

        try:
            resp = requests.post(
                url, json=payload, headers=headers, verify=False)
            resp.raise_for_status()
            token = resp.json().get("token")
            if not tokenaxmaril_payload:
                raise Exception("Token non reçu depuis Azumaril v1")
            return token
        except requests.exceptions.RequestException as e:
            logger.error(
                "Impossible d'obtenir un nouveau token Azumaril: %s", e)
            raise

    # === CORRECTION 4: Gestion automatique des tokens expirés ===
    # Modifier create_secret_in_axmaril pour gérer l'expiration automatiquement :

    def create_secret_in_axmaril_with_retry(self, axmaril_token: str, secret_payload: dict, user_credentials: dict = None) -> dict:
        """
        Version avec retry automatique en cas de token expiré
        """
        try:
            return self.create_secret_in_axmaril(axmaril_token, secret_payload)
        except Exception as e:
            if "Token" in str(e) and "expiré" in str(e) and user_credentials:
                logger.info("Token expiré, tentative de renouvellement...")
                new_token = self.get_fresh_axmaril_token(
                    user_credentials["uid"],
                    user_credentials["password"]
                )

                return self.create_secret_in_axmaril(new_token, secret_payload)
            raise
