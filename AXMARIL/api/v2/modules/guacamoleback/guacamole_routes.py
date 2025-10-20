# api/v2/modules/guacamole/guacamole_routes.py
import traceback
from flask import Flask, request, jsonify, Blueprint, g
from flask_cors import CORS
from .guacamole_model import GuacamoleModel
from .guacamole_schema import GuacamoleSchema, GuacamoleUpdateSchema, GuacamoleSearchSchema
from .guacamole_service import GuacamoleService
from ...database.db_manager import DBManager
from datetime import datetime, timedelta
from ...utils.helpers import success_response, error_response, save_icon_file, config_data
import json, requests
from ...utils.custom_exception import ApplicationNotFoundException, InvalidDataException, DatabaseUpdateException
from ...utils.middleware import jwt_validation
import base64
from flask import Blueprint, request, jsonify
from modules.guacamole_auth import login_backend, logout_backend
from modules.guacamole_group import group_handler, extract_token
# Import des fonctions métier depuis modules/
from modules.guacamole_auth import (
    login_backend, logout_backend, check_user_exists, 
    create_guacamole_user, generate_random_password, get_admin_token
)

# Instances existantes
guacamole_model = GuacamoleModel()
guacamole_schema = GuacamoleSchema()
guacamole_service = GuacamoleService()
guacamole_schema_update = GuacamoleUpdateSchema()
guacamole_schema_search = GuacamoleSearchSchema()

# Blueprint existant (PAS de namespace)
guacamole_bp = Blueprint('v2_guacamole', __name__)
guacamole_bp = Blueprint("guacamole", __name__, url_prefix="/api/v1/guacamole")


guacd_host = str(config_data.get('GUACD_HOSTNAME', '127.0.0.1'))
guacd_port = str(config_data.get('GUACD_PORT', '4822'))
# ---------------------------------------------------
# NOUVEAU : Workflow principal pour intégration Axmaril
# ---------------------------------------------------

@guacamole_bp.route('/users/create-with-secret', methods=['POST'])
def create_user_with_secret():
    """
    Workflow complet Axmaril : vérifier/créer utilisateur Guacamole, l'ajouter à guac_user,
    puis créer la connexion (SSH/RDP) et donner les droits.
    """
    data = request.json
    user_email = data.get('email')
    secret_data = data.get('secret_data')
    
    if not user_email or not secret_data:
        return {"error": "Email et secret_data requis"}, 400
    
    try:
        # 1. Obtenir token admin
        success, admin_token = get_admin_token()
        if not success:
            return {"error": f"Erreur authentification admin: {admin_token}"}, 500

        headers = {
            "Guacamole-Token": admin_token,
            "Content-Type": "application/json"
        }
        
        # 2. Vérifier si utilisateur existe
        user_exists, check_result = check_user_exists(user_email, admin_token)
        
        # 3. Créer utilisateur si nécessaire
        if not user_exists:
            password = generate_random_password()
            success, create_result = create_guacamole_user({'email': user_email}, password, admin_token)
            if not success:
                return {"error": f"Erreur création utilisateur: {create_result}"}, 500

        # 3.b AJOUT : s'assurer que l'utilisateur est membre du groupe 'guac_user'
        # (idempotent : le PUT est safe si déjà membre)
        group_name = "guac_user"
        add_member_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/userGroups/{group_name}/members/{user_email}"
        add_resp = requests.put(add_member_url, headers=headers)
        if add_resp.status_code not in (200, 204):
            # Optionnel : si le groupe n'existe pas (404), on peut tenter de le créer puis réessayer
            if add_resp.status_code == 404:
                # création basique du groupe (si ton instance le permet)
                create_group_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/userGroups"
                group_payload = {
                    "identifier": group_name,
                    "attributes": {
                        "disabled": "",
                        "expired": "",
                        "access-window-start": "",
                        "access-window-end": "",
                        "timezone": ""
                    }
                }
                cg = requests.post(create_group_url, headers=headers, json=group_payload)
                if cg.status_code in (200, 201):
                    # réessayer l'ajout de membre
                    add_resp = requests.put(add_member_url, headers=headers)
            # Si après tentative ça échoue encore, on continue mais on le signale
            if add_resp.status_code not in (200, 204):
                # On n'interrompt pas tout le workflow, mais on retourne l’info
                group_warning = f"Impossible d'ajouter {user_email} au groupe '{group_name}': {add_resp.status_code} {add_resp.text}"
        else:
            group_warning = None

        # 4. Créer la connexion selon le type
        if secret_data.get('type') == 'ssh':
            success, conn_result = create_ssh_connection_internal(secret_data, user_email, admin_token)
        elif secret_data.get('type') == 'rdp':
            success, conn_result = create_rdp_connection_internal(secret_data, user_email, admin_token)
        else:
            return {"error": "Type de secret non supporté. Utilisez 'ssh' ou 'rdp'"}, 400
        
        if not success:
            return {"error": f"Erreur création connexion: {conn_result}"}, 500
        
        resp = {
            "message": "Utilisateur, groupe et connexion configurés",
            "user_existed": user_exists,
            "connection_created": True,
            "user_email": user_email,
            "connection_url": conn_result.get('connection_url')
        }
        if group_warning:
            resp["warning"] = group_warning
        return resp, 201
        
    except Exception as e:
        return {"error": f"Erreur interne: {str(e)}"}, 500

@guacamole_bp.route('/users/<string:email>/exists', methods=['GET'])
def check_user(email):
    """Vérifier si un utilisateur existe"""
    try:
        success, admin_token = get_admin_token()
        if not success:
            return {"error": f"Erreur authentification admin: {admin_token}"}, 500
        
        user_exists, result = check_user_exists(email, admin_token)
        return {"email": email, "exists": user_exists}, 200
        
    except Exception as e:
        return {"error": f"Erreur interne: {str(e)}"}, 500

# ---------------------------------------------------
# Fonctions internes pour créer connexions
# ---------------------------------------------------



def find_connection_by_name(name: str, admin_token: str):
    """
    Vérifie si une connexion existe déjà par son nom.
    Retourne (True, conn) si trouvée, sinon (False, None).
    """
    headers = {
        "Guacamole-Token": admin_token,
        "Content-Type": "application/json"
    }
    list_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"
    resp = requests.get(list_url, headers=headers)
    if resp.status_code != 200:
        return False, None
    for cid, conn in resp.json().items():
        if conn.get("name") == name:
            conn["identifier"] = cid
            return True, conn
    return False, None

def create_ssh_connection_internal(secret_data, user_email, admin_token):
    """Crée une connexion SSH en utilisant la logique existante, idempotente"""
    try:
        headers = {
            "Guacamole-Token": admin_token,
            "Content-Type": "application/json"
        }

        create_connection_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"
        guacd_host = str(config_data.get('GUACD_HOSTNAME', '127.0.0.1'))
        guacd_port = str(config_data.get('GUACD_PORT', '4822'))

        payload = {
            "parentIdentifier": "ROOT",
            "name": secret_data.get('name'),
            "protocol": "ssh",
            "parameters": {
                "hostname": secret_data.get('hostname'),
                "port": str(secret_data.get('port', 22)),
                "username": secret_data.get('username'),
                "password": secret_data.get('password')
            },
            "attributes": {
                "max-connections": "5",
                "max-connections-per-user": "1",
                "guacd-hostname": guacd_host,
                "guacd-port": guacd_port
            }
        }

        # 🔑 Vérifier si la connexion existe déjà
        exists, existing = find_connection_by_name(secret_data.get('name'), admin_token)
        if exists:
            connection_id = existing["identifier"]
        else:
            response = requests.post(create_connection_url, headers=headers, json=payload)
            if response.status_code in [200, 201]:
                connection_id = response.json().get('identifier')
                if not connection_id:
                    return False, {"error": "ID de connexion manquant"}
            else:
                return False, {"error": "Création connexion échouée", "details": response.text}

        # Attribution des permissions
        permissions_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users/{user_email}/permissions"
        permissions_payload = [
            {
                "op": "add",
                "path": f"/connectionPermissions/{connection_id}",
                "value": "READ"
            }
        ]
        permissions_response = requests.patch(permissions_url, headers=headers, json=permissions_payload)

        if permissions_response.status_code == 204:
            connection_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/#/client/{generate_guac_base64(connection_id)}"
            return True, {"connection_url": connection_url, "connection_id": connection_id}
        else:
            return False, {"error": "Attribution permissions échouée", "details": permissions_response.text}

    except Exception as e:
        return False, {"error": str(e)}

def create_rdp_connection_internal(secret_data, user_email, admin_token):
    """Crée une connexion RDP idempotente et attribue les permissions à l'utilisateur."""
    try:
        headers = {
            "Guacamole-Token": admin_token,
            "Content-Type": "application/json"
        }

        # Config guacd depuis config.json (fallbacks sûrs)
        guacd_host = str(config_data.get('GUACD_HOSTNAME', '127.0.0.1'))
        guacd_port = str(config_data.get('GUACD_PORT', '4822'))

        # Paramètres RDP (prend depuis secret_data si fournis)
        width = str(secret_data.get('width', '1280'))
        height = str(secret_data.get('height', '720'))
        color_depth = str(secret_data.get('color_depth', '24'))
        domain = secret_data.get('domain', '')

        payload = {
            "parentIdentifier": "ROOT",
            "name": secret_data.get('name'),
            "protocol": "rdp",
            "parameters": {
                "hostname": secret_data.get('hostname'),
                "port": str(secret_data.get('port', 3389)),
                "username": secret_data.get('username'),
                "password": secret_data.get('password'),
                "domain": domain,
                "security": "",
                "disable-auth": "false",
                "ignore-cert": "true",
                "color-depth": color_depth,
                "width": width,
                "height": height
            },
            "attributes": {
                "max-connections": "5",
                "max-connections-per-user": "1",
                "guacd-hostname": guacd_host,
                "guacd-port": guacd_port
            }
        }

        create_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"

        # 🔑 Idempotence : vérifier si une connexion du même nom existe déjà
        exists, existing = find_connection_by_name(secret_data.get('name'), admin_token)
        if exists:
            connection_id = existing["identifier"]
        else:
            response = requests.post(create_url, headers=headers, json=payload)
            if response.status_code in [200, 201]:
                connection_id = response.json().get('identifier')
                if not connection_id:
                    return False, {"error": "ID de connexion manquant"}
            else:
                return False, {"error": "Création connexion échouée", "details": response.text}

        # Attribution des permissions READ au user
        permission_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users/{user_email}/permissions"
        permission_payload = [{
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": "READ"
        }]
        permission_response = requests.patch(permission_url, headers=headers, json=permission_payload)

        if permission_response.status_code == 204:
            connection_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/#/client/{generate_guac_base64(connection_id)}"
            return True, {"connection_url": connection_url, "connection_id": connection_id}
        else:
            return False, {"error": "Attribution permissions échouée", "details": permission_response.text}

    except Exception as e:
        return False, {"error": str(e)}

def generate_guac_base64(identifier: str, auth_provider: str = "mysql") -> str:
    """Generate the Base64-encoded string for a Guacamole connection URL."""
    raw_string = f"{identifier}\0c\0{auth_provider}"
    encoded_bytes = base64.b64encode(raw_string.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

# ---------------------------------------------------
# ROUTES EXISTANTES (toutes vos routes gardées telles quelles)
# ---------------------------------------------------
@guacamole_bp.route('/guacamole/auth/login', methods=['POST'])
def guacamole_login():
    data = request.get_json(force = True)
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return {"error": "Nom d'utilisateur et mot de passe requis"}, 400

    # Utilise la fonction métier du module
    success, result = login_backend(username, password)
    
    if success:
        g.current_token = result.get('authToken')
        g.token_expiration = datetime.utcnow() + timedelta(seconds=result.get('expires_in', 86400))
    
    return result, 200 if success else 401

@guacamole_bp.route('/guacamole/auth/logout', methods=['POST'])
def guacamole_logout():
    """Déconnexion de l'utilisateur dans Guacamole"""
    args = dict(request.args)
    token = args["guacamole_token"]

    # Utilise la fonction métier du module
    success, result = logout_backend(token)
    return result, 200 if success else 400

@guacamole_bp.route('/guacamole/connexion/rdp', methods=['POST'])
def guacamole_rdp():
    data = request.get_json(force = True)
    args = dict(request.args)
    token = args["guacamole_token"]

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    name = data.get('name')
    hostname = data.get('hostname')
    port = data.get('port', '3389')
    username = data.get('username')
    password = data.get('password')
    domain = data.get('domain', '')
    width = data.get('width', '1280')
    height = data.get('height', '720')
    color_depth = data.get('color_depth', '24')
    guac_user = data.get('guac_user')

    rdp_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"

    headers = {
        "Guacamole-Token": token,
        "Content-Type": "application/json"
    }

    payload = {
        "parentIdentifier": "ROOT",
        "name": name,
        "protocol": "rdp",
        "parameters": {
            "hostname": hostname,
            "port": port,
            "username": username,
            "password": password,
            "domain": domain,
            "security": "",
            "disable-auth": "false",
            "ignore-cert": "true",
            "color-depth": color_depth,
            "width": width,
            "height": height
        },
        "attributes": {
            "max-connections": "5",
            "max-connections-per-user": "1",
            "guacd-hostname": guacd_host,
            "guacd-port": guacd_port
        }    
    }

    try:
        response = requests.post(rdp_url, headers=headers, json=payload)
        if response.status_code in [200, 201]:
            connection_id = response.json().get('identifier')
            if not connection_id:
                return {
                    "error": "Connexion créée, mais aucun identifiant n'a été retourné",
                    "details": response.json()
                }, 500

            permission_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users/{guac_user}/permissions"
            permission_payload = [
                {
                    "op": "add",
                    "path": f"/connectionPermissions/{connection_id}",
                    "value": "READ"
                }
            ]

            permission_response = requests.patch(permission_url, headers=headers, json=permission_payload)
            if permission_response.status_code == 204:
               
                connection_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/#/client/{generate_guac_base64(connection_id)}"

                return {
                    "message": f"Connexion RDP créée et attribuée à l'utilisateur {guac_user} avec succès",
                    "connection_url": connection_url
                }, 201
            else:
                return {
                    "error": "Connexion créée, mais attribution des permissions échouée",
                    "details": permission_response.text
                }, permission_response.status_code
        else:
            return {
                "error": "Échec de la création de la connexion RDP",
                "details": response.json() if response.headers.get("Content-Type") == "application/json" else response.text
            }, response.status_code
    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/guacamole/connexion/ssh', methods=['POST'])
def guacamole_ssh_post():
    try:
        data = request.get_json(force=True)
        args = dict(request.args)
        api_token = args["guacamole_token"]

        if api_token.startswith("Bearer "):
            api_token = api_token.split(" ")[1]

        name = data.get('name')
        hostname = data.get('hostname')
        port = data.get('port', '22')
        ssh_username = data.get('username')
        ssh_password = data.get('password')  # utilisé côté cible, pas pour login guacamole
        guac_user = data.get('guac_user')

        headers = {
            "Guacamole-Token": api_token,
            "Content-Type": "application/json"
        }

        create_connection_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"
        guacd_host = str(config_data.get('GUACD_HOSTNAME', '127.0.0.1'))
        guacd_port = str(config_data.get('GUACD_PORT', '4822'))

        payload = {
            "parentIdentifier": "ROOT",
            "name": name,
            "protocol": "ssh",
            "parameters": {
                "hostname": hostname,
                "port": str(port),
                "username": ssh_username,
                "password": ssh_password
            },
            "attributes": {
                "max-connections": "5",
                "max-connections-per-user": "1",
                "guacd-hostname": guacd_host,
                "guacd-port": guacd_port
            }
        }

        # Créer la connexion
        response = requests.post(create_connection_url, headers=headers, json=payload)
        if response.status_code not in [200, 201]:
            return {
                "error": "Échec de la création de la connexion SSH",
                "details": response.text
            }, response.status_code

        connection_id = response.json().get('identifier')
        if not connection_id:
            return {"error": "Erreur : ID de connexion manquant après la création."}, 500

        # Attribuer la permission READ au user Guacamole
        permissions_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users/{guac_user}/permissions"
        permissions_payload = [
            {
                "op": "add",
                "path": f"/connectionPermissions/{connection_id}",
                "value": "READ"
            }
        ]
        permissions_response = requests.patch(permissions_url, headers=headers, json=permissions_payload)
        if permissions_response.status_code != 204:
            return {
                "error": "Connexion créée, mais attribution des permissions échouée",
                "details": permissions_response.text
            }, 500

        # ✅ URL directe avec token admin (pas de login user avec mot de passe SSH)
        admin_token_for_url = guacamole_service.get_admin_token()
        connection_url = (
            f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/#/client/"
            f"{generate_guac_base64(connection_id)}?token={admin_token_for_url}"
        )

        return {
            "message": f"Connexion SSH créée et attribuée à l'utilisateur {guac_user} avec succès",
            "connection_url": connection_url,
            "connection_id": connection_id
        }, 201

    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/guacamole/connexion/ssh', methods=['PUT'])
def guacamole_ssh_put():
    data = request.get_json(force = True)
    args = dict(request.args)
    token = args["guacamole_token"]

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    name = data.get('name')
    hostname = data.get('hostname')
    port = data.get('port', '22')
    ssh_username = data.get('username')
    ssh_password = data.get('password')
    guac_user = data.get('guac_user')

    headers = {
        "Guacamole-Token": token,
        "Content-Type": "application/json"
    }

    create_connection_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"
    payload = {
        "parentIdentifier": "ROOT",
        "name": name,
        "protocol": "ssh",
        "parameters": {
            "hostname": hostname,
            "port": port,
            "username": ssh_username,
            "password": ssh_password
        },
        "attributes": {
            "max-connections": "5",
            "max-connections-per-user": "1",
            "guacd-hostname": guacd_host,
            "guacd-port": guacd_port
        }
    }

    try:
        response = requests.post(create_connection_url, headers=headers, json=payload)

        if response.status_code in [200, 201]:
            connection_id = response.json().get('identifier')

            if not connection_id:
                return {
                    "error": "La connexion a été créée, mais aucun identifiant n'a été retourné.",
                    "details": response.json()
                }, 500

            permissions_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users/{guac_user}/permissions"
            permissions_payload = [
                {
                    "op": "add",
                    "path": f"/connectionPermissions/{connection_id}",
                    "value": "READ"
                }
            ]
            permissions_response = requests.patch(permissions_url, headers=headers, json=permissions_payload)

            if permissions_response.status_code == 204:
                return {"message": f"Connexion SSH créée et attribuée à l'utilisateur {guac_user} avec succès"}, 201
            else:
                return {
                    "error": "Connexion créée, mais attribution des permissions échouée",
                    "details": permissions_response.text
                }, permissions_response.status_code
        else:
            return {
                "error": "Échec de la création de la connexion SSH",
                "details": response.json() if response.headers.get("Content-Type") == "application/json" else response.text
            }, response.status_code

    except Exception as e:
        return {"error": str(e)}, 500    

@guacamole_bp.route('/guacamole/auth/register', methods=['POST'])
def guacamole_register():
    data = request.get_json(force = True)
    args = dict(request.args)
    token = args["guacamole_token"]

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    username = data.get('username')
    password = data.get('password')

    headers = {"Guacamole-Token": token, "Content-Type": "application/json"}

    create_user_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users"
    user_payload = {
        "username": username,
        "password": password,
        "attributes": {}
    }
    try:
        user_response = requests.post(create_user_url, json=user_payload, headers=headers)
        if user_response.status_code not in [200, 201]:
            return {
                "error": "Impossible de créer l'utilisateur dans Guacamole",
                "details": user_response.text
            }, user_response.status_code

        permissions_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users/{username}/permissions"
        permissions_payload = [
            {
                "op": "add",
                "path": f"/connectionGroupPermissions/{config_data['GUACAMOLE_DEFAULT_GROUP']}",
                "value": "READ"
            }
        ]
        permissions_response = requests.patch(permissions_url, json=permissions_payload, headers=headers)

        if permissions_response.status_code == 204:
            return {"message": f"Utilisateur créé et ajouté au groupe {config_data['GUACAMOLE_DEFAULT_GROUP']} avec succès"}, 201
        else:
            return {
                "error": f"Utilisateur créé, mais échec de l'ajout au groupe {config_data['GUACAMOLE_DEFAULT_GROUP']}",
                "details": permissions_response.text
            }, permissions_response.status_code

    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/guacamole/connexion', methods=['DELETE'])
def guacamole_connexion_delete():
    args = dict(request.args)
    connection_id = args["connection_id"]
    token = args["guacamole_token"]
    
    check_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections/{connection_id}"
    headers = {"Guacamole-Token": token}

    try:
        check_response = requests.get(check_url, headers=headers)
        if check_response.status_code == 404:
            return {"error": f"Connexion avec ID {connection_id} introuvable"}, 404

        delete_url = check_url
        delete_response = requests.delete(delete_url, headers=headers)
        if delete_response.status_code == 204:
            return {"message": f"Connexion {connection_id} supprimée avec succès"}, 200
        else:
            return {
                "error": "Impossible de supprimer la connexion",
                "details": delete_response.text
            }, delete_response.status_code
    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/guacamole/auth/cleanup', methods=['DELETE'])
def guacamole_cleanup():
    GUACAMOLE_URL = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/users"
    DATE_LIMITE = datetime.utcnow() - timedelta(days=config_data['GUACAMOLE_DEFAULT_INNACTIVITY_DAYS'])

    args = dict(request.args)
    token = args["guacamole_token"]

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    headers = {"Guacamole-Token": token}
    try:
        response = requests.get(GUACAMOLE_URL, headers=headers)
        if response.status_code != 200:
            return {
                "error": "Erreur lors de la récupération des utilisateurs",
                "details": response.text
            }, response.status_code

        users = response.json()
        removed_users = []

        for user in users:
            last_active_timestamp = user.get("lastActive")
            if last_active_timestamp is None:
                continue  

            last_active = datetime.utcfromtimestamp(last_active_timestamp / 1000)

            if last_active < DATE_LIMITE:
                user_id = user["username"]
                delete_url = f"{GUACAMOLE_URL}/{user_id}"
                delete_response = requests.delete(delete_url, headers=headers)

                if delete_response.status_code == 204:
                    removed_users.append(user_id)
                else:
                    return {
                        "error": f"Échec de la suppression de l'utilisateur {user_id}",
                        "details": delete_response.text
                    }, delete_response.status_code

        return {
            "message": "Utilisateurs inactifs supprimés avec succès",
            "removed_users": removed_users
        }, 200

    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/guacamole/connexion', methods=['GET'])
def guacamole_connexion_list():
    args = dict(request.args)
    token = args["guacamole_token"]

    list_url = f"{config_data.get('GUACAMOLE_URL', None)}/guacamole/api/session/data/mysql/connections"
    headers = {"Guacamole-Token": token}

    try:
        response = requests.get(list_url, headers=headers)
        if response.status_code == 200:
            connections = response.json()
            formatted_connections = [
                {"id": conn["identifier"], "name": conn["name"], "protocol": conn["protocol"]}
                for conn in connections.values()
            ]
            return {"connections": formatted_connections}, 200
        else:
            return {
                "error": "Impossible de récupérer les connexions",
                "details": response.text
            }, response.status_code
    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/health')
def health():
    """Test de santé de l'API Guacamole"""
    return {"status": "healthy", "service": "guacamole-api"}, 200



# ----- Auth -----
@guacamole_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    success, result = login_backend(username, password)
    status_code = 200 if success else result.get("status_code", 401)
    return jsonify(result), status_code

@guacamole_bp.route("/auth/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization", "")
    success, result = logout_backend(token)
    status_code = 200 if success else result.get("status_code", 401)
    return jsonify(result), status_code

# ----- Group Actions -----
@guacamole_bp.route("/groups/<action>", methods=["POST"])
def group_action(action):
    token = extract_token(request.headers.get("Authorization"))
    if not token:
        return jsonify({"error": "Token manquant"}), 401
    
    data = request.get_json() or {}
    success, err = group_handler.validate_permissions("dummy_user", token, action)
    if not success:
        return jsonify({"error": err}), 403

    result, status_code = group_handler.execute_action(action, data, token)
    return jsonify(result), status_code