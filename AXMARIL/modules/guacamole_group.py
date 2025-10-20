# modules/guacamole_group.py

import os
import json
import requests
import logging
from urllib.parse import quote
from typing import Tuple, List
from flask import Blueprint, request, jsonify

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

GUACAMOLE_API_URL = config_data.get("GUACAMOLE_URL", "http://127.0.0.1:8080").rstrip("/")
DATA_SOURCE = config_data.get("GUACAMOLE_DATASOURCE", "mysql")

# ---------------------------------------------------
# Blueprint (facultatif à exposer)
# ---------------------------------------------------
guacamole_group_bp = Blueprint("guacamole_groups", __name__, url_prefix="/groups")

# ---------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------

def _guac_base_url() -> str:
    """
    Retourne la base Guacamole *avec* /guacamole, quel que soit GUACAMOLE_API_URL.
    Ex:
      - si GUACAMOLE_API_URL = http://IP:8080        -> http://IP:8080/guacamole
      - si GUACAMOLE_API_URL = http://IP:8080/guacamole -> http://IP:8080/guacamole
    """
    base = GUACAMOLE_API_URL.rstrip('/')
    return base if base.endswith('/guacamole') else base + '/guacamole'

def guacamole_api_url(endpoint: str) -> str:
    """
    Construit une URL API valide:
      http(s)://.../guacamole/api/<endpoint>
    """
    base = _guac_base_url()
    endpoint = endpoint if endpoint.startswith('/') else '/' + endpoint
    return f"{base}/api{endpoint}"

def extract_token(header_value: str) -> str | None:
    if not header_value:
        return None
    return header_value[len("Bearer "):] if header_value.startswith("Bearer ") else header_value

# ---------------------------------------------------
# Handler métier groupes
# ---------------------------------------------------
class GuacGroupHandler:
    """Gestion des actions sur les groupes Guacamole"""

    ADMIN_ACTIONS = [
        "create_group", "update_group", "delete_group",
        "assign_permissions", "revoke_permissions"
    ]

    def __init__(self, data_source: str = DATA_SOURCE):
        self.data_source = data_source
        self.actions = {
            "list_groups": self.list_groups,
            "get_group_details": self.get_group_details,
            "create_group": self.create_group,
            "update_group": self.update_group,
            "delete_group": self.delete_group,
            "add_members": self.add_members,           # users → group
            "add_member_groups": self.add_member_groups,  # groups → group
            "assign_permissions": self.assign_permissions,
            "revoke_permissions": self.revoke_permissions,
            # alias simples
            "assign_connections": self.assign_permissions,
            "revoke_connections": self.revoke_permissions,
        }

    # --------------------------
    # Validation permissions
    # --------------------------
    def validate_permissions(self, username: str, token: str, action: str) -> Tuple[bool, str | None]:
        if action in self.ADMIN_ACTIONS:
            user_groups = self.get_user_groups(username, token)
            if "guac-admin" not in user_groups:
                return False, f"Accès refusé : action '{action}' réservée aux administrateurs"
        return True, None

    def get_user_groups(self, username: str, token: str) -> List[str]:
        url = guacamole_api_url(f"/session/data/{self.data_source}/users/{quote(username)}/userGroups")
        headers = {"Guacamole-Token": token}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            return [g.get("identifier") for g in resp.json()]
        return []

    # --------------------------
    # Actions principales
    # --------------------------
    def list_groups(self, data: dict, token: str) -> Tuple[dict, int]:
        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups")
        headers = {"Guacamole-Token": token}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            groups = resp.json()
            return {"groups": groups, "total": len(groups)}, 200
        return {"error": resp.text}, resp.status_code

    def get_group_details(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        if not group_id:
            return {"error": "group_identifier requis"}, 400
        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups/{quote(group_id)}")
        headers = {"Guacamole-Token": token}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            return {"group_details": resp.json()}, 200
        if resp.status_code == 404:
            return {"error": "Groupe non trouvé"}, 404
        return {"error": resp.text}, resp.status_code

    def create_group(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        if not group_id:
            return {"error": "group_identifier requis"}, 400
        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups")
        headers = {"Content-Type": "application/json", "Guacamole-Token": token}
        payload = {"identifier": group_id, "attributes": data.get("attributes", {})}
        resp = requests.post(url, headers=headers, json=payload, timeout=8)
        if resp.status_code in (200, 201):
            return {"message": f"Groupe '{group_id}' créé"}, 201
        return {"error": resp.text}, resp.status_code

    def update_group(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        if not group_id:
            return {"error": "group_identifier requis"}, 400
        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups/{quote(group_id)}")
        headers = {"Content-Type": "application/json", "Guacamole-Token": token}
        payload = {"identifier": group_id, "attributes": data.get("attributes", {})}
        resp = requests.put(url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 204:
            return {"message": f"Groupe '{group_id}' mis à jour"}, 200
        return {"error": resp.text}, resp.status_code

    def delete_group(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        if not group_id:
            return {"error": "group_identifier requis"}, 400
        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups/{quote(group_id)}")
        headers = {"Guacamole-Token": token}
        resp = requests.delete(url, headers=headers, timeout=8)
        if resp.status_code == 204:
            return {"message": f"Groupe '{group_id}' supprimé"}, 200
        if resp.status_code == 404:
            return {"error": "Groupe non trouvé"}, 404
        return {"error": resp.text}, resp.status_code

    # --------------------------
    # Gestion membres et permissions
    # --------------------------
    def patch_group(self, group_id: str, token: str, path_suffix: str, values: list) -> Tuple[dict, int]:
        """
        path_suffix ∈ {"userMembers", "userGroupMembers"}
        PATCH /userGroups/{group}/members
          payload: [{ "op":"add", "path":"/<path_suffix>", "value": <user_or_group> }]
        """
        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups/{quote(group_id)}/members")
        headers = {"Content-Type": "application/json", "Guacamole-Token": token}
        payload = [{"op": "add", "path": f"/{path_suffix}", "value": v} for v in values]
        resp = requests.patch(url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 204:
            return {"message": f"Patch appliqué sur '{group_id}' -> {path_suffix}"}, 200
        return {"error": resp.text}, resp.status_code

    def add_members(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        members = data.get("members", [])
        if not group_id or not members:
            return {"error": "group_identifier et members requis"}, 400
        return self.patch_group(group_id, token, "userMembers", members)

    def add_member_groups(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        groups = data.get("member_groups", [])
        if not group_id or not groups:
            return {"error": "group_identifier et member_groups requis"}, 400
        return self.patch_group(group_id, token, "userGroupMembers", groups)

    def assign_permissions(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        system_permissions = data.get("system_permissions", [])            # ex: ["ADMINISTER"]
        connection_permissions = data.get("connection_permissions", {})   # ex: {"<conn_id>":"READ"}
        if not group_id:
            return {"error": "group_identifier requis"}, 400

        payload = []
        for p in system_permissions:
            payload.append({"op": "add", "path": "/systemPermissions", "value": p})
        for cid, perm in connection_permissions.items():
            payload.append({
                "op": "add",
                "path": "/connectionPermissions",
                "value": {"identifier": cid, "permission": perm}
            })

        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups/{quote(group_id)}/permissions")
        headers = {"Content-Type": "application/json", "Guacamole-Token": token}
        resp = requests.patch(url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 204:
            return {"message": f"Permissions appliquées au groupe '{group_id}'"}, 200
        return {"error": resp.text}, resp.status_code

    def revoke_permissions(self, data: dict, token: str) -> Tuple[dict, int]:
        group_id = data.get("group_identifier")
        system_permissions = data.get("system_permissions", [])
        connection_permissions = data.get("connection_permissions", {})
        if not group_id:
            return {"error": "group_identifier requis"}, 400

        payload = []
        for p in system_permissions:
            payload.append({"op": "remove", "path": "/systemPermissions", "value": p})
        for cid, perm in connection_permissions.items():
            payload.append({
                "op": "remove",
                "path": "/connectionPermissions",
                "value": {"identifier": cid, "permission": perm}
            })

        url = guacamole_api_url(f"/session/data/{self.data_source}/userGroups/{quote(group_id)}/permissions")
        headers = {"Content-Type": "application/json", "Guacamole-Token": token}
        resp = requests.patch(url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 204:
            return {"message": f"Permissions révoquées du groupe '{group_id}'"}, 200
        return {"error": resp.text}, resp.status_code

    # --------------------------
    # Execute action
    # --------------------------
    def execute_action(self, action: str, data: dict, token: str) -> Tuple[dict, int]:
        if action not in self.actions:
            return {"error": f"Action '{action}' non supportée"}, 400
        return self.actions[action](data, token)

# ---------------------------------------------------
# Helpers exposés au niveau module (importés par le service)
# ---------------------------------------------------
def add_user_to_group(admin_token: str, username: str, group: str, data_source: str = DATA_SOURCE) -> Tuple[dict, int]:
    """
    Ajoute un utilisateur à un groupe Guacamole.
    PATCH /session/data/{ds}/userGroups/{group}/members
      [{ "op":"add", "path":"/userMembers", "value":"username" }]
    """
    url = guacamole_api_url(f"/session/data/{data_source}/userGroups/{quote(group)}/members")
    headers = {"Content-Type": "application/json", "Guacamole-Token": admin_token}
    payload = [{"op": "add", "path": "/userMembers", "value": username}]
    r = requests.patch(url, headers=headers, json=payload, timeout=8)
    if r.status_code == 204:
        return {"message": f"{username} ajouté à {group}"}, 200
    return {"error": r.text}, r.status_code

def grant_connection_to_group(admin_token: str, connection_id: str, group: str, permission: str = "READ", data_source: str = DATA_SOURCE) -> Tuple[dict, int]:
    """
    Donne une permission de connexion à un groupe.
    PATCH /session/data/{ds}/userGroups/{group}/permissions
      [{ "op":"add", "path":"/connectionPermissions",
         "value":{"identifier":"<id>", "permission":"READ"} }]
    """
    url = guacamole_api_url(f"/session/data/{data_source}/userGroups/{quote(group)}/permissions")
    headers = {"Content-Type": "application/json", "Guacamole-Token": admin_token}
    payload = [{
        "op": "add",
        "path": "/connectionPermissions",
        "value": {"identifier": connection_id, "permission": permission}
    }]
    r = requests.patch(url, headers=headers, json=payload, timeout=8)
    if r.status_code == 204:
        return {"message": f"Connexion {connection_id} -> {group} ({permission})"}, 200
    return {"error": r.text}, r.status_code

# ---------------------------------------------------
# Instance handler
# ---------------------------------------------------
group_handler = GuacGroupHandler()

# ---------------------------------------------------
# Routes Flask (facultatives à exposer, protéger si besoin)
# ---------------------------------------------------
@guacamole_group_bp.route("/<string:action>", methods=["POST"])
def group_action(action: str):
    token = extract_token(request.headers.get("Authorization"))
    if not token:
        return jsonify({"error": "Token manquant"}), 401

    data = request.get_json() or {}
    ok, err = group_handler.validate_permissions("dummy_user", token, action)
    if not ok:
        return jsonify({"error": err}), 403

    result, status = group_handler.execute_action(action, data, token)
    return jsonify(result), status

@guacamole_group_bp.route("/actions", methods=["GET"])
def list_group_actions():
    return jsonify({"available_actions": list(group_handler.actions.keys())}), 200
