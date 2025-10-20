# Corrections principales pour guacamole_connect.py

import json
import os
import requests
import logging
from typing import Dict, Any, Tuple, Optional
import time
import re
import uuid
import mysql.connector

from modules.guacamole_db import get_db_connection

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Chargement de config.json
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) 
CONFIG_FILE_PATH = os.path.join(BASE_DIR, 'static', 'config.json')

with open(CONFIG_FILE_PATH, 'r') as f:
    config_data = json.load(f)

# Configuration Guacamole - CORRIGÉE
GUACD_HOSTNAME = config_data.get("GUACD_HOSTNAME", "127.0.0.1")
GUACD_PORT = config_data.get("GUACD_PORT", "4822")  # Port guacd, pas le port web
GUACAMOLE_API_URL = config_data.get("GUACAMOLE_URL", "http://62.161.252.154:8080")

REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 1

def guacamole_api_url(endpoint: str) -> str:
    """Construit l'URL de l'API Guacamole - CORRIGÉE"""
    return f"{GUACAMOLE_API_URL}{endpoint}"

def guacamole_client_url(connection_id: str, token: str = None) -> str:
    """Construit l'URL client Guacamole - CORRIGÉE"""
    url = f"{GUACAMOLE_API_URL}/guacamole/#/client/{connection_id}"  # AJOUT de /guacamole
    if token:
        url += f"?token={token}"
    return url

def validate_input_data(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Valide les données d'entrée pour la création de connexion"""
    required_fields = ['name', 'hostname', 'username', 'password', 'guac_user']
    for field in required_fields:
        if not data.get(field):
            return False, f"Le champ '{field}' est requis"
    
    if not re.match(r'^[a-zA-Z0-9_\-\s\.]+$', data.get('name', '')):
        return False, "Nom invalide - caractères autorisés: lettres, chiffres, _, -, espaces, points"
    
    return True, None

def make_api_request(method: str, url: str, headers: Dict[str, str], json_data=None, data=None) -> requests.Response:
    """Effectue une requête API avec retry automatique"""
    for attempt in range(MAX_RETRIES):
        try:
            logger.debug(f"Tentative {attempt + 1} - {method} {url}")
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                data=data,
                timeout=REQUEST_TIMEOUT
            )
            logger.debug(f"Réponse: {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                logger.error(f"Erreur de requête finale : {e}")
                raise
            logger.warning(f"Retry {attempt + 1} après erreur : {e}")
            time.sleep(RETRY_DELAY)
    raise requests.RequestException("Échec de requête après retries")

def assign_connection_permissions(connection_id: str, guac_user: str, token: str, readonly: bool = False) -> Tuple[bool, Optional[str]]:
    """Assigne les permissions de connexion à un utilisateur Guacamole - CORRIGÉE"""
    try:
        headers = {
            "Guacamole-Token": token,
            "Content-Type": "application/json"
        }
        url = guacamole_api_url(f"/api/session/data/mysql/users/{guac_user}/permissions")

        # Permissions de base
        permissions = ["READ"]
        if not readonly:
            permissions.extend(["UPDATE", "DELETE"])

        payload = []
        for perm in permissions:
            payload.append({
                "op": "add",
                "path": f"/connectionPermissions/{connection_id}",
                "value": perm
            })

        logger.info(f"Attribution permissions {permissions} à {guac_user} pour connexion {connection_id}")
        response = make_api_request("PATCH", url, headers, json_data=payload)
        
        if response.status_code == 204:
            logger.info(f"Permissions attribuées avec succès")
            return True, None
        else:
            logger.error(f"Erreur attribution permissions: {response.status_code} - {response.text}")
            return False, response.text
    except Exception as e:
        logger.error(f"Erreur permissions: {e}")
        return False, str(e)

def create_ssh_payload(data: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Crée le payload pour une connexion SSH - CORRIGÉ"""
    name = data['name']
    params = {
        "hostname": data['hostname'],
        "port": str(data.get('port', '22')),
        "username": data['username'],
        "password": data['password'],
        "server-alive-interval": "30",
        "keep-alive": "true",
        "enable-sftp": "true",
        "connection-timeout": "30000",
        "login-success-regex": "[$#>]\\s*$",
        "login-failure-regex": "(Login failed|Permission denied|Authentication failed)",
        "host-key": ""
    }
    
    # Enregistrement SSH
    if data.get("enable_recording", True):
        params.update({
            "recording-path": "/var/lib/guacamole/recordings",
            "recording-name": "${HISTORY_UUID}",
            "create-recording-path": "true"
        })
        
        if data.get("enable_typescript_recording", True):
            params.update({
                "typescript-path": "/var/lib/guacamole/recordings",
                "typescript-name": "${HISTORY_UUID}_${GUAC_DATE}_${GUAC_TIME}.typescript",
                "create-typescript-path": "true"
            })
    
    return {
        "parentIdentifier": "ROOT",
        "name": name,
        "protocol": "ssh",
        "parameters": params,
        "attributes": {
            "max-connections": "5",
            "max-connections-per-user": "2",
            "guacd-hostname": GUACD_HOSTNAME,
            "guacd-port": str(GUACD_PORT),  # Convertir en string
            "guacd-encryption": "none"
        }
    }

def create_rdp_payload(data: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """Crée le payload pour une connexion RDP - CORRIGÉ"""
    name = data['name']
    params = {
        "hostname": data['hostname'],
        "port": str(data.get('port', '3389')),
        "username": data['username'],
        "password": data['password'],
        "domain": data.get('domain', ''),
        "security": "any",
        "disable-auth": "false",
        "ignore-cert": "true",
        "color-depth": str(data.get('color_depth', '24')),
        "width": str(data.get('width', '1280')),
        "height": str(data.get('height', '720')),
        "dpi": "96",
        "resize-method": "display-update",
        "enable-drive": "false",
        "enable-printing": "false",
        "console": "false",
        "initial-program": "",
        "client-name": "",
        "preconnection-id": "",
        "preconnection-blob": ""
    }
    
    # Enregistrement RDP
    if data.get("enable_recording", True):
        params.update({
            "recording-path": "/var/lib/guacamole/recordings",
            "recording-name": "${HISTORY_UUID}",
            "create-recording-path": "true"
        })
    
    return {
        "parentIdentifier": "ROOT",
        "name": name,
        "protocol": "rdp",
        "parameters": params,
        "attributes": {
            "max-connections": "5",
            "max-connections-per-user": "2",
            "guacd-hostname": GUACD_HOSTNAME,
            "guacd-port": str(GUACD_PORT),  # Convertir en string
            "guacd-encryption": "none"
        }
    }

def create_connection(protocol: str, data: Dict[str, Any], token: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Fonction principale pour créer une connexion Guacamole - CORRIGÉE
    """
    try:
        # 1. Validation du protocole
        protocol = protocol.lower()
        if protocol not in ['ssh', 'rdp']:
            return False, {"error": f"Protocole '{protocol}' non supporté. Utilisez 'ssh' ou 'rdp'"}
        
        # 2. Validation des données
        valid, err = validate_input_data(data)
        if not valid:
            return False, {"error": err}
        
        # 3. Génération du payload selon le protocole
        session_id = str(uuid.uuid4())
        
        if protocol == 'ssh':
            payload = create_ssh_payload(data, session_id)
        else:  # rdp
            payload = create_rdp_payload(data, session_id)
        
        logger.info(f"Création connexion {protocol.upper()} '{data['name']}' pour {data.get('guac_user')}")
        logger.debug(f"Payload: {json.dumps(payload, indent=2)}")
        
        # 4. Appel API pour créer la connexion
        headers = {"Guacamole-Token": token, "Content-Type": "application/json"}
        api_url = guacamole_api_url("/api/session/data/mysql/connections")
        
        logger.debug(f"URL API: {api_url}")
        response = make_api_request("POST", api_url, headers, json_data=payload)

        if response.status_code not in [200, 201]:
            logger.error(f"Échec création {protocol}: {response.status_code} - {response.text}")
            return False, {
                "error": f"Création échouée (HTTP {response.status_code})", 
                "details": response.text,
                "url": api_url
            }
        
        # 5. Traitement de la réponse
        try:
            connection_data = response.json()
        except json.JSONDecodeError:
            logger.error(f"Réponse JSON invalide: {response.text}")
            return False, {"error": "Réponse API invalide", "details": response.text}
        
        connection_id_int = connection_data.get('identifier')
        if connection_id_int is None:
            return False, {"error": "ID de connexion non retourné", "response": connection_data}

        # 6. Sauvegarde UUID si la fonction existe
        connection_id_uuid = str(uuid.uuid4())
        try:
            save_connection_uuid(connection_id_int, connection_id_uuid)
        except Exception as e:
            logger.warning(f"Impossible de sauvegarder UUID: {e}")
            # On continue sans UUID pour les tests

        # 7. Attribution des permissions
        success, msg = assign_connection_permissions(str(connection_id_int), data['guac_user'], token)
        if not success: 
            logger.error(f"Erreur permission utilisateur: {msg}")
            return False, {"error": "Permission échouée", "details": msg}
        
        # Permission pour le groupe monitor (optionnel)
        success_monitor, msg_monitor = assign_connection_permissions(str(connection_id_int), 'guac-monitor', token)
        if not success_monitor:
            logger.warning(f"Impossible d'attribuer la permission au groupe guac-monitor : {msg_monitor}")
                                
        # Permission admin readonly si spécifié
        admin_user = data.get('admin_readonly_user')
        if admin_user:
            readonly_success, readonly_msg = assign_connection_permissions(str(connection_id_int), admin_user, token, readonly=True)
            if not readonly_success:
                logger.warning(f"Permission admin échouée: {readonly_msg}")

        logger.info(f"Connexion {protocol.upper()} créée avec succès: ID={connection_id_int}")

        return True, {
            "message": f"Connexion {protocol.upper()} '{data['name']}' créée et attribuée à '{data['guac_user']}'",
            "connection_id": connection_id_uuid if 'save_connection_uuid' in globals() else str(connection_id_int),
            "connection_url": guacamole_client_url(str(connection_id_int)),
            "protocol": protocol,
            "session_id": session_id,
            "guacamole_id": connection_id_int
        }

    except requests.RequestException as e:
        logger.error(f"Erreur API Guacamole: {e}")
        return False, {"error": "Erreur API Guacamole", "details": str(e)}
    except Exception as e:
        logger.error(f"Erreur interne: {e}")
        import traceback
        traceback.print_exc()
        return False, {"error": f"Erreur serveur: {str(e)}"}

def get_supported_protocols() -> Dict[str, Any]:
    """Retourne les protocoles supportés"""
    return {
        "supported_protocols": ["ssh", "rdp"],
        "endpoints": {
            "ssh": "Connexion SSH avec SFTP activé",
            "rdp": "Connexion RDP avec enregistrement"
        }
    }