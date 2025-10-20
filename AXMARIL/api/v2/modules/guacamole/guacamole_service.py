# api/v2/modules/guacamole/guacamole_service.py
from builtins import Exception
import os
import time
import requests
import jwt
from bson import ObjectId
from werkzeug.utils import secure_filename
from typing import Optional, Tuple
from urllib.parse import quote
from .guacamole_model import GuacamoleModel

from .guacamole_schema import GuacamoleSchema
from ...database.db_manager import DBManager
from ...utils.helpers import (
    generate_guac_base64,  # si utilisé ailleurs
    error_response, save_icon_file, config_data,
    get_system_safe, generate_ssh_password, reveal_secret
)

from ...utils.custom_exception import (
    ApplicationNotFoundException, InvalidDataException, DatabaseUpdateException
)

# Helpers groupes (dans modules/guacamole_group.py)
from modules.guacamole_group import (
    add_user_to_group
)

import os
import json

# --- Chargement du fichier config.json depuis le dossier /static ---
CONFIG_PATH = "/home/ubuntu/AXMARIL/static/config.json"

if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"❌ Fichier de configuration introuvable : {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

def _cfg(key, default=None):
    """Récupère une valeur depuis les variables d'environnement ou config.json"""
    return os.getenv(key) or config.get(key) or default


# --- Variables Guacamole ---
GUAC_BASE_URL = (_cfg("GUACAMOLE_URL") or "").rstrip("/")
DATASOURCE = _cfg("GUACAMOLE_DATASOURCE", "mysql")
DEFAULT_USER_GROUP = _cfg("GUACAMOLE_DEFAULT_GROUP")
DEFAULT_ADMIN_GROUP = _cfg("GUACAMOLE_ADMIN_GROUP") or _cfg("DEFAULT_ADMIN_GROUP")
ADMIN_USER = _cfg("GUACAMOLE_ADMIN_USERNAME")
ADMIN_PASS = _cfg("GUACAMOLE_ADMIN_PASSWORD")

# --- Logs utiles pour vérifier ---
print("============================================================")
print("CONFIGURATION GUACAMOLE CHARGÉE:")
print(f"  GUAC_BASE_URL      : {GUAC_BASE_URL}")
print(f"  DATASOURCE         : {DATASOURCE}")
print(f"  DEFAULT_USER_GROUP : {DEFAULT_USER_GROUP}")
print(f"  DEFAULT_ADMIN_GROUP: {DEFAULT_ADMIN_GROUP or 'non défini'}")
print(f"  ADMIN_USER         : {'✅ OK' if ADMIN_USER else '❌ MANQUANT'}")
print(f"  ADMIN_PASS         : {'✅ OK' if ADMIN_PASS else '❌ MANQUANT'}")
print("============================================================")

API_PREFIX = f"{GUAC_BASE_URL}/guacamole/api/session/data/{DATASOURCE}"

def _require_guac_config():
    missing = []
    if not GUAC_BASE_URL:
        missing.append("GUACAMOLE_URL")
    if not ADMIN_USER:
        missing.append("GUACAMOLE_ADMIN_USERNAME")
    if not ADMIN_PASS:
        missing.append("GUACAMOLE_ADMIN_PASSWORD")
    if missing:
        error_msg = f"Configuration Guacamole manquante: {', '.join(missing)}"
        print(f"[ERROR] {error_msg}")
        raise RuntimeError(error_msg)
# ---------------------------
# Token admin (cache simple)
# ---------------------------
_guacadmin_token = None
_guacadmin_token_exp = 0


def _admin_headers():
    return {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}


def _user_headers(token: str):
    return {"Guacamole-Token": token, "Content-Type": "application/json"}


def _url(path: str) -> str:
    return f"{API_PREFIX}/{path.lstrip('/')}"


class GuacamoleService:
    def __init__(self):
        self.guacamole_model = GuacamoleModel()
        self.guacamole_schema = GuacamoleSchema()

    # ---------------------------
    # Résolution headers Guacamole
    # ---------------------------
    
    def _get_client_ip(self, data: dict, request=None) -> str:
        """
        Récupère l'IP du client depuis différentes sources possibles
        """
        # Depuis les données passées explicitement
        if data.get("client_ip"):
            return data["client_ip"]
        
        # Depuis l'objet request Flask (si disponible)
        if request:
            # Vérifier les headers proxy
            ip = request.headers.get('X-Forwarded-For')
            if ip:
                return ip.split(',')[0].strip()
            
            ip = request.headers.get('X-Real-IP')
            if ip:
                return ip
            
            # Fallback sur remote_addr
            return request.remote_addr or "unknown_ip"
        
        return "unknown_ip"
    
    
    def _generate_recording_filename(
        self, 
        username: str, 
        hostname: str,
        session_id: str,
        timestamp: str,
        client_ip: str = "unknown_ip"
    ) -> str:
        """
        Génère un nom de fichier d'enregistrement sécurisé et informatif.
        Format: username_clientIP_hostname_timestamp_sessionID
        """
        # Nettoyer le username (email → remplacer @ et .)
        safe_user = username.replace("@", "_at_").replace(".", "_").replace(" ", "_")
        
        # Nettoyer l'IP (remplacer les points)
        safe_ip = client_ip.replace(".", "_").replace(":", "_")
        
        # Nettoyer le hostname
        safe_host = hostname.replace(".", "_").replace(" ", "_").replace("/", "_")
        
        # Format final avec tous les éléments
        return f"{safe_user}_{safe_ip}_{safe_host}_{timestamp}_{session_id}"

    def _resolve_headers(
        self,
        guac_user_creds: Optional[dict] = None,
        guac_token: Optional[str] = None
    ) -> Tuple[dict, bool]:
        """
        Construit les headers Guacamole.
        - Si un token utilisateur est fourni, on l'utilise.
        - Sinon, si des creds utilisateur sont fournis, on récupère un token utilisateur et on l'utilise.
        - Sinon, fallback sur le token admin.
        Retourne: (headers, used_admin)
        """
        if guac_token:
            return _user_headers(guac_token), False

        if guac_user_creds and guac_user_creds.get("username") and guac_user_creds.get("password"):
            utok = self.get_user_token(guac_user_creds)
            if utok:
                return _user_headers(utok), False

        self.get_admin_token()
        return _admin_headers(), True

    # ---------------------------
    # Auth
    # ---------------------------
    def get_user_token(self, guac):
        """Token d’un UTILISATEUR (jamais admin côté navigateur)."""
        url = f"{GUAC_BASE_URL}/guacamole/api/tokens"
        payload = {"username": guac["username"], "password": guac["password"]}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        print("=== DEBUG LOGIN GUAC ===")
        print(f"URL = {url}")
        print(f"USERNAME = '{ADMIN_USER}'")
        print(f"PASSWORD = '{ADMIN_PASS}'")

        r = requests.post(url, data=payload, headers=headers, timeout=8)
        if r.status_code == 200:
            return r.json().get("authToken")
        return None
    
    def get_admin_token(self):
        _require_guac_config()
        """Récupère et met en cache le token admin Guac."""
        global _guacadmin_token, _guacadmin_token_exp
        now = time.time()
        if _guacadmin_token and now < _guacadmin_token_exp - 30:
            return _guacadmin_token

        url = f"{GUAC_BASE_URL}/guacamole/api/tokens"
        payload = {"username": ADMIN_USER, "password": ADMIN_PASS}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        print("=== DEBUG LOGIN GUAC (ADMIN) ===")
        print(f"URL = {url}")
        print(f"USERNAME = '{ADMIN_USER}'")
        print(f"PASSWORD = '{ADMIN_PASS}'")

        r = requests.post(url, data=payload, headers=headers, timeout=8)
        r.raise_for_status()
        data = r.json()
        _guacadmin_token = data["authToken"]
        ttl = data.get("expires", 300)  # fallback 5 min si non renvoyé
        _guacadmin_token_exp = now + (ttl if isinstance(ttl, (int, float)) else 300)
        return _guacadmin_token
 
    # ---------------------------
    # Utilisateurs
    # ---------------------------
   
    def create_user(self, user_dict):
        """
        Idempotent: crée/màj l’utilisateur Guacamole puis l’ajoute au groupe par défaut.
        user_dict attendu: { "username": "...", "password": "...?" }
        """
        self.get_admin_token()
        headers = _admin_headers()

        username = user_dict.get("username")
        if not username:
            return {"error": "username requis"}, 400

        password = user_dict.get("password") or generate_ssh_password()

        # 1) create or update user
        create_url = _url("users")
        payload = {
            "username": username,
            "password": password,
            "attributes": user_dict.get("attributes", {})
        }
        r = requests.post(create_url, json=payload, headers=headers, timeout=8)
        if r.status_code == 409:
            put = requests.put(_url(f"users/{username}"), json=payload, headers=headers, timeout=8)
            if put.status_code not in (200, 204):
                return {"error": put.text}, put.status_code
        elif r.status_code not in (200, 201):
            return {"error": r.text}, r.status_code

        # 2) add to default group (optionnel)
        if DEFAULT_USER_GROUP:
            try:
                self._ensure_default_group()
                add_user_to_group(_guacadmin_token, username, DEFAULT_USER_GROUP, DATASOURCE)
            except Exception:
                # on n'échoue pas la création si l’ajout au groupe rate
                pass

        return {"message": f"Utilisateur {username} OK", "username": username, "password": password}, 201

    # ---------------------------
    # Résolution du secret via reveal_secret
    # ---------------------------
    
    
    def is_in_group(self, username: str, group: str) -> bool:
        """Vérifie si `username` appartient au groupe `group` dans Guacamole."""
        try:
            self.get_admin_token()
            headers = {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}
            # Liste des groupes “effectifs” de l’utilisateur
            url = _url(f"users/{quote(username)}/effectiveGroups")
            r = requests.get(url, headers=headers, timeout=8)
            if r.status_code == 200:
                groups = r.json() or []
                return group in groups
            # fallback (au cas où): tester les membres du groupe
            gurl = _url(f"userGroups/{quote(group)}/memberUsers")
            rg = requests.get(gurl, headers=headers, timeout=8)
            if rg.status_code == 200:
                members = rg.json() or []
                # selon versions de Guacamole: array de strings ou dict {username: {...}}
                if isinstance(members, dict):
                    return username in members.keys()
                return username in members
        except Exception:
            pass
        return False
    def _resolve_secret(self, data, owner_uid: Optional[str] = None):
        """
        Retourne (secret_dict, None) si OK, sinon (None, (status, body)).
        - Accepte 'secret' directement (déjà en clair)
        - Sinon résout via reveal_secret(secret_id) -> déchiffré
        """
        # 0) secret inline (déjà en clair)
        s = data.get("secret")
        if s:
            return s, None

        # 1) secret_id requis
        secret_id = data.get("secret_id")
        if not secret_id:
            return None, (400, {"error": "secret requis: fournir 'secret' ou 'secret_id'"})

        try:
            # ✅ Appel correct avec UN SEUL paramètre (secret_id)
            creds = reveal_secret(secret_id)

            if not creds:
                return None, (404, {"error": f"Secret '{secret_id}' introuvable"})

            hostname = creds.get("hostname")
            username = creds.get("username")
            password = creds.get("password")
            private_key_pem = creds.get("private_key_pem") or creds.get("private_key")
            passphrase = creds.get("passphrase")
            port = creds.get("port", 22)

            resolved = {
                "hostname": hostname,
                "port": port or 22,
                "username": username,
                "password": password,
                "private_key_pem": private_key_pem,
                "passphrase": passphrase,
                # champs optionnels
                "domain": creds.get("domain"),
                "width": creds.get("width"),
                "height": creds.get("height"),
                "color_depth": creds.get("color_depth"),
                "max_connections": creds.get("max_connections", "5"),
                "max_connections_per_user": creds.get("max_connections_per_user", "1"),
                # infos utiles si dispo
                "_secret_name": creds.get("secret_name") or creds.get("name"),
                "_owner_uid": creds.get("owner_uid"),
            }

            missing = [k for k in ("hostname", "username") if not resolved.get(k)]
            if missing:
                return None, (400, {"error": f"Champs manquants dans le secret déchiffré: {', '.join(missing)}"})

            return resolved, None

        except Exception as e:
            return None, (500, {"error": f"Erreur lors de la récupération du secret: {str(e)}"})
   
    def _resolve_secret_and_owner(self, data: dict, _axm_bearer_unused: Optional[str]):
        """
        Retourne (secret_dict, owner_uid, secret_name, err).
        """
        if data.get("secret"):
            s = data["secret"]
            owner_uid = data.get("owner_uid") or s.get("owner_uid")
            secret_name = data.get("secret_name") or s.get("secret_name") or s.get("name")
            return s, owner_uid, secret_name, None

        # ✅ Passer owner_uid à _resolve_secret
        owner_uid_hint = data.get("owner_uid")
        s, err = self._resolve_secret(data, owner_uid=owner_uid_hint)
        if err:
            return None, None, None, err

        owner_uid = owner_uid_hint or s.get("_owner_uid")
        secret_name = data.get("secret_name") or s.get("_secret_name") or f"{s['username']}@{s['hostname']}"

        if not owner_uid:
            return None, None, None, (400, {"error": "owner_uid requis (absent du payload et du secret)"})

        return s, owner_uid, secret_name, None
    # ---------------------------
    # Email depuis JWT / DB + ensure user
    # ---------------------------

    def _extract_email_from_bearer(self, axm_bearer: Optional[str]) -> Optional[str]:
        if not axm_bearer or not axm_bearer.startswith("Bearer "):
            return None
        token = axm_bearer.split(" ", 1)[1].strip()
        try:
            claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            email = claims.get("email")
            if email and isinstance(email, str) and "@" in email:
                return email.lower()
            sub = claims.get("sub")
            # ✅ si sub ressemble à un email
            if sub and isinstance(sub, str) and "@" in sub:
                return sub.lower()
            # ❗ sinon on ne retourne pas ici — on laisse None
        except Exception:
            pass
        return None 
    def _lookup_email_from_db(self, owner_uid: Optional[str]) -> Optional[str]:
        """
        Si l'email n'est pas dans le token, tente de le retrouver en base.
        Essaie plusieurs schémas possibles pour compatibilité.
        """
        if not owner_uid:
            return None
        try:
            db = DBManager()
            candidates = [
                ("users", "uid"),
                ("users", "user_id"),
                ("users", "id"),
                ("users", "_id"),
                ("user", "uid"),
                ("user", "user_id"),
            ]
            for coll_name, field in candidates:
                try:
                    coll = db.get_collection(coll_name) if hasattr(db, "get_collection") else db.db[coll_name]
                except Exception:
                    continue
                doc = coll.find_one({field: owner_uid})
                if doc:
                    email = doc.get("email") or doc.get("mail")
                    if email and isinstance(email, str) and "@" in email:
                        return email.lower()
            return None
        except Exception:
            return None

    def _ensure_default_group(self):
        if not DEFAULT_USER_GROUP:
            return True  # rien à faire s'il n'y a pas de groupe par défaut
        self.get_admin_token()
        headers_admin = {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}
        g = requests.get(_url(f"userGroups/{quote(DEFAULT_USER_GROUP)}"), headers=headers_admin, timeout=8)
        if g.status_code == 200:
            return True
        if g.status_code != 404:
            return False
        payload = {"identifier": DEFAULT_USER_GROUP, "name": DEFAULT_USER_GROUP, "attributes": {}}
        c = requests.post(_url("userGroups"), headers=headers_admin, json=payload, timeout=8)
        return c.status_code in (200, 201, 204)

    
     # Dans guacamole_service.py, remplacer la méthode ensure_user_from_axmaril (lignes ~215-280)
    def ensure_user_from_axmaril(self, axm_bearer: Optional[str], owner_uid_hint: Optional[str] = None):
        """
        Retourne un tuple (payload, status):
        - ({"username": <email_ou_uid>, "created": False, "password": <temp>}, 200) si l'utilisateur existe déjà (mot de passe régénéré)
        - ({"username": <email_ou_uid>, "created": True,  "password": <temp>},   201) si créé maintenant
        - ({"error": "..."} , <status>) en cas d'erreur

        PRIORITÉ:
        1. owner_uid_hint explicite (si fourni)
        2. Email depuis JWT
        3. sub depuis JWT (peut être un UID)
        4. Lookup email en base via owner_uid_hint
        """
        # 1️⃣ Déterminer le username
        username = None
        if owner_uid_hint:
            if "@" in owner_uid_hint:
                username = owner_uid_hint.lower()
            else:
                email_from_db = self._lookup_email_from_db(owner_uid_hint)
                username = email_from_db or owner_uid_hint

        if not username:
            username = self._extract_email_from_bearer(axm_bearer)

        if not username and axm_bearer and isinstance(axm_bearer, str) and axm_bearer.startswith("Bearer "):
            token = axm_bearer.split(" ", 1)[1].strip()
            try:
                claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
                sub_hint = claims.get("sub")
                if sub_hint:
                    if "@" in sub_hint:
                        username = sub_hint.lower()
                    else:
                        email_from_db = self._lookup_email_from_db(sub_hint)
                        username = email_from_db or sub_hint
            except Exception:
                pass

        if not username:
            return {
                "error": "Impossible de déterminer le username Guacamole (aucun email/UID trouvé dans le token ou la base)."
            }, 400

        # 2️⃣ Vérifier ou créer l'utilisateur Guacamole (via token admin)
        self.get_admin_token()
        headers_admin = {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}

        chk = requests.get(_url(f"users/{username}"), headers=headers_admin, timeout=8)

        # ✅ Si l'utilisateur existe déjà → régénérer un mot de passe temporaire
        if chk.status_code == 200:
            temp_pass = generate_ssh_password()
            payload = {"username": username, "password": temp_pass, "attributes": {}}
            update = requests.put(_url(f"users/{username}"), headers=headers_admin, json=payload, timeout=8)

            if update.status_code not in (200, 204):
                return {"error": f"Mise à jour du mot de passe échouée : {update.text}"}, update.status_code

            try:
                self._ensure_default_group()
                add_user_to_group(_guacadmin_token, username, DEFAULT_USER_GROUP, DATASOURCE)
            except Exception:
                pass

            return {
                "username": username,
                "created": False,
                "password": temp_pass,
                "note": "Mot de passe temporaire régénéré pour cet utilisateur"
            }, 200

        # 3️⃣ Si l'utilisateur n'existe pas → le créer
        if chk.status_code not in (404,):
            return {"error": f"Vérification utilisateur Guacamole échouée: {chk.text}"}, 502

        temp_pass = generate_ssh_password()
        payload = {
            "username": username,
            "password": temp_pass,
            "attributes": {
                "disabled": "",
                "expired": "",
                "access-window-start": "",
                "access-window-end": "",
                "valid-from": "",
                "valid-until": ""
            }
        }

        cu = requests.post(_url("users"), headers=headers_admin, json=payload, timeout=8)
        if cu.status_code not in (200, 201, 204):
            return {"error": f"Création utilisateur Guacamole échouée: {cu.text}"}, cu.status_code

        try:
            self._ensure_default_group()
            add_user_to_group(_guacadmin_token, username, DEFAULT_USER_GROUP, DATASOURCE)
        except Exception:
            pass

        return {
            "username": username,
            "created": True,
            "password": temp_pass,
            "note": "Utilisateur Guacamole créé avec un mot de passe temporaire"
        }, 201
 
    # ---------------------------
    # Création des connexions SSH / RDP

    def create_ssh_connexion(
        self, data, axmaril: bool = False, guac_user_creds: Optional[dict] = None,
        guac_token: Optional[str] = None, axm_bearer: Optional[str] = None, request=None
    ):
        """
        Crée une connexion SSH Guacamole avec enregistrement automatique.
        Si data['read_only'] = True, la connexion sera en lecture seule.
        """
        try:
            from datetime import datetime
            import uuid

            s, owner_uid, secret_name, err = self._resolve_secret_and_owner(data, axm_bearer)
            if err: return err

            guac_user = owner_uid
            name = data.get('secret_name') or secret_name

            self.get_admin_token()
            headers_admin = {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}

            chk = requests.get(_url(f"users/{guac_user}"), headers=headers_admin, timeout=8)
            if chk.status_code == 404:
                cu = requests.post(_url("users"), headers=headers_admin,
                                json={"username": guac_user, "password": generate_ssh_password(), "attributes": {}}, timeout=8)
                if cu.status_code not in (200, 201, 204):
                    return 500, {"error": "Création utilisateur échouée", "details": cu.text}

            client_ip = self._get_client_ip(data, request)
            
            hostname = s["hostname"]
            session_id = str(uuid.uuid4())
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            record_filename = self._generate_recording_filename(
                username=guac_user,
                hostname=hostname,
                session_id=session_id,
                timestamp=timestamp,
                client_ip=client_ip
            )

            params = {
                "hostname": hostname,
                "port": str(s.get("port", 22)),
                "username": s["username"],
                **({"private-key": s["private_key_pem"], "passphrase": s.get("passphrase")} if s.get("private_key_pem") else {"password": s["password"]}),
                "recording-path": "/var/lib/guacamole/recordings",
                "recording-name": f"{record_filename}",
                "create-recording-path": "true",
                "typescript-path": "/var/lib/guacamole/recordings",
                "typescript-name": f"{record_filename}",
                "create-typescript-path": "true",
            }
            
            # ✅ AJOUT : Si read_only est True, activer le mode lecture seule
            if data.get("read_only"):
                params["read-only"] = "true"

            payload = {
                "parentIdentifier": "ROOT",
                "name": name,
                "protocol": "ssh",
                "parameters": params,
                "attributes": {
                    "max-connections": "5",
                    "max-connections-per-user": "1"
                }
            }

            headers, used_admin = self._resolve_headers(guac_user_creds, guac_token)
            r = requests.post(_url("connections"), headers=headers, json=payload, timeout=10)
            if r.status_code == 403 and not used_admin:
                self.get_admin_token()
                r = requests.post(_url("connections"), headers=_admin_headers(), json=payload, timeout=10)

            if r.status_code not in (200, 201):
                return 500, {"error": "Échec de la création SSH", "details": r.text}

            connection_id = r.json().get("identifier")
            if not connection_id:
                return 500, {"error": "Connexion sans identifiant"}

            return 201, {
                "connection_id": connection_id,
                "message": f"Connexion SSH créée pour {guac_user}",
                "record_filename": record_filename,
                "secret_name": name,
                "owner_uid": guac_user,
                "client_ip": client_ip,
                "read_only": data.get("read_only", False)  # ✅ Indiquer si c'est en lecture seule
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return 500, {"error": str(e)} 
    # ---------------------------
    # CRÉATION CONNEXION RDP
    # ---------------------------
    def create_rdp_connexion(
        self, data, axmaril: bool = False, guac_user_creds: Optional[dict] = None,
        guac_token: Optional[str] = None, axm_bearer: Optional[str] = None, request=None
    ):
        """
        Crée une connexion RDP Guacamole avec enregistrement automatique.
        Si data['read_only'] = True, la connexion sera en lecture seule.
        """
        try:
            from datetime import datetime
            import uuid

            s, owner_uid, secret_name, err = self._resolve_secret_and_owner(data, axm_bearer)
            if err: return err

            guac_user = owner_uid
            name = data.get('secret_name') or secret_name

            self.get_admin_token()
            headers_admin = {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}

            chk = requests.get(_url(f"users/{guac_user}"), headers=headers_admin, timeout=8)
            if chk.status_code == 404:
                cu = requests.post(_url("users"), headers=headers_admin,
                                json={"username": guac_user, "password": generate_ssh_password(), "attributes": {}}, timeout=8)
                if cu.status_code not in (200, 201, 204):
                    return 500, {"error": "Création utilisateur échouée", "details": cu.text}

            client_ip = self._get_client_ip(data, request)
            
            hostname = s["hostname"]
            session_id = str(uuid.uuid4())
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            record_filename = self._generate_recording_filename(
                username=guac_user,
                hostname=hostname,
                session_id=session_id,
                timestamp=timestamp,
                client_ip=client_ip
            )

            params = {
                "hostname": s["hostname"],
                "port": str(s.get("port", 3389)),
                "username": s.get("username", ""),
                "password": s.get("password", ""),
                "domain": s.get("domain", ""),
                "security": "",
                "ignore-cert": "true",
                "color-depth": "24",
                "width": "1280",
                "height": "720",
                "recording-path": "/var/lib/guacamole/recordings",
                "recording-name": f"{record_filename}",
                "create-recording-path": "true",
                "typescript-path": "/var/lib/guacamole/recordings",
                "typescript-name": f"{record_filename}",
                "create-typescript-path": "true",
            }
            
            # ✅ AJOUT : Si read_only est True, activer le mode lecture seule
            if data.get("read_only"):
                params["read-only"] = "true"

            payload = {
                "parentIdentifier": "ROOT",
                "name": name,
                "protocol": "rdp",
                "parameters": params,
                "attributes": {
                    "max-connections": "5",
                    "max-connections-per-user": "1"
                }
            }

            headers, used_admin = self._resolve_headers(guac_user_creds, guac_token)
            r = requests.post(_url("connections"), headers=headers, json=payload, timeout=10)
            if r.status_code == 403 and not used_admin:
                self.get_admin_token()
                r = requests.post(_url("connections"), headers=_admin_headers(), json=payload, timeout=10)

            if r.status_code not in (200, 201):
                return 500, {"error": "Échec de la création RDP", "details": r.text}

            connection_id = r.json().get("identifier")
            if not connection_id:
                return 500, {"error": "Connexion créée sans identifiant"}

            return 201, {
                "connection_id": connection_id,
                "message": f"Connexion RDP créée pour {guac_user}",
                "record_filename": record_filename,
                "secret_name": name,
                "owner_uid": guac_user,
                "client_ip": client_ip,
                "read_only": data.get("read_only", False)  # ✅ Indiquer si c'est en lecture seule
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return 500, {"error": str(e)}
    # ---------------------------
    # URL client (sans admin)
    # ---------------------------
    def get_connexion_url(self, connexion_id, guac_user_creds=None):
        """
        On ne renvoie JAMAIS d’URL signée avec le token admin.
        """
        if not guac_user_creds:
            return None
        token = self.get_user_token(guac_user_creds)
        if not token:
            return None
        return f"{GUAC_BASE_URL}/guacamole/#/client/{connexion_id}?token={token}"

    # ---------------------------
    # CRUD “application”
    # ---------------------------
    def create_guacamole(self, data, app_icon):
        existing_guacamole = self.guacamole_model.find_by_name(data['app_name'])
        if existing_guacamole['data']:
            raise ApplicationNotFoundException('An application with the same name already exists')

        if app_icon:
            filename = secure_filename(app_icon.filename)
            icon_dir = 'static/app_icons'
            new_filename = f"{str(ObjectId())}_{filename}"
            save_icon_file(icon_dir, app_icon, new_filename)
            icon_path = os.path.join(icon_dir, new_filename)
            data['app_icon_path'] = '/' + icon_path

        self.guacamole_model.create_guacamole(data)

    def update_guacamole(self, app_id, data, app_icon):
        existing_guacamole = self.guacamole_model.find_by_id(app_id)
        if not existing_guacamole:
            raise ApplicationNotFoundException('Application not found')

        if app_icon:
            icon_path = existing_guacamole['app_icon_path'].lstrip('/')
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
        existing_guacamole = self.guacamole_model.find_by_id(app_id)
        if not existing_guacamole:
            raise ApplicationNotFoundException('Application not found')
        return existing_guacamole

    def find_guacamole_by_type(self, app_type):
        existing_guacamole = self.guacamole_model.find_by_type(app_type)
        if not existing_guacamole:
            raise ApplicationNotFoundException('Application not found')
        return existing_guacamole

    def find_guacamole_by_name(self, app_name, page, per_page):
        return self.guacamole_model.find_by_name_with_paginate(app_name, page, per_page)

    def find_all_guacamoles(self, page, per_page):
        return self.guacamole_model.find_all_with_paginate(page, per_page)

    def delete_guacamole(self, app_id):
        existing_guacamole = self.guacamole_model.find_by_id(app_id)
        if not existing_guacamole:
            raise ApplicationNotFoundException('Application not found')
        self.guacamole_model.delete_guacamole(app_id)


    def get_or_create_viewonly_profile(self, connection_id: str):
        """
        Crée ou récupère un sharing profile en lecture seule pour une connexion donnée.
        """
        self.get_admin_token()
        headers = {"Guacamole-Token": _guacadmin_token, "Content-Type": "application/json"}

        list_url = _url("sharingProfiles")
        r = requests.get(list_url, headers=headers, timeout=8)
        if r.status_code == 200:
            profiles = r.json()
            for p in profiles.values():
                if (
                    p.get("primaryConnectionIdentifier") == connection_id
                    and p.get("parameters", {}).get("read-only") == "true"
                ):
                    return p["identifier"]

        payload = {
            "primaryConnectionIdentifier": connection_id,
            "name": f"viewonly_{connection_id}",
            "parameters": {"read-only": "true"},
            "attributes": {},
        }

        create_url = _url("sharingProfiles")
        c = requests.post(create_url, headers=headers, json=payload, timeout=8)
        if c.status_code not in (200, 201):
            raise Exception(f"Erreur création sharing profile : {c.text}")

        new_id = c.json().get("identifier")
        print(f"[SHARING PROFILE] ✅ Créé profil view-only {new_id} pour {connection_id}")
        return new_id

        # ---------------------------
    # Supervision lecture seule (admin)
    # ---------------------------
    def supervise_connection(self, connection_id, admin_user, axm_bearer=None):
        """
        L'admin rejoint une session existante en mode lecture seule FORCÉ.
        Vérifie que l'utilisateur appartient au groupe guac-admin.
        """
        try:
            # 1️⃣ Vérifier que l'utilisateur est bien admin
            if not self.is_in_group(admin_user, DEFAULT_ADMIN_GROUP or "guac-admin"):
                return 403, {"error": f"L'utilisateur {admin_user} n'appartient pas au groupe admin"}

            # 2️⃣ Récupère le token utilisateur admin
            admin_creds = {
                "username": admin_user, 
                "password": ADMIN_PASS  # Utiliser la variable globale déjà définie
            }
            token = self.get_user_token(admin_creds)
            if not token:
                return 401, {"error": "Impossible d'obtenir un token admin Guacamole"}
            sharing_id = self.get_or_create_viewonly_profile(connection_id)
            # 3️⃣ Appelle l'API Guacamole avec readOnly=true FORCÉ
            # ⚠️ IMPORTANT: Le paramètre readOnly est TOUJOURS à true pour les admins
            join_url = f"{API_PREFIX}/sharingProfiles/{sharing_id}/connections/{connection_id}/join"
            headers = {"Guacamole-Token": token, "Content-Type": "application/json"}
            
            print(f"[SUPERVISION] Admin '{admin_user}' rejoint via sharing profile {sharing_id}")

            r = requests.post(join_url, headers=headers, timeout=8)

            if r.status_code not in (200, 201):
                return r.status_code, {
                    "error": f"Échec de la supervision : {r.text}",
                    "details": "Vérifiez que la connexion est active et que l'utilisateur a les permissions nécessaires"
                }

            data = r.json()
            client_identifier = data.get("identifier") or data.get("id") or connection_id

            # 4️⃣ URL finale lecture seule avec token
            url = f"{GUAC_BASE_URL}/guacamole/#/client/{client_identifier}?token={token}"
            
            return 200, {
                "message": "Supervision en lecture seule active (mode admin)",
                "url": url,
                "connection_id": client_identifier,
                "admin_user": admin_user,
                "read_only": True,  # ✅ Toujours True
                "note": "Les administrateurs ne peuvent effectuer aucune action en écriture"
            }

        except Exception as e:
            import traceback
            traceback.print_exc()
            return 500, {"error": f"Erreur lors de la supervision : {str(e)}"}
    # ---------------------------
    # Liste des connexions actives
    # ---------------------------
    def list_active_connections(self):
        """
        Retourne la liste des connexions actives dans Guacamole.
        (nécessite le token admin)
        """
        try:
            self.get_admin_token()
            headers = {
                "Guacamole-Token": _guacadmin_token,
                "Content-Type": "application/json"
            }
            url = f"{API_PREFIX}/activeConnections"
            r = requests.get(url, headers=headers, timeout=8)

            if r.status_code != 200:
                return r.status_code, {"error": "Impossible de récupérer les connexions actives", "details": r.text}

            active = r.json()
            formatted = []

            for item in active:
                formatted.append({
                    "connection_id": item.get("connectionIdentifier"),
                    "connection_name": item.get("connectionName"),
                    "username": item.get("username"),
                    "remote_host": item.get("remoteHost"),
                    "start_date": item.get("startDate"),
                    "active_duration": item.get("activeDuration"),
                    "attributes": item.get("attributes", {})
                })

            return 200, {"count": len(formatted), "items": formatted}

        except Exception as e:
            import traceback
            traceback.print_exc()
            return 500, {"error": str(e)}
