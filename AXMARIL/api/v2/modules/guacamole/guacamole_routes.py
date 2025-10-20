# api/v2/modules/guacamole/guacamole_routes.py
import os
import base64
import traceback
import subprocess
import threading
import shutil
from datetime import datetime, timedelta

import requests
from flask import Blueprint, jsonify, request, send_file, abort
from werkzeug.utils import safe_join
from urllib.parse import quote

from .guacamole_service import GuacamoleService
from ...utils.helpers import config_data

# -------------------------------------------------------------------
# Blueprint & service
# -------------------------------------------------------------------
guacamole_bp = Blueprint('v2_guacamole', __name__)
service = GuacamoleService()

GUAC_BASE = config_data.get("GUACAMOLE_URL", "").rstrip("/")
DATASOURCE = config_data.get("GUACAMOLE_DATASOURCE", "mysql")
RECORD_DIR = "/var/lib/guacamole/recordings"
ALLOWED_EXTS = (".m4v", ".mp4")  # autorise m4v et mp4
CONVERTED_DIR = os.path.join(RECORD_DIR, "converted")


def _admin_headers():
    """Construit un header admin côté serveur (jamais transmis par le client)."""
    token = service.get_admin_token()
    return {"Guacamole-Token": token, "Content-Type": "application/json"}

def _api_url(path: str) -> str:
    return f"{GUAC_BASE}/guacamole/api/session/data/{DATASOURCE}/{path.lstrip('/')}"

def _ensure_record_dir():
    if not os.path.isdir(RECORD_DIR):
        return False
    return True

def _guacenc_path():
    return shutil.which("guacenc")

def _is_safe_basename(name: str) -> bool:
    # évite path traversal et limite aux extensions autorisées
    return (
        bool(name)
        and "/" not in name
        and "\\" not in name
        and name.lower().endswith(ALLOWED_EXTS)
    )

def _ensure_dirs():
    """
    Vérifie / crée RECORD_DIR et CONVERTED_DIR.
    Retourne (ok: bool, error: str|None)
    """
    try:
        if not os.path.isdir(RECORD_DIR):
            return False, f"record dir '{RECORD_DIR}' introuvable"
        if not os.path.isdir(CONVERTED_DIR):
            os.makedirs(CONVERTED_DIR, exist_ok=True)
        return True, None
    except Exception as e:
        return False, str(e)


def _run_guacenc_async(input_path: str, out_format: str = "m4v"):
    """
    Lance guacenc en thread, puis déplace le .m4v/.mp4 généré vers CONVERTED_DIR.
    - input_path peut être un répertoire (enregistrement binaire) ou un .guac (rare).
    - guacenc sort par défaut un fichier <input_path>.<ext> à côté de l'input.
    """
    def _worker():
        try:
            exe = _guacenc_path()
            if not exe:
                print("[guacenc] introuvable dans le PATH")
                return

            ok, err = _ensure_dirs()
            if not ok:
                print(f"[guacenc] {_ensure_dirs.__name__} KO: {err}")
                return

            # Lancer la conversion
            # Exemple: guacenc -f m4v /var/lib/guacamole/recordings/<UUIDdir>
            # Sortie attendue: /var/lib/guacamole/recordings/<UUIDdir>.m4v
            subprocess.run([exe, "-f", out_format, input_path], check=True)

            # Déterminer les chemins potentiels de sortie créés par guacenc
            candidate_out_m4v = input_path + ".m4v"
            candidate_out_mp4 = input_path + ".mp4"

            # Déplacer si présent
            for candidate in (candidate_out_m4v, candidate_out_mp4):
                if os.path.isfile(candidate):
                    base_name = os.path.basename(candidate)
                    dest = os.path.join(CONVERTED_DIR, base_name)
                    try:
                        # overwrite s’il existe déjà
                        if os.path.exists(dest):
                            os.remove(dest)
                        os.replace(candidate, dest)
                        print(f"[guacenc] converti -> {dest}")
                    except Exception as move_err:
                        print(f"[guacenc] déplacement échec {candidate} -> {dest}: {move_err}")

        except subprocess.CalledProcessError as e:
            print(f"[guacenc] échec conversion '{input_path}': returncode {e.returncode}")
        except Exception as e:
            print(f"[guacenc] erreur: {e}")

    threading.Thread(target=_worker, daemon=True).start()
   

def _maybe_convert_guac(entry):
    """
    Si entry est un .guac et que le .m4v n'existe pas encore,
    lance une conversion asynchrone (sans bloquer la réponse).
    """
    name = entry.name
    if not name.lower().endswith(".guac"):
        return
    base = name[:-5]  # retire ".guac"
    m4v = os.path.join(RECORD_DIR, base + ".m4v")
    mp4 = os.path.join(RECORD_DIR, base + ".mp4")
    if not os.path.exists(m4v) and not os.path.exists(mp4):
        # Option: attend que le fichier soit "stable" (par ex. mtime > 10s)
        st = entry.stat()
        age = (datetime.utcnow().timestamp() - st.st_mtime)
        if age > 10:  # on évite de convertir un fichier en cours d’écriture
            _run_guacenc_async(os.path.join(RECORD_DIR, name), out_format="m4v")


def _caller_guac_username():
    axm_bearer = request.headers.get("Authorization")
    ensured = service.ensure_user_from_axmaril(axm_bearer)
    body, status = (ensured, 200) if not isinstance(ensured, tuple) else ensured
    if status >= 400 or body.get("error"):
        return None
    return body["username"]
# -------------------------------------------------------------------
# Auth utilisateur (token utilisateur, jamais admin)
# -------------------------------------------------------------------
@guacamole_bp.route('/guacamole/auth/login', methods=['POST'])
def guacamole_login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return {"error": "username et password requis"}, 400

    url = f"{GUAC_BASE}/guacamole/api/tokens"
    r = requests.post(
        url,
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=8
    )
    if r.status_code == 200:
        j = r.json()
        return {
            "message": "Authentification réussie",
            "authToken": j.get("authToken"),
            "expires_in": j.get("expires") or 86400
        }, 200
    return {"error": "Échec de l'authentification", "details": r.text}, r.status_code

@guacamole_bp.route('/guacamole/auth/logout', methods=['POST'])
def guacamole_logout():
    """Invalidate un token **utilisateur** envoyé en Authorization: Bearer <token>"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    else:
        return {"error": "Authorization Bearer token requis"}, 401

    url = f"{GUAC_BASE}/guacamole/api/tokens"
    r = requests.delete(url, headers={"Authorization": f"Bearer {token}"}, timeout=8)
    if r.status_code == 204:
        return {"message": "Déconnexion réussie"}, 200
    return {"error": "Échec de la déconnexion", "details": r.text}, r.status_code

# -------------------------------------------------------------------
# Enregistrement utilisateur (idempotent) + ajout au groupe défaut
# -------------------------------------------------------------------
@guacamole_bp.route('/guacamole/auth/register', methods=['POST'])
def guacamole_register():
    data = request.get_json(force=True)

    token = request.args.get("guacamole_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
    if not token:
        return {"error": "Guacamole token manquant (query ?guacamole_token= ou Authorization: Bearer)"}, 400

    username = data.get('username')
    password = data.get('password')
    if not username:
        return {"error": "username requis"}, 400

    headers_json = {"Content-Type": "application/json"}
    create_user_url = f"{GUAC_BASE}/guacamole/api/session/data/{DATASOURCE}/users?token={token}"
    user_payload = {
        "username": username,
        "password": password,
        "attributes": {
            "disabled": "", "expired": "",
            "access-window-start": "", "access-window-end": "",
            "valid-from": "", "valid-until": ""
        }
    }
    user_resp = requests.post(create_user_url, json=user_payload, headers=headers_json, timeout=8)
    if user_resp.status_code not in (200, 201, 204):
        return {"error": "Création utilisateur échouée", "details": user_resp.text}, user_resp.status_code

    default_group = config_data.get("GUACAMOLE_DEFAULT_USER_GROUP") or config_data.get("GUACAMOLE_DEFAULT_GROUP")
    if default_group:
        group_members_url = (
            f"{GUAC_BASE}/guacamole/api/session/data/{DATASOURCE}"
            f"/userGroups/{quote(default_group)}/memberUsers?token={token}"
        )
        patch = [{"op": "add", "path": "/", "value": username}]
        headers = {"Content-Type": "application/json"}
        grp_resp = requests.patch(group_members_url, json=patch, headers=headers, timeout=8)
        if grp_resp.status_code not in (200, 204):
            return {"error": "Ajout au groupe échoué", "details": grp_resp.text}, grp_resp.status_code

    return {"message": f"Utilisateur '{username}' créé avec succès"}, 201

# -------------------------------------------------------------------
# Endpoint unifié: créer connexion SSH/RDP et retourner l'URL client
# -------------------------------------------------------------------

# Dans guacamole_routes.py, remplacer la section de /guacamole/connect (lignes ~140-175)

# Dans guacamole_routes.py, remplacer complètement /guacamole/connect

@guacamole_bp.route('/guacamole/connect', methods=['POST'])
def guacamole_connect():
    print("=== [DEBUG] Appel /guacamole/connect ===")
    try:
        data = request.get_json(force=True, silent=True) or {}
        print(f"[DEBUG] Payload reçu : {data}")
        protocol = (data.get("protocol") or "ssh").lower()
        axm_bearer = request.headers.get("Authorization")

        # ✅ AJOUT : Récupération de l'IP cliente et injection dans data
        client_ip = request.headers.get('X-Forwarded-For')
        if client_ip:
            client_ip = client_ip.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr or "unknown_ip"
        
        data["client_ip"] = client_ip  # ✅ Injection de l'IP dans le payload
        print(f"[DEBUG] IP cliente détectée : {client_ip}")

        if protocol not in ("ssh", "rdp"):
            return {"error": "protocol requis: 'ssh' ou 'rdp'"}, 400

        owner_uid_hint = data.get("owner_uid")
        if not owner_uid_hint and axm_bearer and axm_bearer.startswith("Bearer "):
            token = axm_bearer.split(" ", 1)[1].strip()
            try:
                import jwt
                claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
                owner_uid_hint = claims.get("sub") or claims.get("email")
            except Exception:
                pass

        print(f"[DEBUG] ensure_user_from_axmaril avec owner_uid_hint={owner_uid_hint}")
        ensured = service.ensure_user_from_axmaril(axm_bearer, owner_uid_hint)
        ensured_body, ensured_status = (ensured, 200) if not isinstance(ensured, tuple) else ensured
        print(f"[DEBUG] ensured_body={ensured_body}, ensured_status={ensured_status}")

        if ensured_status >= 400 or ensured_body.get("error"):
            return ensured_body, ensured_status

        guac_username = ensured_body["username"]
        guac_password = ensured_body.get("password")
        print(f"[DEBUG] guac_username={guac_username}, guac_password={'***' if guac_password else 'None'}")

        guac_creds = None
        if guac_password:
            guac_creds = {"username": guac_username, "password": guac_password}

        data["owner_uid"] = guac_username
        
        # 🧠 Vérifie si l'utilisateur courant est un admin
        is_admin = service.is_in_group(guac_username, "guac-admin")

        # 👀 Si l'admin supervise une autre session (target_user ≠ lui-même)
        target_user = data.get("target_user")
        if is_admin and target_user and target_user != guac_username:
            print(f"[INFO] 🧩 Supervision activée : {guac_username} supervise {target_user}")
            data["owner_uid"] = target_user
            data["read_only"] = True
            print(f"[SECURITY] 🔒 Mode lecture seule FORCÉ pour la supervision admin")
        
        # ✅ Protection anti-contournement
        if is_admin and target_user and target_user != guac_username:
            if data.get("read_only") is False:
                print(f"[SECURITY] ⚠️ Tentative de contournement détectée !")
                data["read_only"] = True
        
        if data.get("read_only") is True:
            print(f"[INFO] 👀 Mode surveillance : connexion en lecture seule activée")

        print(f"[DEBUG] Appel service.create_{protocol}_connexion() avec IP={client_ip} ...")
        
        # ✅ MODIFICATION : Passer l'objet request à la méthode
        if protocol == "ssh":
            status, res = service.create_ssh_connexion(
                data,
                axmaril=False,
                guac_user_creds=guac_creds,
                guac_token=None,
                axm_bearer=axm_bearer,
                request=request  # ✅ Ajout de l'objet request
            )
        else:
            status, res = service.create_rdp_connexion(
                data,
                axmaril=False,
                guac_user_creds=guac_creds,
                guac_token=None,
                axm_bearer=axm_bearer,
                request=request  # ✅ Ajout de l'objet request
            )

        print(f"[DEBUG] Résultat connexion : status={status}, res={res}")

        if status >= 400:
            return res, status

        out = res if isinstance(res, dict) else {}
        out.setdefault("guacamole_user", guac_username)
        out.setdefault("client_ip", client_ip)  # ✅ Retourner l'IP dans la réponse

        if guac_password:
            out["temporary_password"] = guac_password
            note = ensured_body.get("note") or (
                "Utilisateur Guacamole créé. Utilisez ce mot de passe pour vous connecter."
                if ensured_body.get("created") else
                "Mot de passe temporaire régénéré pour cet utilisateur."
            )
            out["note"] = note

        return out, status

    except Exception as e:
        tb = traceback.format_exc()
        print("\n[ERROR] ===== ERREUR GLOBALE DANS /guacamole/connect =====")
        print(f"Exception : {str(e)}")
        print(tb)
        print("[ERROR] ===============================================\n")
        return {
            "error": "Erreur interne lors de la création de la connexion",
            "exception": str(e),
            "trace": tb
        }, 500


# -------------------------------------------------------------------
# Routes "legacy" maintenues pour compat
# -------------------------------------------------------------------
@guacamole_bp.route('/guacamole/connexion/ssh', methods=['POST'])
def guacamole_ssh_post():
    data = request.get_json(force=True)
    
    # ✅ Récupération de l'IP cliente
    client_ip = request.headers.get('X-Forwarded-For')
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    else:
        client_ip = request.headers.get('X-Real-IP') or request.remote_addr or "unknown_ip"
    
    wrapped = {
        "protocol": "ssh",
        "secret_name": data.get("name"),
        "owner_uid": data.get("guac_user"),
        "client_ip": client_ip,  # ✅ Ajout de l'IP
        "secret": {
            "hostname": data.get("hostname"),
            "port": data.get("port", 22),
            "username": data.get("username"),
            "password": data.get("password")
        },
        "guac_user_creds": {
            "username": data.get("guac_user"),
            "password": data.get("password")
        }
    }
    status, res = service.create_ssh_connexion(
        wrapped, 
        axmaril=False, 
        guac_user_creds=wrapped["guac_user_creds"],
        request=request  # ✅ Passer l'objet request
    )
    return res, status


@guacamole_bp.route('/guacamole/connexion/rdp', methods=['POST'])
def guacamole_rdp_post():
    data = request.get_json(force=True)
    
    # ✅ Récupération de l'IP cliente
    client_ip = request.headers.get('X-Forwarded-For')
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    else:
        client_ip = request.headers.get('X-Real-IP') or request.remote_addr or "unknown_ip"
    
    wrapped = {
        "protocol": "rdp",
        "secret_name": data.get("name"),
        "owner_uid": data.get("guac_user"),
        "client_ip": client_ip,  # ✅ Ajout de l'IP
        "secret": {
            "hostname": data.get("hostname"),
            "port": data.get("port", 3389),
            "username": data.get("username"),
            "password": data.get("password"),
            "domain": data.get("domain", ""),
            "width": data.get("width", "1280"),
            "height": data.get("height", "720"),
            "color_depth": data.get("color_depth", "24")
        },
        "guac_user_creds": {
            "username": data.get("guac_user"),
            "password": data.get("password")
        }
    }
    status, res = service.create_rdp_connexion(
        wrapped, 
        axmaril=False, 
        guac_user_creds=wrapped["guac_user_creds"],
        request=request  # ✅ Passer l'objet request
    )
    return res, status

# -------------------------------------------------------------------
# Liste et suppression des connexions
# -------------------------------------------------------------------
@guacamole_bp.route('/guacamole/connexion', methods=['GET'])
def guacamole_connexion_list():
    try:
        headers = _admin_headers()
        r = requests.get(_api_url("connections"), headers=headers, timeout=10)
        if r.status_code == 200:
            raw = r.json()
            formatted = [
                {"id": v["identifier"], "name": v["name"], "protocol": v["protocol"]}
                for v in raw.values()
            ]
            return {"connections": formatted}, 200
        return {"error": "Impossible de récupérer les connexions", "details": r.text}, r.status_code
    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route('/guacamole/connexion', methods=['DELETE'])
def guacamole_connexion_delete():
    connection_id = request.args.get("connection_id")
    if not connection_id:
        return {"error": "connection_id requis"}, 400
    try:
        headers = _admin_headers()
        chk = requests.get(_api_url(f"connections/{connection_id}"), headers=headers, timeout=8)
        if chk.status_code == 404:
            return {"error": f"Connexion {connection_id} introuvable"}, 404
        d = requests.delete(_api_url(f"connections/{connection_id}"), headers=headers, timeout=8)
        if d.status_code == 204:
            return {"message": f"Connexion {connection_id} supprimée"}, 200
        return {"error": "Suppression échouée", "details": d.text}, d.status_code
    except Exception as e:
        return {"error": str(e)}, 500

# -------------------------------------------------------------------
# Nettoyage utilisateurs inactifs
# -------------------------------------------------------------------
@guacamole_bp.route('/guacamole/auth/cleanup', methods=['DELETE'])
def guacamole_cleanup():
    try:
        days = int(config_data.get('GUACAMOLE_DEFAULT_INNACTIVITY_DAYS', 190))
        date_limite = datetime.utcnow() - timedelta(days=days)

        headers = _admin_headers()
        users_url = _api_url("users")
        r = requests.get(users_url, headers=headers, timeout=10)
        if r.status_code != 200:
            return {"error": "Récupération des utilisateurs échouée", "details": r.text}, r.status_code

        users = r.json()
        removed = []
        for u in users:
            last_active_ts = u.get("lastActive")
            if last_active_ts is None:
                continue
            last_active = datetime.utcfromtimestamp(last_active_ts / 1000.0)
            if last_active < date_limite:
                del_url = _api_url(f"users/{u['username']}")
                d = requests.delete(del_url, headers=headers, timeout=8)
                if d.status_code == 204:
                    removed.append(u['username'])
                else:
                    return {"error": f"Suppression {u['username']} échouée", "details": d.text}, d.status_code

        return {"message": "Nettoyage effectué", "removed_users": list(set(removed))}, 200
    except Exception as e:
        return {"error": str(e)}, 500

# -------------------------------------------------------------------
# Recordings (.m4v/.mp4)
# -------------------------------------------------------------------

@guacamole_bp.route("/guacamole/recordings", methods=["GET"])
def list_recordings():
    user = _caller_guac_username()
    if not user:
        return {"error": "Non autorisé"}, 401
    if not service.is_in_group(user, "guac-admin"):
        return {"error": "Accès réservé aux membres du groupe guac-admin"}, 403

    ok, err = _ensure_dirs()
    if not ok:
        return {"error": err}, 500

    items = []
    try:
        # 🔹 Fusionne les deux dossiers : converted + recordings
        for folder in (CONVERTED_DIR, RECORD_DIR):
            if not os.path.isdir(folder):
                continue
            for entry in os.scandir(folder):
                if not entry.is_file():
                    continue

                name = entry.name.lower()
                st = entry.stat()

                if name.endswith((".m4v", ".mp4")):
                    type_ = "video"
                elif name.endswith((".typescript", ".typescript.timing")):
                    type_ = "raw"
                elif "." not in name:
                    type_ = "session"
                else:
                    continue  # ignore les autres extensions

                items.append({
                    "name": entry.name,
                    "path": folder,
                    "type": type_,
                    "size_bytes": st.st_size,
                    "modified_utc": datetime.utcfromtimestamp(st.st_mtime).isoformat(timespec="seconds") + "Z",
                    "download_url": f"/api/v2/guacamole/recordings/{entry.name}"
                })

        items.sort(key=lambda x: x["modified_utc"], reverse=True)
        return {"count": len(items), "items": items}, 200

    except PermissionError:
        return {"error": "Permission refusée pour lire le répertoire des enregistrements."}, 403
    except Exception as e:
        return {"error": str(e)}, 500


@guacamole_bp.route("/guacamole/recordings/download/<path:name>", methods=["GET"])
def download_recording(name):
    """
    Télécharge une vidéo convertie (.m4v/.mp4) depuis CONVERTED_DIR.
    """
    user = _caller_guac_username()
    if not user:
        return {"error": "Non autorisé"}, 401
    if not service.is_in_group(user, "guac-admin"):
        return {"error": "Accès réservé aux membres du groupe guac-admin"}, 403

    ok, err = _ensure_dirs()
    if not ok:
        return {"error": err}, 500

    if not _is_safe_basename(name):
        abort(404)

    fullpath = safe_join(CONVERTED_DIR, name)
    if not fullpath or not os.path.isfile(fullpath):
        abort(404)

    try:
        return send_file(fullpath, as_attachment=True)
    except PermissionError:
        return {"error": "Permission refusée pour lire ce fichier."}, 403
    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route("/guacamole/recordings/convertibles", methods=["GET"])
def list_convertibles():
    user = _caller_guac_username()
    if not user:
        return {"error": "Non autorisé"}, 401
    if not service.is_in_group(user, "guac-admin"):
        return {"error": "Accès réservé aux membres du groupe guac-admin"}, 403

    if not _ensure_record_dir():
        return {"count": 0, "items": []}, 200

    items = []
    try:
        # Index de ce qui existe pour vérifier les couples base + .m4v/.mp4
        existing = set(e.name for e in os.scandir(RECORD_DIR) if e.is_file())

        for entry in os.scandir(RECORD_DIR):
            if not entry.is_file():
                continue
            name = entry.name

            # On ignore d’office ce qui N’EST PAS convertissable
            if name.endswith(".typescript") or name.endswith(".typescript.timing"):
                continue
            if name.endswith(".m4v") or name.endswith(".mp4"):
                continue

            # Cas 1: vrai .guac
            if name.endswith(".guac"):
                base = name[:-5]
            else:
                # Cas 2: fichier SANS extension (UUID) => c’est un stream Guacamole brut
                if "." in name:
                    # il a une extension inconnue -> pas un stream guac
                    continue
                base = name  # pas d'extension, donc c'est un stream convertissable

            # Déjà converti ?
            already = (base + ".m4v" in existing) or (base + ".mp4" in existing)
            if already:
                continue

            st = entry.stat()
            items.append({
                "name": name,                # source convertissable
                "base": base,                # base sans extension
                "size_bytes": st.st_size,
                "modified_utc": datetime.utcfromtimestamp(st.st_mtime).isoformat(timespec="seconds") + "Z",
                "convert_target": base + ".m4v"
            })

        items.sort(key=lambda x: x["modified_utc"], reverse=True)
        return {"count": len(items), "items": items}, 200

    except PermissionError:
        return {"error": "Permission refusée pour lire le répertoire des enregistrements."}, 403
    except Exception as e:
        return {"error": str(e)}, 500

@guacamole_bp.route("/guacamole/recordings/convert/<path:basename>", methods=["POST"])
def force_convert_recording(basename):
    user = _caller_guac_username()
    if not user:
        return {"error": "Non autorisé"}, 401
    if not service.is_in_group(user, "guac-admin"):
        return {"error": "Accès réservé aux membres du groupe guac-admin"}, 403

    if not _ensure_record_dir():
        return {"error": "recordings introuvable"}, 404

    # Interdit: typescript
    if basename.endswith(".typescript") or basename.endswith(".typescript.timing"):
        return {"error": "Ce type d'enregistrement (typescript) n'est pas convertible via guacenc."}, 400

    # Normalisation: accepte "UUID" ou "UUID.guac"
    if basename.endswith(".guac"):
        base = basename[:-5]
    else:
        base = basename

    # Candidat 1: fichier sans extension
    raw_path = safe_join(RECORD_DIR, base)
    # Candidat 2: fichier .guac
    guac_path = safe_join(RECORD_DIR, base + ".guac")

    src = None
    if raw_path and os.path.isfile(raw_path):
        src = raw_path
    elif guac_path and os.path.isfile(guac_path):
        src = guac_path
    else:
        return {"error": "Flux Guacamole introuvable (ni sans extension, ni .guac)"}, 404

    # Si déjà converti, on évite un doublon
    if os.path.isfile(safe_join(RECORD_DIR, base + ".m4v")) or os.path.isfile(safe_join(RECORD_DIR, base + ".mp4")):
        return {"message": "Déjà converti", "target": base + ".m4v"}, 200

    # Lance guacenc en asynchrone
    _run_guacenc_async(src, out_format="m4v")
    return {"message": "Conversion lancée", "source": os.path.basename(src), "target": base + ".m4v"}, 202

@guacamole_bp.route("/guacamole/supervise/<connection_id>", methods=["POST"])
def guacamole_supervise(connection_id):
    """
    Permet à un admin de rejoindre une session active en LECTURE SEULE uniquement.
    """
    try:
        axm_bearer = request.headers.get("Authorization")
        ensured = service.ensure_user_from_axmaril(axm_bearer)
        body, status = (ensured, 200) if not isinstance(ensured, tuple) else ensured

        if status >= 400 or body.get("error"):
            return body, status

        admin_user = body["username"]
        
        # ✅ Vérification du groupe admin
        if not service.is_in_group(admin_user, "guac-admin"):
            print(f"[SECURITY] ⚠️ Tentative d'accès non autorisée par '{admin_user}'")
            return {"error": "Accès refusé : réservé aux administrateurs du groupe guac-admin"}, 403

        print(f"[SUPERVISION] 🔒 {admin_user} demande la supervision de la connexion {connection_id}")
        
        code, res = service.supervise_connection(connection_id, admin_user, axm_bearer)
        return res, code

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}, 500


@guacamole_bp.route("/guacamole/active", methods=["GET"])
def guacamole_active_connections():
    """
    Retourne la liste des connexions Guacamole actuellement actives.
    Accessible uniquement aux membres du groupe guac-admin.
    """
    try:
        axm_bearer = request.headers.get("Authorization")
        ensured = service.ensure_user_from_axmaril(axm_bearer)
        body, status = (ensured, 200) if not isinstance(ensured, tuple) else ensured

        if status >= 400 or body.get("error"):
            return body, status

        admin_user = body["username"]
        if not service.is_in_group(admin_user, "guac-admin"):
            return {"error": "Accès refusé : réservé aux administrateurs"}, 403

        print(f"[INFO] 🔍 {admin_user} consulte les connexions actives...")
        code, res = service.list_active_connections()
        return res, code

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}, 500


# -------------------------------------------------------------------
# Utilitaire
# -------------------------------------------------------------------
def generate_guac_base64(identifier: str, auth_provider: str = "mysql") -> str:
    raw = f"{identifier}\0c\0{auth_provider}"
    return base64.b64encode(raw.encode('utf-8')).decode('utf-8')
