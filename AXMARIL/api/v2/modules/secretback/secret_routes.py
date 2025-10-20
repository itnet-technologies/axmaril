from flask import request, Blueprint, send_file, url_for
from flask_cors import CORS
from .secret_model import SecretModel
from .secret_schema import SecretSchema, SecretCredentialSchema, SecretFileSchema, SecretIdSchema, SecretUpdateSchema, SecretFileUpdateSchema, SecretSshSchema, SecretUpdateSshPassword, SecretKmipSchema, SecretKmipIdSchema,  SecretCertificateSchema, CaCertificateModifySchema, SecretCACsrSchema
from .secret_service import SecretService
from ..coffre.safe_service import CoffreService
from ..application.application_service import ApplicationService
from ...database.db_manager import DBManager
from datetime import datetime, timedelta
from ...utils.helpers import success_response, error_response, download_ssh_key, pop_kmip_user_key
import json
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import AttemptsExceeded, InvalidDataException, NotFoundException, SomethingWentWrong, CustomException, InsufficientRight, NameAlreadyExist, KeyMissing, ErrorOccurred, TokenInvalidError
from ..kmip.kmip_service import KmipService
from ..CA.ca_service import CaService
import traceback
import base64
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.hazmat.primitives import serialization
# from pprint import pprint
from flask import Blueprint, request, jsonify
from .secret_service import SecretService

secret_bp = Blueprint('secret_bp', __name__)
secret_service = SecretService()
secret_model = SecretModel()
secret_schema = SecretSchema()
secret_service = SecretService()
safe_service = CoffreService()
application_service = ApplicationService()
secret_credentials_schema = SecretCredentialSchema()
secret_ssh_schema = SecretSshSchema()
secret_ssh_password_schema = SecretUpdateSshPassword()
secret_kmip_schema = SecretKmipSchema()
secret_update_schema = SecretUpdateSchema()
secret_file_update_schema = SecretFileUpdateSchema()
secret_file_schema = SecretFileSchema()
secret_id_schema = SecretIdSchema()
kmip_service = KmipService()
secret_kmip_id_schema = SecretKmipIdSchema()
secret_certif_schema = SecretCertificateSchema()
ca_service = CaService()
ca_modify_schema = CaCertificateModifySchema()
ca_csr_schema = SecretCACsrSchema()

#secret_bp = Blueprint('v2_secret', __name__)

@secret_bp.route('/secrets', methods=['POST'])
@jwt_validation
def create_secret(user_data):
    try:
        data = request.get_json(force=True)

        # 1) Champs internes issus du JWT (pour Guacamole uniquement)
        data['owner_uid'] = user_data['uid']
        email = user_data.get('mail') or user_data.get('email')
        if email:
            data['owner_email'] = email  # interne, NE DOIT PAS passer au schéma

        # 2) IMPORTANT : retirer les champs internes avant validation du schéma
        _owner_email_internal = data.pop('owner_email', None)

        # 3) Validation schéma (inchangée)
        if data.get('secret_type') == 'credentials':
            errors = secret_credentials_schema.validate(data)
            if errors:
                return error_response(error=errors)
        elif data.get('secret_type') == 'other':
            errors = secret_schema.validate(data)
            if errors:
                return error_response(error=errors)

        # 4) Remettre le champ interne pour le service (après validation)
        if _owner_email_internal:
            data['owner_email'] = _owner_email_internal

        # 5) Création + synchro Guacamole
        created_secret, guac_result = secret_service.create_secret_and_sync_guacamole(data)
        if created_secret is None:
            logger.error(f"Error creating secret or syncing Guacamole: {guac_result}")
            return jsonify({"error": "Error creating secret or syncing Guacamole", "details": guac_result}), 500

        logger.info(f"Secret created and Guacamole sync success: {created_secret.get('secret_name')}")
        return jsonify({
            "secret": created_secret,
            "guacamole": guac_result
        }), 201

    except Exception as e:
        logger.error(f"Exception in create_secret: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@secret_bp.route('/secret/ssh', methods=['POST'])
@jwt_validation
def create_ssh_secret(user_data):
    try:
        data = dict(request.form)
        data["owner_uid"] = user_data["uid"]
        data['secret_type'] = "credentials"
        if 'secret' in data:
            data['secret'] = json.loads(data['secret'])
        errors = secret_ssh_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        ssh_key = request.files.get('ssh_key')
        secret_service.connect_with_ssh_key(data, ssh_key)
        
        # AJOUT : Intégration Guacamole pour SSH
        try:
            from api.v2.modules.guacamole.guacamole_service import GuacamoleService
            guac_service = GuacamoleService()
            data['app_type'] = 'ssh'
            success, result = guac_service.auto_create_connection_from_secret(data, user_data)
            if success:
                logger.info(f"Connexion SSH Guacamole créée: {result.get('connection_id')}")
            else:
                logger.warning(f"Échec intégration Guacamole SSH: {result}")
        except Exception as e:
            logger.error(f"Erreur intégration Guacamole: {e}")
            # On continue même si Guacamole échoue
        
        return success_response(message="Secret ssh created successfully", code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        logger.error(f"Erreur create_ssh_secret: {e}")
        return error_response(error=str(e), code=500)
    
@secret_bp.route('/secret/kmip', methods=['POST'])
@jwt_validation
def create_kmip_secret(user_data):
    try:
        data = dict(request.form)
        data["owner_uid"] = user_data["uid"]
        data['secret_type'] = "credentials"

        if 'secret' in data:
            data['secret'] = json.loads(data['secret'])

        errors = secret_kmip_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        user_cert = request.files.get("user_cert")
        user_key = request.files.get("user_key")

        response = secret_service.create_kmip_secret(data, user_cert, user_key)
        print(response)

        return success_response(message="Secret kmip created successfully", data=response, code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except InvalidDataException as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))
    
@secret_bp.route('/secret/kmip/secret_id', methods=['POST'])
@jwt_validation
def create_kmip_secret_with_id(user_data):
    try:
        #data = dict(request.form)
        data = request.get_json(force=True)
        data["owner_uid"] = user_data["uid"]
        data['secret_type'] = "credentials"

        # if 'secret' in data:
        #     data['secret'] = json.loads(data['secret'])

        errors = secret_kmip_id_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        # user_cert = request.files.get("user_cert")
        # user_key = request.files.get("user_key")

        response = secret_service.create_kmip_secret_by_secret_id(data)
        #print(response)

        return success_response(message="Secret kmip created successfully", data=response, code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except InvalidDataException as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))

@secret_bp.route('/secret/update', methods=['PUT'])
@jwt_validation
def update_secret(user_data):
    try:
        if request.content_type == "application/json":
            data = request.get_json(force=True)
            print(data)

            errors = secret_update_schema.validate(data)
            if errors:
                return error_response(error=errors)
            
            secret_service.update_secret(user_data["uid"], data, None)

            return success_response(message="Secret updated successfully")
        else:
            data = dict(request.form)
            data['secret_type'] = "file"
            print(data)

            errors = secret_file_update_schema.validate(data)
            if errors:
                return error_response(error=errors)

            secret_file = request.files.get('secret_file')

            secret_service.update_secret(user_data["uid"], data, secret_file)

            return success_response(message="Secret File updated successfully")

    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except AttemptsExceeded as e:
        return error_response(error=str(e))
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except KeyMissing as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))

@secret_bp.route('/secret/ssh/changepassword', methods=['PUT'])
@jwt_validation
def update_ssh_password(user_data):
    try:
        secret_id = request.args.get("secret_id")
                
        # data = dict(request.form)
        
        # if "secrets" in data: # and isinstance(secrets["secrets"], list):
        #    data["secrets"] = json.loads(data["secrets"])
        #
        # errors = secret_ssh_password_schema.validate(data)
        # if errors:
        #    return error_response(error=errors)
        #
        #    
        # secret_service.update_ssh_password(user_data["uid"], data)
        #
        # return success_response(message="Secret(s) SSH password(s) updated successfully")
        
        secret_service.update_ssh_password(user_data["uid"], secret_id)

        return success_response(message="Secret SSH password updated successfully")
        
    except SomethingWentWrong as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))

@secret_bp.route('/secret/reveal', methods=['GET'])
@jwt_validation
def reveal_secret(user_data):
    try:
        secret_id = request.args.get("secret_id")
        reveal_key = request.args.get("reveal_key", "false")
        can_upload = request.args.get("can_upload", "false")

        response_data = secret_service.reveal_secret(user_data['uid'], secret_id)
        
        if 'masterKey' in response_data:
            kmip_data = {"key_id" : response_data["masterKey"]["keyId"], "secret_id":secret_id}
            kmip_state = kmip_service.status_key(kmip_data)
            pop_kmip_user_key(response_data, status=kmip_state, reveal_key=reveal_key)
                
        # pprint(response_data)
       
        if can_upload.lower() == "true":
            return download_ssh_key(response_data)
        else:
            return success_response(message="Reveal secret successfully", data=response_data)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except AttemptsExceeded as e:
        return error_response(error=str(e), code=403)
    except CustomException as e:
        return error_response(error=str(e))
    except SomethingWentWrong as e:
        return error_response(error=str(e))
    except ErrorOccurred as e:
        return error_response(error=str(e))
    except KeyMissing as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))

@secret_bp.route('/secrets/all', methods=['GET'])
@jwt_validation
def get_all_secret(user_data):
    try:
        owner_uid = user_data['uid']
        secrets = secret_service.find_secrets_user(owner_uid)
        return success_response(message="Secrets user list", data = secrets)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)

@secret_bp.route('/secret/delete', methods=['DELETE'])
@jwt_validation
def delete_secret(user_data):
    try:
        data = request.get_json(force=True)
        errors = secret_id_schema.validate(data)
        if errors:
            return error_response(error=errors)

        secret_service.delete_secret(user_data['uid'], data['secret_id'])
        return success_response(message="secret deleted successfully")
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except AttemptsExceeded as e:
        return error_response(error=str(e), code=403)
    except SomethingWentWrong as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))


@secret_bp.route('/remote/connect', methods=['POST'])
@jwt_validation
def remote_connect(user_data):
    """
    Provisionne Guacamole à la demande pour un secret donné et renvoie l’URL directe.
    Entrée JSON: { "secret_id": "<ID>" }  (ou { "safe_id": "...", "secret_name": "..." } si tu préfères)
    """
    from api.v2.modules.guacamole.guacamole_service import GuacamoleService
    guac = GuacamoleService()

    try:
        data = request.get_json(force=True) or {}
        secret_id = data.get("secret_id")
        if not secret_id:
            return jsonify({"status": "failed", "message": "secret_id is required"}), 400

        uid = user_data["uid"]
        # 1) Récupère + déchiffre le secret utilisateur (vérifie les droits via ton service existant)
        sec = secret_service.reveal_secret(uid, secret_id)  # ← utilise ta logique d’ACL existante
        # sec doit contenir hostname/port/username/password (car app_type = ssh|rdp "credentials")

        # 2) Détermine le protocole
        app_type = sec.get("app_type") or data.get("app_type")
        if not app_type:
            port = str(sec.get("port") or sec.get("secret", {}).get("port") or "")
            if port == "22":
                app_type = "ssh"
            elif port == "3389":
                app_type = "rdp"
            else:
                return jsonify({"status": "failed", "message": "Cannot infer protocol (ssh/rdp) from secret"}), 400

        # 3) Infos user (email → username Guacamole)
        user_email = user_data.get("email") or user_data.get("mail")
        if not user_email:
            return jsonify({"status": "failed", "message": "No email in JWT to create Guacamole user"}), 400
        guac_username = user_email.split("@")[0]

        # 4) Token admin Guacamole
        admin_token = guac.get_admin_token()

        # 5) Crée/MAJ l’utilisateur Guacamole + ajoute au groupe par défaut
        new_pwd = guac.ensure_guac_user(guac_username, user_email, admin_token)

        # 6) Crée/MAJ la connexion Guacamole (idempotent)
        conn_name = sec.get("name") or sec.get("secret_name") or f"SSH_{uid}"
        secret_info = {
            "name": conn_name,
            "type": app_type,
            "hostname": sec.get("hostname"),
            "port": sec.get("port") or 22,
            "username": sec.get("username"),
            "password": sec.get("password")
        }
        connection_id = guac.ensure_connection(secret_info, uid, user_email, admin_token)

        # 7) Génère l’URL directe avec token admin (évite tout login user avec mdp SSH)
        url = guac.get_connexion_url(connection_id)

        # (optionnel) sauvegarder l’identifier dans le secret pour réutilisation
        try:
            secret_model.update_secret(secret_id, {"guacamole_connection_id": connection_id})
        except Exception:
            pass

        return jsonify({
            "status": "success",
            "connection_id": connection_id,
            "connection_url": url
        }), 200

    except Exception as e:
        return jsonify({"status": "failed", "message": str(e)}), 500

@secret_bp.route('/secret/generate_cert', methods=['POST'])
@jwt_validation
def generate_cert(user_data):
    try:
        if request.content_type.startswith("application/json"):
            data = request.get_json(force=True)
            
        elif request.content_type.startswith("multipart/form-data"):
            data = request.form.to_dict()
            #print(data)
            data['operation_type'] = "create"
            file = request.files.get("csr_file")
            print(file)
            if file:
                filename = secure_filename(file.filename)
                
                if not filename.endswith((".csr", ".pem")):
                    return error_response(error="Invalid file extension. Expected .csr or .pem", code=400)
                csr_content = file.read().decode("utf-8")
                
                try:
                    csr = x509.load_pem_x509_csr(csr_content.encode("utf-8"))
                    data["csr"] = csr_content  # Stocke le CSR valide
                except ValueError:
                    return error_response(error="Invalid file content. Expected a CSR", code=400)
            else:
                return error_response(error="Missing CSR file", code=400)
        else:
            return error_response(error="Unsupported content type", code=415)
        
        if data['operation_type'] == "create":
            
            if "csr" in data:
                errors = ca_csr_schema.validate(data)
                if errors:
                    return error_response(error=errors)
                print("YYYYYYYYYYYYYYYY")
            else:
                errors = secret_certif_schema.validate(data)
                if errors:
                    return error_response(error=errors)
            data["secret_type"] = "credentials"
            data["owner_uid"] = user_data["uid"]
            
            response = secret_service.generate_certificate(data)
            return success_response(message="secret created successfully", data=response, code=201)
        elif data['operation_type'] == "modify":
            errors = ca_modify_schema.validate(data)
            if errors:
                return error_response(error=errors)
             
            data["secret_type"] = "credentials"
            data["owner_uid"] = user_data["uid"]
            old_data = secret_model.find_by_id(data['owner_uid'], data['cert_secret_id'])
            print(old_data)

            new_cert = ca_service.modify_certificate(data)
            print(new_cert)
            new_secret = {
                "cert": new_cert
            }
            new_cert_str = base64.b64encode(new_cert).decode("utf-8")
            old_data['secret'] = new_secret
            secret_service.update_secret(user_data["uid"], old_data, None)
            
            return success_response(message="secret edit successfully", code=201)
        else:
            raise NotFoundException("oparation type not found")
        
        #return success_response(message="secret created successfully", data=response, code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except AttemptsExceeded as e:
        return error_response(error=str(e), code=403)
    except SomethingWentWrong as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))
