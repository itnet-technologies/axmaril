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

secret_bp = Blueprint('v2_secret', __name__)

@secret_bp.route('/secret', methods=['POST'])
@jwt_validation
def create_secret(user_data):
    try:
        if request.content_type == "application/json":
            data = request.get_json(force=True)
            data['owner_uid'] = user_data['uid']
            # print(data)
            
            if data['secret_type'] == 'credentials':
                errors = secret_credentials_schema.validate(data)
                if errors:
                    return error_response(error=errors)
                
            if data['secret_type'] == 'other':
                errors = secret_schema.validate(data)
                if errors:
                    return error_response(error=errors)
            secret_service.create_secret(data, None)

            return success_response(message="Secret created successfully", code=201)

        else:
            data = dict(request.form)
            #data = request.form.to_dict()
            data["owner_uid"] = user_data["uid"]
            # user_cert = request.files.get("user_cert")
            # user_key = request.files.get("user_key")
            data["secret"] = {"nothing": False}
            data['secret_type'] = "file"
            # print(data)
            # if data["app_type"] == "kmip":
            #     if "secret" in data :
            #         try:
            #             data["secret"]=  json.loads(data["secret"])
            #         except json.JSONDecodeError:
            #             raise ValueError("Invalid JSON format for 'secret'")
            # else:
            #     data["secret"] = {"nothing": False}
            #     data['secret_type'] = "file"
                
            # if user_cert and user_key is not None:
            #     user_cert_content = user_cert.read()
            #     user_key_content = user_key.read()
            

            #     data["secret"]["user_cert"]= base64.b64encode(user_cert_content).decode("utf-8")
            #     data["secret"]["user_key"]= base64.b64encode(user_key_content).decode("utf-8")

            errors = secret_file_schema.validate(data)
            if errors:
                return error_response(error=errors)
            
            # print("####################")
            
            secret_file = request.files.get('secret_file')

            response = secret_service.create_secret(data, secret_file)
            
            # print(response)

            if response != None:
                return success_response(message="Secret File created successfully", code=201)  
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))


@secret_bp.route('/secret/ssh', methods=['POST'])
@jwt_validation
def create_ssh_secret(user_data):
    try:
        data = dict(request.form)
        data["owner_uid"] = user_data["uid"]
        data['secret_type'] = "credentials"
        #data['is_blocked'] = False

        if 'secret' in data:
            data['secret'] = json.loads(data['secret'])

        errors = secret_ssh_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        ssh_key = request.files.get('ssh_key')

        secret_service.connect_with_ssh_key(data, ssh_key)

        return success_response(message="Secret ssh created successfully", code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except InvalidDataException as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))

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
