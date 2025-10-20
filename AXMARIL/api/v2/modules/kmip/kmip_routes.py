from flask import request, Blueprint, url_for
from flask_cors import CORS
from .kmip_model import KmipModel
from .kmip_schema import KmipKeySchema, KmipStatusSchema, KmipDeleteSchma, KmipRevokeSchema, KmipActivateSchema, KmipFileSchema
from .kmip_service import KmipService
from ...database.db_manager import DBManager
from datetime import datetime, timedelta
from ...utils.helpers import success_response, error_response
import json
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import AttemptsExceeded, InvalidDataException, NotFoundException, SomethingWentWrong, CustomException, InsufficientRight, NameAlreadyExist, KeyMissing, ErrorOccurred, TokenInvalidError

import traceback
from ..secret.secret_service import SecretService
secret_service = SecretService()
kmip_model = KmipModel()
kmip_service = KmipService()
kmip_key_schema = KmipKeySchema()
kmip_status_schema = KmipStatusSchema()
kmip_revoke_schema = KmipRevokeSchema()
kmip_delete_schema = KmipDeleteSchma()
kmip_activate_schema = KmipActivateSchema()
kmip_file_schema = KmipFileSchema()


kmip_bp = Blueprint('v2_kmip', __name__)

@kmip_bp.route('/kmip/status_key', methods=['GET'])
@jwt_validation
def get_status_key(user_data):
    try:
        data = dict(request.args)
        #data["owner_uid"] = user_data["uid"]
        errors = kmip_status_schema.validate(data)
        if errors:
            return error_response(error=errors)
        data["owner_uid"] = user_data["uid"]
        state_value = kmip_service.status_key(data)

        return success_response(message="success", data = state_value, code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))


@kmip_bp.route('/kmip/secret', methods=['POST'])
@jwt_validation
def secret(data_user):
    try:
        #user_id = data_user["uid"]        
        # #data = request.get_json(force = True)
        data = request.form.to_dict()
        if "secret" in data :
            try:
                data["secret"]=  json.loads(data["secret"])
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format for 'secret'")
            
        user_cert = request.files.get("user_cert")
        user_key = request.files.get("user_key")
        
        if user_cert and user_key is not None:
            user_cert_content = user_cert.read()
            user_key_content = user_key.read()
        
            data["user_cert"] = user_cert_content
            data["user_key"] = user_key_content
        
        errors = kmip_file_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        key_document = kmip_service.generate_key(data)

        return success_response(message="Secret created successfully", code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))
    
@kmip_bp.route('/kmip/generate_key_by_certificate', methods=['POST'])  
#@jwt_validation 
def generate_key_by_certificate():
    try:
        data = request.form.to_dict()
        if "secret" in data :
            try:
                data["secret"]=  json.loads(data["secret"])
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format for 'secret'")
        user_cert = request.files.get("user_cert")
        user_key = request.files.get("user_key")
        
        print(f"FILES RECEIVED: {request.files}")
        
        if not user_cert or not user_key:
            raise ValueError("Missing certificates")
        
        user_cert_content = user_cert.read()
        user_key_content = user_key.read()
        
        data["user_cert"] = user_cert_content
        data["user_key"] = user_key_content
        
        print("✅ Fichiers bien chargés, envoi au service...")
        
        errors = kmip_file_schema.validate(data)
        if errors:
            print("###################1")
            return error_response(error=errors)
        
        
        print ("######################2")
        key_documment = kmip_service.generate_key_by_their_certificate(data)
        return success_response(message="Secret created successfully", code=201)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))

    
@kmip_bp.route('/kmip/delete_key', methods=['POST'])
@jwt_validation
def delete_key(user_data):
    try:
        data = request.get_json(force = True)
        errors = kmip_delete_schema.validate(data)
        if errors:
            return error_response(error=errors)
        data["owner_uid"] = user_data["uid"]
        
        result = kmip_service.delete_key(data)
        return success_response(result, code=201)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))


@kmip_bp.route('/kmip/revoke_key', methods=['POST'])
@jwt_validation
def revoke_key(user_data):
    try:
        data = request.get_json(force = True)
        owner_uid = user_data["uid"]
        errors = kmip_revoke_schema.validate(data)
        if errors:
            return error_response(error=errors)
        user_secret = secret_service.find_secrets_user(owner_uid)
        #print(user_secret)
        for secret in user_secret:
            if secret.get("app_type") == "kmip" and secret.get("secret_name") == data.get("secret_name"):
                secret_id = secret.get("secret_id")
            
                data["owner_uid"] = user_data["uid"]
                data["secret_id"] = secret_id

                response_data = secret_service.reveal_secret(user_data['uid'], secret_id)
                #print(response_data)
                keyId = response_data.get("masterKey", {}).get("keyId", None)
                if keyId != None:
                    data["key_id"] = keyId
                    status = kmip_service.status_key(data)
                #use keyId to get the status
                if status == data["reason"]:
                    raise SomethingWentWrong(f"the key is already {status}")
                # response_data["status"] = status
                # data = request.get_json(force = True)
        
                kmip_service.revoke_key(data)
                return success_response(message="key revoked successfully", code=201)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))

@kmip_bp.route('/kmip/activate_key', methods=['POST'])
@jwt_validation
def activate_key(user_data):
    try:
        data = request.get_json(force = True)
        errors = kmip_activate_schema.validate(data)
        if errors:
            return error_response(error=errors)
        data['owner_uid'] = user_data['uid']
        response_data = secret_service.reveal_secret(user_data['uid'], data.get("secret_id"))
        keyId = response_data.get("masterKey", {}).get("keyId", None)
        if keyId != None:
            data["key_id"] = keyId
            status = kmip_service.activate_key(data)
            #use keyId to get the status
            if status == "ACTIVE":
                raise SomethingWentWrong("key already activated")
            # response_data["status"] = the fetched status
        # data = request.get_json(force = True)
        
        kmip_service.activate_key(data)
        return success_response(message="key activated successfully", code=201)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))