from flask import request, Blueprint, url_for
from flask_cors import CORS
from ...database.db_manager import DBManager
from datetime import datetime, timedelta
from ...utils.helpers import success_response, error_response, reveal_secret
import json
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import AttemptsExceeded, InvalidDataException, NotFoundException, SomethingWentWrong, CustomException, InsufficientRight, NameAlreadyExist, KeyMissing, ErrorOccurred, TokenInvalidError
from .ca_service import CaService
from .ca_schema import CaCertificateModifySchema, CaRevokeSchema, CaSignSchema, CaprivatekeySchema, CaFindKeySckhema
from ..secret.secret_service import SecretService
import traceback
import base64
from cryptography import x509
from pprint import pprint

ca_service = CaService()
modify_certificate_schema = CaCertificateModifySchema()
secret_service = SecretService()
ca_revoke_schema = CaRevokeSchema()
ca_sign_schema = CaSignSchema()
ca_private_key_schema = CaprivatekeySchema()
ca_find_schema = CaFindKeySckhema()

ca_bp = Blueprint('v2_ca', __name__)

@ca_bp.route('/ca/modify_certificate', methods=['POST'])
@jwt_validation
def modify_certificate(user_data):
    try:
        data = request.get_json(force = True)
        errors = modify_certificate_schema.validate(data)
        if errors:
            return error_response(error=errors)
        data["owner_uid"] = user_data["uid"]
        reponse_key = reveal_secret(data['key_secret_id'])
        reponse_cert = reveal_secret(data['cert_secret_id'])
        print(reponse_cert)
        key = base64.b64decode(reponse_key['ca_key'])
        #print(key)
        cert = base64.b64decode(reponse_cert['ca_cert'])
        
        #print(cert)
        print("@@@@@@@@@@@@@@@@@@@")
        new_cert = ca_service.modify_certificate(cert, key, data)
        print(new_cert)
        new_cert_str = base64.b64encode(new_cert).decode("utf-8")
        new_secret = {
            "secret_id": data['cert_secret_id'],
            "secret_name": data['secret_name'],
            "safe_id": data['safe_id'],
            "secret_type": "credentials",
            "secret":{
                "ca_cert": new_cert_str
            }
        }
        secret_service.update_secret(user_data["uid"], new_secret, None)
        
        return success_response(message="Secret updated successfully", code=201)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))
    
@ca_bp.route('/ca/revoke_certificate', methods=['POST'])
@jwt_validation
def revoke_certificate(user_data):
    try:
        data = request.get_json(force = True)
        errors = ca_revoke_schema.validate(data)
        if errors:
            return error_response(error=errors)
        user_reason = data.get("reason", "unspecified")
        
        reponse_cert = reveal_secret(data['secret_id'])
        response_ca_key = reveal_secret(data['root_ca_key_id'])
        response_ca_cert = reveal_secret(data['root_ca_cert_id'])
        
        if user_reason not in x509.ReasonFlags.__members__:
            raise ValueError(" reason not valid ")
        
        
        cert = base64.b64decode(reponse_cert['cert'])
        
        reason_flag = getattr(x509.ReasonFlags, user_reason )
        ca_cert= base64.b64decode(response_ca_cert['cert'])
        ca_key= base64.b64decode(response_ca_key['key'])
        ca_service.revoke_certificate(cert, ca_cert, ca_key ,)
        return success_response(message="Secret revoked successfully", code=201)

    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))
    
@ca_bp.route('/ca/sign_certificate', methods=['POST'])
@jwt_validation
def sign_certificate(user_data):
    try:
        data = request.get_json(force = True)
        errors = ca_sign_schema.validate(data)
        if errors:
            return error_response(error=errors)
        reponse_cert = reveal_secret(data['secret_id_cert'])
        cert = base64.b64decode(reponse_cert['ca_cert'])
        
        response_ca = reveal_secret(data['secret_id_ca'])
        ca = base64.b64decode(response_ca['ca_key'])
        
        ca_service.sign_certificate(cert, ca)
        return success_response(message="Sign certificate successfully", code=201)

    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))
    
@ca_bp.route('/ca/all_key', methods=['GET'])
@jwt_validation
def all_key(user_data):
    try:
        data = dict(request.args)
        errors = ca_find_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        data["owner_uid"] = user_data["uid"]
        all_key = ca_service.all_key(data)
        return success_response(message="all key", data=all_key)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))
    
@ca_bp.route('/ca/all_cert', methods=['GET'])
@jwt_validation
def all_cert(user_data):
    try:
        data = dict(request.args)
        errors = ca_find_schema.validate(data)
        if errors:
            return error_response(error=errors)
        
        data["owner_uid"] = user_data["uid"]
        all_cert = ca_service.all_cert(data)
        return success_response(message="all cert", data=all_cert)
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        print(traceback.format_exc())
        return error_response(error=str(e))