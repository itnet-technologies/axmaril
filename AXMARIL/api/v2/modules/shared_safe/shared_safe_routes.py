from flask import request, Blueprint
from .shared_safe_model import SharedSafeModel
from .shared_safe_schema import (
    SharedSafeSchema,
    # RightSchema,
    AddUsersSchema,
    RightUpdateSchema
    )
from .shared_safe_service import SharedSafeService
from ..secret.secret_schema import SecretUpdateSchema, SecretFileUpdateSchema
from ..kmip.kmip_service import KmipService
# from ..coffre.safe_service import CoffreService
from ...utils.helpers import success_response, error_response, download_ssh_key, pop_kmip_user_key
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import (
    NotFoundException,
    UserAlreadyExist,
    InsufficientRight,
    AttemptsExceeded,
    NameAlreadyExist,
    KeyMissing,
    SomethingWentWrong
    )

shared_safe_schema = SharedSafeSchema()
shared_safe_service = SharedSafeService()
kmip_service = KmipService()
shared_safe_model = SharedSafeModel()
add_safe_user_schema = AddUsersSchema()
rights_schema = RightUpdateSchema()
secret_file_schema = SecretFileUpdateSchema()
secret_schema = SecretUpdateSchema()

shared_safe_bp = Blueprint('v2_shared_safe', __name__)

@shared_safe_bp.route('/shared/safe/create', methods=['POST'])
@jwt_validation
def shared_safe(user_data):
    try:
        data = request.get_json(force=True)
        data['owner_uid'] = user_data['uid']
        # print(data)
        errors = shared_safe_schema.validate(data)
        if errors:
            return error_response(error=errors)
                
        shared_safe_service.create_shared_safe(data)

        return success_response(message="safe shared successfully", code=201)
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e), code=400)
    except SomethingWentWrong as e:
        return error_response(error=str(e), code=400)
    except Exception as e:
        return error_response(error=str(e))

@shared_safe_bp.route('/shared/safe/user/add', methods=['POST'])
@jwt_validation
def add_users_to_shared_safe(user_data):
    try:
        safe_id = request.args.get('safe_id')
        data = request.get_json(force=True)
        
        errors = add_safe_user_schema.validate(data)
        if errors:
            return error_response(error=errors)
                
        shared_safe_service.add_users_to_share(user_data['uid'], safe_id, data)

        return success_response(message="the new user(s) have been successfully added to the shared safe", code=201)
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except UserAlreadyExist as e:
        return error_response(error=str(e), code=400)
    except Exception as e:
        return error_response(error=str(e))

@shared_safe_bp.route('/shared/safe/user/remove', methods=['DELETE'])
@jwt_validation
def remove_user_from_shared_safe(user_data):
    try:
        safe_id = request.args.get('safe_id') 
        receiver_id = request.args.get('receiver_id')
        
        shared_safe_service.remove_safe_user(user_data["uid"], receiver_id, safe_id)
        return success_response(message="user successfully removed")
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e))

@shared_safe_bp.route('/shared/safe/secret/reveal', methods=['GET'])
@jwt_validation
def allowed_access_to_read_secret(user_data):
    try:
        safe_id = request.args.get('safe_id') 
        secret_id = request.args.get('secret_id')
        reveal_key = request.args.get("reveal_key", "false")
        can_upload = request.args.get("can_upload", "false")
        
        response = shared_safe_service.read_secret_access(user_data["uid"], safe_id, secret_id)
        
        if 'masterKey' in response:
            kmip_data = {"key_id" : response["masterKey"]["keyId"], "secret_id":secret_id}
            kmip_state = kmip_service.status_key(kmip_data)
            pop_kmip_user_key(response, status=kmip_state, reveal_key=reveal_key)
        
        if can_upload.lower() == "true":
            return download_ssh_key(response)
        
        return success_response(message="secret successfully revealed", data=response)
        
    except InsufficientRight as e:
        return error_response(error=str(e), code=401) 
    except NotFoundException as e:
        return error_response(error=str(e), code=404)       
    except Exception as e:
        return error_response(error=str(e))

@shared_safe_bp.route('/shared/safe/secret/update', methods=['PUT'])
@jwt_validation
def allowed_access_to_write_secret(user_data):
    try:
        if request.content_type == "application/json":
            data = request.get_json(force=True)
            print(data)

            errors = secret_schema.validate(data)
            if errors:
                return error_response(error=errors)
            
            shared_safe_service.write_secret_access(user_data["uid"], data, None)
            
            return success_response(message="Secret updated successfully")
        else:
            data = dict(request.form)
            data['secret_type'] = "file"
            print(data)

            errors = secret_file_schema.validate(data)
            if errors:
                return error_response(error=errors)

            secret_file = request.files.get('secret_file')
            
            shared_safe_service.write_secret_access(user_data["uid"], data, secret_file)

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

@shared_safe_bp.route('/shared/safe/secret/remove', methods=['DELETE'])
@jwt_validation
def allowed_access_to_remove_secret(user_data):
    try:
        safe_id = request.args.get('safe_id') 
        secret_id = request.args.get('secret_id')
        
        shared_safe_service.delete_secret_access(user_data["uid"], safe_id, secret_id)
        return success_response(message="secret successfully deleted")
    
    except InsufficientRight as e:
        return error_response(error=str(e), code=401) 
    except NotFoundException as e:
        return error_response(error=str(e), code=404)       
    except Exception as e:
        return error_response(error=str(e))
    
@shared_safe_bp.route('/shared/safe/rights/update', methods=['PUT'])
@jwt_validation
def change_user_rights(user_data):
    try:
        safe_id = request.args.get('safe_id') 
        receiver_id = request.args.get('receiver_id')
        # Get receiver rights
        rights = request.get_json(force=True)
        
        errors = rights_schema.validate(rights)
        if errors:
            return error_response(error=errors)
        
        shared_safe_service.update_user_rights(user_data["uid"], receiver_id, safe_id, rights)
        return success_response(message="rights updated successfully")
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e))


# @shared_safe_bp.route('/shared/safes/me', methods=['GET'])
# @jwt_validation
# def get_all_shared_safe_by_me(user_data):
#     try:
#         # Get params of request  
#         params = request.args.to_dict()
#         print(params)
        
#         # per_page is the number of elements per page
#         per_page = int(params.get('per_page', 10))
#         # page is the number of page where you want to get
#         page = int(params.get('page', 1))
        
#         safe_id = request.args.get('safe_id')

#         all_safe_shared = shared_safe_service.find_all_shared_safe_by_me(user_data["uid"], safe_id, page, per_page)
#         return success_response(message="shared list retriveve successfully", data=all_safe_shared)
#     except Exception as e:
#         return error_response(error=str(e))

# @shared_safe_bp.route('/shared/safes/others', methods=['GET'])
# @jwt_validation
# def get_all_shared_safe_by_others(user_data):
#     try:
#         # Get params of request  
#         params = request.args.to_dict()
#         print(params)
        
#         # per_page is the number of elements per page
#         per_page = int(params.get('per_page', 10))
#         # page is the number of page where you want to get
#         page = int(params.get('page', 1))
        
#         safe_id = request.args.get('safe_id')
        
#         if safe_id is not None:
#             shared_safe_content = shared_safe_service.find_shared_safe_content(user_data["uid"], safe_id, page, per_page)
#             return success_response(message="shared safe content retriveve successfully", data=shared_safe_content)
            
#         else:
#             all_safe_shared_with_me = shared_safe_service.find_all_shared_safe_by_others(user_data["uid"], page, per_page)
#             return success_response(message="shared list retriveve successfully", data=all_safe_shared_with_me)
         
#     except NotFoundException as e:
#         return error_response(error=str(e), code=404)       
#     except Exception as e:
#         return error_response(error=str(e))

# "/shared/safes/me": {
#             "get": {
#                 "security": [
#                     {
#                         "bearerAuth": []
#                     }
#                 ],
#                 "parameters": [
#                     {
#                         "name": "safe_id",
#                         "in": "query",
#                         "required": false,
#                         "description": "Put your safe id",
#                         "type": "string"
#                     },
#                     {
#                         "name": "page",
#                         "in": "query",
#                         "required": false,
#                         "description": "page",
#                         "type": "string"
#                     },
#                     {
#                         "name": "per_page",
#                         "in": "query",
#                         "required": false,
#                         "description": "page",
#                         "type": "string"
#                     }
#                 ],
#                 "tags": [
#                     "Shared Safe"
#                 ],
#                 "summary": "Get shared safe details",
#                 "produces": [
#                     "application/json"
#                 ],
#                 "responses": {
#                     "200": {
#                         "description": "OK",
#                         "schema": {
#                             "$ref": ""
#                         }
#                     }
#                 }
#             }
#         },
#         "/shared/safes/others": {
#             "get": {
#                 "security": [
#                     {
#                         "bearerAuth": []
#                     }
#                 ],
#                 "parameters": [
#                     {
#                         "name": "safe_id",
#                         "in": "query",
#                         "required": false,
#                         "description": "Put your safe id",
#                         "type": "string"
#                     },
#                     {
#                         "name": "page",
#                         "in": "query",
#                         "required": false,
#                         "description": "page",
#                         "type": "string"
#                     },
#                     {
#                         "name": "per_page",
#                         "in": "query",
#                         "required": false,
#                         "description": "page",
#                         "type": "string"
#                     }
#                 ],
#                 "tags": [
#                     "Shared Safe"
#                 ],
#                 "summary": "Get shared safe with me",
#                 "produces": [
#                     "application/json"
#                 ],
#                 "responses": {
#                     "200": {
#                         "description": "OK",
#                         "schema": {
#                             "$ref": ""
#                         }
#                     }
#                 }
#             }
#         },