from flask import request, Blueprint
from .shared_model import SharedModel
from .shared_schema import SharedSchema
from .shared_service import SharedService
from ..coffre.safe_service import CoffreService
from ...utils.helpers import success_response, error_response
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import NotFoundException, TokenExpiredError, ErrorOccurred, InsufficientRight


shared_model = SharedModel()
shared_schema = SharedSchema()
shared_service = SharedService()
safe_service = CoffreService()

shared_bp = Blueprint('v2_shared', __name__)

@shared_bp.route('/shared', methods=['POST'])
@jwt_validation
def shared_secret(user_data):
    try:
        data = request.get_json(force=True)
        data['owner_uid'] = user_data['uid']
        data['receiver'] = "default@example.com"
        
        errors = shared_schema.validate(data)
        if errors:
            return error_response(error=errors)
                
        shared_service.shared_secret(data)

        return success_response(message="shared share successfully", code=201)
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e))

@shared_bp.route('/shared/download', methods=['GET'])
def download_shared_secret():
    try:
        shared_token = request.args.get("token")
        
        response = shared_service.download_shared(shared_token)
        
        return response
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except TokenExpiredError as e:
        return error_response(error=str(e))
    except ErrorOccurred as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))

@shared_bp.route('/shared/all', methods=['GET'])
@jwt_validation
def get_all_shared(user_data):
    try:
        all_shared = shared_service.find_all_shared(user_data["uid"])
        return success_response(message="shared share successfully", data=all_shared)
    except Exception as e:
        return error_response(error=str(e))

@shared_bp.route('/shared/cancel', methods=['PUT'])
@jwt_validation
def cancel_shared(user_data):
    try:
        receiver_id = request.args.get("receiver_id")

        shared_service.cancel_shared(receiver_id)
        
        return success_response(message="shared updated successfully")
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e))
