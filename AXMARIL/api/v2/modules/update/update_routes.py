from flask import request, Blueprint, send_file
from .update_model import BulkModel
from .update_schema import BulkSchema
from .update_service import BulkService
from ...utils.helpers import success_response, error_response
import json
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import SomethingWentWrong


update_model = BulkModel()
update_schema = BulkSchema()
update_service = BulkService()

bulk_bp = Blueprint('v2_bulk', __name__)

@bulk_bp.route('/system/update-message', methods=['POST'])
@jwt_validation
def bulk_email_processing(user_data):
    try:
        data = request.get_json(force=True)
        data['owner_uid'] = user_data['uid']

        print(data)
                
        response = update_service.create_bulk_email(data)
        
        return success_response(message="Successfully", data=response, code=201)
        
    except SomethingWentWrong as e:
        return error_response(error=str(e), code=400)
    except Exception as e:
        return error_response(error=str(e))

@bulk_bp.route('/system/all', methods=['GET'])
@jwt_validation
def get_all_message(user_data):
    try:
        messages = update_service.find_all_bulk(user_data["uid"])
        return success_response(message="List successfully retrieve", data=messages)
    except Exception as e:
        return error_response(error=str(e))