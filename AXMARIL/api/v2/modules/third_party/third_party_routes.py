from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from .third_party_model import ThirdPartyModel
from .third_party_schema import ThirdPartySchema, ThirdPartySchemaUpdate, ThirdPartySearchSchema
from .third_party_service import ThirdPartyService
from ...database.db_manager import DBManager
from datetime import datetime
from ...utils.helpers import success_response, error_response, save_icon_file
import json
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, InvalidDataException, DatabaseUpdateException
from ...utils.middleware import jwt_validation

third_party_model = ThirdPartyModel()
third_party_schema = ThirdPartySchema()
third_party_schema_update = ThirdPartySchemaUpdate()
third_party_schema_search = ThirdPartySearchSchema()
third_party_service = ThirdPartyService()

third_party_bp = Blueprint('third_party', __name__)


@third_party_bp.route('/thirdparty', methods=['POST'])
@jwt_validation
def create_third_party_by_admin(user_data):
  try:
      data = request.get_json(force=True)

      errors = third_party_schema.validate(data)
      if errors:
          return error_response(error=errors)

      third_party_service.create_third_party(data)
      return success_response(message="Third party created successfully", code=201)
  except NameAlreadyExist as e:
      return error_response(error=str(e), code=404)

@third_party_bp.route('/thirdparty/<third_id>', methods=['PUT'])
def update_third_party(third_id):
    data = request.get_json(force=True)
    errors = third_party_schema_update.validate(data)
    if errors:
        return error_response(error=errors)
    try:
        third_party_service.update_third_party(third_id, data)
        return success_response(message="Third party updated successfully")
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e), code=500)

@third_party_bp.route('/thirdparty/<third_id>', methods=['GET'])
def find_third_party_by_id(third_id):
  try:
    thirdparty = third_party_service.find_third_party_by_id(third_id)
    return success_response(message="Third party successfully retrieved", data=thirdparty)

  except NotFoundException as e:
    return error_response(error=str(e), code=404)

@third_party_bp.route('/thirdparties/search', methods=['GET'])
def find_third_party_by_name():
  try:
    # Get params of request
    params = request.args.to_dict()
    
    # Toujours valider la data renvoyé
    errors = third_party_schema_search.validate(params)
    if errors:
        return error_response(error=errors)

    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    name = params.get('name')
    apps = third_party_service.find_third_party_by_name(name, page, per_page)

    return success_response(message="Third parties successfully retrieved", data=apps)
  except Exception as e:
    return error_response(error=str(e))

@third_party_bp.route('/thirdparties', methods=['GET'])
def find_all_third_parties():
  try:
    # Get params of request
    params = request.args.to_dict()
    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    third_parties = third_party_service.find_all_third_parties(page, per_page)
    return success_response(message="Third party successfully retrieved", data=third_parties)
  except Exception as e:
    return error_response(error=str(e))

@third_party_bp.route('/thirdparty/<string:third_id>', methods=['DELETE'])
def delete_third_party(third_id):
  try:
    third_party_service.delete_third_party(third_id)
    return success_response(message="Third party deleted successfully")
  except NotFoundException as e:
    return error_response(error=str(e), code=404)