from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from .safe_model import CoffreModel
from .safe_schema import CoffreSchema, CoffreUpdateSchema
from .safe_service import CoffreService

import traceback
from ...database.db_manager import DBManager
from datetime import datetime
from ...utils.helpers import success_response, error_response, save_icon_file
import json
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import *

safe_model = CoffreModel()
safe_schema = CoffreSchema()
safe_service = CoffreService()
safe_schema_update = CoffreUpdateSchema()

safe_bp = Blueprint('v2_coffre', __name__)

@safe_bp.route('/secret/safe/create', methods=['POST'])
@jwt_validation
def create_safe(user_data):
  try:
      data = request.get_json(force=True)
      errors = safe_schema.validate(data)
      if errors:
          return error_response(error=errors)

      # C'est pour differencier les coffres creer par l'utilisateur et celui creer par le systeme azumarill
      safe_id = safe_service.create_safe(user_data['uid'], data)

      return success_response(message="Safe created successfully", data={'safe_id': safe_id}, code=201)
  except NotFoundException as e:
      return error_response(error=str(e))
  except NameAlreadyExist as e:
      return error_response(error=str(e))

@safe_bp.route('/secret/safe/delete', methods=['DELETE'])
@jwt_validation
def delete_safe(user_data):
  try:
    data = request.get_json(force=True)
    safe_service.delete_safe(user_data['uid'], data['safe_name'])
    return success_response(message="Safe deleted successfully")
  except NotFoundException as e:
    return error_response(error=str(e), code=404)

@safe_bp.route('/secret/safe/safe_secrets', methods=['GET'])
@jwt_validation
def safe_secret(user_data):
    try:
        args = dict(request.args)
        owner_uid = user_data['uid']
        secrets = safe_service.safe_secret(args, owner_uid)
        return success_response(message="Secrets user list", data = secrets)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)

@safe_bp.route('/secret/safe/update', methods=['PUT'])
@jwt_validation
def update_safe(user_data):
    data = request.get_json(force=True)
    errors = safe_schema_update.validate(data)
    if errors:
        return error_response(error=errors)
    print("###################--VUE--########################")
    try:
        safe_service.update_safe(user_data['uid'], data['safe_id'], data)
        return success_response(message="Safe updated successfully")
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e), code=500)

@safe_bp.route('/secret/safe/all', methods=['GET'])
@jwt_validation
def find_alll_safe(user_data):
  try:
    # Get params of request  
    params = request.args.to_dict()
    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    safe = safe_service.find_all_safe(user_data['uid'], page, per_page)

    return success_response(message="Coffre successfully retrieved", data=safe)
  except Exception as e:
    return error_response(error=str(e))

@safe_bp.route('/secret/user/safe/all', methods=['GET'])
@jwt_validation
def find_alll_safe_user(user_data):
  try:
    # Get params of request  
    params = request.args.to_dict()
    
    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    safe = safe_service.find_all_safe(user_data['uid'], page, per_page)

    return success_response(message="Coffre successfully retrieved", data=safe)
  except Exception as e:
    return error_response(error=str(e))

@safe_bp.route('/secret/safe/<safe_id>', methods=['GET'])
@jwt_validation
def find_safe_by_id(user_data, safe_id):
  try:
    application = safe_service.find_safe_by_id(user_data['uid'], safe_id)
    return success_response(message="safe successfully retrieved", data=application)

  except NotFoundException as e:
    return error_response(error=str(e), code=404)
