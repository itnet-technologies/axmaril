from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from .third_party_account_model import ThirdPartyAccountModel
from .third_party_account_schema import *
# from .third_party_account_schema import ThirdPartyAccountSchema, ThirdPartyAccountSchemaUpdate, ThirdPartyAccountSearchSchema, CyberArkCheck
from .third_party_account_service import ThirdPartyAccountService
from ...database.db_manager import DBManager
from datetime import datetime
from ...utils.helpers import success_response, error_response, save_icon_file
import json
from ...utils.custom_exception import ThirdPartyAccountNotExist, NameAlreadyExist, NotFoundException, KeyMissing, InsufficientRight, AttemptsExceeded, CustomException, SomethingWentWrong
from ...utils.middleware import jwt_validation

third_party_account_model = ThirdPartyAccountModel()
third_party_account_schema = ThirdPartyAccountSchema()
third_party_schema_update = ThirdPartyAccountSchemaUpdate()
third_party_schema_search = ThirdPartyAccountSearchSchema()
third_party_account_service = ThirdPartyAccountService()
import_safe_from_cyberark_schema = ImportSafeFromCyberArk()
import_secret_from_cyberark_schema = ImportSecretFromCyberArk()
cyberark_schema = CyberArkCheck()
synchronization_schema = Synchronization()

third_party_account_bp = Blueprint('third_party_account', __name__)


@third_party_account_bp.route('/thirdparty/account', methods=['POST'])
@jwt_validation
def create_third_party_account(user_data):
  try:
      data = request.get_json(force=True)
      errors = third_party_account_schema.validate(data)
      if errors:
          return error_response(error=errors)

      third_party_account_service.create_third_party_account(user_data['uid'], data)
      return success_response(message="Third party account created successfully", code=201)
  except NameAlreadyExist as e:
      return error_response(error=str(e), code=400)
  except KeyMissing:
    return error_response(error=str(e), code=400)
  except Exception:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account/update', methods=['PUT'])
@jwt_validation
def update_third_party_account(user_data):
  try:
      data = request.get_json(force=True)
      errors = third_party_schema_update.validate(data)
      if errors:
          return error_response(error=errors)

      third_party_account_service.update_third_party_account(user_data['uid'], data)
      return success_response(message="Third party account updated successfully", code=201)
  except ThirdPartyAccountNotExist as e:
      return error_response(error=str(e), code=400)
  except KeyMissing:
    return error_response(error=str(e), code=400)
  except Exception:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account/all', methods=['GET'])
@jwt_validation
def find_all_third_party_account(user_data):
  try:
      all = third_party_account_service.find_all_third_party_account(user_data['uid'])
      return success_response(data = all, code=201)
  except Exception as e:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account', methods=['GET'])
@jwt_validation
def find_third_party_account_by_id(user_data):
  try:
      data = dict(request.args)
      element= third_party_account_service.find_third_party_account_by_id(user_data['uid'], data['account_id'])
      if not element:
         return error_response(error="Third party account was not found", code=400)
      return success_response(message="Third party account was found", data = element,  code=201)
  except Exception as e:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account', methods=['DELETE'])
@jwt_validation
def delete_third_party_account_by_id(user_data):
  try:
      data = dict(request.args)
      element= third_party_account_service.delete_third_party_account_by_id(user_data['uid'], data['account_id'])
      return success_response(message="Third party account  delected", data = element,  code=201)
  except NotFoundException as e:
    return error_response(error=str(e), code=400)
  except Exception:
    return error_response(error=str(e), code=400)


@third_party_account_bp.route('/thirdparty/account/cyberark/connexion-status', methods=['POST'])
@jwt_validation
def check_cyberark_status_connexion(user_data):
  try:
      data = request.get_json(force=True)
      errors = cyberark_schema.validate(data)
      if errors:
          return error_response(error=errors)
      data = third_party_account_service.check_connexion_status(user_data['uid'], data['account_id'])
      return success_response(data=data, code=200)
  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account/cyberark/safes', methods=['GET'])
@jwt_validation
def get_safes_in_cyberark(user_data):
  try:
      data = request.args.to_dict()
      errors = cyberark_schema.validate(data)
      if errors:
          return error_response(error=errors)
      data = third_party_account_service.get_all_safe_in_cyberark_account(user_data['uid'], data['account_id'])
      return success_response(data=data, code=200)
  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account/cyberark/safes/<safe_id>/secrets', methods=['GET'])
@jwt_validation
def get_all_secrets_in_safe_in_cyberark(user_data, safe_id):
  try:
    data = request.args.to_dict()
    errors = cyberark_schema.validate(data)
    if errors:
        return error_response(error=errors)
    data = third_party_account_service.get_all_secrets_of_safe_in_cyberark_account(user_data['uid'], data['account_id'], safe_id)
    return success_response(data=data, code=200)
  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)


@third_party_account_bp.route('/thirdparty/account/cyberark/safes/<safe_id>/secrets/<secret_id>', methods=['GET'])
@jwt_validation
def read_secret_in_safe_in_cyberark(user_data, safe_id, secret_id):
  try:
    data = request.args.to_dict()
    errors = cyberark_schema.validate(data)
    if errors:
        return error_response(error=errors)
    data = third_party_account_service.read_secret_in_cyberark_account(user_data['uid'], data['account_id'], secret_id)
    return success_response(data=data, code=200)
  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)

@third_party_account_bp.route('/thirdparty/account/cyberark/import', methods=['POST'])
@jwt_validation
def import_safe_from_cyberark(user_data):
  try:
      data = request.get_json(force=True)
      errors = import_safe_from_cyberark_schema.validate(data)
      if errors:
          return error_response(error=errors)
      safe_id = third_party_account_service.import_safe_from_cyberark(user_data['uid'], data)
      return success_response(data={'safe_id': safe_id})
  
  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)
  

@third_party_account_bp.route('/thirdparty/account/cyberark/secret/import', methods=['POST'])
@jwt_validation
def import_secret_from_cyberark(user_data):
  try:
      data = request.get_json(force=True)
      errors = import_secret_from_cyberark_schema.validate(data)
      if errors:
          return error_response(error=errors)
      secret_id = third_party_account_service.import_secret_from_cyberark_into_azumarill(user_data['uid'], data)
      return success_response(data={'secret_id': secret_id})

  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)



@third_party_account_bp.route('/thirdparty/account/cyberark/sync', methods=['POST'])
@jwt_validation
def sync_cyberark_azumarill(user_data):
  try:
      data = request.get_json(force=True)
      errors = synchronization_schema.validate(data)
      if errors:
          return error_response(error=errors)
      secret_id = third_party_account_service.sync_azumarill_to_cyberark(user_data['uid'], data)
      return success_response(message="Sync successfully")

  except NotFoundException as e:
    return error_response(error=str(e), code=404)
  except InsufficientRight as e:
      return error_response(error=str(e), code=403)
  except AttemptsExceeded as e:
      return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e), code=400)