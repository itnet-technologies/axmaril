from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from .application_model import ApplicationModel
from .application_schema import ApplicationSchema, ApplicationUpdateSchema, ApplicationSearchSchema
from .application_service import ApplicationService
from ...database.db_manager import DBManager
from datetime import datetime
from ...utils.helpers import success_response, error_response, save_icon_file
import json
from ...utils.custom_exception import ApplicationNotFoundException, InvalidDataException, DatabaseUpdateException
from ...utils.middleware import jwt_validation

application_model = ApplicationModel()
application_schema = ApplicationSchema()
application_service = ApplicationService()
application_schema_update = ApplicationUpdateSchema()
application_schema_search = ApplicationSearchSchema()

application_bp = Blueprint('v2_application', __name__)
@application_bp.route('/applications', methods=['POST'])
@jwt_validation
def create_application(user_data):
  """
  Create a new application
  ---
  security:
    - BearerAuth: []
  consumes:
    - multipart/form-data
  parameters:
    - in: header
      name: Authorization
      type: string
      required: true
      description: Bearer token for authentication
    - in: formData
      name: app_name
      type: string
      required: true
      description: The name of the application
    - in: formData
      name: app_type
      type: string
      required: true
      description: The type of the application
    - in: formData
      name: app_icon
      type: file
      required: false
      description: The icon of the application
    - in: formData
      name: app_fields
      type: object
      required: true
      description: The key-value pairs of the application fields
  responses:
    200:
      description: Application created successfully
  """
  try:
      data = dict(request.form)
      print(data)
      if 'app_fields' in data:
        data['app_fields'] = json.loads(data['app_fields'])

      errors = application_schema.validate(data)
      if errors:
          return error_response(error=errors)

      app_icon = request.files.get('app_icon')
      
      application_service.create_application(data, app_icon)
      return success_response(message="Application created successfully", code=201)
  except ApplicationNotFoundException as e:
      return error_response(error=str(e))

@application_bp.route('/applications/<app_id>', methods=['PUT'])
def update_application(app_id):
    """
    Update an existing application.
    ---
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: app_id
        type: string
        required: true
        description: ID of the application to update
      - in: header
        name: Authorization
        type: string
        required: true
        description: Bearer token for authentication
      - in: formData
        name: app_name
        type: string
        required: false
        description: The name of the application
      - in: formData
        name: app_type
        type: string
        required: false
        description: The type of the application
      - in: formData
        name: app_fields
        type: object
        required: false
        description: The key-value pairs of the application fields
      - in: formData
        name: app_icon
        type: file
        required: false
        description: The icon file for the application
    responses:
      200:
        description: Application updated successfully
      400:
        description: Invalid data provided
      404:
        description: Application not found
      500:
        description: Internal server error
    """
    data = request.form.to_dict()
    if 'app_fields' in data:
      data['app_fields'] = json.loads(data['app_fields'])

    errors = application_schema_update.validate(data)
    if errors:
        return error_response(error=errors)
    app_icon = request.files.get('app_icon')

    try:
        application_service.update_application(app_id, data, app_icon)
        return success_response(message="Application updated successfully")
    except ApplicationNotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e), code=500)

@application_bp.route('/applications/<app_id>', methods=['GET'])
def find_application_by_id(app_id):
  try:
    application = application_service.find_application_by_id(app_id)
    return success_response(message="Application successfully retrieved", data=application)

  except ApplicationNotFoundException as e:
    return error_response(error=str(e), code=404)

@application_bp.route('/applications/search', methods=['GET'])
def find_application_by_name():
  try:
    # Get params of request
    params = request.args.to_dict()
    
    # Toujours valider la data renvoyé
    errors = application_schema_search.validate(params)
    if errors:
        return error_response(error=errors)

    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    app_name = params.get('app_name')
    apps = application_service.find_application_by_name(app_name, page, per_page)

    return success_response(message="Application successfully retrieved", data=apps)
  except Exception as e:
    return error_response(error=str(e))

@application_bp.route('/applications', methods=['GET'])
def find_all_applications():
  try:
    # Get params of request
    params = request.args.to_dict()
    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    applications = application_service.find_all_applications(page, per_page)
    # applications = [dict(application) for application in response]

    return success_response(message="Applications successfully retrieved", data=applications)
  except Exception as e:
    return error_response(error=str(e))

@application_bp.route('/applications/<string:app_id>', methods=['DELETE'])
def delete_application(app_id):
  try:
    application_service.delete_application(app_id)
    return success_response(message="Application deleted successfully")
  except ApplicationNotFoundException as e:
    return error_response(error=str(e), code=404)