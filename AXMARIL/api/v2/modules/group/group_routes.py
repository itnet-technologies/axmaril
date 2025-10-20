from flask import request, Blueprint
from .group_model import GroupModel
from .group_schema import GroupSchema, GroupSchemaUpdate, AddMemberSchema
from .group_service import GroupService
from ...utils.helpers import success_response, error_response
from ...utils.middleware import jwt_validation
from ...utils.custom_exception import NotFoundException, NameAlreadyExist, UserAlreadyExist

group_model = GroupModel()
group_schema = GroupSchema()
group_schema_update = GroupSchemaUpdate()
add_member_schema = AddMemberSchema()
group_service = GroupService()

group_bp = Blueprint('v2_group', __name__)

@group_bp.route('/group/create', methods=['POST'])
@jwt_validation
def create_new_group(user_data):
    try:
        data = request.get_json(force=True)
        data['owner_uid'] = user_data['uid']
        print(data)
        
        errors = group_schema.validate(data)
        if errors:
            return error_response(error=errors)
               
        response = group_service.create_group_member(data)

        return success_response(message="group created successfully", data=response , code=201)
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e), code=400)
    except Exception as e:
        return error_response(error=str(e))

@group_bp.route('/group/member/add', methods=['POST'])
@jwt_validation
def add_member_to_group(user_data):
    try:
        group_id = request.args.get('group_id')
        data = request.get_json(force=True)
        
        errors = add_member_schema.validate(data)
        if errors:
            return error_response(error=errors)
               
        group_service.add_group_member(group_id, user_data['uid'], data)

        return success_response(message="the new member(s) have been successfully added to group", code=201)
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except UserAlreadyExist as e:
        return error_response(error=str(e), code=400)
    except Exception as e:
        return error_response(error=str(e))

@group_bp.route('/group/member/remove', methods=['DELETE'])
@jwt_validation
def remove_member_from_group(user_data):
    try:
        group_id = request.args.get('group_id') 
        member_uid = request.args.get('member_uid')
        
        group_service.remove_group_member(group_id, user_data["uid"], member_uid)
        return success_response(message="member successfully removed")
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e))

@group_bp.route('/groups/all', methods=['GET'])
@jwt_validation
def get_all_groups(user_data):
    try:
        # Get params of request  
        params = request.args.to_dict()
        print(params)
        
        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        
        owner_groups = group_service.find_group_list(user_data["uid"], page, per_page)
        print(owner_groups)
        return success_response(message="groups list retriveve successfully", data=owner_groups)
    except Exception as e:
        return error_response(error=str(e))

@group_bp.route('/group/detail', methods=['GET'])
@jwt_validation
def find_one_group(user_data):
    try:
        group_id = request.args.get('group_id') 
        foun_group = group_service.find_group_detail(user_data["uid"], group_id)
        return success_response(message="group retrieve successfully", data=foun_group)
    
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except Exception as e:
        return error_response(error=str(e))

@group_bp.route('/group/update', methods=['PUT'])
@jwt_validation
def update_group_name(user_data):
    try:
        group_id = request.args.get('group_id') 
        # Get group data
        group_data = request.get_json(force=True)
        
        errors = group_schema_update.validate(group_data)
        if errors:
            return error_response(error=errors)
        
        group_service.update_group_data(group_id, user_data["uid"], group_data)
        return success_response(message="Group updated successfully")
        
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))