import json, traceback
from flask import jsonify, Blueprint, request, url_for, current_app
from modules.required_packages import (
    isAdmin, get_uid_by_token, run_mongosh_command, SYNC_OBJ, is_leader, leader_validator
)
import logging
import random
import uuid
# from modules.app_factory import (
#     get_distributed_queue, is_leader, get_status, add_node_member, remove_node_member,
#     inc_c1, inc_c2, inc_d1, get_c1, get_c2, get_d1
# )

RAFTSTATE_REQUEST = Blueprint("raft", __name__)

# @RAFTSTATE_REQUEST.route('/task', methods=['POST'])
# def submit_task():
#     if not is_leader():
#         leader_address = get_status()['leader']
#         return jsonify({
#             'status': 'NOT_LEADER',
#             'leader': leader_address,
#         }), 400

#     task = request.json
#     logging.debug(f'Received task: {task}')

#     task_id = str(uuid.uuid4())

#     task['id'] = task_id

#     # TODO: made submitting of tasks more error prone
#     queue = get_distributed_queue()
#     queue.put(task, sync=True)

#     return jsonify({
#         'status': 'SUBMITTED',
#         'id': task_id,
#     })


@RAFTSTATE_REQUEST.route('/status', methods=['GET'])
def raft_status():
    from modules.required_packages import SYNC_OBJ
    args = dict(request.args)
    # uid = get_uid_by_token()
    # if not isAdmin(uid):
    #     return jsonify({
    #         "status" : "failed",
    #         "message" : "not allowed"
    #     }), 403
    # print(is_leader())
    d = SYNC_OBJ.getStatus()
    print(d)
    return jsonify({
        "status" : "success",
        "message" : "example",
        "data" : d['leader'].address
    })


@RAFTSTATE_REQUEST.route('/lead-validator', methods=['GET', 'POST'])
@leader_validator
def lead_v():
    from modules.required_packages import SYNC_OBJ
    args = dict(request.args)
    # uid = get_uid_by_token()
    # if not isAdmin(uid):
    #     return jsonify({
    #         "status" : "failed",
    #         "message" : "not allowed"
    #     }), 403
    # print(is_leader())
    return current_app.response_class(
        json.dumps(SYNC_OBJ.get_status(), indent=4, sort_keys=True),
        mimetype='application/json')
    
@RAFTSTATE_REQUEST.route('/', methods=['POST'])
def raft_add_member():
    '''
        data = {  
            nodes : [
                "localhost:6001",
                "localhost:6002"
            ]
        }
    '''
    # uid = get_uid_by_token()
    # if not isAdmin(uid):
    #     return jsonify({
    #         "status" : "failed",
    #         "message" : "not allowed"
    #     }), 403
    data = request.get_json(force = True)
    for node in data["nodes"]:
        try:
            SYNC_OBJ.addNodeToCluster(node)
        except:
            print(traceback.format_exc())
    return jsonify({
        "status" : "success"
    })   


# @RAFTSTATE_REQUEST.route('/mongosh', methods=['POST'])
# def mongosh():
#     '''
#         data = {  
#             "command" : "rs.status()"
#         }
#     '''
#     uid = get_uid_by_token()
#     if not isAdmin(uid):
#         return jsonify({
#             "status" : "failed",
#             "message" : "not allowed"
#         }), 403
#     data = request.get_json(force = True)
#     run_mongosh_command(data["command"], output = True)
#     return jsonify({
#         "status" : "success"
#     }) 

@RAFTSTATE_REQUEST.route('/', methods=['DELETE'])
def raft_remove_member():
    '''
        data = {  
            nodes : [
                "localhost:6001",
                "localhost:6002"
            ]
        }
    '''
    # uid = get_uid_by_token()
    # if not isAdmin(uid):
    #     return jsonify({
    #         "status" : "failed",
    #         "message" : "not allowed"
    #     }), 403
    data = request.get_json(force = True)
    for node in data["nodes"]:
        try:
            SYNC_OBJ.removeNodeFromCluster(node)
        except:
            print(traceback.format_exc())
    return jsonify({
        "status" : "success"
    })  
    return current_app.response_class(
        json.dumps(SYNC_OBJ.get_status(), indent=4, sort_keys=True),
        mimetype='application/json')