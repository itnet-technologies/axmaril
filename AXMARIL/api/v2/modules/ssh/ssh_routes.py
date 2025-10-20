import ast
from flask import Flask, request, render_template_string, Blueprint
from ...database.db_manager import DBManager
from ..secret.secret_service import SecretService
from .ssh_schema import SshSessionSchema
from .ssh_service import SshSessionService
from ...utils.helpers import (
  success_response, error_response, config_data,
  CustomThread, Thread, isAdmin, isBlacklisted, Blacklisted,
  is_date_expired
)
from datetime import datetime
import random
import time, os
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, InsufficientRight, SomethingWentWrong
from ...utils.middleware import get_user_data_by_token
from flask_sock import Sock
from .sshclient.index import SSHClient
from ...utils.middleware import jwt_validation

LICENSE_INFO = os.environ.get("AXMARIL_LICENSE_INFO", None)
app = Flask(__name__)
# CORS(app, origins="*")
WSPORT = config_data.get("WEBSOCKET_PORT", 5008)
sock = Sock(app)
@app.route('/')
def index():
    html_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Index Page</title>
    </head>
    <body>
        <h1>Welcome to the Index Page</h1>
        <p>This is the main page of the Flask application.</p>
    </body>
    </html>
    '''
    return render_template_string(html_content)

def start_websocket_server(t):

    @sock.route('/echo')
    def echo(ws):
        while True:
            data = ws.receive()
            ws.send(data)
    # from waitress import serve
    # serve(app, host="0.0.0.0", port=WSPORT, url_scheme='https')
    app.run(host='0.0.0.0',port=WSPORT, ssl_context='adhoc')
    # http_server = WSGIServer(
    #         ("0.0.0.0", WSPORT), app)
    # print(f"running ws server at ws://localhost:{WSPORT}")
    # print(f"FRONT URL : https://localhost:{config_data['FRONTEND_PORT']}")
    # http_server.serve_forever()
secret_service = SecretService()
ssh_session_service = SshSessionService()
ssh_session_schema = SshSessionSchema()
db_manager = DBManager()

ssh_bp = Blueprint('ssh', __name__)
clients = {}


def initialize_session(owner_uid):
    session_id = ssh_session_service.create_session(owner_uid)
    return session_id

def save_session_data(session_id, event_data, event_response):
    ssh_session_service.update_session(session_id, event_data, event_response)

def update_session_state(session_id, data):
    ssh_session_service.update_state(session_id, data)

def terminate_session(uid, session_id, data):
    if isAdmin(uid):
        session = ssh_session_service.find_one_session(session_id)
        Blacklisted(session["owner_uid"], is_denied=True)
        ssh_session_service.update_state(session_id, data)
    else:
        raise InsufficientRight('Unauthorized')

@sock.route('/ssh/live')
# @licence_enabled_features
def ssh_sock(ws):
    try:
        data = dict(request.args)
        user_data = get_user_data_by_token(data["token"])
        secret_id = data["secret_id"]

        isBlacklisted(user_data["uid"])

        check_access = db_manager.find_one("users", {"uid": user_data["uid"], "is_blacklisted": True})
        if check_access:
            print("Error: Access denied. Please contact admin for more informations.")
            ws.send("Error: Access denied. Please contact admin for more informations.")
            ws.close()

        data = secret_service.reveal_secret(user_data['uid'], secret_id)    
        host = data['hostname']
        port = config_data.get("SSH_PORT", 22)
        username = data['username']
        if "private_key" in data:        #si c'est un secret contenant une clé ssh (secret/ssh)
            print(f"Connecting to {host} using ssh key...")
            client = SSHClient(ws, host, port, username, private_key_string = data["private_key"])
        else:                                   #si c'est un secret contenant un mot de passe (secret/create)
            print(f"Connecting to {host} using password..")
            password = data['password']
            client = SSHClient(ws, host, port, username, password)
        clients[ws] = client
        client.start()
        try:
            session_id = ssh_session_service.create_session(user_data['uid'], user_data['email'], secret_id)
            print(f"session: {session_id}")
            while True:
                session = ssh_session_service.find_session_by_id(user_data['uid'], session_id)
                      
                if not session['is_active']:
                    query = {'status': 'closed'}
                    Thread(target = update_session_state, args=(session_id, query,)).start()
                    secret_service.update_secret_infos(user_data['uid'], secret_id, {"is_blocked": True})
                    client.disconnect(username)
                    client.ssh.close()
                    print("Session terminated by request")
                    break
                
                data = ws.receive()
                
                if data is not None: 
                    print(f"Received from client: {data}")
                    event_data = data
                    event_response = ssh_session_service.ssh_response(data)

                    Thread(target = save_session_data, args=(session_id, event_data, event_response)).start()
                    client.send(data)
                else:
                    #time.sleep(1)
                    break                  

        except Exception as e:
            print(f"Error: {e}")
        finally:
            del clients[ws]
            client.ssh.close()
            query = {'status': 'closed', 'is_active': False}
            Thread(target = update_session_state, args=(session_id, query,)).start()
            print("Connection closed")
        return success_response(message="Bye!", code=201)
    except SomethingWentWrong as e:
        return error_response(error=str(e))
    except NameAlreadyExist as e:
        return error_response(error=str(e))
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
   
@sock.route('/ssh/login')
def login_ssh(ws):
    try:
        data = dict(request.args)
        
        hostname = data['hostname']
        port = config_data.get("SSH_PORT", 22)
        username = data['username']
        password = data['password']
        
        print(data)       #si c'est un secret contenant un mot de passe (secret/create)
        print(f"Connecting to {hostname} using password..")
        client = SSHClient(ws, hostname, port, username, password)
        clients[ws] = client
        client.start()
        try:
            session_id = random.randint(1,99999)
            print(f"this is session : {session_id}")
            while True:
                data = ws.receive()
                if data:
                    print(f"Received from client: {data}")
                    
                    client.send(data)
                else:
                    break
        except Exception as e:
            print(f"Error: {e}")
        finally:
            del clients[ws]
            client.ssh.close()
            print("Connection closed")
        return success_response(message="Bye!", code=201)
    except NameAlreadyExist as e:
        return error_response(error=str(e), code=400)
    except NotFoundException as e:
        return error_response(error=str(e), code=404) 
    
LICENSE_INFO = None if LICENSE_INFO is None else ast.literal_eval(LICENSE_INFO)
if LICENSE_INFO is not None:
    if not is_date_expired(LICENSE_INFO["expiration_date"]) and LICENSE_INFO["features"]["ssh_web"]:
        t2 = CustomThread(target=start_websocket_server, args=("",))
        t2.start()
    else:
        print("Licenses is expired..running in free mode")
else:
    t2 = CustomThread(target=start_websocket_server, args=("",))
    t2.start()
    print("No licenses found..running in free mode")       


sock = Sock()

@ssh_bp.route('/ssh-session/all', methods=['GET'])
@jwt_validation
def get_all_users_session(user_data):
    try:
        sessions = ssh_session_service.find_session_by_uid(user_data["uid"])
        return success_response(message="Ssh user list", data=sessions)
    except Exception as e:
        return error_response(error=str(e))

@ssh_bp.route('/ssh-session/details', methods=['GET'])
@jwt_validation
def get_my_session(user_data):
    try:
        session_id = request.args.get("session_id")
        found_session = ssh_session_service.find_session_by_id(user_data["uid"], session_id)
        return success_response(message="Ssh user list", data=found_session)
    except NotFoundException as e:
        return error_response(error=str(e))
    except Exception as e:
        return error_response(error=str(e))

@ssh_bp.route('/ssh-session/admin/all', methods=['GET'])
@jwt_validation
def find_all_sessions(user_data):
  try:
    # Get params of request
    params = request.args.to_dict()
    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))

    sessions = ssh_session_service.find_all_sessions(user_data['uid'], page, per_page)
    return success_response(message="Sessions successfully retrieved", data=sessions)
  except InsufficientRight as e:
        return error_response(error=str(e), code=403)
  except Exception as e:
    return error_response(error=str(e))

@ssh_bp.route('/ssh-session/terminate', methods=['PUT'])
@jwt_validation
def terminate_ssh_session(user_data):
    try:
        session_id = request.args.get("session_id")

        data = {"is_active": False, "status": "closed"}
        terminate_session(user_data['uid'], session_id, data)

        return success_response(message="Session terminated successfully")
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except Exception as e:
        return error_response(error=str(e))

@ssh_bp.route('/ssh-session/user/unlock', methods=['PUT'])
@jwt_validation
def unlock_ssh_user(user_data):
    try:
        owner_uid = request.args.get("owner_uid")
        
        ssh_session_service.unlocked_user(user_data["uid"], owner_uid)

        return success_response(message="User successfully unlocked")
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except Exception as e:
        return error_response(error=str(e))

@ssh_bp.route('/ssh-session/delete', methods=['DELETE'])
@jwt_validation
def delete_session(user_data):
    try:
        session_id = request.args.get("session_id")

        ssh_session_service.delete_session(user_data["uid"], session_id)
        return success_response(message="Session deleted successfully") 
    except NotFoundException as e:
        return error_response(error=str(e), code=404)
    except InsufficientRight as e:
        return error_response(error=str(e), code=403)
    except Exception as e:
        return error_response(error=str(e))