import json
import os
import shutil
import requests
import traceback
from base64 import b64encode
from json import dumps
from threading import Thread
# from turtle import right
from flask import jsonify, Blueprint,request, url_for
# from pymongo import MongoClient
from modules.required_packages import (
    encode_token, has_role, mail_sender, parse_json, safe_access, search_user_info, secret_access,
    secrets, users, shares, decrypt, encrypt, isErrorKey, run_dag, leader_validator,
    validation, salt, jwt, db002, file_server_url, delete_safe_util, seal_validator,
    get_uid_by_token, refresh_azumaril_system_safe, cd_secret_collection, ecptk, config_data,
    impersonate_middleware
)
from bson import ObjectId
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from pathlib import Path
import math

from modules.required_packages import success_response, error_response
from api.v2.modules.guacamole.guacamole_service import GuacamoleService

from flask import request, jsonify
from bson import ObjectId
from datetime import datetime, timedelta
import shutil, os, traceback
from pathlib import Path
import jwt
from werkzeug.utils import secure_filename



SHARE_REQUEST = Blueprint("secret", __name__)

tasks = db002["tasks"]
safes = db002["safe"]
creds = db002["creds"]
policies = db002["policies"]
account = db002["account"]
applications = db002["applications"]
st = db002["secret_type"]
phistory = db002["propagate_history"]


def shared_secret_info(secret_ids, owner_uid, rights):
    shared_secret_info = []
    for sid in secret_ids:
        secret_access_info = secret_access(sid, owner_uid)
        if secret_access_info[0] :
            if not secret_access_info[2]["share"] :     #if right share is not allowed for one of the secrets
                return False, 401
            ssi_rights = rights
            if not secret_access_info[2]["owner"] :     #if the connected user is not the owner of the secrets restrict access rights
                ssi_rights = secret_access_info[2]
                del ssi_rights["owner"]
                del ssi_rights["all"]
                for k,v in rights.items():
                    if ssi_rights[k]:
                        ssi_rights[k] = v
            shared_secret_info.append({
                "secret_id" : sid,
                "rights" : ssi_rights
            })
        else:
            return False, 404
    return True, shared_secret_info

def check_attempts(access_info, owner_uid):
    attempts = access_info[4]
    if attempts is not None and len(attempts) != 0 :
        for ua in attempts:
            if ua["uid"] == owner_uid :
                if ua["attempts"] is None:
                    return True, ua
                if ua["attempts"] > 0 :
                    ua["attempts"] -=1
                    #NOTE Récupérer l'id du share et mettre a jour le nombre d'attempts
                    share_id = access_info[5]
                    shares.update_one(
                        {"share_id":share_id},
                        {"$set":{"attempts_info":attempts}}
                    )
                else:
                    return False, (jsonify({
                        "status" : "failed",
                        "status" : "secret access attempts exceeded"
                    }), 403)
                return True, ua

def shared_safe_info(safe_ids, owner_uid, rights):
    shared_secret_info = []
    for sid in safe_ids:
        safe_access_info = safe_access(sid, owner_uid)
        if safe_access_info[0] :
            if not safe_access_info[2]["share"] :     #if right share is not allowed for one of the secrets
                return False, 401
            ssi_rights = rights
            if not safe_access_info[2]["owner"] :     #if the connected user is not the owner of the secrets restrict access rights
                ssi_rights = safe_access_info[2]
                del ssi_rights["owner"]
                del ssi_rights["all"]
                for k,v in rights.items():
                    if ssi_rights[k]:
                        ssi_rights[k] = v
            shared_secret_info.append({
                "safe_id" : sid,
                "rights" : ssi_rights
            })
        else:
            return False, 404
    return True, shared_secret_info

def total_secrets(safe_id):
    secrets_obj = secrets.find({"safe_id" : safe_id})
    nb_secrets = 0
    for i in secrets_obj:
        nb_secrets += 1
    return nb_secrets

@SHARE_REQUEST.route('/create', methods=['POST'])
@leader_validator
@seal_validator
@impersonate_middleware

def create_app():
    try:
        token_uid = get_uid_by_token()

        # Gestion OPTIONS
        if request.method == "OPTIONS":
            return jsonify({"status": "success", "message": "ready"}), 200

        # Validation du JSON
        if request.content_type != "application/json":
            return jsonify({"status":"failed","message":"Content-Type must be application/json"}), 400

        validated = validation(allowNullData=True)
        if not validated[0]:
            return validated[1]
        req = validated[1]  # JSON validé

        # --- Normalisation des champs ---
        # On travaille uniquement avec 'secret_name' (si 'name' est fourni on le mappe)
        if 'secret_name' not in req and 'name' in req:
            req['secret_name'] = req.pop('name')

        owner_uid   = req.get("owner_uid", token_uid)
        owner_email = req.get("owner_email")
        secret_name = req.get("secret_name")
        secret      = req.get("secret")
        safe_id     = req.get("safe_id")
        secret_type = req.get("secret_type")

        # Sanity checks de base
        if not secret_name:
            return jsonify({"status":"failed","message":"secret_name is required"}), 400
        if not safe_id:
            return jsonify({"status":"failed","message":"safe_id is required"}), 400
        if not secret_type:
            return jsonify({"status":"failed","message":"secret_type is required"}), 400

        # Existence du secret (même owner, même nom)
        if secrets.find_one({"secret_name": secret_name, "owner_uid": owner_uid}):
            return jsonify({"message": f"secret {secret_name} already exists", "status": "failed"}), 400

        # Droit d’accès au safe
        safe_access_info = safes.find_one({"safe_id": safe_id, "owner_uid": owner_uid})
        if not safe_access_info:
            return jsonify({"message": "safe not found", "status": "failed"}), 404

        # Préparation infos du secret
        secret_id = str(ObjectId())
        if "id" in req:
            secret_id = req["id"]
        date_of_creation = datetime.now()

        secret_infos = {
            "owner_uid": owner_uid,
            "secret_id": secret_id,
            "secret_name": secret_name,   # <-- clé normalisée
            "date": date_of_creation,
            "secret_type": "other",       # valeur par défaut, ajustée plus bas
            "safe_id": safe_id
        }

        # Expiration optionnelle
        if "exp_time" in req:
            expiration_date_time = date_of_creation + timedelta(seconds=req["exp_time"])
            secret_infos["exp_time"] = expiration_date_time

        # Gestion des types
        if secret_type == "file":
            secret_infos["secret_type"] = "file"
            return jsonify({"status":"coming soon", "message": f"the secret type {secret_type} isn't supported yet!"})

        apt = None  # pour l’intégration Guacamole éventuelle
        if secret_type == "credentials":
            secret_infos["secret_type"] = "credentials"

            apt = req.get("app_type")
            if not apt:
                return jsonify({"status":"failed","message":"app_type is required"}), 400

            app_infos = applications.find_one({"type": apt, "owner_uid": {"$in": ["SYSTEM", owner_uid]}})
            if not app_infos:
                return jsonify({"status":"failed","message":f"The application of type {apt} is not defined in azumaril"}), 400

            secret_infos["app_type"] = apt

            # Vérification des champs requis
            if not isinstance(secret, dict):
                return jsonify({"status":"failed","message":"secret must be an object"}), 400
            required_key = [k for k, v in app_infos["fields"].items() if v]
            missing_key = [rk for rk in required_key if rk not in secret]
            if missing_key:
                return jsonify({"status":"failed","message":f"missing attributes: {missing_key} in the secret"}), 400

        # Chiffrement du secret
        secret_jwt = jwt.encode(secret, salt, algorithm='HS256')
        enc_ct, enc_tag, enc_nonce = encrypt(secret_jwt)
        encrypted_data_jwt = jwt.encode({
            "ciphertext": enc_ct,
            "tag": enc_tag,
            "nonce": enc_nonce
        }, salt, algorithm='HS256')
        secret_infos["secret"] = encrypted_data_jwt

        # Insertion
        secrets.insert_one(secret_infos)

        # --- Intégration Guacamole (seulement credentials + ssh/rdp) ---
        guacamole_result = None
        if secret_type == "credentials" and apt in ["ssh", "rdp"]:
            try:
                guacamole_service = GuacamoleService()
                user_info = users.find_one({"uid": owner_uid}) or {}
                user_data = {
                    'username': user_info.get('username', owner_uid),
                    'password': user_info.get('password', owner_uid)
                }

                secret_data_for_guac = {
                    'secret_name': secret_name,
                    'type': apt,
                    'owner_email': owner_email,
                    'owner_uid': owner_uid,
                    'secret': secret
                }

                success, result = guacamole_service.auto_create_connection_from_secret(
                    secret_data_for_guac, user_data
                )

                if success:
                    guacamole_result = {
                        'guacamole_integration': True,
                        'connection_id': result['connection_id'],
                        'connection_url': result.get('connection_url'),
                        'message': result.get('message', '')
                    }
                    # Sauvegarder l’ID de connexion Guacamole
                    secrets.update_one(
                        {"secret_id": secret_id},
                        {"$set": {"guacamole_connection_id": result['connection_id']}}
                    )
                else:
                    print(f"Erreur intégration Guacamole pour secret {secret_id}: {result}")
                    guacamole_result = {'guacamole_integration': False, 'error': result}

            except Exception as e:
                print(f"Exception intégration Guacamole: {str(e)}")
                guacamole_result = {'guacamole_integration': False, 'error': str(e)}

        # Réponse
        response_data = {
            "status": "success",
            "secret_id": secret_id,
            "created_at": date_of_creation
        }
        if guacamole_result:
            response_data["guacamole"] = guacamole_result

        return jsonify(response_data)

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"status": "failed","message": "something went wrong","error": str(e)}), 500
       
        
@SHARE_REQUEST.route('/reveal', methods=['GET'])
@seal_validator
# @leader_validator
@impersonate_middleware
def reveal():
    try:
        validated = validation(allowNullData=True)
        auth_token = request.headers.get('Authorization').split()[1]
        if not validated[0]:
            return validated[1]
        args = request.args
        data = args.to_dict()
        owner_uid = get_uid_by_token()
        if not isErrorKey(data, "secret_id"):
            return jsonify({
                "status" : "failed",
                "message" : "secret_id is required"
            }), 400
        access_info = secret_access(data["secret_id"], owner_uid)
        if not access_info[0]:
            return jsonify({
                "status" : "failed",
                "message" : "secret not found"
            }), 404
        else:
            if not access_info[2]["read"]:
                return jsonify({
                    "status" : "failed",
                    "message" : "access denied, can't perform this action on this secret"
                }), 403
            secret = access_info[1]
            if(not access_info[2]["owner"]):
                check_result = check_attempts(access_info, owner_uid)
                if(not check_result[0]):
                    return check_result[1]
            # print(secret)
            if secret["secret_type"] == "file":
                random_str = str(ObjectId())
                temp_folder = os.path.dirname(__file__) + f"/temp/.temp_{random_str}"
                os.makedirs(temp_folder)
                if secret["secret"] is not None:
                    with open(f'{temp_folder}/{secret["name"]}.azumaril', 'w') as f:
                        f.write(secret["secret"])
                        f.close()
                    print("not downloading the file secret is not None")
                    decrypt(is_file = True, file_path = f'{temp_folder}/{secret["name"]}.azumaril')
                else:
                    if(not access_info[2]["owner"]):
                        auth_token = encode_token("access_token", secret["owner_uid"], {}, 1)['token']
                    url = file_server_url.replace("Azumaril/", f"{auth_token}/Azumaril/") + secret['file_path']
                    r = requests.get(url, allow_redirects=True)
                    with open(f'{temp_folder}/{secret["name"]}.azumaril', 'wb') as f:
                        f.write(r.content)
                        f.close()
                    decrypt(is_file = True, file_path = f'{temp_folder}/{secret["name"]}.azumaril')
                with open(f'{temp_folder}/{secret["file_name"]}', 'rb') as file:
                    # byte64 = base64.b64encode(file.read())
                    data = file.read()
                    # json_str = json.dumps({'message': byte64.decode('utf-8')})
                    file.close()
                # if(not access_info[2]["owner"]):
                #     tokens.delete_one({"token" : auth_token})
                # base64_bytes = b64encode(data)
                # base64_string = base64_bytes.decode("utf-8")
                # raw_data = {
                #     "name" : {secret["file_name"]},
                #     "byte64" : base64_string
                # }
                # json_data = dumps(raw_data, indent=2)
                # # data = byte64.decode('unicode_escape')
                # with open(f"{temp_folder}/{secret['name']}.json", 'w') as another_open_file:
                #     another_open_file.write(json_data)
                #     another_open_file.close()
                # with open(f"{temp_folder}/{secret['name']}.json", 'r') as ann:
                #     data = ann.read()
                #     ann.close()
                shutil.rmtree(temp_folder)
                # return json_data
                return jsonify(
                    {
                        "status" : "success",
                        "message" : "",
                        "data" : data.hex(),
                        "name" : secret['file_name']
                    }
                )

            try:
                # print(secret["secret"])
                if type(secret["secret"]) == type({}):
                    if "$binary" in secret["secret"]:
                        secret["secret"] = secret["secret"]["$binary"]
                is_def_secret = False
                if "app_type" in secret :
                    if secret["app_type"] == "azumaril":
                        if "deletable" in secret :
                            if not secret["deletable"]:
                                is_def_secret = True
                if is_def_secret:
                    encrypted_data = jwt.decode(secret["secret"], ecptk, algorithms=["HS256"])
                else:
                    encrypted_data = jwt.decode(secret["secret"], salt, algorithms=["HS256"])
                decrypted_data = decrypt(encrypted_data)
                if isinstance(decrypted_data, tuple):
                    return jsonify({
                        "status" : "failed",
                        "message" : decrypted_data[1]
                    }), 403
                
                if is_def_secret:
                    decrypted_data = jwt.decode(decrypted_data, ecptk, algorithms=["HS256"])
                else:
                    decrypted_data = jwt.decode(decrypted_data, salt, algorithms=["HS256"])
                    
                return jsonify({
                    "status" : "success",
                    "message" : "successfully decrypted",
                    "data" : decrypted_data
                })
            except:
                print(traceback.format_exc())
                return jsonify({
                    "status" : "failed",
                    "message" : "Something went wrong"
                }), 400
    except:
            print(traceback.format_exc())
            return jsonify({
                "status" : "failed",
                "message" : "Something went wrong"
            }), 400

@SHARE_REQUEST.route('/update', methods=['PUT'])
@seal_validator
@leader_validator
@impersonate_middleware
def update_secret():
    global config_data, salt
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    req = validated[1]
    owner_uid = get_uid_by_token()
    try:
        if request.content_type == "application/json":
            if not isErrorKey(req, "secret_id"):
                return jsonify({"status": "failed", "message": "secret_id is required"}), 400
            secret_id = req["secret_id"]
            is_system = False
            fsecret = db002.secrets.find_one({"secret_id" : secret_id})
            if fsecret is not None:
                deletable = fsecret.get("deletable", None)
                if deletable is not None and not deletable:
                    is_system = True
            owner_uid = get_uid_by_token()
            access_info = secret_access(secret_id, owner_uid)
            if not access_info[0]:
                return jsonify({
                    "status" : "failed",
                    "message" : "secret not found"
                }), 404
            # print(access_info[2])
            if not access_info[2]["write"]:
                return jsonify({
                    "status" : "failed",
                    "message" : "access denied, can't perform this action on this secret"
                }), 401
            secret_found = access_info[1]
            if not access_info[2]["owner"]:
                check_result = check_attempts(access_info, owner_uid)
                if(not check_result[0]):
                    return check_result[1]
            safe_id = secret_found["safe_id"]
            if isErrorKey(req, "safe_id"):
                if is_system:
                    return jsonify({
                        "status" : "failed",
                        "message" : "not allowed"
                    }), 403
                if safes.find_one({"safe_id":req["safe_id"]}) is None:
                    return jsonify({"status": "failed", "message": "bad safe_id or safe isn't existing anymore"}), 400
                safe_id = req["safe_id"]

            if isErrorKey(req, "name"):
                if is_system:
                    return jsonify({
                        "status" : "failed",
                        "message" : "not allowed"
                    }), 403
                if secrets.find_one({"owner_uid" : owner_uid, "safe_id" : safe_id, "name" : req["name"], "secret_id" : {"$ne":secret_id}}) is not None:
                    return jsonify({
                        "status" : "failed",
                        "message" : "there is already a secret with this name"
                    }), 409

            if isErrorKey(req, "secret"):
                secret = req["secret"]
                if secret_found["secret_type"] == "credentials":
                    if type(req["secret"]) != dict:
                        return jsonify({"status": "failed", "message": "the secret field must be an object"}), 400
                    if not is_system:
                        app_infos = applications.find_one({"type": secret_found["app_type"], "owner_uid" : {"$in" : ["SYSTEM", owner_uid]}})
                        if app_infos is not None:
                            required_key = []
                        for a,b in app_infos["fields"].items():
                            if b:
                                required_key.append(a)
                        missing_key = []

                        for rk in required_key:
                            if rk not in secret:
                                missing_key.append(rk)

                        if len(missing_key) > 0:
                            return jsonify({"status":"failed", "message":"missing this attributes : " + str(missing_key) +" in the secrets"}), 400
                    else:
                        salt = ecptk
                    encrypted_data = jwt.decode(secret_found["secret"], salt, algorithms=["HS256"])
                    decrypted_data = decrypt(encrypted_data)
                    sf_secret_decrypted = jwt.decode(decrypted_data, salt, algorithms=["HS256"])
                    for k,v in req["secret"].items():
                        if k not in sf_secret_decrypted:
                            return jsonify({"status": "failed", "message": f"key {k} is not in secret value so you can't update it"}), 400
                #1 encode secret data object to json web token
                secret_jwt = jwt.encode(
                    secret,
                    salt,
                    algorithm='HS256'
                )
                # print(secret_jwt)
                #2 encrypt this jwt
                encrypted_data = encrypt(secret_jwt)
                # print(encrypted_data)
                #3 get the ciphertext,tag and nonce from the encrypted secret_jwt and encode again to jwt
                encrypted_data_jwt = jwt.encode(
                    {
                        "ciphertext" : encrypted_data[0],
                        "tag" : encrypted_data[1],
                        "nonce" : encrypted_data[2]
                    },
                    salt,
                    algorithm='HS256'
                )
                # print(encrypted_data_jwt)
                # secret_infos["secret"] = secret
                req["secret"] = encrypted_data_jwt
                if is_system:
                    cd_secret_collection.update_one({"id" : secret_id}, {"$set" : {"secret" : encrypted_data_jwt}})
                    config_data = secret
            del req["secret_id"]
            secrets.update_one(
                {'secret_id':secret_id},
                { '$set': req }
            )
            return jsonify({"status": "success", "message": f"the secret {secret_id} updated successfully"})
        else:
            update_info = {"owner_uid" : owner_uid}
            data = dict(request.form)
            if not isErrorKey(data, "secret_id"):
                return jsonify({"status": "failed", "message": "secret_id is required"}), 400
            secret_id = data["secret_id"]
            update_info["secret_id"] = secret_id
            access_info = secret_access(secret_id, owner_uid)
            if not access_info[0]:
                return jsonify({
                    "status" : "failed",
                    "message" : "secret not found"
                }), 404
            # print(access_info[2])
            if not access_info[2]["write"]:
                return jsonify({
                    "status" : "failed",
                    "message" : "access denied, can't perform this action on this secret"
                }), 401
            secret_found = access_info[1]
            if not access_info[2]["owner"]:
                check_result = check_attempts(access_info, owner_uid)
                if(not check_result[0]):
                    return check_result[1]
            safe_id = secret_found["safe_id"]
            if isErrorKey(data, "safe_id"):
                # print(data)
                if safe_id != data["safe_id"]:
                    update_info["safe_id"] = data["safe_id"]
                    if safes.find_one({"safe_id" : data["safe_id"], "owner_uid" : owner_uid}) is None:
                        return jsonify({
                            "status" : "failed",
                            "message" : "safe not found"
                        }), 404
                safe_id = data["safe_id"]
            if 'file' in request.files:
                file = request.files['file']
                random_str = str(ObjectId())
                temp_folder = os.path.dirname(__file__) + f"/temp/.temp_{random_str}"
                os.makedirs(temp_folder)                        #create random temp folder
                filename = secure_filename(file.filename)       #get file original name
                filepath = f"{temp_folder}/{filename}"          #set path for the file in the temp folder
                file.save(os.path.join(filepath))               #save file in the temp folder
                update_info["file_path"] = filepath
                update_info["file_name"] = filename
                name = filename.split(".")[0]
                update_info["name"] = name
            # app_type = None
            # update_info["app_type"] = app_type
            if isErrorKey(data, "name"):
                name = data["name"]
                if secrets.find_one({"owner_uid" : owner_uid, "safe_id" : safe_id, "name" : name, "secret_id" : {"$ne":secret_id}}) is not None:
                    return jsonify({
                        "status" : "failed",
                        "message" : "there is already a secret with this name"
                    }), 409
                update_info["name"] = name
                if 'file' in request.files:
                    p = Path(filepath)           #get file path info
                    ext = p.suffix               #get extension of the file
                    p.rename(Path(p.parent, f"{data['name']}{ext}"))    #change original file name with provided name
                    filepath = f"{temp_folder}/{data['name']}{ext}"
                    update_info["file_path"] = filepath
                    update_info["file_name"] = f"{data['name']}{ext}"
            if isErrorKey(data, "app_type"):
                app_type = data["app_type"]
                update_info["app_type"] = app_type
            encrypt(
                update_info,
                True,
                True
            )
            if 'file' in request.files:
                shutil.rmtree(temp_folder)
            fsecret = secrets.find_one(
                {"secret_id" : secret_id},
                {"_id":0,"secret":0}
            )
            return jsonify({
                "status" : "success",
                "message" : "secret file successfully updated",
                "data" : fsecret
            })
    except:
        print(traceback.format_exc())
        return jsonify({"status": "failed", "message": "Something went wrong"}), 400

#TODO il faudrait que quand un utilisateur qui n'est pas le propriétaire d'un secret le supprime ça soit supprimer dans tous les partages
@SHARE_REQUEST.route('/delete', methods=['DELETE'])
@seal_validator
@leader_validator
@impersonate_middleware
def delete_secret():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        if not isErrorKey(req, "secret_id"):
            return jsonify({"status": "failed", "message": "secret_id is required"}), 400
        secret_id = req["secret_id"]
        owner_uid = get_uid_by_token()
        access_info = secret_access(secret_id, owner_uid)
        if not access_info[0]:
            return jsonify({
                "status" : "failed",
                "message" : "secret not found"
            }), 404
        else:
            if not access_info[2]["delete"]:
                return jsonify({
                    "status" : "failed",
                    "message" : "access denied, can't perform this action on this secret"
                }), 401
        if not access_info[2]["owner"]:
            check_result = check_attempts(access_info, owner_uid)
            if(not check_result[0]):
                return check_result[1]
        found_shares = shares.find({"secret_ids" : {"$all" : [secret_id]}})
        for fs in found_shares:
            sids = fs["secret_ids"]
            to_update = {}
            sids.remove(secret_id)
            if len(sids) != 0:
                ssi = shared_secret_info(sids, owner_uid, fs["rights"])
                to_update["shared_secret_info"] = ssi[1]
                to_update["secret_ids"] = sids
                shares.update_one(
                    {"share_id" : fs["share_id"]},
                    {"$set" : to_update}
                )
            else:
                to_update["shared_secret_info"] = []
                to_update["secret_ids"] = []
                shares.delete_one({"share_id" : fs["share_id"]})
        secrets.delete_one({"secret_id":secret_id})
        return jsonify({
            "status": "success",
            "message": f"the secret {secret_id} deleted successfully"
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@SHARE_REQUEST.route('/all', methods=['GET'])
@seal_validator
@impersonate_middleware
def get_secrets():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    try:
        owner_uid = get_uid_by_token()
        user_secrets = secrets.find({"owner_uid": owner_uid}, {"_id": 0, "secret":0})
        list_of_secrets = []
        for secret in user_secrets:
            # print(secret["date"])
            # timestamp = secret["date"]["$date"] / 1000
            # date_object = datetime.fromtimestamp(timestamp)
            # year = date_object.year
            # month = date_object.month
            # day = date_object.day
            # secret["date"] = f"{year}-{month}-{day}"
            secret["rights"] = {
                "read" : True,
                "write" : True,
                "delete": True,
                "propagate" : True,
                "share" : True
            }
            list_of_secrets.append(secret)
        owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})
        found_shares = shares.find(
            {
                "users_mails" : {"$all" : [owner["email"]]},
                "type" : "secret"
            },
            {"_id" : 0}
        )
        for fs in found_shares:
            if isErrorKey(fs, "secret_ids"):
                for sid in fs["secret_ids"]:
                    found_secret = secrets.find_one({"secret_id" : sid}, {"_id" : 0, "secret":0})
                    if found_secret is None:
                        continue
                    # found_secret["date"] = found_secret["date"].strftime('%Y-%m-%d')
                    # timestamp = found_secret["date"]["$date"] / 1000
                    # date_object = datetime.fromtimestamp(timestamp)
                    # year = date_object.year
                    # month = date_object.month
                    # day = date_object.day
                    # found_secret["date"] = f"{year}-{month}-{day}"
                    ssi_rights = None
                    for ssi in fs["shared_secret_info"]:
                        if ssi["secret_id"] == sid :
                            ssi_rights = ssi["rights"]
                            break
                    if found_secret is not None :
                        found_secret["rights"] = ssi_rights
                        list_of_secrets.append(found_secret)
            if isErrorKey(fs, "safe_ids"):
                for sid in fs["safe_ids"]:
                    found_secrets = secrets.find({"safe_id" : sid}, {"_id" : 0, "secret":0})
                    ssi_rights = None
                    for ssi in fs["shared_safe_info"]:
                        if ssi["safe_id"] == sid :
                            ssi_rights = ssi["rights"]
                            break
                    for each_found_secret in found_secrets:
                        each_found_secret["date"] = each_found_secret["date"].strftime('%Y-%m-%d')
                        each_found_secret["rights"] = ssi_rights
                    list_of_secrets.extend(found_secrets)
        for secret in list_of_secrets:
            if secret.get("app_type") == "kmip":
                secret.pop("user_cert", None)
                secret.pop("user_key", None)
                    
        #print(list_of_secrets)

        return jsonify({
            "status":"success",
            "data":list_of_secrets
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status": "failed",
            "message":"Something went wrong!"
        }), 400

@SHARE_REQUEST.route('/safe/create', methods=['POST'])
@seal_validator
@leader_validator
@impersonate_middleware
def safe_create():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    owner_uid = get_uid_by_token()
    safe_name = req["name"]

    check = safes.find_one({"owner_uid": owner_uid, "name" : safe_name})
    if check :
        return jsonify({"message":"safe " + safe_name + " already exists", "status": "failed"}), 400
    safe_id = str(ObjectId())
    date_of_creation = datetime.now()
    safe_info = {"owner_uid": owner_uid, "safe_id": safe_id, "name": safe_name, "date": date_of_creation}
    try:
        safes.insert_one(safe_info)
    except:
        print(traceback.format_exc())
        return jsonify({"message": "Cannot create the safe", "status": "failed"}),400
    return jsonify({"status": "success", "safe_id": safe_id, "created the": date_of_creation }),200

@SHARE_REQUEST.route('/safe/update', methods=['PUT'])
@seal_validator
@leader_validator
@impersonate_middleware
def safe_update():
    try:
        validated = validation()
        if not validated[0]:
            return validated[1]
        req = validated[1]
        owner_uid = get_uid_by_token()
        if not isErrorKey(req, "safe_id"):
            return jsonify({
                "status" : "failed",
                "message" : "safe_id is required"
            }), 400
        safe_id = req["safe_id"]
        fsafe = safes.find_one({"safe_id" : safe_id, "owner_uid": owner_uid})
        if fsafe is None:
            return jsonify({
                "status" : "failed",
                "message" : "safe not found"
            }), 404
        safe_type = fsafe.get("type", None)
        is_system = True if safe_type is not None and safe_type == "system" else False
        if is_system:
            return jsonify({
                "status" : "failed",
                "message" : "not allowed"
            }), 403
        update_info = {}
        if isErrorKey(req, "name"):
            fsafe2 = safes.find_one({"safe_id" : {"$ne":safe_id}, "name":req["name"], "owner_uid": owner_uid})
            if fsafe2 is not None:
                return jsonify({
                    "status" : "failed",
                    "message" : "safe with this name already exist"
                }), 409
            update_info["name"] = req["name"]
        safes.update_one(
            {"safe_id" : safe_id, "owner_uid": owner_uid},
            {
                "$set" : update_info
            }
        )
        fsafe = safes.find_one({"safe_id" : safe_id, "owner_uid": owner_uid}, {"_id":0})
        return jsonify({
            "status" : "success",
            "message" : "safe successfully updated",
            "data" : fsafe
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400

@SHARE_REQUEST.route('/safe/all', methods=['GET'])   #ADMIN
@seal_validator
def safe_all():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        if not has_role(["admin"], "one"):
            return jsonify({
                "status": "failed",
                "message": "Insufficient access rights, you have not role admin or rh"
            }), 401
        safes = safes.find({}, {"_id": 0})
        data = []
        for us in safes:
            data.append(us)
        return jsonify({
            "status":"success",
            "safes":data
        })
    except:
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

#TODO il faut qu'on puisse voir le contenu d'un coffre-fort partagé
@SHARE_REQUEST.route('/safe/safe_secrets', methods=['GET'])
@seal_validator
def safe_secrets():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:

        # Get params of request
        params = request.args.to_dict()
        safe_id = params.get('safe_id', None)
        if not safe_id:
            return jsonify({"status":"failed","message": "key safe_id not provided"}), 400
        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page


        owner_uid = get_uid_by_token()
        print(owner_uid)
        safe_retrieve = safes.find_one({"safe_id": safe_id, "owner_uid": owner_uid})
        print(safe_retrieve)
        if not safe_retrieve:
            return jsonify({"status":"failed","message": "safe not found"}), 404
        safe_type = safe_retrieve.get("type", None)
        print(safe_type)
        if safe_type is not None and safe_type == "system":
            refresh_azumaril_system_safe()

        user_safe_secrets = secrets.find({"safe_id" : safe_id, "owner_uid": owner_uid}, {"_id": 0, "secret" : 0}).skip(skip_count).limit(per_page)

        total_user_secrets = secrets.count_documents({"safe_id" : safe_id, "owner_uid": owner_uid})

        last_page = math.ceil(total_user_secrets / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('secret.safe_secrets', page=1, _external=True)

        # Générer l'URL de la dernière page
        last_page_url = url_for('secret.safe_secrets', page=last_page, _external=True)  if last_page >= 1 else None

        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('secret.safe_secrets', page=page + 1, _external=True) if page < last_page else None

        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('secret.safe_secrets', page=page - 1, _external=True) if page > 1 else None


        # list_of_secrets = []
        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_user_secrets
        }
        for secret in user_safe_secrets:
            if type(secret["date"]) == type(datetime.strptime("2022-10-1", '%Y-%m-%d')):
                secret["date"] = secret["date"].strftime('%Y-%m-%d')
            else:
                timestamp = secret["date"]["$date"] / 1000
                date_object = datetime.fromtimestamp(timestamp)
                year = date_object.year
                month = date_object.month
                day = date_object.day
                secret["date"] = f"{year}-{month}-{day}"
                # cr_date = datetime.strptime(secret["date"], '%Y-%m-%d')
                # cr_date = cr_date.strftime('%Y-%m-%d')
                # secret["date"] = cr_date
                """
                    # "users_mails" : {"$all" : [owner["email"]]},"secret_ids":{"$all" : [secret["secret_id"]]}
                    # shareinfo = shares.find({"owner_uid" : owner_uid, "secret_ids":{"$all" : [secret["secret_id"]]}}, {"_id": 0,})
                    # data = []
                    # for j in list(shareinfo):
                    #     del j["secret_ids"]
                    #     del j["share_ids"]
                    #     del j["rights"]
                    #     j["shared_user_info"] = []
                    #     for em in j["users_mails"]:
                    #         fuser = users.find_one(
                    #             {"email" : em},
                    #             {"_id":0,"business_roles":0,"log_mode":0,"is_activated":0}
                    #         )
                    #         j["shared_user_info"].append(fuser)
                    #     del j["users_mails"]
                    #     del j["owner_uid"]
                    #     for ssi in j["shared_secret_info"]:
                    #         if secret["secret_id"] == ssi["secret_id"]:
                    #             j["rights"] = ssi["rights"]
                    #             break
                    #         # sinfo = secrets.find_one({"secret_id":ssi["secret_id"]})
                    #         # ssi["name"] = sinfo["name"]
                    #         # ssi["secret_type"] = sinfo["secret_type"]
                    #         # ssi["app_type"] = sinfo["app_type"]
                    #     del j["shared_secret_info"]
                    #     del j["type"]
                    #     data.append(j)
                    # secret["share_info"] = data
                """
            data['data'].append(secret)
        return jsonify({"status":"success", "data":data})
    except ValueError as error:
        print(traceback.format_exc())
        return jsonify({"message":"Parameters (page or per_page) must be integers greater than or equal to 1 ", "status": "failed"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong!", "status": "failed"}), 400

@SHARE_REQUEST.route('/types', methods=['GET'])
@seal_validator
def secretTypes():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        stf = st.find({}, {"_id":0})
        list_of_stf = []
        for secret in stf:
            list_of_stf.append(secret)
        return jsonify({"status":"success","data":list_of_stf})
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}), 400

@SHARE_REQUEST.route('/user/safe/all', methods=['GET'])
@seal_validator
@impersonate_middleware
def user_safe_all():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    try:
        # Get params of request
        params = request.args.to_dict()
        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page



        owner_uid = get_uid_by_token()
        owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})
        # user_safes = safes.find({"owner_uid":owner_uid}, {"_id": 0,})
        # This code is for pagination
        if params.get("shared", "false") == "true":
            query = {"receivers.receiver": owner["email"]}

            # Execute the query
            user_safes = list(db002.shared_safe.find(query, {"_id" : 0}).skip(skip_count).limit(per_page))

            # Print the results
            # for doc in user_safes:
            #     print(doc)
            # pass
        else:
            user_safes = safes.find({"owner_uid":owner_uid}, {"_id": 0,}).skip(skip_count).limit(per_page)
        total_user_safes = safes.count_documents({"owner_uid":owner_uid})
        last_page = math.ceil(total_user_safes / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('secret.user_safe_all', page=1, _external=True)

        # Générer l'URL de la dernière page
        last_page_url = url_for('secret.user_safe_all', page=last_page, _external=True)  if last_page >= 1 else None

        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('secret.user_safe_all', page=page + 1, _external=True) if page < last_page else None

        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('secret.user_safe_all', page=page - 1, _external=True) if page > 1 else None

        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_user_safes
        }

        """
        This code has been posted as a comment for inclusion in another special route.
        It also retrieves the list of safes shared with the user

        # found_shares = shares.find(
        #     {
        #         "owner_uid" : {"$ne":owner_uid},
        #         "users_mails" : {"$all" : [owner["email"]]},
        #         "type" : "safe"
        #     },
        #     {"_id" : 0}
        # )


        # for fs in found_shares:
        #     for fi in fs["safe_ids"]:
        #         safe_sh = safes.find_one({"safe_id" : fi}, {"_id": 0})
        #         safe_sh['total_secrets'] = total_secrets(safe_sh['safe_id'])
        #         data.append(safe_sh)

        """
        for us in user_safes:
            us['total_secrets'] = total_secrets(us['safe_id'])
            fshare = db002.shared_safe.find_one({"owner_uid" : owner_uid, "safe_id" : us['safe_id']}, {"_id" : 0, "receivers" : 1})#, "rights" : 
            us["share_info"] = None
            if fshare is not None:
                us["share_info"] = fshare
            if params.get("shared", "false") == "true":
                us["share_info"] = {}
                us["share_info"]["receivers"] = us["receivers"]
                us["name"] = us["safe_name"]
                us["date"] = db002.safe.find_one({"safe_id" : us["safe_id"]})["date"]
                del us["receivers"]
                del us["receiver"]
                del us["created_at"]
                del us["visibility"]
                del us["shared_safe_id"]
                del us["safe_name"]
            # data.append(us)
            # This code is for pagination
            data['data'].append(us)
        return jsonify({"status":"success", "data": data}),200
    except ValueError as error:
        print(traceback.format_exc())
        return jsonify({"message":"Parameters (page or per_page) must be integers greater than or equal to 1 ", "status": "failed"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

#NOTE  lors de la propagation le serveur airflow prends les valeurs déchiffrées des secrets pour faire sa propagation..
# on a retenu que le serveur airflow allait exécuté un secret/reveal pour chopper les données du secret déchiffrées
# sauf que le serveur airflow doit pouvoir se connecter a la base de donné qui elle est embarquée..
# du coup comment faire pour que le serveur airflow puisse acceder à cette base de données qui est local et embarquée
# doit on créer un nouveau binaire aussi dans le binaire de l'api? comme pour la base de données embarquées?

@SHARE_REQUEST.route('/propagate', methods=['POST'])
@seal_validator
@impersonate_middleware
def propagate():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        if not isErrorKey(req, "user_secret_id"):
            return jsonify({
                "status" : "failed",
                "message" : "user_secret_id is required"
            }), 400
        if not isErrorKey(req, "admin_secret_id"):
            return jsonify({
                "status" : "failed",
                "message" : "admin_secret_id is required"
            }), 400
        user_secret_id = req["user_secret_id"]
        admin_secret_id = req["admin_secret_id"]
        owner_uid = get_uid_by_token()
        user_secret_access_info = secret_access(user_secret_id, owner_uid)
        admin_secret_access_info = secret_access(admin_secret_id, owner_uid)
        if user_secret_access_info[0] and admin_secret_access_info[0]:
            if not user_secret_access_info[2]["propagate"] :
                return jsonify({
                    "status" : "failed",
                    "message" : "access denied, can't perform this action on the user_secret"
                }), 400
            else:
                if not user_secret_access_info[2]["owner"]:
                    check_result = check_attempts(user_secret_access_info, owner_uid)
                    if(not check_result[0]):
                        return check_result[1]
            if not admin_secret_access_info[2]["propagate"] :
                return jsonify({
                    "status" : "failed",
                    "message" : "access denied, can't perform this action on the admin_secret"
                }), 400
            else:
                if not admin_secret_access_info[2]["owner"]:
                    check_result = check_attempts(admin_secret_access_info, owner_uid)
                    if(not check_result[0]):
                        return check_result[1]
        else:
            return jsonify({
                "status" : "failed",
                "message" : "can't do propagation, secrets not found or access is denied"
            }), 400

        user_secret = secrets.find_one({"secret_id" : user_secret_id})
        if user_secret is None:
            return jsonify({"status":"failed", "message":"user_secret_id is incorrect or secret does not exist"}), 400
        else:
            typeuser = applications.find_one({"type": user_secret["app_type"]})
            if typeuser is None:
                errType = user_secret["app_type"]
                return jsonify({"status":"failed", "message": f"The propagation of the {errType} type is not supported by azumaril"}), 400

        admin_secret = secrets.find_one({"secret_id" : admin_secret_id})
        if admin_secret is None:
            return jsonify({"status":"failed", "message":"admin_secret_id is incorrect or secret does not exist"}), 400
        else:
            typeadm = applications.find_one({"type":admin_secret["app_type"]})
            if typeadm is None:
                errType = admin_secret["app_type"]
                return jsonify({"status":"failed", "message": f"The propagation of the {errType} type is not supported  by azumaril"}), 400
        if admin_secret["app_type"] != user_secret["app_type"]:
            return jsonify({"status":"failed", "message":"application type of the secrets are not of the same, can't propagate "+ user_secret["app_type"] + "to " + admin_secret["app_type"]}), 400

        if admin_secret["secret_type"] != user_secret["secret_type"]:
            return jsonify({"status":"failed", "message":"the secrets are not of the same type, can't propagate "+ user_secret["secret_type"] + "to " + admin_secret["secret_type"]}), 400

        if admin_secret["secret_type"] == "credentials":
            taskid = str(ObjectId())
            tasks.insert_one({
                "taskid" : taskid,
                "type" : admin_secret["app_type"]+"_propagate",
                "user_secret_id" : user_secret_id,
                "admin_secret_id" : admin_secret_id,
                "account_id":req["account_id"],
                "status":"pending"
            })
            run_dag(taskid)
            return jsonify({
                "status":"success",
                "message":"secret is now spreading"
            }),200
        else:
            sct = admin_secret["secret_type"]
            return jsonify({"message":f"the propagation of secret type {sct} is not yet supported by azumaril coming soon..", "status":"failed"}),400
    except:
        return jsonify({"message":"Something went wrong!", "status":"failed"}),400

@SHARE_REQUEST.route('/propagate_history', methods=['GET'])
@impersonate_middleware
def propagate_history():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]

    owner_uid = get_uid_by_token()
    # if not owner_uid:
    #     return jsonify({"message": "Please log In again", "status":"failed"}),401

    params = request.args.to_dict()

    # per_page is the number of elements per page
    per_page = int(params.get('per_page', 10))
    # page is the number of page where you want to get
    page = int(params.get('page', 1))
    # skip count for know how element we must skip based on per_page and page
    skip_count = (page - 1) * per_page

    total_user_history = phistory.count_documents({"uid": owner_uid})

    last_page = math.ceil(total_user_history / per_page)

    # Générer l'URL de la première page
    first_page_url = url_for('secret.propagate_history', page=1, _external=True)

    # Générer l'URL de la dernière page
    last_page_url = url_for('secret.propagate_history', page=last_page, _external=True)  if last_page >= 1 else None

    # Générer l'URL de la page suivante (si disponible)
    next_page_url = url_for('secret.propagate_history', page=page + 1, _external=True) if page < last_page else None

    # Générer l'URL de la page précédente (si disponible)
    prev_page_url = url_for('secret.propagate_history', page=page - 1, _external=True) if page > 1 else None

    userHistory = {
        "data": [],
        "per_page": per_page,
        "current_page": page,
        "last_page": last_page,
        "first_page_url": first_page_url,
        "last_page_url": last_page_url,
        "next_page_url": next_page_url,
        "prev_page_url": prev_page_url,
        "total": total_user_history
    }

    try:
        History = phistory.find({"uid": owner_uid}).skip(skip_count).limit(per_page)
        for doc in History:
            sec_name = secrets.find_one({"secret_id":doc["secret_id"] })
            if sec_name is not None:
                # doc["date"] = doc["date"].strftime('%Y-%m-%d')
                print(doc)
                doc["name"] = sec_name["name"]
                del doc["_id"]
                userHistory["data"].append(doc)
            elif sec_name is None:
                phistory.delete_one({'_id' : doc.get('_id', '')})
        results = {
            "status": "success",
            "data": userHistory,
        }
        return jsonify(results),200
    except ValueError:
        print(traceback.format_exc())
        return jsonify({"message":"Parameters (page or per_page) must be integers greater than or equal to 1 ", "status": "failed"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong !", "status":"failed"}),400

@SHARE_REQUEST.route('/find', methods=['GET'])
@seal_validator
@impersonate_middleware
def find_secret_by_name():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    owner_uid = get_uid_by_token()
    try:
        import re
        params = request.args.to_dict()
        safe_id = params.get('safe_id', None)
        name = params.get('name', None)
        if not safe_id:
            return error_response(message="Please provide a safe id")
        if not name:
            return error_response(message="Name not provided. Please try again")

        regex = re.compile('.*{}.*'.format(re.escape(name)), re.IGNORECASE)

        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page

        secrets_found = secrets.find({'owner_uid': owner_uid, 'name': {'$regex': regex}}, {"_id": 0, "secret" : 0}).skip(skip_count).limit(per_page)

        total_secrets_found = secrets.count_documents({'owner_uid': owner_uid, 'name': {'$regex': regex}})

        last_page = math.ceil(total_secrets_found / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('secret.find_secret_by_name', name=name, page=1, _external=True)

        # Générer l'URL de la dernière page
        last_page_url = url_for('secret.find_secret_by_name', name=name, page=last_page, _external=True)  if last_page >= 1 else None

        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('secret.find_secret_by_name', name=name, page=page + 1, _external=True) if page < last_page else None

        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('secret.find_secret_by_name', name=name, page=page - 1, _external=True) if page > 1 else None

        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_secrets_found
        }
        for secret in list(secrets_found):
            secret["date"] = secret["date"].strftime('%Y-%m-%d')
            data["data"].append(secret)
        return success_response(data=data)
    except Exception as error:
        return error_response(message=str(error))

@SHARE_REQUEST.route('/safe/find', methods=['GET'])
@seal_validator
@impersonate_middleware
def find_safe_by_name():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    owner_uid = get_uid_by_token()
    try:
        import re
        params = request.args.to_dict()
        name = params.get('name', None)
        if not name:
            return error_response(message="Name not provided. Please try again")

        regex = re.compile('.*{}.*'.format(re.escape(name)), re.IGNORECASE)

        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page

        safes_found = safes.find({'owner_uid': owner_uid, 'name': {'$regex': regex}}, {"_id": 0}).skip(skip_count).limit(per_page)

        total_safes_found = safes.count_documents({'owner_uid': owner_uid, 'name': {'$regex': regex}})

        last_page = math.ceil(total_safes_found / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('secret.find_safe_by_name', name=name, page=1, _external=True)

        # Générer l'URL de la dernière page
        last_page_url = url_for('secret.find_safe_by_name', name=name, page=last_page, _external=True)  if last_page >= 1 else None

        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('secret.find_safe_by_name', name=name, page=page + 1, _external=True) if page < last_page else None

        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('secret.find_safe_by_name', name=name, page=page - 1, _external=True) if page > 1 else None

        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_safes_found
        }
        for safe in list(safes_found):
            safe["date"] = safe["date"].strftime('%Y-%m-%d')
            safe['total_secrets'] = total_secrets(safe['safe_id'])
            data["data"].append(safe)
        return success_response(data=data)
    except Exception as error:
        return error_response(message=str(error))


@SHARE_REQUEST.route('/share', methods=['POST'])
@seal_validator
@leader_validator
@impersonate_middleware
def secret_sharing():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    if isErrorKey(req, "rights") :
        rights = req["rights"]
    if isErrorKey(req, "policie_id") :
        policie_id = req["policie_id"]
        found_policie = policies.find_one({"policie_id" : policie_id})
        if found_policie is None:
            return jsonify({
                "status" : "success",
                "message" : "policie not found"
            }), 404
        rights = found_policie["rights"]
    users_mails = req["users_mails"]
    if isErrorKey(req, "attempts") :
        attempts = req["attempts"]
    else:
        attempts = None
    #NOTE Tell user if users_mail is empty array or contain invalid emails
    # if(len(users_mails==0)): #Altara01*
    #     return jsonify({
    #         "message":" users_mail can not be an empty array "
    #     }), 400
    # if "" in users_mails:
    #     return jsonify({
    #         "message":"Invalid email found in users_mail"
    #     }), 400
    users_mails = list(dict.fromkeys(users_mails))
    secret_ids = req["secret_ids"]
    secret_ids = list(dict.fromkeys(secret_ids))
    owner_uid = get_uid_by_token()
    attempts_info = []
    try:
        shared_secret_info = []
        fuser_email = users.find_one({"uid" : owner_uid}, {"email" : 1})["email"]
        users_uid = []
        clean_users_mails = [] #will contain users that pass the first verification
        #VERIFICATION--------------------------------------------------------------------------------------------------------------
        for um in users_mails:      #check if emails are existing in the db
            fuser = users.find_one({"email" : {"$regex": f"^{um}$", "$options": "i"}}, {"uid" : 1, "email" : 1, "_id" : 0})
            if fuser is None:
                fuser = users.find_one({"uid" : {"$regex": f"^{um}$", "$options": "i"}}, {"uid" : 1, "email" : 1, "_id" : 0})
                if fuser is None:
                    if config_data["LDAP"]:
                        found_user = search_user_info(um, True)
                        if found_user is None:
                            continue
                        fuser_uid = um
                        users_mails.remove(um)
                        mail = config_data["LDAP_USER_ATTRIBUTES"]["email"]
                        um = found_user.get(mail, "")
                        users_mails.append(found_user.get(mail, ""))
                    else:
                        continue
                else:
                    fuser_uid = um
                    users_mails.remove(um)
                    um = fuser["email"]
                    users_mails.append(fuser["email"])
            else:
                fuser_uid = fuser["uid"]
                um = fuser["email"]
            users_uid.append(fuser_uid)
            if um == fuser_email:
                return jsonify({
                    "status" : "failed",
                    "message" : f"user can't share secret to himself"
                }), 400
            attempts_info.append(
                {
                    "uid" : fuser_uid,
                    "email" : um,
                    "attempts" : attempts
                }
            )
            clean_users_mails.append(um)
        if len(clean_users_mails) == 0:
            return jsonify({
                "status" : "failed",
                "message" : "user with emails provided were not found"
            }), 404
        #NOTE Check if a user in the list doesn't already have access to a secret being shared
        if len(secret_ids) == 0 :       #at least one secret must be provided to make a share
            return jsonify({
                "status" : "failed",
                "message" : "at least one secret must be provided"
            }), 400
        owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})       #get connected user email
        for u in clean_users_mails:
            for s in secret_ids:
                share_concerning_secret = shares.find_one({ "secret_ids": s, "users_mails":u }) #Check if a share with the secret and the user doesn't already exists
                if share_concerning_secret is None:
                    message = f"User {owner['email']} share secret with you"
                    azumaril_secret_share_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('azumaril_secret_share', None)
                    if os.path.exists(azumaril_secret_share_html_path):
                        with open(azumaril_secret_share_html_path, "r", encoding='utf-8') as f:
                            message = f.read().replace("email", f"{str({owner['email']})}")
                            f.close()
                    Thread(target = mail_sender, args=(
                        u, 
                        f"Azumaril secret share", 
                        message,
                        )).start()
                    continue
                current_user_id = users.find_one({ "email": u })["uid"]
                users_uid.remove(current_user_id)
                break
        if len(users_uid)==0:
            return jsonify({
                "status":"failed",
                "message":"User has already access to this secret"
            }), 400


        if len(secret_ids) == 0 :       #at least one secret must be provided to make a share
            return jsonify({
                "status" : "failed",
                "message" : "at least one secret must be provided"
            }), 400
        if len(users_mails) == 0 :      #at least one email must be provided to make a share
            return jsonify({
                "status" : "failed",
                "message" : "at least one email must be provided"
            }), 400
        for k,v in rights.items():      #check if rights object is corrected provided with value like true or false
            if v != True and v != False:
                return jsonify({
                    "status" : "failed",
                    "message" : "the value of rights dict must be true or false"
                }), 400
            if not (k in ["read", "write", "share", "delete", "propagate"]):
                return jsonify({
                    "status" : "failed",
                    "message" : f"{k} is not a right, the rights are read and write"
                }), 400
        #--------------------------------------------------------------------------------------------------------------------------

        share_id = str(ObjectId())
        # original_share_id = share_id
        share_ids = [share_id]
        for sid in secret_ids:          #check access rights of every secret we want to share
            for fusers_uid in users_uid:
                fsecret = secrets.find_one({"owner_uid" : fusers_uid, "secret_id" : sid})
                if fsecret is not None:
                    fuser_email = users.find_one({"uid" : fusers_uid}, {"email" : 1})["email"]
                    return jsonify({
                        "status" : "failed",
                        "message" : f"user with this email {fuser_email} have already access to the secret(s)"
                    }), 400
            secret_access_info = secret_access(sid, owner_uid)
            if secret_access_info[0] :
                if not secret_access_info[2]["share"] :     #if right share is not allowed for one of the secrets
                    return jsonify({
                        "status" : "failed",
                        "message" : f"can't perform this action on secret {sid}, access denied"
                    }), 401
                else:
                    if not secret_access_info[2]["owner"]:
                        check_result = check_attempts(secret_access_info, owner_uid)
                        if(not check_result[0]):
                            return check_result[1]
                ssi_rights = rights
                if not secret_access_info[2]["owner"] :     #if the connected user is not the owner of the secrets restrict access rights

                    ssi_rights = secret_access_info[2]
                    del ssi_rights["owner"]
                    del ssi_rights["all"]
                    for k,v in rights.items():
                        if ssi_rights[k]:
                            ssi_rights[k] = v
                    share_ids.extend(secret_access_info[3])
                    # original_share_id = secret_access_info[3]
                shared_secret_info.append({
                    "secret_id" : sid,
                    "rights" : ssi_rights
                })
            else:       #if the secrets are not found or access is denied
                return jsonify({
                    "status" : "failed",
                    "message" : f"can't perform this action on secret {sid}, secret not found or access is denied"
                }), 400
        share_ids = list(dict.fromkeys(share_ids))
        message_mail = ""
        for um in users_mails:
            message_mail += f"{um},"
        share_info = {
            "owner_uid" : owner_uid,
            "type" : "secret",
            "share_id" : share_id,
            "users_mails" : users_mails,
            "secret_ids" : secret_ids,
            "shared_secret_info" : shared_secret_info,      #all the shared secrets and thier access rights
            "rights" : rights,
            # "original_share_id" : original_share_id,
            "attempts" : attempts,
            "attempts_info" : attempts_info,
            "share_ids" : share_ids
        }
        shares.insert_one(share_info)
        del share_info["_id"]
        return jsonify({
            "status" : "success",
            "message" : f"secret successfully shared with {message_mail[:-1]}",
            "data" : share_info
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@SHARE_REQUEST.route('/safe/share', methods=['POST'])
@seal_validator
@leader_validator
@impersonate_middleware
def safe_sharing():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    if isErrorKey(req, "rights") :
        rights = req["rights"]
    if isErrorKey(req, "policie_id") :
        policie_id = req["policie_id"]
        found_policie = policies.find_one({"policie_id" : policie_id})
        rights = found_policie["rights"]
    users_mails = req["users_mails"]
    safe_ids = req["safe_ids"]
    owner_uid = get_uid_by_token()
    try:
        shared_safe_info = []
        fuser_email = users.find_one({"uid" : owner_uid}, {"email" : 1})["email"]
        users_uid = []
        #VERIFICATION--------------------------------------------------------------------------------------------------------------
        for um in users_mails:      #check if emails are existing in the db
            fuser_uid = users.find_one({"email" : um}, {"uid" : 1})["uid"]
            users_uid.append(fuser_uid)
            if um == fuser_email:
                return jsonify({
                    "status" : "failed",
                    "message" : f"user can't share safe to himself"
                }), 400
            if users.find_one({"email" : um}) is None:
                return jsonify({
                    "status" : "failed",
                    "message" : f"user with this email {um} not found"
                }), 404
        owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})       #get connected user email
        for um in users_mails :
            message = f"User {owner['email']} share safe with you"
            azumaril_safe_share_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('azumaril_safe_share', None)
            if os.path.exists(azumaril_safe_share_html_path):
                with open(azumaril_safe_share_html_path, "r", encoding='utf-8') as f:
                    message = f.read().replace("email", f"{str({owner['email']})}")
                    f.close()
            Thread(target = mail_sender, args=(
                um,
                f"Azumaril safe share",
                message,
                )).start()
        if len(safe_ids) == 0 :       #at least one secret must be provided to make a share
            return jsonify({
                "status" : "failed",
                "message" : "at least one safe must be provided"
            }), 400
        if len(users_mails) == 0 :      #at least one email must be provided to make a share
            return jsonify({
                "status" : "failed",
                "message" : "at least one email must be provided"
            }), 400
        for k,v in rights.items():      #check if rights object is corrected provided with value like true or false
            if v != True and v != False:
                return jsonify({
                    "status" : "failed",
                    "message" : "the value of rights dict must be true or false"
                }), 400
            if not (k in ["read", "write", "share", "delete", "propagate"]):
                return jsonify({
                    "status" : "failed",
                    "message" : f"{k} is not a right, the rights are read and write"
                }), 400
        #--------------------------------------------------------------------------------------------------------------------------

        share_id = str(ObjectId())
        share_ids = [share_id]
        for sid in safe_ids:          #check access rights of every safe we want to share
            for fusers_uid in users_uid:
                fsafe = safes.find_one({"owner_uid" : fusers_uid})
                if fsafe is not None:
                    fuser_email = users.find_one({"uid" : fusers_uid}, {"email" : 1})["email"]
                    return jsonify({
                        "status" : "failed",
                        "message" : f"user with this email {fuser_email} have already access to the safe(s)"
                    }), 400
            safe_access_info = safe_access(sid, owner_uid)
            if safe_access_info[0] :
                if not safe_access_info[2]["share"] :     #if right share is not allowed for one of the safes
                    return jsonify({
                        "status" : "failed",
                        "message" : f"can't perform this action on safe {sid}, access denied"
                    }), 401
                ssi_rights = rights
                if not safe_access_info[2]["owner"] :     #if the connected user is not the owner of the safes, restrict access rights
                    ssi_rights = safe_access_info[2]
                    del ssi_rights["owner"]
                    del ssi_rights["all"]
                    for k,v in rights.items():
                        if ssi_rights[k]:
                            ssi_rights[k] = v
                    share_ids.extend(safe_access_info[3])
                shared_safe_info.append({
                    "safe_id" : sid,
                    "rights" : ssi_rights
                })
            else:       #if the secrets are not found or access is denied
                return jsonify({
                    "status" : "failed",
                    "message" : f"can't perform this action on safe {sid}, safe not found or access is denied"
                }), 400
        share_ids = list(dict.fromkeys(share_ids))
        message_mail = ""
        for um in users_mails:
            message_mail += f"{um},"
        share_info = {
            "owner_uid" : owner_uid,
            "type" : "safe",
            "share_id" : share_id,
            "users_mails" : users_mails,
            "safe_ids" : safe_ids,
            "shared_safe_info" : shared_safe_info,      #all the shared secrets and thier access rights
            "rights" : rights,
            # "original_share_id" : original_share_id,
            "share_ids" : share_ids
        }
        shares.insert_one(share_info)
        del share_info["_id"]
        return jsonify({
            "status" : "success",
            "message" : f"safe successfully shared with {message_mail[:-1]}",
            "data" : share_info
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@SHARE_REQUEST.route('/share/update', methods=['PUT'])
@seal_validator
@leader_validator
@impersonate_middleware
def secret_sharing_update():
    validated = validation(required_keys=["share_id"])
    if not validated[0]:
        return validated[1]
    req = validated[1]
    share_id = req["share_id"]
    try:
        owner_uid = get_uid_by_token()
        found_share = shares.find_one({"share_id" : share_id, "owner_uid" : owner_uid}, {"_id":0})
        if found_share is None:
            return jsonify({
                "status" : "failed",
                "message" : "share not found"
            }), 404
        rights = found_share["rights"]
        users_mails = found_share["users_mails"]
        secret_ids = found_share["secret_ids"]
        data_to_update = req
        if isErrorKey(req, "removed_emails"):
            pass
        if isErrorKey(req, "rights"):
            rights = req["rights"]
        if isErrorKey(req, "policie_id"):
            found_policie = policies.find_one({"policie_id" : req['policie_id'], "owner_uid" : owner_uid})
            if found_policie is None:
                return jsonify({
                    "status" : "failed",
                    "message" : f"policie {req['policie_id']} not found"
                }), 404
            rights = found_policie["rights"]
        if isErrorKey(req, "users_mails"):
            users_mails = req["users_mails"]
            clean_mails = []
            attempts_info = []
            for um in users_mails:      #check if emails are existing in the db
                receiver_info = users.find_one({"email" : um})
                if receiver_info is None:
                    receiver_info = users.find_one({"uid" : um})
                    if receiver_info is None:
                        continue
                    else:
                        um = receiver_info["email"]
                attempts_info.append(
                    {
                        "uid" : receiver_info["uid"],
                        "email" : receiver_info["email"],
                        "attempts" : found_share["attempts"]
                    }
                )
                clean_mails.append(um)
                if not (um in found_share["users_mails"]):
                    message = f"User {owner['email']} share secret with you"
                    azumaril_secret_share_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('azumaril_secret_share', None)
                    if os.path.exists(azumaril_secret_share_html_path):
                        with open(azumaril_secret_share_html_path, "r", encoding='utf-8') as f:
                            message = f.read().replace("email", f"{str({owner['email']})}")
                            f.close()
                    Thread(target = mail_sender, args=(
                        um, 
                        f"Azumaril secret share", 
                        message,
                        )).start()
            data_to_update["users_mails"] = list(set(found_share["users_mails"] + clean_mails))
            data_to_update["attempts_info"] = attempts_info
            
            owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})       #get connected user email
            # for um in users_mails :
            #     if not (um in found_share["users_mails"]):
            #         Thread(target = mail_sender, args=(um, f"Azumaril secret share", f"User {owner['email']} share secret with you",)).start()
        if isErrorKey(req, "secret_ids"):
            secret_ids = req["secret_ids"]
        if isErrorKey(req, "rights") or isErrorKey(req, "secret_ids") or isErrorKey(req, "policie_id"):
            ssi = shared_secret_info(secret_ids, owner_uid, rights)
            if ssi[0]:
                data_to_update["shared_secret_info"] = ssi[1]
                data_to_update["rights"] = rights
            else:
                return jsonify({
                    "status" : "failed",
                    "message" : "secret not found" if ssi[1] == 404 else "access denied"
                }), ssi[1]
        del data_to_update["share_id"]
        shares.find_one_and_update(
            {"share_id" : share_id},
            {
                "$set":data_to_update
            }
        )
        found_share = shares.find_one({"share_id" : share_id, "owner_uid" : owner_uid}, {"_id":0})
        #update every share---
        other_share_to_update = shares.find({       #all shares where this share secret where found
            "share_id" : {"$ne" : share_id},
            "share_ids" : {"$in" : [share_id]}
        },{"_id" : 0})
        for ostu in other_share_to_update:
            for obj in ostu["shared_secret_info"]:
                if obj["secret_id"] in found_share["secret_ids"] :
                    # ostu["rights"] = found_share["rights"]
                    ssi_rights = found_share["rights"]
                    for k,v in ostu["rights"].items():
                        if ssi_rights[k]:
                            ssi_rights[k] = v
                    obj["rights"] = ssi_rights
            shares.update_one(
                {"share_id" : ostu["share_id"]},
                {
                    "$set" : ostu
                }
            )
            ostu_share_id = ostu["share_id"]
            shared_secret_info(ostu["secret_ids"], owner_uid, rights)
        #---
        # found_share = shares.find_one({"share_id" : share_id}, {"_id":0})
        return jsonify({
            "status" : "success",
            "message" : f"share successfully updated",
            "data" : parse_json(found_share)
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@SHARE_REQUEST.route('/safe/share/update', methods=['PUT'])
@seal_validator
@impersonate_middleware
def safe_sharing_update():
    validated = validation(required_keys=["share_id"])
    if not validated[0]:
        return validated[1]
    req = validated[1]
    share_id = req["share_id"]
    try:
        owner_uid = get_uid_by_token()
        found_share = shares.find_one({"share_id" : share_id, "owner_uid" : owner_uid}, {"_id":0})
        if found_share is None:
            return jsonify({
                "status" : "failed",
                "message" : "share not found"
            }), 404
        rights = found_share["rights"]
        users_mails = found_share["users_mails"]
        safe_ids = found_share["safe_ids"]
        data_to_update = req
        if isErrorKey(req, "rights"):
            rights = req["rights"]
        if isErrorKey(req, "policie_id"):
            found_policie = policies.find_one({"policie_id" : req['policie_id'], "owner_uid" : owner_uid})
            if found_policie is None:
                return jsonify({
                    "status" : "failed",
                    "message" : f"policie {req['policie_id']} not found"
                }), 404
            rights = found_policie["rights"]
        if isErrorKey(req, "users_mails"):
            users_mails = req["users_mails"]
            for um in users_mails:      #check if emails are existing in the db
                if users.find_one({"email" : um}) is None:
                    return jsonify({
                        "status" : "failed",
                        "message" : f"user with this email {um} not found"
                    }), 404
            owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})       #get connected user email
            for um in users_mails :
                if not (um in found_share["users_mails"]):
                    message = f"User {owner['email']} share secret with you"
                    azumaril_secret_share_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('azumaril_secret_share', None)
                    if os.path.exists(azumaril_secret_share_html_path):
                        with open(azumaril_secret_share_html_path, "r", encoding='utf-8') as f:
                            message = f.read().replace("email", f"{str({owner['email']})}")
                            f.close()
                    Thread(target = mail_sender, args=(
                        um, 
                        f"Azumaril secret share", 
                        message,
                        )).start()
        if isErrorKey(req, "safe_ids"):
            safe_ids = req["safe_ids"]
        if isErrorKey(req, "rights") or isErrorKey(req, "safe_ids") or isErrorKey(req, "policie_id"):
            ssi = shared_safe_info(safe_ids, owner_uid, rights)
            if ssi[0]:
                data_to_update["shared_safe_info"] = ssi[1]
            else:
                return jsonify({
                    "status" : "failed",
                    "message" : "secret not found" if ssi[1] == 404 else "access denied"
                }), ssi[1]
        del data_to_update["share_id"]
        shares.find_one_and_update(
            {"share_id" : share_id},
            {
                "$set":data_to_update
            }
        )
        found_share = shares.find_one({"share_id" : share_id, "owner_uid" : owner_uid}, {"_id":0})
        #update every share---
        other_share_to_update = shares.find({       #all shares where this share secret where found
            "share_id" : {"$ne" : share_id},
            "share_ids" : {"$in" : [share_id]}
        },{"_id" : 0})
        for ostu in other_share_to_update:
            for obj in ostu["shared_safe_info"]:
                if obj["safe_id"] in found_share["safe_ids"] :
                    # ostu["rights"] = found_share["rights"]
                    ssi_rights = found_share["rights"]
                    for k,v in ostu["rights"].items():
                        if ssi_rights[k]:
                            ssi_rights[k] = v
                    obj["rights"] = ssi_rights
            shares.update_one(
                {"share_id" : ostu["share_id"]},
                {
                    "$set" : ostu
                }
            )
            ostu_share_id = ostu["share_id"]
            shared_safe_info(ostu["safe_ids"], owner_uid, rights)
        #---
        # found_share = shares.find_one({"share_id" : share_id}, {"_id":0})
        return jsonify({
            "status" : "success",
            "message" : f"share successfully updated",
            "data" : parse_json(found_share)
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@SHARE_REQUEST.route('/share/delete', methods=['DELETE'])
@seal_validator
@leader_validator
@impersonate_middleware
def secret_sharing_delete():
    validated = validation(required_keys=["share_id"])
    if not validated[0]:
        return validated[1]
    req = validated[1]
    share_id = req["share_id"]
    owner_uid = get_uid_by_token()
    try:
        found_share = shares.find_one({"share_id" : share_id, "owner_uid" : owner_uid})
        if found_share is None:
            return jsonify({
                "status" : "failed",
                "message" : "share not found"
            }), 404
        shares.delete_one({"share_id" : share_id, "owner_uid" : owner_uid})
        return jsonify({
           "status" : "success",
           "message" : "share successfully deleted"
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@SHARE_REQUEST.route('/share/all', methods=['GET'])
@seal_validator
@impersonate_middleware
def secret_sharing_all():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    owner_uid = get_uid_by_token()
    try:
        args = request.args
        req = args.to_dict()
        data = []
        if isErrorKey(req, "type"):
            if req["type"] != "sharer" and req["type"] != "receiver":
                return jsonify({
                    "status" : "failed",
                    "message" : f"type is sharer or receiver but {req['type']} was provided"
                }), 400
            if req["type"] == "sharer":
                all_shares = shares.find(
                    {
                        "owner_uid" : owner_uid,
                        'type': {'$ne': 'new_format'}
                    },
                    {"_id" : 0}
                )
            if req["type"] == "receiver":
                owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})
                if owner is None:
                    all_shares = []
                else:
                    # all_shares = shares.find(
                    #     {
                    #         "users_mails" : {"$all" : [owner["email"]]},
                    #         'type': {'$ne': 'new_format'}
                    #     },
                    #     {"_id" : 0}
                    # )
                    all_shares = shares.find(
                        {
                            "users_mails": {
                                "$elemMatch": {
                                    "$regex": f"^{owner['email']}$", 
                                    "$options": "i"
                                }
                            },
                            'type': {'$ne': 'new_format'}
                        },
                        {"_id": 0}
                    )
        else:
            sharreds = shares.find(
                {
                    "owner_uid" : owner_uid,
                    'type': {'$ne': 'new_format'}
                },
                {"_id" : 0}
            )
            owner = users.find_one({"uid" : owner_uid}, {"_id":0, "email":1})
            all_shared_with_me = shares.find(
                {
                    "users_mails" : {"$all" : [owner["email"]]},
                    'type': {'$ne': 'new_format'}
                },
                {"_id" : 0}
            )
            all_shares = list(sharreds) + list(all_shared_with_me)
        for j in all_shares:
            for to_check in ["secret_ids", "users_mails", "type", "rights"]:
                if to_check in j:
                    del j[to_check]

            for receiver_secret in j.get("attempts_info", []):
                fuser = users.find_one(
                    {"uid" : receiver_secret["uid"]},
                    {"_id":0,"business_roles":0,"log_mode":0,"is_activated":0}
                )
                if fuser:
                    receiver_secret['firstname'] = fuser.get('firstname', None)
                    receiver_secret['lastname'] = fuser.get('lastname', None)

            fuser = users.find_one(
                {"uid" : j["owner_uid"]},
                {"_id":0,"business_roles":0,"log_mode":0,"is_activated":0}
            )
            j["owner_info"] = fuser
            del j["owner_uid"]
            to_remove = []
            if "shared_secret_info" not in j:
                continue
                # j["shared_secret_info"] = []
            for ssi in j["shared_secret_info"]:
                sinfo = secrets.find_one({"secret_id":ssi["secret_id"]})
                if sinfo is None:
                    to_remove.append(ssi)
                    continue
                ssi["name"] = sinfo.get("name", None)
                ssi["secret_type"] = sinfo["secret_type"]
                ssi["file_type"] = sinfo.get("file_type", None)
                ssi["app_type"] = sinfo.get("app_type", None)
            for tr in to_remove:
                # Pourquoi ca fais a maintenant ? Les cles la existe pourtant Oubien ton secret est corrompu
                j["shared_secret_info"].remove(tr)
            data.append(j)
        # data.reverse()
        data = data[::-1]
        return jsonify({
            "status" : "success",
            "message" : "",
            "data" : data #parse_json(all_shared_secrets)
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

#TODO Supprimer un secret
@SHARE_REQUEST.route('/safe/delete', methods=['DELETE'])
@seal_validator
@leader_validator
@impersonate_middleware
def delete_safe():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    owner_uid = get_uid_by_token()
    try:
        req = validated[1]
        print(req)
        fuser = users.find_one({"uid" : owner_uid})
        if( fuser is None ):
            return jsonify({
                "message":"User not authenticated"
            }), 401
        if (not isErrorKey(req, "safe_name")):
            return jsonify({
                "message":"safe_name is a required parameter"
            }), 400
        safe_name = req["safe_name"]
        fsafe = safes.find_one({
            "name":safe_name,
            "owner_uid": owner_uid
        })
        if(fsafe is None ):
            return jsonify({
                "message":"Safe not found"
            }), 404
        safe_type = fsafe.get("type", None)
        is_system = True if safe_type is not None and safe_type == "system" else False
        if is_system:
            return jsonify({
                "status" : "failed",
                "message" : "not allowed"
            }), 403
        delete_result = delete_safe_util(owner_uid, fsafe["safe_id"])
        if(not delete_result):
            return jsonify({
                "message":"Safe not deleted, something went wrong"
            }), 500
        return jsonify({
            "message":"Safe deleted successfully"
        }), 200
    except:
        print(traceback.format_exc())
        return jsonify({
            "message":"Something went wrong"
        }), 500
    
