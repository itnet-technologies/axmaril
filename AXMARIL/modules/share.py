import json
import os
import shutil
import requests
import traceback
from base64 import b64encode
from json import dumps
from threading import Thread
# from turtle import right
from flask import jsonify, Blueprint,request
# from pymongo import MongoClient
from modules.required_packages import (
    encode_token, has_role, mail_sender, parse_json, safe_access, secret_access, 
    secrets, users, shares, decrypt, encrypt, get_userid_by_token, isErrorKey, run_dag,
    validation, salt, jwt, client, db002, file_server_url, delete_safe_util, tokens, check_required_keys,
    verify_dict_keys, handleRequestToGetUserUid
)
from bson import ObjectId
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from pathlib import Path

from modules.required_packages import success_response, error_response

SHARE_REQUEST = Blueprint("share", __name__)

tasks = db002["tasks"]
safes = db002["safe"]
creds = db002["creds"]
policies = db002["policies"]
account = db002["account"]
applications = db002["applications"]
st = db002["secret_type"]
phistory = db002["propagate_history"]

# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2ODc4MDQ2MDYsImlhdCI6MTY4NzE5OTgwNiwic3ViIjoiMDAwMDEyNyJ9.26BnJyjIGBL-p9M2-8Bo7_DHMmfZ2WZWgj6M_9MEcw8

@SHARE_REQUEST.route('/secret/vtest', methods=['POST'])
def better_secret_sharing():
    try:
        validated= validation(required_keys=[], allowNullData=False)
        if not validated[0]:
            return validated[1]
        req = validated[1]
        
        # Get owner of request
        owner_uid = get_userid_by_token()
        owner = users.find_one({"uid" : owner_uid})
        if not owner:
            return error_response(message="Unable to perfom this action. Something went wrong.", code=500) 
        
        #Get data from request body
        users_mails = req.get("users_mails", [])
        rights = req.get("rights", [])
        secret_ids = req.get("secret_ids", [])
        policie_id = req.get("policie_id", None)
        attempts = req.get("attempts", 0)
        
        at_least_one_shared = False

        # Check validity of datas
        # Don't need to check attempts value. If it's not provided the default value is 0 and the atempts is illimited
        # If the policie_id field is supplied and found in the database, the rights used will be those defined otherwise the right field will be taken into account. 
        
    
        # Check if secret ids is provided in data
        if not secret_ids:
            return error_response(message="Secret ids not provided")

        # Check is policy is provided in data
        if policie_id:
            found_policie = policies.find_one({"policie_id" : policie_id})
            if not found_policie:
                return error_response(message="Policie not found", code=404)

            # Init rights with policy right
            rights = found_policie.get("rights", [])

        # If rights is still empty throw error
        if not rights:
            return error_response(message="Rights not provided")
        
        # Check validity of rights
        allowed_rights = ["read", "write", "share", "delete", "propagate"]
        if not (verify_dict_keys(rights, allowed_rights, bool)):
            return error_response(message="Please define the right rights. If you use policies please update this last one.")

        # Check if users_mails is provided in data
        if not users_mails:
            return error_response(message="User mails not provided")
        
        # Delete same multiple secrets ids
        secret_ids = list(dict.fromkeys(secret_ids))
        
        # Check if user is the owner of alls secrets
        for secret in secret_ids:
            secret_retrieve = secrets.find_one({"owner_uid": owner_uid, "secret_id": secret})
            if not secret_retrieve:
                secret_ids.remove(secret)
                
        # If after clean secret list, the list is empty...
        if not any(secret_ids):
            return error_response(message="Please provide a valid secret to share")
        
        # ------ Step to get users from emails provided  ------  #

        # Delete multiple same email in table
        users_mails = list(dict.fromkeys(users_mails))
        
        # Delete owner from list if he is in the list
        if owner.get('email', '') in users_mails:
            users_mails.remove(owner.get('email', ''))

        # Delete users that not existe in database
        
        for user in users_mails:
            user_retrieve = users.find_one({"email": user})
            if not user_retrieve:
                users_mails.remove(user)
                
        # If after clean user mails receivers the list is empty...
        if not any(users_mails):
            return error_response(message="Please provide a valid emails")
                
        # ------ Step to share secret   ------  #
        # But before share one  secret with someone 
        # we'll check if this user don't already have access to this secret
        
        for user in users_mails:
            user_retrieve = users.find_one({"email": user}, {"email": 1, "firstname": 1, "lastname": 1, "uid": 1})
            if user_retrieve:
                for secret in secret_ids:
                    secret_retrieve = secrets.find_one({"secret_id": secret})
                    if secret_retrieve:
                        have_access_to_secret = shares.find_one({
                            "receiver_mail": user_retrieve.get('email'),
                            "secret_id": secret_retrieve.get('secret_id'),
                        })
                        have_access_to_safe_of_secret = shares.find_one({
                            "receiver_mail": user_retrieve.get('email'),
                            "safe_id": secret_retrieve.get('safe_id'),
                        })
                        if not have_access_to_secret and not have_access_to_safe_of_secret:
                            share_new_secret = {
                                "share_id" : str(ObjectId()),
                                "owner_uid": owner.get('uid'),
                                "receiver_mail": user_retrieve.get('email'),
                                "type": "new_format",
                                "share_type": "secret",
                                "secret_id": str(secret_retrieve.get('secret_id')),
                                "rights": rights,
                                "created_at": datetime.utcnow(),
                                "updated_at": datetime.utcnow(),
                            }
                            shares.insert_one(share_new_secret)
                            at_least_one_shared = True
        if at_least_one_shared:
            return success_response(message=f"Succesfull share secret with {' '.join(users_mails)}")
        return error_response(message=f"Shared secrets are already shared with the user")
    except Exception as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))
    except ValueError as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))

@SHARE_REQUEST.route('/safe/vtest', methods=['POST'])
def better_safe_sharing():
    try:
        validated= validation(required_keys=[], allowNullData=False)
        if not validated[0]:
            return validated[1]
        req = validated[1]
        
        # Get owner of request
        owner_uid = get_userid_by_token()
        owner = users.find_one({"uid" : owner_uid})
        if not owner:
            return error_response(message="Unable to perfom this action. Something went wrong.", code=500) 
        
        #Get data from request body
        users_mails = req.get("users_mails", [])
        rights = req.get("rights", [])
        safe_ids = req.get("safe_ids", [])
        policie_id = req.get("policie_id", None)
        attempts = req.get("attempts", 0)
        
        at_least_one_shared = False

        # Check validity of datas
        # Don't need to check attempts value. If it's not provided the default value is 0 and the atempts is illimited
        # If the policie_id field is supplied and found in the database, the rights used will be those defined otherwise the right field will be taken into account. 
        
    
        # Check if secret ids is provided in data
        if not safe_ids:
            return error_response(message="Safe ids not provided", code=400)

        # Check is policy is provided in data
        if policie_id:
            found_policie = policies.find_one({"policie_id" : policie_id})
            if not found_policie:
                return error_response(message="Policie not found", code=404)

            # Init rights with policy right
            rights = found_policie.get("rights", [])

        # If rights is still empty throw error
        if not rights:
            return error_response(message="Rights not provided", code=404)
        
        # Check validity of rights
        allowed_rights = ["read", "write", "share", "delete", "propagate"]
        if not (verify_dict_keys(rights, allowed_rights, bool)):
            return error_response(message="Please define the right rights. If you use policies please update this last one.")

        # Check if users_mails is provided in data
        if not users_mails:
            return error_response(message="User mails not provided", code=400)
        
        # Delete same multiple secrets ids
        safe_ids = list(dict.fromkeys(safe_ids))
        
        # Check if user is the owner of alls secrets
        for safe in safe_ids:
            safe_retrieve = safes.find_one({"owner_uid": owner_uid, "safe_id": safe})
            if not safe_retrieve:
                safe_ids.remove(safe)
                
        # If after clean secret list, the list is empty...
        if not any(safe_ids):
            return error_response(message="Please provide a valid secret to share")
        
        # ------ Step to get users from emails provided  ------  #

        # Delete multiple same email in table
        users_mails = list(dict.fromkeys(users_mails))
        
        # Delete owner from list if he is in the list
        if owner.get('email', '') in users_mails:
            users_mails.remove(owner.get('email', ''))

        # Delete users that not existe in database
        
        for user in users_mails:
            user_retrieve = users.find_one({"email": user})
            if not user_retrieve:
                users_mails.remove(user)
                
        # If after clean user mails receivers the list is empty...
        if not any(users_mails):
            return error_response(message="Please provide a valid emails")
                
        # ------ Step to share secret   ------  #
        # But before share one  secret with someone 
        # we'll check if this user don't already have access to this secret
        
        for user in users_mails:
            user_retrieve = users.find_one({"email": user}, {"email": 1, "firstname": 1, "lastname": 1, "uid": 1})
            if user_retrieve:
                for safe in safe_ids:
                    safe_retrieve = safes.find_one({"safe_id": safe})
                    if safe_retrieve:
                        have_access_to_safe = shares.find_one({
                            "receiver_mail": user_retrieve.get('email'),
                            "safe_id": safe_retrieve.get('safe_id'),
                        })
                        if not have_access_to_safe:
                            share_new_safe = {
                                "share_id" : str(ObjectId()),
                                "owner_uid": owner.get('uid'),
                                "receiver_mail": user_retrieve.get('email'),
                                "type": "new_format",
                                "share_type": "safe",
                                "safe_id": str(safe_retrieve.get('safe_id')),
                                "rights": rights,
                                "created_at": datetime.utcnow(),
                                "updated_at": datetime.utcnow(),
                            }
                            shares.insert_one(share_new_safe)
                            at_least_one_shared = True
        if at_least_one_shared:
            return success_response(message=f"Succesfull share safe with {' '.join(users_mails)}")
        return error_response(message=f"Shared safe are already shared with the user")
    except Exception as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))
    except ValueError as error:
        print(traceback.format_exc())
        
        return error_response(errors=str(error))

@SHARE_REQUEST.route('/secret/history/vtest', methods=['GET'])
def get_secret_history():
    try:
        validated= handleRequestToGetUserUid()
        if not validated[0]:
            return validated[1]
        owner_uid = validated[1]
        
        # Get params of request
        params = request.args.to_dict()
        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page
        
        
        # Get owner of request
        owner = users.find_one({"uid": owner_uid})
        if not owner:
            return error_response(message="We cannot perfom this action for now. Please contact us to pull up your account", code=500)
        
        type_of_sharing = params.get('type', 'sharer')
        
        allShared = {
            "data": [],
            "per_page": per_page,
            "page": page,
            "total": 0
        }
        
        
        if type_of_sharing == "sharer":
            getAllShared = shares.find({"owner_uid" : owner_uid, "type": "new_format", "share_type": "secret"}).skip(skip_count).limit(per_page)
            allShared["total"] = shares.count_documents({"owner_uid" : owner_uid, "type": "new_format", "share_type": "secret"})
            for shared in getAllShared:
                secret_retrieve = secrets.find_one({"secret_id": shared.get('secret_id')})
                if secret_retrieve:
                    receiverRetrieve = users.find_one({"email": shared.get('receiver_mail')})
                    receiver = {}
                    if receiverRetrieve:
                        receiver = {
                            "fullname": f"{receiverRetrieve.get('firstname', '')} {receiverRetrieve.get('lastname', '')}",
                            "email": receiverRetrieve.get('email', '')
                        }
                        oneShare = {
                            "share_id": shared.get('share_id'),
                            "secret": {
                                "name": secret_retrieve.get('name'),
                                "secret_id": shared.get('secret_id')
                            },
                            "owner": {
                                "fullname": f"{owner.get('firstname', '')} {owner.get('lastname', '')}",
                                "email": owner.get('email', '')
                            },
                            "receiver": receiver,
                            "rights": shared.get('rights')
                        }
                        allShared["data"].append(oneShare)
        if type_of_sharing == "receiver":
            getAllShared = shares.find({"receiver_mail" : owner.get('email'), "type": "new_format", "share_type": "secret"}).skip(skip_count).limit(per_page)
            allShared["total"] = shares.count_documents({"receiver_mail" : owner.get('email'), "type": "new_format", "share_type": "secret"})
            for shared in getAllShared:
                secret_retrieve = secrets.find_one({"secret_id": shared.get('secret_id')})
                if secret_retrieve:
                    receiverRetrieve = owner
                    ownerRetrieve = users.find_one({"uid": shared.get('owner_uid')})
                    receiver = {}
                    if receiverRetrieve:
                        receiver = {
                            "fullname": f"{receiverRetrieve.get('firstname', '')} {receiverRetrieve.get('lastname', '')}",
                            "email": receiverRetrieve.get('email', '')
                        }
                        oneShare = {
                            "share_id": shared.get('share_id'),
                            "secret": {
                                "name": secret_retrieve.get('name'),
                                "secret_id": shared.get('secret_id')
                            },
                            "owner": {
                                "fullname": f"{ownerRetrieve.get('firstname', '')} {ownerRetrieve.get('lastname', '')}",
                                "email": ownerRetrieve.get('email', '')
                            },
                            "receiver": receiver,
                            "rights": shared.get('rights')
                        }
                        allShared["data"].append(oneShare)
        return success_response(data=allShared)
    except Exception as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))
    except ValueError as error:
        print(traceback.format_exc())
        
        return error_response(errors=str(error))

@SHARE_REQUEST.route('/safe/history/vtest', methods=['GET'])
def get_safe_history():
    try:
        validated= handleRequestToGetUserUid()
        if not validated[0]:
            return validated[1]
        owner_uid = validated[1]
        
        # Get params of request
        params = request.args.to_dict()
        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page
        
        # Get owner of request 
        owner = users.find_one({"uid": owner_uid})
        if not owner:
            return error_response(message="We cannot perfom this action for now. Please contact us to pull up your account", code=500)
        
        type_of_sharing = params.get('type', 'sharer')
        
        allShared = {
            "data": [],
            "per_page": per_page,
            "page": page,
            "total": 0
        }
        
        if type_of_sharing == "sharer":
            getAllShared = shares.find({"owner_uid" : owner_uid, "type": "new_format", "share_type": "safe"}).skip(skip_count).limit(per_page)
            allShared["total"] = shares.count_documents({"owner_uid" : owner_uid, "type": "new_format", "share_type": "safe"})
            for shared in getAllShared:
                safe_retrieve = safes.find_one({"safe_id": shared.get('safe_id', '')})
                if safe_retrieve:
                    receiverRetrieve = users.find_one({"email": shared.get('receiver_mail')})
                    receiver = {}
                    if receiverRetrieve:
                        receiver = {
                            "fullname": f"{receiverRetrieve.get('firstname', '')} {receiverRetrieve.get('lastname', '')}",
                            "email": receiverRetrieve.get('email', '')
                        }
                        oneShare = {
                            "share_id": shared.get('share_id'),
                            "safe": {
                                "name": safe_retrieve.get('name'),
                                "safe_id": shared.get('safe_id')
                            },
                            "owner": {
                                "fullname": f"{owner.get('firstname', '')} {owner.get('lastname', '')}",
                                "email": owner.get('email', '')
                            },
                            "receiver": receiver,
                            "rights": shared.get('rights')
                        }
                        allShared["data"].append(oneShare)
        if type_of_sharing == "receiver":
            getAllShared = shares.find({"receiver_mail" : owner.get('email'), "type": "new_format", "share_type": "safe"}).skip(skip_count).limit(per_page)
            allShared["total"] = shares.count_documents({"receiver_mail" : owner.get('email'), "type": "new_format", "share_type": "safe"})
            for shared in getAllShared:
                safe_retrieve = safes.find_one({"safe_id": shared.get('safe_id', '')})
                if safe_retrieve:
                    receiverRetrieve = owner
                    ownerRetrieve = users.find_one({"uid": shared.get('owner_uid')})
                    receiver = {}
                    if receiverRetrieve:
                        receiver = {
                            "fullname": f"{receiverRetrieve.get('firstname', '')} {receiverRetrieve.get('lastname', '')}",
                            "email": receiverRetrieve.get('email', '')
                        }
                        oneShare = {
                            "share_id": shared.get('share_id'),
                            "secret": {
                                "name": safe_retrieve.get('name'),
                                "safe_id": shared.get('safe_id')
                            },
                            "owner": {
                                "fullname": f"{ownerRetrieve.get('firstname', '')} {ownerRetrieve.get('lastname', '')}",
                                "email": ownerRetrieve.get('email', '')
                            },
                            "receiver": receiver,
                            "rights": shared.get('rights')
                        }
                        allShared["data"].append(oneShare)
        return success_response(data=allShared)
    except ValueError as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))
    except Exception as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))

@SHARE_REQUEST.route('/delete/share/vtest', methods=['DELETE'])
def delete_secret_history():
    try:
        validated= validation(required_keys=[], allowNullData=False)
        if not validated[0]:
            return validated[1]
        data = validated[1]
        
        owner_uid = get_userid_by_token()
        atLeastOneIsDeleted = False
        
        # Get owner of request
        owner = users.find_one({"uid": owner_uid})
        if not owner:
            return error_response(message="We cannot perfom this action for now. Please contact us to pull up your account", code=500)
        
        share_ids = data.get('share_ids', [])
        
        share_ids = list(dict.fromkeys(share_ids))
        
        if not any(share_ids):
            return error_response(message="share_ids is empty !")
        
        clean_share_ids = []

        for share_id in share_ids:
            share = shares.find_one({"share_id": share_id, "owner_uid": owner_uid})
            if share:
                clean_share_ids.append(share_id)
        
        if not any(clean_share_ids):
            return error_response(message="Cannot find the this share data")
        
        print(clean_share_ids)
        
        for share_id in clean_share_ids:
            shares.delete_one({"share_id": share_id})
            atLeastOneIsDeleted = True
            
        if atLeastOneIsDeleted:
            return success_response(message="Delete successfully")
        return error_response(message="Nothing is deleted")
    except Exception as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))
    except ValueError as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))

@SHARE_REQUEST.route('/update/share/vtest', methods=['PUT'])
def update_secret_share():
    try:
        validated= validation(required_keys=[], allowNullData=False)
        if not validated[0]:
            return validated[1]
        data = validated[1]

        owner_uid = get_userid_by_token()
        atLeastOneIsDeleted = False
   
        return success_response(message="Update successfully")
    except ValueError as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))
    except Exception as error:
        print(traceback.format_exc())
        return error_response(errors=str(error))