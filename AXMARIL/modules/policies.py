import traceback
from flask import jsonify, Blueprint,request
from pymongo import MongoClient
from modules.ldapauth import getUserDn, getUserGroup
from modules.required_packages import db002, decrypt, encrypt, get_userid_by_token, isErrorKey, parse_json, run_dag, validation, salt, jwt, client
from bson import ObjectId
import datetime

POLICIES_REQU = Blueprint("policies", __name__)
policies = db002["policies"]
@POLICIES_REQU.route('/create', methods=['POST'])
def create_policie():
    validated = validation(required_keys = ["name", "rights"])
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try :
        owner_uid = get_userid_by_token()
        user_dn = getUserDn(owner_uid)
        user_groups = getUserGroup(user_dn, owner_uid)
        print(user_groups)
        policie_id = str(ObjectId())
        req["policie_id"] = policie_id
        req["owner_uid"] = owner_uid
        policies.insert_one(req)
        del req["_id"]
        return jsonify({
            "status" : "success",
            "message" : f"Policie {req['name']} successfully created",
            "data" : req
        })
    except :
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400
  
@POLICIES_REQU.route('/all', methods=['GET'])
def policie_all():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
    try : 
        owner_uid = get_userid_by_token()
        found_policies = policies.find({"owner_uid" : owner_uid}, {"_id" : 0})
        return jsonify({
            "status" : "success",
            "message" : "successfully fetched data",
            "data" : parse_json(found_policies)
        })
    except : 
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400

@POLICIES_REQU.route('/update', methods=['put'])
def policie_update():
    validated = validation(required_keys = ["policie_id"])
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try : 
        policie_id = req["policie_id"]
        owner_uid = get_userid_by_token()
        found_policie = policies.find_one({"policie_id" : policie_id, "owner_uid" : owner_uid})
        if found_policie is None :
            return jsonify({
                "status" : "failed",
                "message" : "policie not found"
            }), 404
        del req["policie_id"]
        policies.update_one(
            {"policie_id" : policie_id, "owner_uid" : owner_uid},
            {"$set" : req}
        )
        found_policie = policies.find_one({"policie_id" : policie_id, "owner_uid" : owner_uid}, {"_id" : 0})
        return jsonify({
            "status" : "success",
            "message" : "successfully fetched data",
            "data" : parse_json(found_policie)
        })
    except : 
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400
        
@POLICIES_REQU.route('/delete', methods=['DELETE'])
def policie_delete():
    validated = validation(required_keys = ["policie_id"])
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try : 
        policie_id = req["policie_id"]
        owner_uid = get_userid_by_token()
        found_policie = policies.find_one({"policie_id" : policie_id, "owner_uid" : owner_uid})
        if found_policie is None :
            return jsonify({
                "status" : "failed",
                "message" : "policie not found"
            }), 404
        policies.delete_one({"policie_id" : policie_id, "owner_uid" : owner_uid})
        return jsonify({
            "status" : "success",
            "message" : f"policie {found_policie['name']} successfully deleted"
        })
    except : 
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400