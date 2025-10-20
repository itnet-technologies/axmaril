from genericpath import exists
import random
import sys
from textwrap import indent
from threading import Thread
import traceback
from flask import redirect, request,jsonify, Blueprint, json, send_file

from modules.required_packages import (
    encode_token, get_uid_by_token, passwdKey, policy, run_dag, mail_sender, creds,
    search_user_info, store_captcha, validation, encode_auth_token, getUserDn, get_userid_by_token,
    leader_validator, send2FA_code, get_data, getUserGroup, changePassword,
    randNumber, updateAttributes, isAdmin, cache, isMaster, removeAdminRight,get_userInfo,
    captcha_validation, addNewUser, connectUser, generate_captcha, generate_random_text,
    jwt_validation, db002, server, config_data, tryConnexion, isErrorKey, retries,
    isDeleted, define_user_for_deletion, encode_permission_token, check_user_permissions
)
from ldap3 import Connection,HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
from ldap3.core.exceptions import LDAPException
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUsersInGroups
# from flask_ldap3_login import LDAP3LoginManager
import ast
import pymongo
import pyotp
import os, hashlib
from bson import ObjectId
from datetime import datetime
import subprocess
from datetime import timedelta
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from flask import Flask, render_template, request, redirect, url_for, session
import random
import base64
from datetime import timedelta



FA2 = db002["2FA"]
FA2info = db002["info2FA"]
users = db002["users"]
tasks = db002["tasks"]
tokens = db002["tokens"]
right_requests = db002["right_requests"]
internal_secrets = db002["internal_secrets"]
permissions_user  = db002["permission_management"]

ldap_server = creds.find_one({"type":"ldap"},{"_id":0})

config = dict()
config['LDAP_HOST'] = ldap_server["url"]
config['LDAP_BASE_DN'] = ldap_server["value"]["base_dn"]
config['LDAP_USER_DN'] = ldap_server["value"]["user_dn"]
config['LDAP_GROUP_DN'] = ldap_server["value"]["group_dn"]

readonly_group = ldap_server["value"]["readonly"]

# ldap_manager = LDAP3LoginManager()
# ldap_manager.init_config(config)

LDAP_REQUEST = Blueprint('ldap_request', __name__)

@LDAP_REQUEST.route("/2FA/register",  methods=['POST'])
@leader_validator
def register_2fa():
    try:
        validated = validation()
        if not validated[0]:
            return validated[1]
        req = validated[1]
        
        user_uid = get_uid_by_token()
        
        user_2fa = FA2info.find_one({"uid":user_uid})
        foundUser = db002.users.find_one({"uid":user_uid})
        print(user_uid)        
        print(user_2fa)        
        if user_2fa["2fa"] != "no":
            return jsonify({
                "status" : "foundUsfailed",
                "message" : f"User {user_uid} has already set double authentication"
            }), 400
        
        required_keys = ["password"]
        if foundUser["auth_type"] == "google":
            if db002.temp_password.find_one({"uid" : user_uid, "password" : passwdKey(req["password"])}) is None:
                return jsonify({
                    "status" : "failed",
                    "message" : "wrong password"
                }), 401
            # required_keys = []
            pass
        
        for rk in required_keys:
            if not isErrorKey(req, rk):
                return jsonify({
                    "status" : "failed",
                    "message" : f"{rk} is required"
                }), 400

        userFA2info = FA2.find_one({"mail" : user_2fa["mail"]})
        if userFA2info is not None:
            if config_data["LDAP"]:
                if db002.temp_password.find_one({"uid" : user_uid, "password" : passwdKey(req["password"])}) is None:
                    if not tryConnexion(user_uid, req["password"]):
                        return jsonify({
                            "status" : "failed",
                            "message" : "Authentication failed"
                        }), 401
            comand = "qr "+ userFA2info["qr_url"]
            print(comand)
            os.system(comand)
            #------------ 
            return jsonify({
                "status" : "success",
                "message" : "User has already qr code to scan",
                "data" : {
                    "otp_secret":userFA2info["otp_secret"],
                    "qr_url":userFA2info["qr_url"]
                }
            })
        if foundUser["auth_type"] != "google":
            if not((passwdKey(req["password"]) == foundUser["password"])):
                if db002.temp_password.find_one({"uid" : user_uid, "password" : passwdKey(req["password"])}) is None:
                    return jsonify({
                        "status" : "failed",
                        "message" : "Authentication failed"
                    }), 401
        # if config_data["LDAP"]:
        #     user_dn = getUserDn(user_uid)
        #     if not tryConnexion(user_uid, req["password"]):
        #         return jsonify({
        #             "status" : "failed",
        #             "message" : "Authentication failed"
        #         }), 401
        # else:
        #     if not((passwdKey(req["password"]) == foundUser["password"])):
        #         return jsonify({
        #             "status" : "failed",
        #             "message" : "Authentication failed"
        #         }), 401
            
        
        data = send2FA_code(foundUser["email"], user_uid)
        if data is None:
            return jsonify({"message":"Something went wrong", "status": "failed"}), 400
        # FA2info.find_one_and_update({"mail":mail},{'$set': { "2fa" : 'yes'}})
        return jsonify(
            {
                "response":"2FA code sent!",
                "data":{
                    "mail":data["mail"],
                    "otp_secret":data["otp_secret"],
                    "qr_url":data["qr_url"]
                }
            }
        )
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@LDAP_REQUEST.route("/2FA/deactivate",  methods=['PUT'])
@leader_validator
def deactivate_2fa():
    try:
        validated = validation()
        if not validated[0]:
            return validated[1]
        req = validated[1]
        user_uid = get_uid_by_token()
        user_2fa = FA2info.find_one({"uid":user_uid})
        required_keys = ["password"]
        for rk in required_keys:
            if not isErrorKey(req, rk):
                return jsonify({
                    "status" : "failed",
                    "message" : f"{rk} is required"
                }), 400
        if user_2fa["2fa"] != "yes":
            if not tryConnexion(user_uid, req["password"]):
                return jsonify({
                    "status" : "failed",
                    "message" : "Authentication failed"
                }), 401
            return jsonify({
                "status" : "failed",
                "message" : f"User {user_uid} has already deactivate double authentication"
            }), 400
        
        if not tryConnexion(user_uid, req["password"]):
            return jsonify({
                "status" : "failed",
                "message" : "Authentication failed"
            }), 401
        
        FA2info.find_one_and_update(
            {"uid" : user_uid},
            {
                '$set': {"2fa" : "no"}
            }
        )
        FA2.find_one_and_delete(
            {"mail" : user_2fa["mail"]}
        )
        return jsonify({
           "status" : "success",
           "meassage" : "Double authentication successfully deactivated" 
        })
    except:
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@LDAP_REQUEST.route("/login",  methods=['POST'])
@leader_validator
def ldap_connect(is_search=False):
    try:
        print("=== DEBUG: Début de ldap_connect ===")
        
        req_data = get_data()
        print(f"=== DEBUG: req_data récupéré = {req_data} ===")
        
        req_data["uid"] = req_data["uid"].lower()
        print(f"=== DEBUG: uid en minuscules = {req_data['uid']} ===")
        
        scope = {"uid": req_data["uid"]}
        print(f"=== DEBUG: Recherche avec scope = {scope} ===")
        
        fuser = db002.users.find_one(scope)
        print(f"=== DEBUG: Utilisateur trouvé par uid = {fuser is not None} ===")
        
        if fuser is None:
            scope = {"email": req_data["uid"]}
            print(f"=== DEBUG: Recherche par email avec scope = {scope} ===")
            fuser = db002.users.find_one(scope)
            print(f"=== DEBUG: Utilisateur trouvé par email = {fuser is not None} ===")
            
            if fuser is None:
                print("=== DEBUG: Aucun utilisateur trouvé ===")
                return jsonify({
                    "status" : "failed",
                    "message" : "user not found",
                }), 404
            else:
                if fuser.get("marked_for_deletion", False):
                    print("=== DEBUG: Compte marqué pour suppression ===")
                    return jsonify({
                        "status" : "failed",
                        "message" : "This account is set to be deleted",
                    }), 403
        
        print("=== DEBUG: Appel à connectUser ===")
        return connectUser(req_data)
        
    except Exception as e:
        print(f"=== DEBUG ERROR: {str(e)} ===")
        import traceback
        print(f"=== DEBUG TRACEBACK: {traceback.format_exc()} ===")
        return jsonify({
            "status": "failed",
            "message": "Internal server error",
            "error": str(e)
        }), 500      
        
        
        
@LDAP_REQUEST.route("/password-request",  methods=['GET'])
@leader_validator
def password_request():
    try:
        validated = validation(allowNullData=True)
        if not validated[0]:
            return validated[1]
        user_uid = get_userid_by_token()
        password = generate_random_text()
        db002.temp_password.delete_many({"uid" : user_uid})
        db002.temp_password.insert_one(
            {
                "uid" : user_uid,
                "password" : passwdKey(password)
            }
        )
        body = f"""
            Azumaril unique code : {password}.
            
            If this wasn't you who made this request just ignore it.
        """
        # if os.path.exists(forgot_password_html_path):
        #     with open(forgot_password_html_path, "r", encoding='utf-8') as f:
        #         body = f.read().replace("reset_code", f"{str(reset_code)}")
        #         f.close()
        foundUser = users.find_one({"uid" : user_uid}, {"_id": 0})
        Thread(target = mail_sender, args=(foundUser["email"], "PASSWORD REQUEST", body,)).start()
        # send email with this password
        # send email with this password
        
        return jsonify({
            "status" : "success",
            "message" : "An email containing the password had been sent"
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "failed something went wrong"
        }), 400

@LDAP_REQUEST.route("/impersonate/login",  methods=['POST'])
@leader_validator
def impersonate():
    try:
        """
            {
                "giver_uid" : ""
            }
        """
        validated = validation(allowNullData=True)
        if not validated[0]:
            return validated[1]
        data = validated[1]
        user_uid = get_userid_by_token()
        # data = request.get_json(force = True)
        # check if the user has access to the giver account
        access, exp_date, receiver_info, rigths = check_user_permissions(data["giver_uid"], user_uid)
        if access is False:
            return jsonify({
                "status" : "failed",
                "message" : "user don't have access to the giver account"
            }), 403

        # get the token after
        if exp_date > 24:
            exp_date = 24
        token = encode_permission_token(data["giver_uid"], user_uid, exp_date)
        # token = encode_permission_token(data["giver_uid"], user_uid, exp_date = 24)
        uid = data["giver_uid"]
        fa2 = FA2info.find_one({"uid": uid})
        print(fa2)
        print(uid)
        if fa2 is None:
            fa2 = FA2info.find_one({"mail": uid})
            if fa2 is None:
                fa22 = "no"
            else:
                fa22 = fa2["2fa"]
        else:
            fa22 = fa2["2fa"]
        response = {
            "status": "success",
            "message": "Successfully authenticated",
            "2FA": fa22,
            "impersonate" : True
        }
        foundUser = users.find_one({"uid" : data["giver_uid"]}, {"_id": 0, "password" : 0})
        if fa22 == "no":
            response["token"] = token["token"]
            response["user_groups"] = foundUser["groups"]
            homeDirectory = (
                "/home/" + foundUser["firstname"][0] + foundUser["lastname"]
            )
            default_user_info = {
                "businessCategory": "",
                "cn": foundUser["firstname"],
                "displayName": f"{foundUser['firstname']} {foundUser['lastname']}",
                "gidNumber": 10002,
                "homeDirectory": homeDirectory,
                "loginShell": "/bin/bash",
                "mail": foundUser["email"],
                "manager": "",
                "sn": foundUser["lastname"],
                "telephoneNumber": foundUser["tel"],
                "uid": foundUser["uid"],
                "uidNumber": 10002,
            }
            foundUser.update(default_user_info)
            response["user_info"] = foundUser
        else:
            response["uid"] = uid
        return jsonify(response), 200
        # return jsonify({
        #     "status" : "success",
        #     "message" : "success",
        #     "data" : data
        # })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "failed something went wrong"
        }), 400

@LDAP_REQUEST.route("/impersonate/history",  methods=['GET'])
@leader_validator
def impersonate_history():

    try:
        """
            {
                "method" : "get"
            }
        """
        results = db002.impersonate_history.find({"giver_uid": get_uid_by_token()})
        # results = db002.impersonate_history.find({})
        data = []
        for result in results:
            result['_id'] = str(result['_id'])
            data.append(result)

        return jsonify({
            "status" : "success",
            "message" : "success",
            "data" : data})
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "failed something went wrong"
        }), 400

@LDAP_REQUEST.route('/info', methods=['GET'])
def auth_info():
    try:
        # global config_data
        validated = validation(allowNullData=True)
        if not validated[0]:
            return validated[1]
        from modules.required_packages import config_data
        print("------------------------CONFIG DATA ----------------------")
        print(config_data)
        print("------------------------CONFIG DATA ----------------------")
        uid = get_uid_by_token()
        print(uid)
        fuser = db002.users.find_one({"uid" : uid})
        print(fuser)
        if not config_data["LDAP"]:
            data = {
                "uid" : fuser.get("uid",None),
                "email" : fuser.get("email",None),
                "firstname" : fuser.get("firstname",None),
                "lastname" : fuser.get("lastname",None),
                "groups" : fuser.get("groups",None),
                "tel" : fuser.get("tel",None)
            }
            return jsonify({
                "status" : "success",
                "message" : "",
                "data" : data
            })
        # search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']       
        # userInfo = get_userInfo(search_dn, uid)
        data = {
            "uid" : fuser.get("uid",None),
            "email" : fuser.get("email",None),
            "firstname" : fuser.get("firstname",None),
            "lastname" : fuser.get("lastname",None),
            "groups" : fuser.get("groups",None),
            "tel" : fuser.get("tel",None)
        }
        return jsonify({
            "status" : "success",
            "message" : "",
            "data" : data
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400

@LDAP_REQUEST.route("/logout",  methods=['POST'])
@leader_validator
def ldap_deconnect():
    try:
        auth_token = request.headers.get('Authorization')
        token = auth_token.split()[1]
        user_token = tokens.find_one({"token": token})
        if user_token:
            user_uid = user_token["user_uid"]
            query = {"user_uid": user_uid, "type":"auth_token"}
            tokens.delete_many(query)
            return jsonify({"message":"User successfuly logged out", "status":"success"})
        else:
            return jsonify({"message":"token not provided", "status":"failed"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong, may be you're already logged out", "status": "failed"}), 400

@LDAP_REQUEST.route("/change/password",  methods=['POST'])
@leader_validator
def change_password():
    try:
        validated = validation()
        if not validated[0]:
            return validated[1]
        req = validated[1]
        # if not config_data["LDAP"]:
        passwordTest = policy(req["newPassword"])
        if not passwordTest[0]:
            # invalidity_found = passwordTest[1]
            return jsonify(
                {
                    "error":"The password must be at least 8 chars long, \
                                contain capital letter, a number and a special character"
                }
            ), 400
        fuser = db002.users.find_one({"uid" : req["uid"]})
        password = passwdKey(req["newPassword"])
        if "password" not in fuser:
            connecionSucces = connectUser({"password" : req["oldPassword"], "uid" : req["uid"]})
            success = connecionSucces[1] == 200
        else:
            success = passwdKey(req["oldPassword"]) == fuser["password"]
        if success:
            users.update_one({"uid" : req["uid"]}, {"$set" : {"password" : password}})
            if config_data["LDAP"]:
                # user_dn = getUserDn(req["uid"])
                user_dn = search_user_info(req["uid"])
                return changePassword(user_dn, req)
            return jsonify({"status":"success","message":"password change successfully"})
        else:
            return jsonify({"status":"failed","message":"password incorect"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Someting went wrong",
            "details" : traceback.format_exc()
        }), 500

@LDAP_REQUEST.get("/list")
@leader_validator
@jwt_validation
def auth_list():
    try:
        """
            args = {
                "email" : "",
                "fullname" : "",
                "firstname" : "",
                "lastname" : "",
            }
        """
        uid = get_uid_by_token()
        if not isAdmin(uid):
            return jsonify({
                "status" : "failed",
                "message" : "not allowed"
            }), 403
        args = dict(request.args)
        enabled_users = list(db002.users.find({"is_activated" : True}, {"_id" : 0}))
        disabled_users = list(db002.users.find({"is_activated" : False}, {"_id" : 0}))
        data = {
            "enabled_users" : enabled_users,
            "disabled_users" : disabled_users
        }
        
        if "email" in args:
            data = {
                "enabled_users" : [],
                "disabled_users" : []
            }
            for u in enabled_users:
                data["enabled_users"].append(u["email"])
            for u in disabled_users:
                data["disabled_users"].append(u["email"])
        if "firstname" in args:
            data = {
                "enabled_users" : [],
                "disabled_users" : []
            }
            for u in enabled_users:
                data["enabled_users"].append(u["firstname"])
            for u in disabled_users:
                data["disabled_users"].append(u["firstname"])
        if "lastname" in args:
            data = {
                "enabled_users" : [],
                "disabled_users" : []
            }
            for u in enabled_users:
                data["enabled_users"].append(u["lastname"])
            for u in disabled_users:
                data["disabled_users"].append(u["lastname"])
        if "fullname" in args:
            data = {
                "enabled_users" : [],
                "disabled_users" : []
            }
            for u in enabled_users:
                data["enabled_users"].append(f'{u["firstname"]} {u["lastname"]}')
            for u in disabled_users:
                data["disabled_users"].append(f'{u["firstname"]} {u["lastname"]}')
        return jsonify({
            "status" : "success",
            "message" : "success",
            "data" : data
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Someting went wrong",
            "details" : traceback.format_exc()
        }), 500

@LDAP_REQUEST.route("/change/resetpassword", methods=['PUT'])  #/<string:token>
@leader_validator
def change_password_token():
    req = get_data()
    print(req)
    if not isErrorKey(req, "code"):
        return jsonify({
            "status" : "failed",
            "message" : "code is required"
        }), 400
    tok = tokens.find_one({
        "type" : "password_reset",
        "code" : int(req["code"])
    })
    if tok is None:
        return jsonify({"message": "Invalid code", "status": "failed"}), 400
    if datetime.now() > tok.get('expiration_date', datetime.now()):
        tokens.delete_many({"user_uid": tok.get('user_uid'), "type" : "password_reset"})
        return jsonify({"message": "Code expired", "status": "failed"}), 400
    if not config_data["LDAP"]:
        passwordTest = policy(req["newPassword"])
        if not passwordTest[0]:
            # invalidity_found = passwordTest[1]
            return jsonify(
                {
                    "error":"The password must be at least 8 chars long, \
                                contain capital letter, a number and a special character"
                }
            ), 400
        password = passwdKey(req["newPassword"])
        users.update_one({"uid" : tok.get('user_uid')}, {"$set" : {"password" : password}})
        return jsonify({"status":"success","message":"password change successfully"})
    user_dn = getUserDn(tok["user_uid"])
    print(user_dn)
    return changePassword(user_dn, req, isReseting=True)

@LDAP_REQUEST.route("/activation",  methods=['PUT'])
@leader_validator
def account_activation():
    req = get_data()
    if not isErrorKey(req, "uid"):
        return jsonify({
            "status" : "failed",
            "message" : "uid is required"
        }), 400
    if not isErrorKey(req, "activation_code"):
        return jsonify({
            "status" : "failed",
            "message" : "activation_code is required"
        }), 400
    activation_code = req["activation_code"]
    tok = tokens.find_one({"type" : "activation", "user_uid" : req["uid"], "activation_code" : str(activation_code)})
    if tok is None:
        return jsonify({"message": "Invalid code please retry", "status": "failed"}), 400
    try:
        users.find_one_and_update(
            {"uid" : tok["user_uid"]},
            {'$set': {"is_activated" : True}}
        )
        token = encode_auth_token(tok["user_uid"])["token"]
        if config_data["LDAP"]:
            # user_dn = getUserDn(tok["user_uid"])
            user_dn = search_user_info(tok["user_uid"])
            # user_info = {}
            # for k, v in get_userInfo(user_dn, tok["user_uid"]).items():
            #     try :
            #         user_info[k] = v[0]
            #     except :
            #         user_info[k] = ""
            firstname = config_data["LDAP_USER_ATTRIBUTES"]["firstname"]
            lastname = config_data["LDAP_USER_ATTRIBUTES"]["lastname"]
            tel = config_data["LDAP_USER_ATTRIBUTES"]["tel"]
            mail = config_data["LDAP_USER_ATTRIBUTES"]["email"]
            ref = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
            user_info = search_user_info(tok["user_uid"], True)
            if user_info is not None:
                user_info = {
                    firstname : user_info[firstname],
                    lastname : user_info[lastname],
                    tel : user_info.get(tel, None),
                    mail : user_info[mail],
                    ref : user_info[ref]
                }
                groups = getUserGroup(user_dn, tok["user_uid"])
            else:
                user_info = db002.users.find_one({"uid" : tok["user_uid"]}, {"_id" : 0, "password" : 0})
                groups = user_info["groups"]
        else:
            user_info = db002.users.find_one({"uid" : tok["user_uid"]}, {"_id" : 0, "password" : 0})
            groups = user_info["groups"]
        return jsonify({
            "status" : "success",
            "meassage" : f"Account successfully activated",
            "token" : token,
            "data" : user_info,
            "user_groups":groups
        })
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "Something went wrong"
        }), 400

@LDAP_REQUEST.route("/forgot/password/captcha",  methods=['GET', 'POST'])
def forgot_password_captcha():
    try:
        captcha_text = generate_random_text()
        captcha_image = "Captcha ..."
        # print(f"-------------- GET this is the captcha_text : {captcha_text} --------------")
        session['captcha_text'] = captcha_text
        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            user_ip = request.environ['REMOTE_ADDR']
        else:
            user_ip = request.environ['HTTP_X_FORWARDED_FOR'] # if behind a proxy
        cache.set(user_ip, captcha_text, timeout=60*5)
        # print(f"cache is {cache.get(user_ip)}")
        print(f"captcha : {captcha_text}")
        store_captcha(captcha_text, user_ip)
        captcha_image = generate_captcha(captcha_text)
        # print("start captcha")

        # return render_template('index.html', captcha_image=captcha_image)
        # return render_template('form.html', captcha_image=captcha_image)

        return send_file(captcha_image, mimetype='image/png')

        # return jsonify(
        #     {
        #         "captcha_image":captcha_image,
        #         "captcha_text": captcha_text
        #      }), 200
    except:
        print(traceback.format_exc())
        return jsonify({"message": "Captcha Something went wrong", "status": "failed"}), 400

@LDAP_REQUEST.route("/forgot/password",  methods=['POST'])
@captcha_validation
def forgot_password():
    # print(f"-------------- GET this is the captcha_text : {session.get('captcha_text')} --------------")
    # return {}
    req = get_data()
    try:
        if isErrorKey(req, 'uid'):
            uid = req["uid"]
        else:
            return jsonify({"message": "uid or email is required", "status": "failed"}), 400
        
        
        fuser = users.find_one({"email":uid})
        if fuser is None:
            fuser = users.find_one({"uid":uid})
            if fuser is None:
                return jsonify({"message": "bad uid or this user has no mail please set one", "status": "failed"}), 400
            mail = fuser["email"]
        else:
            mail = uid
            uid = fuser['uid']
        # search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
        # uinfo = get_userInfo(search_dn, uid)
        # if uinfo is None:
        #     return jsonify({"message": "bad uid or this user has no mail please set one", "status": "failed"}), 400
        # mail = uinfo["mail"][0]
        objet = "Password reset"
        # token = encode_auth_token(uid)["token"]
        reset_code = randNumber(6)
        tokens.delete_many({"user_uid": uid, "type" : "password_reset"})
        encode_token("password_reset", uid, {"code" : reset_code, "email" : mail}, 1)
        # forgot_password_link = creds.find_one({"type" : "frontend_endpoint"})["endpoints"]["forgot_password"]
        config_data.get("EMAIL_TEMPLATE_PATHS", None)
        forgot_password_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('forgot_password', None)
        body = f"""
            Azumaril reset code request : {str(reset_code)}.
            
            If this wasn't you who made this request just ignore it.
        """
        if os.path.exists(forgot_password_html_path):
            with open(forgot_password_html_path, "r", encoding='utf-8') as f:
                body = f.read().replace("reset_code", f"{str(reset_code)}")
                f.close()
        Thread(target = mail_sender, args=(mail, objet, body,)).start()
        return jsonify({"status":"success","message":f"email sent to {mail}"})
    except:
        print(traceback.format_exc())
        return jsonify({"message": "Something went wrong", "status": "failed"}), 400

#=============================================================================

@LDAP_REQUEST.route('/permission', methods=['POST'])
def give_permissions():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({
            "message":"uid none"
        }), 400
    user_data = users.find_one({"uid" : uid})

    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400
    
    success_list = []
    error_list = []

    users_collection = permissions_user

    for permission_item in data:
        # giver_email = permission_item.get('giver_email')
        giver_email = user_data["email"]
        receiver_email = permission_item.get('receiver_email')
        permissions = permission_item.get('permissions')
        duration = permission_item.get('duration', [0, 0, 0])
        
        if not all([giver_email, receiver_email, permissions, 'read' in permissions, 'write' in permissions]):
            error_list.append({
                "permission_item": permission_item,
                "error": "Missing required fields"
            })
            continue
        
        
        receiver_data = users.find_one({"email" : receiver_email})
        if receiver_data is None:
            error_list.append({
                "permission_item": permission_item,
                "error": "receiver_email is not user"
            })
            continue

        read_permission = permissions['read']
        write_permission = permissions['write']
        
        # Extract duration values
        duration_days, duration_hours, duration_minutes = duration
        
        # Calculate the expiration date of the permission
        expiration_date = datetime.utcnow() + timedelta(days=duration_days, hours=duration_hours, minutes=duration_minutes)
        
        try:
            # Check if the giver exists
            giver = users_collection.find_one({"email": giver_email})
            
            if giver:
                # Check if the permission already exists in the giver's access_list_given
                access_list_given = giver.get('access_list_given', [])
                existing_permission = next((perm for perm in access_list_given if perm['receiver_email'] == receiver_email), None)
                
                if existing_permission:
                    # Update the existing permission in the giver's access_list_given
                    users_collection.update_one(
                        {"email": giver_email, "access_list_given.receiver_email": receiver_email},
                        {"$set": {
                            "access_list_given.$.permissions.read": read_permission,
                            "access_list_given.$.permissions.write": write_permission,
                            "access_list_given.$.expiration_date": expiration_date
                        }}
                    )
                else:
                    # Add the new permission to the giver's access_list_given
                    new_permission_given = {
                        "receiver_email": receiver_email,
                        "permissions": {
                            "read": read_permission,
                            "write": write_permission
                        },
                        "expiration_date": expiration_date
                    }
                    
                    users_collection.update_one(
                        {"email": giver_email},
                        {"$push": {"access_list_given": new_permission_given}}
                    )
            else:
                # Create the new giver user and add the permission to access_list_given
                new_giver = {
                    "email": giver_email,
                    "access_list_given": [
                        {
                            "receiver_email": receiver_email,
                            "permissions": {
                                "read": read_permission,
                                "write": write_permission
                            },
                            "expiration_date": expiration_date
                        }
                    ],
                    "access_list_received": []
                }
                
                users_collection.insert_one(new_giver)
            
            # Check if the receiver exists
            receiver = users_collection.find_one({"email": receiver_email})
            
            if receiver:
                # Check if the permission already exists in the receiver's access_list_received
                access_list_received = receiver.get('access_list_received', [])
                existing_permission_received = next((perm for perm in access_list_received if perm['giver_email'] == giver_email), None)
                
                if existing_permission_received:
                    # Update the existing permission in the receiver's access_list_received
                    users_collection.update_one(
                        {"email": receiver_email, "access_list_received.giver_email": giver_email},
                        {"$set": {
                            "access_list_received.$.permissions.read": read_permission,
                            "access_list_received.$.permissions.write": write_permission,
                            "access_list_received.$.expiration_date": expiration_date
                        }}
                    )
                else:
                    # Add the new permission to the receiver's access_list_received
                    new_permission_received = {
                        "giver_email": giver_email,
                        "permissions": {
                            "read": read_permission,
                            "write": write_permission
                        },
                        "expiration_date": expiration_date
                    }
                    
                    users_collection.update_one(
                        {"email": receiver_email},
                        {"$push": {"access_list_received": new_permission_received}}
                    )
            else:
                # Create the new receiver user and add the permission to access_list_received
                new_receiver = {
                    "email": receiver_email,
                    "access_list_given": [],
                    "access_list_received": [
                        {
                            "giver_email": giver_email,
                            "permissions": {
                                "read": read_permission,
                                "write": write_permission
                            },
                            "expiration_date": expiration_date
                        }
                    ]
                }
                
                users_collection.insert_one(new_receiver)
            
            success_list.append(permission_item)
        except Exception as e:
            error_list.append({
                "permission_item": permission_item,
                "error": str(e)
            })
    
    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route('/permission', methods=['DELETE'])
def delete_permissions():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400

    success_list = []
    error_list = []

    users_collection = permissions_user

    for permission_item in data:
        giver_email = user_data["email"]
        receiver_email = permission_item.get('receiver_email')
        
        if not receiver_email:
            error_list.append({
                "permission_item": permission_item,
                "error": "Missing required fields"
            })
            continue

        receiver_data = users.find_one({"email" : receiver_email})
        if receiver_data is None:
            error_list.append({
                "permission_item": permission_item,
                "error": "receiver_email User not found"
            })
            continue

        try:
            # Remove permission from giver's access_list_given
            users_collection.update_one(
                {"email": giver_email},
                {"$pull": {"access_list_given": {"receiver_email": receiver_email}}}
            )

            # Remove permission from receiver's access_list_received
            users_collection.update_one(
                {"email": receiver_email},
                {"$pull": {"access_list_received": {"giver_email": giver_email}}}
            )

            success_list.append(permission_item)
        except Exception as e:
            error_list.append({
                "permission_item": permission_item,
                "error": str(e)
            })
    
    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route('/permission', methods=['GET'])
def get_permissions():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    users_collection = permissions_user

    giver_email = user_data["email"]

    try:
        # Retrieve permissions the user has given
        giver_permissions = users_collection.find_one({"email": giver_email}, {"access_list_given": 1, "_id": 0})
        if giver_permissions:
            given_permissions = giver_permissions.get("access_list_given", [])
        else:
            given_permissions = []

        # Retrieve permissions the user has received
        receiver_permissions = users_collection.find_one({"email": giver_email}, {"access_list_received": 1, "_id": 0})
        if receiver_permissions:
            received_permissions = receiver_permissions.get("access_list_received", [])
        else:
            received_permissions = []

        return jsonify({
            "given_permissions": given_permissions,
            "received_permissions": received_permissions
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@LDAP_REQUEST.route('/permission', methods=['PUT'])
def update_permissions():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400
    
    success_list = []
    error_list = []

    users_collection = permissions_user
    giver_email = user_data["email"]

    for permission_item in data:
        receiver_email = permission_item.get('receiver_email')
        permissions = permission_item.get('permissions')
        duration = permission_item.get('duration', [0, 0, 0])
        
        if not all([receiver_email, permissions, 'read' in permissions, 'write' in permissions]):
            error_list.append({
                "permission_item": permission_item,
                "error": "Missing required fields"
            })
            continue

        try:
            # Extract duration values
            duration_days, duration_hours, duration_minutes = duration
            
            # Calculate the new expiration date of the permission
            expiration_date = datetime.utcnow() + timedelta(days=duration_days, hours=duration_hours, minutes=duration_minutes)
            
            read_permission = permissions['read']
            write_permission = permissions['write']

            # Update permission in giver's access_list_given
            users_collection.update_one(
                {"email": giver_email, "access_list_given.receiver_email": receiver_email},
                {"$set": {
                    "access_list_given.$.permissions.read": read_permission,
                    "access_list_given.$.permissions.write": write_permission,
                    "access_list_given.$.expiration_date": expiration_date
                }}
            )

            # Update permission in receiver's access_list_received
            users_collection.update_one(
                {"email": receiver_email, "access_list_received.giver_email": giver_email},
                {"$set": {
                    "access_list_received.$.permissions.read": read_permission,
                    "access_list_received.$.permissions.write": write_permission,
                    "access_list_received.$.expiration_date": expiration_date
                }}
            )

            success_list.append(permission_item)
        except Exception as e:
            error_list.append({
                "permission_item": permission_item,
                "error": str(e)
            })

    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route('/permission/request', methods=['POST'])
def request_permissions():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400
    
    success_list = []
    error_list = []

    users_collection = permissions_user
    requester_email = user_data["email"]

    for request_item in data:
        giver_email = request_item.get('giver_email')
        permissions = request_item.get('permissions')
        duration = request_item.get('duration', [0, 0, 0])
        
        if not all([giver_email, permissions, 'read' in permissions, 'write' in permissions]):
            error_list.append({
                "request_item": request_item,
                "error": "Missing required fields"
            })
            continue
        
        try:
            # Extract duration values
            duration_days, duration_hours, duration_minutes = duration
            
            # Calculate the requested expiration date
            expiration_date = datetime.utcnow() + timedelta(days=duration_days, hours=duration_hours, minutes=duration_minutes)
            
            read_permission = permissions['read']
            write_permission = permissions['write']

            # Check if the giver exists
            giver = users_collection.find_one({"email": giver_email})
            if giver:
                # Add the request to the giver's permission_requests_received
                request_received = {
                    "requester_email": requester_email,
                    "permissions": {
                        "read": read_permission,
                        "write": write_permission
                    },
                    "expiration_date": expiration_date,
                    "status": "pending"
                }
                
                users_collection.update_one(
                    {"email": giver_email},
                    {"$push": {"permission_requests_received": request_received}}
                )
            else:
                # Create the new giver user and add the request to permission_requests_received
                new_giver = {
                    "email": giver_email,
                    "access_list_given": [],
                    "access_list_received": [],
                    "permission_requests_received": [
                        {
                            "requester_email": requester_email,
                            "permissions": {
                                "read": read_permission,
                                "write": write_permission
                            },
                            "expiration_date": expiration_date,
                            "status": "pending"
                        }
                    ]
                }
                
                users_collection.insert_one(new_giver)

            # Check if the requester exists
            requester = users_collection.find_one({"email": requester_email})
            if requester:
                # Add the request to the requester's permission_requests_made
                request_made = {
                    "giver_email": giver_email,
                    "permissions": {
                        "read": read_permission,
                        "write": write_permission
                    },
                    "expiration_date": expiration_date,
                    "status": "pending"
                }

                users_collection.update_one(
                    {"email": requester_email},
                    {"$push": {"permission_requests_made": request_made}}
                )
            else:
                # Create the new requester user and add the request to permission_requests_made
                new_requester = {
                    "email": requester_email,
                    "access_list_given": [],
                    "access_list_received": [],
                    "permission_requests_made": [
                        {
                            "giver_email": giver_email,
                            "permissions": {
                                "read": read_permission,
                                "write": write_permission
                            },
                            "expiration_date": expiration_date,
                            "status": "pending"
                        }
                    ]
                }

                users_collection.insert_one(new_requester)

            success_list.append(request_item)
        except Exception as e:
            error_list.append({
                "request_item": request_item,
                "error": str(e)
            })

    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route('/permission/request', methods=['GET'])
def view_permission_requests():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    email = user_data["email"]
    
    user_permissions_data = permissions_user.find_one({"email": email})
    
    if not user_permissions_data:
        return jsonify({"error": "No data found for this user"}), 404
    
    permission_requests_made = user_permissions_data.get("permission_requests_made", [])
    permission_requests_received = user_permissions_data.get("permission_requests_received", [])
    
    return jsonify({
        "permission_requests_made": permission_requests_made,
        "permission_requests_received": permission_requests_received
    }), 200

@LDAP_REQUEST.route('/permission/request', methods=['PUT'])
def update_permission_request():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    email = user_data["email"]
    data = request.get_json()

    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400

    success_list = []
    error_list = []

    for request_item in data:
        requester_email = email
        giver_email = request_item.get("giver_email")
        permissions = request_item.get("permissions")
        duration = request_item.get("duration", [0, 0, 0])

        if not all([requester_email, giver_email, permissions, 'read' in permissions, 'write' in permissions]):
            error_list.append({
                "request_item": request_item,
                "error": "Missing required fields"
            })
            continue

        read_permission = permissions["read"]
        write_permission = permissions["write"]

        # Extract duration values
        duration_days, duration_hours, duration_minutes = duration

        # Calculate the new expiration date of the permission request
        expiration_date = datetime.utcnow() + timedelta(days=duration_days, hours=duration_hours, minutes=duration_minutes)

        try:
            # Check if the request exists in the requester's permission_requests_made
            user_permissions_data = permissions_user.find_one({"email": requester_email})
            
            if user_permissions_data:
                existing_request = next((req for req in user_permissions_data.get("permission_requests_made", []) if req["giver_email"] == giver_email), None)
                
                if existing_request:
                    # Update the existing request in permission_requests_made
                    permissions_user.update_one(
                        {"email": requester_email, "permission_requests_made.giver_email": giver_email},
                        {"$set": {
                            "permission_requests_made.$.permissions.read": read_permission,
                            "permission_requests_made.$.permissions.write": write_permission,
                            "permission_requests_made.$.expiration_date": expiration_date
                        }}
                    )
                    success_list.append(request_item)
                else:
                    error_list.append({
                        "request_item": request_item,
                        "error": "Request not found"
                    })
            else:
                # Create the new user entry with the updated request
                new_request_made = {
                    "giver_email": giver_email,
                    "permissions": {
                        "read": read_permission,
                        "write": write_permission
                    },
                    "expiration_date": expiration_date,
                    "status": "pending"
                }

                new_user = {
                    "email": requester_email,
                    "access_list_given": [],
                    "access_list_received": [],
                    "permission_requests_made": [new_request_made],
                    "permission_requests_received": []
                }

                permissions_user.insert_one(new_user)
                success_list.append(request_item)

        except Exception as e:
            error_list.append({
                "request_item": request_item,
                "error": str(e)
            })

    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route('/permission/request', methods=['DELETE'])
def delete_permission_request():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    email = user_data["email"]
    data = request.get_json()

    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400

    success_list = []
    error_list = []

    for request_item in data:
        giver_email = request_item.get("giver_email")

        if not giver_email:
            error_list.append({
                "request_item": request_item,
                "error": "Missing required fields"
            })
            continue

        try:
            user_permissions_data = permissions_user.find_one({"email": email})

            if user_permissions_data:
                # Check if the request exists in the requester's permission_requests_made
                existing_request = next((req for req in user_permissions_data.get("permission_requests_made", []) if req["giver_email"] == giver_email), None)

                if existing_request:
                    # Remove the existing request from permission_requests_made
                    permissions_user.update_one(
                        {"email": email},
                        {"$pull": {"permission_requests_made": {"giver_email": giver_email}}}
                    )
                    success_list.append(request_item)
                else:
                    error_list.append({
                        "request_item": request_item,
                        "error": "Request not found"
                    })
            else:
                error_list.append({
                    "request_item": request_item,
                    "error": "No requests found for user"
                })

        except Exception as e:
            error_list.append({
                "request_item": request_item,
                "error": str(e)
            })

    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route('/permission/request/approve', methods=['POST'])
def approve_permission_request():
    uid = get_uid_by_token()
    if uid is None:
        return jsonify({"message": "uid none"}), 400

    user_data = users.find_one({"uid": uid})
    if user_data is None:
        return jsonify({"error": "User not found"}), 400

    email = user_data["email"]
    data = request.get_json()

    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid input"}), 400


    success_list = []
    error_list = []
    users_collection = permissions_user

    for request_item in data:
        requester_email = request_item.get("requester_email")

        if not requester_email:
            error_list.append({
                "request_item": request_item,
                "error": "Missing required fields"
            })
            continue

        try:
            # Fetch the user's permission data
            user_permissions_data = permissions_user.find_one({"email": email})

            if user_permissions_data:
                # Find the permission request in permission_requests_received
                existing_request = next((req for req in user_permissions_data.get("permission_requests_received", []) if req["requester_email"] == requester_email), None)

                if existing_request:
                    # Grant the permission by adding it to access_list_given and access_list_received
                    permissions = existing_request["permissions"]
                    expiration_date = existing_request["expiration_date"]

                    # Update the giver's access_list_given
                    users_collection.update_one(
                        {"email": email},
                        {"$push": {"access_list_given": {
                            "receiver_email": requester_email,
                            "permissions": permissions,
                            "expiration_date": expiration_date
                        }}}
                    )

                    # Update the requester's access_list_received
                    users_collection.update_one(
                        {"email": requester_email},
                        {"$push": {"access_list_received": {
                            "giver_email": email,
                            "permissions": permissions,
                            "expiration_date": expiration_date
                        }}}
                    )

                    # Mark the request as approved
                    users_collection.update_one(
                        {"email": email, "permission_requests_received.requester_email": requester_email},
                        {"$set": {"permission_requests_received.$.status": "approved"}}
                    )

                    success_list.append(request_item)
                else:
                    error_list.append({
                        "request_item": request_item,
                        "error": "Request not found"
                    })
            else:
                error_list.append({
                    "request_item": request_item,
                    "error": "No requests found for user"
                })

        except Exception as e:
            error_list.append({
                "request_item": request_item,
                "error": str(e)
            })

    return jsonify({
        "success": success_list,
        "errors": error_list
    }), 200

@LDAP_REQUEST.route("/admin/change/password",  methods=['POST'])
def admin_change_password():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    user_dn = getUserDn(req["user_uid"])
    admin_dn = getUserDn(req["admin_uid"])
    admin_password = req["admin_password"]
    hashed_password = hashed(HASHED_SALTED_SHA, req["newPassword"])
    isCorrectOldPassword = Connection(
        server,
        user = admin_dn,
        password = admin_password
    )
    if(isCorrectOldPassword.bind()):
        taskid = str(ObjectId())
        tasks.insert_one({
            "taskid" : taskid,
            "type" : "ldap_change",
            "user_dn" : user_dn,
            "newPassword" : hashed_password,
            "admin_dn": admin_dn,
            "admin_password":admin_password,
            "admin_mod" : "yes",
            "status":"pending"
        })
        run_dag(taskid)
        return jsonify({"status":"success","message":"change password request is now processing.."}),200
    else:
        return jsonify({"message":"Unable to change password, bad admin credentials", "status": "failed"}) ,400

@LDAP_REQUEST.route("/2FA/login",  methods=['POST'])
@leader_validator
def ldap_2fa(is_search=False):
    try:
        req_data = get_data()
        if not isErrorKey(req_data, "uid"):
            return jsonify({
                "status" : "failed",
                "message" : "uid is required"
            }), 400
        req_data["uid"] = req_data["uid"].lower()
        user_uid = req_data["uid"]
        foundUser = db002.users.find_one({"uid" : user_uid}, {"_id" : 0})
        if foundUser is None:
            foundUser = db002.users.find_one({"email" : user_uid}, {"_id" : 0})
        fa2 = FA2info.find_one({"uid":user_uid})
        if fa2 is None:
            fa2 = FA2info.find_one({"mail":user_uid})
            if fa2 is None:
                return jsonify({
                    "status" : "failed",
                    "message" : "User not found"
                }), 404
        else:
            fa22 = fa2["2fa"]
            userFA2info = FA2.find_one({"mail" : fa2["mail"]})
            if fa22 == "no" and userFA2info is None:
                return jsonify({
                    "status" : "failed",
                    "message" : "This user has not set double factor authentication"
                }), 400
        
        mail = fa2["mail"]
        print(mail)
        
        #----get 2fa secret url
        fa2Info = FA2.find_one({"mail":mail})
        if fa2Info is None:
            return jsonify({"message":"Authentication failed, bad email", "status": "failed"}), 400
        qr_url = dict(fa2Info)["qr_url"]
        #----
        
        #----time-based one time password (totp)
        code = req_data["code"]             #this is provided by google authenticator app
        totp = pyotp.parse_uri(qr_url)      #instantiate pyotp class by parsing 2fa secret url
        fa2totp_status = totp.verify(code)  #finaly verify and fa2totp_status is true or false
        if not fa2totp_status:
            return jsonify({"message":"Authentication failed, bad 2FA otp", "status": "failed"}), 400
        fa22 = fa2["2fa"]
        print(fa22)
        if fa22 == "no":
            FA2info.find_one_and_update(
                {"mail":mail},
                {
                    "$set": {"2fa" : "yes"}
                },
                upsert=True
            )
        if not config_data["LDAP"] :
            token = encode_auth_token(user_uid)["token"]
            groups = foundUser["groups"]
            homeDirectory = "/home/"+foundUser['firstname'][0]+foundUser['lastname']
            user_info = foundUser
            default_user_info = {
                "businessCategory": "",
                "cn": foundUser["firstname"],
                "displayName": f"{foundUser['firstname']} {foundUser['lastname']}",
                "gidNumber": 10002,
                "homeDirectory": homeDirectory,
                "loginShell": "/bin/bash",
                "mail": foundUser["email"],
                "manager": "",
                "sn": foundUser["lastname"],
                "telephoneNumber": foundUser["tel"],
                "uid": foundUser["uid"],
                "uidNumber": 10002
            }
            user_info.update(default_user_info)
        else:
            founduser_dn = search_user_info(
                foundUser["uid"]
            )
            homeDirectory = "/home/"+foundUser['firstname'][0]+foundUser['lastname']
            firstname = config_data["LDAP_USER_ATTRIBUTES"]["firstname"]
            lastname = config_data["LDAP_USER_ATTRIBUTES"]["lastname"]
            tel = config_data["LDAP_USER_ATTRIBUTES"]["tel"]
            mail = config_data["LDAP_USER_ATTRIBUTES"]["email"]
            ref = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
            fuser = db002.users.find_one({"uid" : {"$regex": f"^{foundUser['uid']}$", "$options": "i"}}, {"_id" : 0})
            groups = getUserGroup(founduser_dn, foundUser["uid"])
            user_info = search_user_info(foundUser['uid'], True)
            user_info = {
                firstname : user_info.get(firstname, None),
                lastname : user_info.get(lastname, None),
                tel : user_info.get(tel, None),
                mail : user_info.get(mail, None),
                ref : user_info.get(ref, None)
            }
            default_user_info = {
                "businessCategory": "",
                "cn": user_info[firstname],
                "displayName": f"{user_info[firstname]} {user_info[lastname]}",
                "gidNumber": 10002,
                "homeDirectory": homeDirectory,
                "loginShell": "/bin/bash",
                "mail": user_info[mail],
                "manager": "",
                "sn": user_info[lastname],
                "telephoneNumber": user_info[tel],
                "uid": user_info[ref],
                "uidNumber": 10002,
            }
            fuser.update(default_user_info)
            token = encode_auth_token(user_uid)["token"]
        response = {
            "status":"success",
            "message":"Double factor authentication success",
            "token" : token,
            "user_groups":groups,
            "user_info" : fuser
        }
        return jsonify(response)
    except:
        print(traceback.format_exc())
        return jsonify({
            "status" : "failed",
            "message" : "something went wrong"
        }), 400

@LDAP_REQUEST.route('/register', methods=['POST'])
@leader_validator
def RegisterLdap():
    data = request.get_json(force = True)
    if "email" in data:
        data["email"] = data["email"].lower()
    return addNewUser(data)

@LDAP_REQUEST.route('/application/login', methods=['POST'])
@leader_validator
def log_app():
    user = get_data()
    resultat = False
    try:
        #get the encoded creds
        config_content = user["credfile_content"].replace("'", '"')
        config_content = json.loads(config_content)
        creds = config_content["creds"]["v1"]
        priv_key = internal_secrets.find_one({"type": "private_key"})["value"]

        #prepare the private key for use
        priv_key = serialization.load_pem_private_key(
        priv_key.encode(),
        password=None,
        backend=default_backend())
        
        #decrypt the bail
        encrypted = base64.b64decode(creds)
        decrypted = priv_key.decrypt(
        encrypted,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        ))
        decrypted = decrypted.decode('utf-8').replace("'", '"')
    except Exception as e:
        return jsonify(
        {
            "status" : "failed",
            "message" : "Invalid credfile",
            "error" : str(e)
        }
    ), 400

    decrypted = json.loads(decrypted)
    #get the decoded creds
    uid = config_content["username"]
    password = decrypted["p"]
    #check ip
    client_ip = request.remote_addr
    print("Origin Ip =",request.headers.get('X-Forwarded-For', client_ip))
    if client_ip in decrypted["ip"]:
        pass
    elif request.headers.get('X-Forwarded-For', client_ip) in decrypted["ip"]:
        print("Origin Ip =",request.headers.get('X-Forwarded-For', client_ip))
        pass
    else:
        if retries(uid) <= 5:
            return jsonify({
                "status" : "failed",
                "message" : "Max tries reached"
            }), 400
        retries(uid, incr=True)
        return jsonify({
            "status" : "failed",
            "message" : "unhauhorised ip"
        }), 400
    #login
    foundUser = users.find_one({"uid": uid})
    if foundUser is None :
        foundUser = users.find_one({"email": uid})
    if foundUser is None :
        return jsonify({
            "status" : "failed",
            "message" : "bad uid or email"
        }), 400
    

    
    if not foundUser["is_activated"]:
        objet = "Azumaril account activation"
        ftoken = db002["tokens"].find_one({"type" : "activation", "user_uid" : foundUser["uid"]})
        if ftoken is None:
            return jsonify({
                "status" : "failed",
                "message" : "Account not activated yet, please activate account and retry"
            }), 400
        else:
            message = (
                f"Voici votre code d'activation : {ftoken['activation_code']},\n"
                f"voici votre identifiant : {foundUser['uid']}"
            )
            activation_code_html_path = config_data.get('EMAIL_TEMPLATE_PATHS', {}).get('activation_code', None)
            print(activation_code_html_path)
            if os.path.exists(activation_code_html_path):
                with open(activation_code_html_path, "r", encoding='utf-8') as f:
                    template = f.read()
                body = (template.replace("{{activation_code}}", str(ftoken['activation_code']))
                        .replace("{{identifiant}}", str(foundUser['uid'])))
                message = body
            Thread(target = mail_sender, args=(foundUser["email"], objet, message,)).start()
        return jsonify({
            "status" : "failed",
            "message" : "Account not activated yet, please activate account by verifiying your email and retry"
        }), 400
    if not config_data["LDAP"]:
        if (passwdKey(password) == foundUser["password"]):
            fa2 = FA2info.find_one({"uid":uid})
            if fa2 is None:
                fa22 = "no"
            else:
                fa22 = fa2["2fa"]
            response = {
                "status" : "success",
                "message" : "Successfully authenticated",
                "2FA" : fa22
            }
            if fa22 == "no":
                response["token"] = encode_auth_token(uid)["token"]
                response["user_groups"] = foundUser["groups"]
                response["user_info"] = foundUser
            else:
                response["uid"] = uid
            return json.dumps(
                response, 
                indent = 2
            )
    
    search_dn1 = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    
    uid = foundUser["uid"]
    user_dn = 'uid=' + uid + ',' + search_dn1
    
    result = Connection(
        server,
        user = user_dn,
        password = password
    )
    if result.bind():
        try:
            fa2 = FA2info.find_one({"uid":uid})
            if fa2 is None:
                fa22 = "no"
            else:
                fa22 = fa2["2fa"]
        except:
            #check tries
            if retries(uid) <= 5:
                return jsonify({
                    "status" : "failed",
                    "message" : "Max tries reached"
                }), 400
            retries(uid, incr=True)
            return jsonify({"message":"Authentication failed, this user has no email", "status": "failed"}), 400
        response = {
            "status" : "success",
            "message" : "Successfully authenticated",
            "2FA" : fa22
        }
        if fa22 == "no":
            groups = getUserGroup(user_dn, uid)
            # user_info = {}
            # for k, v in get_userInfo(user_dn, uid).items() :
            #     try :
            #         user_info[k] = v[0]
            #     except :
            #         user_info[k] = ""
            firstname = config_data["LDAP_USER_ATTRIBUTES"]["firstname"]
            lastname = config_data["LDAP_USER_ATTRIBUTES"]["lastname"]
            tel = config_data["LDAP_USER_ATTRIBUTES"]["tel"]
            mail = config_data["LDAP_USER_ATTRIBUTES"]["email"]
            ref = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
            user_info = search_user_info(uid, True)
            user_info = {
                firstname : user_info[firstname],
                lastname : user_info[lastname],
                tel : user_info[tel],
                mail : user_info[mail],
                ref : user_info[ref]
            }
            response["token"] = encode_auth_token(uid)["token"]
            response["user_groups"] = groups
            response["user_info"] = user_info
        else:
            response["uid"] = uid
        #rest the remaining tries
        retries(uid, reset=True)
        return json.dumps(
            response, 
            indent = 2
        )
    else:
        if retries(uid) <= 5:
            return jsonify({
                "status" : "failed",
                "message" : "Max tries reached"
            }), 400
        retries(uid, incr=True)
        return jsonify({"message":"Authentication failed", "status": "failed"}), 400

@LDAP_REQUEST.route('/update', methods=['POST'])
@leader_validator
def updateUser():
    validated = validation()
    if not validated[0]:
        return validated[1]
    user = validated[1]
    uid = get_uid_by_token()
    # if not config_data["LDAP"]:
    if "uid" in user:
        del user["uid"]
    db002.users.update_one({"uid" : uid}, {"$set" : user})
    # return jsonify({"status":"success"})
    # search_dn = config['LDAP_USER_DN'] +','+ config['LDAP_BASE_DN']
    # default = get_userInfo(search_dn, uid)
    try:
        if config_data["LDAP"]:
            firstname = config_data["LDAP_USER_ATTRIBUTES"]["firstname"]
            lastname = config_data["LDAP_USER_ATTRIBUTES"]["lastname"]
            tel = config_data["LDAP_USER_ATTRIBUTES"]["tel"]
            mail = config_data["LDAP_USER_ATTRIBUTES"]["email"]
            ref = config_data["LDAP_USER_ATTRIBUTES"]["uid"]
            default = search_user_info(uid, True)
            default = {
                firstname : default[firstname],
                lastname : default[lastname],
                tel : default[tel],
                mail : default[mail],
                ref : default[ref]
            }
            user["uid"] = uid
            updateAttributes(default, user)
        return jsonify({"status":"success"}), 200
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@LDAP_REQUEST.route('/admin/account/cancel', methods=['PUT'])
def cancel_user_deletion():
    try:
        uid = get_uid_by_token()
        args = request.args.to_dict()
        owner_uid = args.get("onwer_uid", None)

        if isAdmin(uid):
            check_user = users.find_one({"uid": owner_uid})
            if not check_user:
                return jsonify({"message":"User not found", "status": "failed"}), 404
            
            if "marked_for_deletion" in check_user:
                users.update_one({"uid": owner_uid}, {"$set": {"marked_for_deletion": False}})
                return jsonify({"status":"success", "message":"account deletion is cancelled"}), 200
            else:
                return jsonify({"message":"this user is not flagged for deletion", "status": "failed"}), 400
        else:
            return jsonify({"message":"Unauthorized", "status": "failed"}), 401         
        
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@LDAP_REQUEST.route('/admin/account/delete', methods=['DELETE'])
def define_delete_user():
    try:
        uid = get_uid_by_token()
        args = request.args.to_dict()
        owner_uid = args.get("owner_uid", None)

        if isAdmin(uid):
            isDeleted(owner_uid)
            return jsonify({"status":"success", "message":"deletion account request is now processing.."}), 200
        else:
            return jsonify({"message":"Unauthorized", "status": "failed"}), 401         
        
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@LDAP_REQUEST.route('/account/delete', methods=['DELETE'])
def delete_user():
    try:
        uid = get_uid_by_token()
        args = request.args.to_dict()

        confirm = args.get("confirm", None)

        if confirm.lower() == "true":
            isDeleted(uid)
            return jsonify({"status":"success", "message":"deletion account request is now processing.."}), 200
        else:
            return jsonify({"status":"success", "message":"type 'true' for confirmation"}), 400
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400


# @LDAP_REQUEST.route('/right/request', methods=['POST'])
# def rrequest():
#     try:
#         validated = validation(allowNullData=True)
#         if not validated[0]:
#             return validated[1]
#         uid = get_uid_by_token()
#         if isAdmin(uid):
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "user is already an admin"
#             }), 409
#         fuser = users.find_one({"uid" : uid})
#         frr = right_requests.find_one({"user_uid" : uid, "email" : fuser["email"]}, {"_id" : 0})
#         if frr is not None:
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "user has already make a rights request",
#                 "data" : frr
#             }), 400
#         date = datetime.now()
#         right_requests.insert_one(
#             {
#                 "request_id" : str(ObjectId()),
#                 "status" : "pending",
#                 "user_uid" : uid,
#                 "firstname" : fuser["firstname"],
#                 "lastname" : fuser["lastname"],
#                 "email" : fuser["email"],
#                 "date" : date.strftime('%Y-%m-%d'),
#                 "approbation_info" : {
#                     "approver_uid" : "",
#                     "approver_mail": "",
#                     "reason" : ""
#                 }
#             }
#         )
#         return jsonify({
#             "status" : "success",
#             "message" : "request is now processing.."
#         })
#     except:
#         print(traceback.format_exc())
#         return jsonify({
#             "status" : "failed",
#             "message" : "something went wrong"
#         }), 400
        
# @LDAP_REQUEST.route('/right/request/all', methods=['GET'])
# def rrequest_all():
#     try:
#         validated = validation(allowNullData=True)
#         if not validated[0]:
#             return validated[1]
#         uid = get_uid_by_token()
#         args = request.args
#         req = args.to_dict()
#         data = right_requests.find(req, {"_id" : 0})
#         if isAdmin(uid):
#             return jsonify({
#                 "status" : "success",
#                 "message" : "request is now processing..",
#                 "data" : list(data)
#             })
#         else:
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "not allowed to view rights request"
#             }), 403
#     except:
#         return jsonify({
#             "status" : "failed",
#             "message" : "something went wrong"
#         }), 400

# @LDAP_REQUEST.route('/right/request/grant-deny', methods=['PUT'])
# def rrequest_gd():
#     try:
#         validated = validation(allowNullData=True)
#         if not validated[0]:
#             return validated[1]
#         uid = get_uid_by_token()
#         if not isAdmin(uid):
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "not allowed to do this action"
#             }), 403
#         args = request.args
#         req = args.to_dict()
#         fuser = users.find_one({"uid" : uid})
#         if not isErrorKey(req, "request_id"):
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "request_id is required"
#             }), 400
#         if not isErrorKey(req, "answer"):
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "answer is required"
#             }), 400
#         if req["answer"] != "grant" and req["answer"] != "deny":
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "answer must be grant or deny"
#             }), 400
#         status = "rejected"
#         frr = right_requests.find_one({"request_id" : req["request_id"]})
#         if frr is None:
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "request not found"
#             }), 404   
#         if frr["status"] != "pending":
#             return jsonify({
#                 "status" : "failed",
#                 "message" : f"request had been already {frr['status']}"
#             }), 409
#         if req["answer"] == "grant" :
#             status = "accepted"
#         else:
#             return jsonify({
#                 "status" : "success",
#                 "message" : "right denied"
#             })
#         reason = ""
#         if isErrorKey(req, "reason"):
#             reason = req["reason"]
#         right_requests.update_one(
#             {"request_id" : req["request_id"]},
#             {
#                 "$set" : {
#                     "approbation_info" : {
#                         "approver_uid" : uid,
#                         "approver_mail": fuser["email"],
#                         "reason" : reason
#                     },
#                     "status" : status
#                 }
#             }
#         )
#         addAdminRight(fuser["uid"])
#         return jsonify({
#             "status" : "success",
#             "message" : "right granted"
#         })
#     except:
#         return jsonify({
#             "status" : "failed",
#             "message" : "something went wrong"
#         }), 400

# @LDAP_REQUEST.route('/right/add', methods=['PUT'])
# def rrequest_grant():
#     try:
#         validated = validation()
#         if not validated[0]:
#             return validated[1]
#         req = validated[1]
#         if not isErrorKey(req, "uid_email"):
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "uid_email is required"
#             }), 400
#         uid = get_uid_by_token()
#         if isAdmin(uid) or isMaster(uid):
#             fuser = users.find_one({"uid" : req["uid_email"]})
#             if fuser is None:
#                 fuser = users.find_one({"email" : req["uid_email"]})
#                 if fuser is None:
#                     return jsonify({
#                         "status" : "failed",
#                         "message" : "user not found"
#                     }), 404
#             if isAdmin(fuser["uid"]):
#                 return jsonify({
#                     "status" : "failed",
#                     "message" : "user has already right admin"
#                 }), 409
#             else:
#                 addAdminRight(fuser["uid"])
#                 return jsonify({
#                     "status" : "success",
#                     "message" : "user successfully have right admin"
#                 })
#         else:
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "not allowed to add rights"
#             }), 403
#     except:
#         return jsonify({
#             "status" : "failed",
#             "message" : "something went wrong"
#         }), 400

# @LDAP_REQUEST.route('/right/remove', methods=['PUT'])
# def rrequest_remove():
#     try:
#         validated = validation()
#         if not validated[0]:
#             return validated[1]
#         req = validated[1]
#         if not isErrorKey(req, "uid_email"):
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "uid_email is required"
#             }), 400
#         uid = get_uid_by_token()
#         if isAdmin(uid) or isMaster(uid):
#             fuser = users.find_one({"uid" : req["uid_email"]})
#             if fuser is None:
#                 fuser = users.find_one({"email" : req["uid_email"]})
#                 if fuser is None:
#                     return jsonify({
#                         "status" : "failed",
#                         "message" : "user not found"
#                     }), 404
#             if isAdmin(fuser["uid"]):
#                 if isMaster(fuser["uid"]):
#                     return jsonify({
#                         "status" : "failed",
#                         "message" : "cannot remove right from this user operation not allowed"
#                     }), 403
#                 removeAdminRight(fuser["uid"])
#                 return jsonify({
#                     "status" : "success",
#                     "message" : "user successfully been removed admin right"
#                 })
#             else:
#                 return jsonify({
#                     "status" : "failed",
#                     "message" : "user is already not an admin"
#                 }), 400
#         else:
#             return jsonify({
#                 "status" : "failed",
#                 "message" : "not allowed to remove rights"
#             }), 403
#     except:
#         return jsonify({
#             "status" : "failed",
#             "message" : "something went wrong"
#         }), 400

# @LDAP_REQUEST.route('/admin/all', methods=['GET'])
# def admin_all():
#     try:
#         validated = validation(allowNullData=True)
#         if not validated[0]:
#             return validated[1]
#         uid = get_uid_by_token()
#         if isAdmin(uid) or isMaster(uid):
#             admin_list = get_admins()
#             azumaril_admins = []
#             for aadmin in admin_list:
#                 fuser = users.find_one({"uid" : aadmin}, {"_id" : 0, "business_roles" : 0, "is_activated" : 0, "log_mode" : 0})
#                 if fuser is not None:
#                     azumaril_admins.append(fuser)
#             return jsonify({
#                 "status" : "success",
#                 "message" : "",
#                 "data" : azumaril_admins
#             })
#         else:
#            return jsonify({
#                 "status" : "failed",
#                 "message" : "not allowed to see admins"
#             }), 403 
#     except:
#         return jsonify({
#             "status" : "failed",
#             "message" : "something went wrong"
#         }), 400

