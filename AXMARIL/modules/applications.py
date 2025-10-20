import json
import os
import shutil
import traceback
from flask import Flask, jsonify, request, Blueprint, url_for
from bson import ObjectId
import pymongo
from datetime import datetime, timedelta
# from dateutil.relativedelta import relativedelta
from modules.ldapauth import isErrorKey
from modules.required_packages import db002, leader_validator, validation, creds
from werkzeug.utils import secure_filename
import math
from modules.required_packages import (error_response, success_response, get_uid_by_token)

applications = db002["applications"]
account = db002["account"]
app_account = db002["account"]
api_url = creds.find_one({"type" : "frontend_endpoint"})["endpoints"]["api_url"]
def get_data():
    if not request.get_json():
        return jsonify({"message":"missing params", "status": "failed"}),400
    data = request.get_json(force=True)
    return data


APP_REQU = Blueprint("application", __name__)
@APP_REQU.route('/create', methods=['POST'])
@leader_validator
def create_app():
    try: 
        validated = validation(allowNullData=True)
        if not validated[0]:
            return validated[1]
        req = dict(request.form)
        #check if it exists
        owner_uid = get_uid_by_token()
        check = applications.find_one({"name" : req["name"], "owner_uid" : owner_uid})
        if (check):
            return jsonify({"message":"App " + req["name"] + " already exists", "status": "failed"}), 409
        check = applications.find_one({"name" : req["name"], "owner_uid" : "SYSTEM", "type": req["type"]})
        if (check):
            return jsonify({"message":"App " + req["name"] + " already exists", "status": "failed"}), 409
        #insert
        date_of_creation = datetime.now()
        
        app_id = str(ObjectId())
        app_infos = { 
            "app_id": app_id,
            "owner_uid": owner_uid,
            "type": req["type"],
            "name": req["name"],
            "fields":json.loads(req["fields"]),
            "date": date_of_creation,
            "icon_path": None
        }
        if 'icon' in request.files:
            file = request.files['icon']
            random_str = str(ObjectId())
            temp_folder = os.path.dirname(__file__) + f"/../static/temp/.temp_{random_str}"
            os.makedirs(temp_folder)                                            #create random temp folder
            filename = secure_filename(file.filename)       #get file original name
            filepath = f"{temp_folder}/{filename}"          #set path for the file in the temp folder
            file.save(os.path.join(filepath))               #save file in the temp folder
            app_infos["icon_path"] = f"static/temp/.temp_{random_str}/{filename}"
            # app_infos["icon_path"] = "apps/icons/" + filename
            # upload_file(f"apps/icons", file)
            # shutil.rmtree(temp_folder)
        try:
            applications.insert_one(app_infos)
        except:
            print(traceback.format_exc())
            return ({"message": "Cannot create the application", "status": "failed"}),400
        return jsonify({"message": "App " + req["name"] + " created successfully", "app_id": app_id, "type": req["type"], 
        "created the": date_of_creation, "status": "success" }), 200
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@APP_REQU.route('/update', methods=['PUT'])
@leader_validator
def update_app():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    req = dict(request.form)
    #check if it exists
    try: 
        if not isErrorKey(req, "app_id"):
            return jsonify({
                "status" : "failed",
                "message" : "app_id is required"
            }), 400
        check1 = applications.find_one({"app_id" : req["app_id"], "owner_uid": get_uid_by_token()})
        if check1 is None:
            return jsonify({
                "status": "failed",
                "message":"app not found", 
            }), 404
        
        update_infos = {}
        if isErrorKey(req, "name"):
            check = applications.find_one({"name" : req["name"], "app_id" : {"$ne" : req["app_id"]}})
            if check is not None:
                return jsonify({
                    "status" : "failed",
                    "message" : "app with this name already exist"
                }), 409
            update_infos["name"] = req["name"]
        if isErrorKey(req, "fields"):
            update_infos["fields"] = json.loads(req["fields"])
        if isErrorKey(req, "type"):
            update_infos["type"] = req["type"]
            
        if 'icon' in request.files:
            file = request.files['icon']
            if check1["icon_path"] == "" or check1["icon_path"] is None:
                random_str = str(ObjectId())
                temp_folder = os.path.dirname(__file__) + f"/../static/temp/.temp_{random_str}"
                ipath = f"static/temp/.temp_{random_str}"
            else:
                # print(os.path.dirname(__file__) + f'/../{check1["icon_path"]}')
                os.remove(os.path.dirname(__file__) + f'/../{check1["icon_path"]}')
                temp_folder = check1["icon_path"].replace(f'/{check1["icon_path"].split("/")[-1]}', "")
                ipath = temp_folder
                temp_folder = os.path.dirname(__file__) + f'/../{temp_folder}'
            if not os.path.exists(temp_folder):
                os.makedirs(temp_folder)                                            #create random temp folder
            filename = secure_filename(file.filename)       #get file original name
            ipath += f"/{filename}"
            filepath = f"{temp_folder}/{filename}"          #set path for the file in the temp folder
            file.save(os.path.join(filepath))               #save file in the temp folder
            # print(filepath)
            update_infos["icon_path"] = ipath
            # app_infos["icon_path"] = "apps/icons/" + filename
            # upload_file(f"apps/icons", file)
            # shutil.rmtree(temp_folder)
        if update_infos != {}:
            applications.update_one(
                {"app_id" : req["app_id"]},
                {
                    "$set" : update_infos
                }
            )
        check1 = applications.find_one({"app_id" : req["app_id"]}, {"_id" : 0})
        return jsonify({
            "status": "success", 
            "message": "App successfully updated",
            "data" : check1
        }), 201
    except:
        print(traceback.format_exc())
        return jsonify({"message":"Something went wrong", "status": "failed"}), 400

@APP_REQU.route('/delete', methods=['DELETE'])
@leader_validator
def delete_app():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    found = applications.find_one({"name" : req["name"], "owner_uid": get_uid_by_token()})
    if found is not None:
        applications.delete_one({"name" : req["name"], "owner_uid": get_uid_by_token()})
    return jsonify({"message": "App " + req["name"] + " deleted successfully", "status": "success"}),200

@APP_REQU.route('/account/create', methods=['POST'])
@leader_validator
def add_account():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    
    # if not isErrorKey(req["fields"], "admin_username"):
    #     req["fields"]["admin_username"] = req["username"]
    # if not isErrorKey(req["fields"], "admin_password"):
    #     req["fields"]["admin_password"] = req["password"]

    # app = applications.find_one({"app_id":req["app_id"]})    
    # for k,v in app["fields"].items():
    #     try:
    #         if v:
    #             req["fields"][k]
    #     except KeyError:
    #         return jsonify({"message":f"key {k} is required", "status": "failed"}), 400
    
    date_of_creation = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    account_id = str(ObjectId())
    data_to_store = {
        "account_id": account_id,
        "app_id": req["app_id"],
        "user_uid": req["user_uid"],
        "username": req["username"],
        # "password": req["password"],
        "date": date_of_creation
        # "is_expired": False
    }
    try:
        account.insert_one(data_to_store)
        return ({"status":"success", "account_id": account_id}), 200
    except:
        return jsonify({"message": "Failed to create", "status": "failed"}),400

@APP_REQU.route('/all', methods=['GET'])
def getApp():
    validated = validation(allowNullData=True)
    if not validated[0]:
        return validated[1]
    try:
        params = request.args.to_dict()
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page
        
        apps = applications.find({"$or" : [{"owner_uid" : get_uid_by_token()}, {"owner_uid" : "SYSTEM"}]},{ "_id": 0,
            "app_id": 1,
            "name": 1,
            "type": 1,
            "date": 1,
            "fields": 1,
            "icon_path" : 1}
        ).skip(skip_count).limit(per_page)
        
        total_applications = applications.count_documents({})
        
        last_page = math.ceil(total_applications / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('application.getApp', page=1, _external=True)
    
        # Générer l'URL de la dernière page
        last_page_url = url_for('application.getApp', page=last_page, _external=True)  if last_page >= 1 else None
        
        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('application.getApp', page=page + 1, _external=True) if page < last_page else None
        
        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('application.getApp', page=page - 1, _external=True) if page > 1 else None
        
        
        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_applications
        }

        for app in apps:
            accounts = account.find({"app_id": app["app_id"]})
            nb_account = len(list(accounts))
            app["nb_account"] = nb_account
            app["icon_url"] = f"{api_url}/{app['icon_path']}"
            data["data"].append(app)
        return jsonify({"data": data, "status": "success"}), 200
    except ValueError as error:
        print(traceback.format_exc())
        return jsonify({"message":"Parameters (page or per_page) must be integers greater than or equal to 1 ", "status": "failed"}), 400
    except:
        print(traceback.format_exc())
        
        return jsonify({"message":"Something went wrong", "status": "failed"}),400

@APP_REQU.route('/find', methods=['GET'])
def find_application_by_name():
    validated = validation(allowNullData = True)
    if not validated[0]:
        return validated[1]
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
        
        apps_found = applications.find(
            {'name': {'$regex': regex}}, 
            {
                "_id": 0,
                "app_id": 1,
                "name": 1,
                "type": 1,
                "date": 1,
                "fields": 1,
                "icon_path" : 1
            }
            ).skip(skip_count).limit(per_page)
        
        total_apps_found = applications.count_documents({'name': {'$regex': regex}})
        
        last_page = math.ceil(total_apps_found / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('application.find_application_by_name', name=name, page=1, _external=True)
    
        # Générer l'URL de la dernière page
        last_page_url = url_for('application.find_application_by_name', name=name, page=last_page, _external=True)  if last_page >= 1 else None
        
        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('application.find_application_by_name', name=name, page=page + 1, _external=True) if page < last_page else None
        
        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('application.find_application_by_name', name=name, page=page - 1, _external=True) if page > 1 else None
        
        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_apps_found
        }
        for app in apps_found:
            accounts = account.find({"app_id": app["app_id"]})
            nb_account = len(list(accounts))
            app["nb_account"] = nb_account
            app["date"] = app["date"].strftime('%Y-%m-%d')
            app["icon_url"] = f"{api_url}/{app['icon_path']}"
            data["data"].append(app)
        return success_response(data=data)
    except ValueError as error:
        print(traceback.format_exc())
        return jsonify({"message":"Parameters (page or per_page) must be integers greater than or equal to 1 ", "status": "failed"}), 400
    except Exception as error:
        return error_response(message=str(error))


#for admin---
@APP_REQU.route('/account/all', methods=['POST'])
@leader_validator
def list_accounts():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        accounts = app_account.find({"app_id" : req["app_id"]}, { "_id": 0})
        list_of_accounts = []
        for i in accounts:
            list_of_accounts.append(i)
        return jsonify({"status":"success","data":list_of_accounts}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400

#get all account of all app of user
@APP_REQU.route('/account/user/all', methods=['POST'])
@leader_validator
def list_accounts_of_user():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        accounts = app_account.find({"user_uid" : req["user_uid"]})
        list_of_accounts = []
        for i in accounts:
            list_of_accounts.append({i["username"] : i["password"]})
        return jsonify({"status":"success","data":list_of_accounts}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400
  
#get all account of an app for an user  
@APP_REQU.route('/account/user', methods=['POST'])
@leader_validator
def app_account_of_user():
    validated = validation()
    if not validated[0]:
        return validated[1]
    req = validated[1]
    try:
        accounts = app_account.find({"app_id" : req["app_id"], "user_uid": req["user_uid"]})
        list_of_accounts = []
        for i in accounts:
            list_of_accounts.append({i["username"] : i["password"]})
        return jsonify({"status":"success","data":list_of_accounts}),200
    except:
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400

@APP_REQU.route('/account/search', methods=['POST'])
@leader_validator
def search_account():
    req = get_data()
    app_account = db002["account"]

    try :
        find = app_account.find_one({"app_id" : req["app_id"], "user_uid": req["user_uid"], "username": req["account_username"]})
        if not find:
            return jsonify("")
        account_searched = {find["username"] : find["password"]}
        return jsonify({"status":"success","data":account_searched}),200
    except :
        return jsonify({"message":"Something went wrong!", "status": "failed"}),400
        