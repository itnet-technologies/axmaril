import json
import os
import sys
dotenv_content_path = os.path.abspath(os.path.dirname(__file__)  + '/../config.txt')


def config_data(name):
    return os.getenv(name)

def initEnv(config_data, database):
    if database["creds"].find_one({"type" : ".env"}) is None:
        database["creds"].insert_one({
            "type" : ".env",
            "content" : config_data
        })
        initializer(database, config_data)
    else:
        existing_content = database["app"].find_one({"type" : ".env"})["content"]
        compare_content = config_data
        if not(existing_content==compare_content):
            print("There was modified content since last run..")
            print("resting database env var..")
            initializer(database, config_data)

def initializer(db, config_data):
    print("initializing database")
    #delete all-----------------------------------------------------------------
    db["logs_code"].delete_many({})
    db["pwd_policy"].delete_many({})
    db["secret_type"].delete_many({})
    db["creds"].delete_many({})
    db["smtp"].delete_many({})
    
    #insert all-----------------------------------------------------------------
    if getattr(sys, 'frozen', False):
        logs_path = f"{sys._MEIPASS}/static/db_templates/logs_code.json"
        pwd_path = f"{sys._MEIPASS}/static/db_templates/pwd_policy.json"
        secret_path = f"{sys._MEIPASS}/static/db_templates/secret_type.json"
    else:
        logs_path = os.path.abspath(os.path.dirname(__file__) +'/../static/db_templates/logs_code.json')
        pwd_path = os.path.abspath(os.path.dirname(__file__) +'/../static/db_templates/pwd_policy.json')
        secret_path = os.path.abspath(os.path.dirname(__file__) +'/../static/db_templates/secret_type.json')
    logs_code = pwd_policy = secret_type = ''
    with open(f"{logs_path}" ) as file:
        logs_code = json.load(file)
    with open(f"{pwd_path}") as file:
        pwd_policy = json.load(file)
    with open(f"{secret_path}") as file:
            secret_type = json.load(file)
    db["logs_code"].insert_many(logs_code)
    db["pwd_policy"].insert_many(pwd_policy)
    db["secret_type"].insert_many(secret_type)
    creds_objects = []
    ldap_object = {}
    ldap_object["type"] = "ldap"
    ldap_object["url"] = config_data.get('LDAP_URL', None)
    lvalue = {}
    lvalue["default_user_dn"] = config_data.get('LDAP_DEFAULT_USER_DN', None)
    lvalue["default_password"] = config_data.get('LDAP_DEFAULT_PASSWORD', None)
    lvalue["base_dn"] = config_data.get('LDAP_BASE_DN', None)
    lvalue["user_dn"] = config_data.get('LDAP_USER_DN', None)
    lvalue["group_dn"] = config_data.get('LDAP_GROUP_DN', None)
    lvalue["readonly"] = config_data.get('LDAP_READONLY', None)
    lvalue["profil_role_mgr"] = config_data.get('LDAP_PROFIL_ROLE_MGR', None)
    lvalue["technical_profil_mgr"] = config_data.get('LDAP_TECHNICAL_PROFIL_MGR', None)
    lvalue["profil_role_viewer"] = config_data.get('LDAP_PROFIL_ROLE_VIEWER', None)
    lvalue["technical_profil_viewer"] = config_data.get('LDAP_TECHNICAL_PROFIL_VIEWER', None)
    ldap_object["value"] = lvalue

    creds_objects.append(ldap_object)

    airflow_object = {}
    airflow_object["type"] = 'airflow'
    airflow_object["url"] = config_data.get('AIRFLOW_URL', None)
    avalue = {}
    avalue["username"] = config_data.get('AIRFLOW_USERNAME', None)
    avalue["password"] = config_data.get('AIRFLOW_PASSWORD', None)
    airflow_object["value"] = avalue
    airflow_object["dagInfo"] = {
        "send_mail": "send_mail",
        "launch_dag": "launch_dag",
        "approval": "approval_workflow_dev",
        "confirm": "confirm_approval_role_dev"
    }
    creds_objects.append(airflow_object)

    token_object = {}
    token_object["type"] = "token_secret"
    token_object["salt"] = config_data['TOKEN_SECRET_SALT']
    tobject = {}
    tobject["auth_token"] = config_data['TOKEN_SECRET_AUTH_TOKEN']
    tobject["task_token"] = int(config_data['TOKEN_SECRET_TASK_TOKEN'])
    token_object["time"] = tobject

    creds_objects.append(token_object)

    airflow_dev_object = {}
    airflow_dev_object["endpoint"] = config_data.get('AIRFLOW_ENDPOINT', None)

    creds_objects.append(airflow_dev_object)

    altara_airflow_dev = {
        "type":"altara_airflow_dev",
        "username": config_data.get('ALTARA_AIRFLOW_DEV_USERNAME', None),
        "password": config_data.get('ALTARA_AIRFLOW_DEV_PASSWORD', None)
    }

    creds_objects.append(altara_airflow_dev)

    frontendpoint_object = {
        "type": "frontend_endpoint",
        "endpoints":{
            "api_url": config_data['API_URL'] + f":{config_data['API_PORT']}"
        }
    }

    creds_objects.append(frontendpoint_object)

    smtp_object = {
        "host": config_data['SMTP_HOST'],
        "port": config_data['SMTP_PORT'],
        "from": config_data['SMTP_FROM'],
        "username": config_data['SMTP_USERNAME'],
        "password": config_data['SMTP_PASSWORD']
    }
    
    for obj in creds_objects:
        db["creds"].insert_one(obj)
    db["smtp"].insert_one(smtp_object)
    db["creds"].insert_one({
        "type": "File_Server",
        "ip": config_data.get("FILE_SERVER_IP", None),
        "value": {
            "username": config_data.get("FILE_SERVER_USERNAME", None),
            "password": config_data.get("FILE_SERVER_PASSWORD", None)
        }
    })



 