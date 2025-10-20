import pathlib
from typing import Final
from flask import request, jsonify, send_file, url_for
from .custom_exception import ErrorOccurred, KeyMissing, NotFoundException, InsufficientRight, AttemptsExceeded, CustomException, SomethingWentWrong, UserAlreadyExist
from ..database.db_manager import DBManager
from werkzeug.utils import secure_filename
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from bson import ObjectId
from threading import Thread
import tempfile
import subprocess
import paramiko
import io
import string
import random
import getpass
import requests
import math
import traceback
import shutil
import time
import os
import sys
import jwt
import ast
import binascii
import smtplib
import secrets
import subprocess
import shlex
from datetime import datetime, timedelta
import base64
import tempfile2
#from api.v2.modules.secret.secret_model import SecretModel
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from bson.codec_options import CodecOptions
from bson.binary import UUID_SUBTYPE
from mongita import MongitaClientDisk
from ldap3 import (
    LEVEL,
    MODIFY_ADD,
    MODIFY_REPLACE,
    MODIFY_DELETE,
    Server,
    Connection,
    ALL,
    SUBTREE,
    ALL_ATTRIBUTES,
    HASHED_SALTED_SHA,
)

db_manager = DBManager()

AZUMARIL_KEYS = os.getenv("AZUMARIL_KEYS")
AIDBPATH = os.path.join(pathlib.Path.home(), '.mongita')
if "AZUMARIL_INITIATOR_DBPATH" in os.environ:
    print(f"Variable AZUMARIL_INITIATOR_DBPATH found. Value: {os.environ['AZUMARIL_INITIATOR_DBPATH']}")
    AIDBPATH = os.environ["AZUMARIL_INITIATOR_DBPATH"]
    if not os.path.exists(AIDBPATH):
        print("Path not existing")
        print("Generating path")
        os.makedirs(AIDBPATH, exist_ok=True)

client_mongita = MongitaClientDisk(host = AIDBPATH)
azumaril_app = client_mongita["azumaril_app"]
shamir_app = client_mongita["shamir"]
azumaril_app_info = azumaril_app["azumaril_app_info"]
cd_secret_collection = azumaril_app["azumaril_app_config_data_secret"]
cd_secret_type_collection = azumaril_app["config_data_secret_type"]
app_state = shamir_app["app_state"]
ldap_server = db_manager.find_one("creds", {"type": "ldap"})
def mail_sender(receiver, subject, message):
    """
    Generates the Auth Token
    :return: string
    """
    msg = MIMEMultipart()
    msg["From"] = config_data["SMTP_FROM"]
    msg["To"] = receiver
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "html"))
    text = msg.as_string()
    try:
        smtp = smtplib.SMTP(config_data["SMTP_HOST"], config_data["SMTP_PORT"])
        if config_data["SMTP_TLS"]:
            smtp.starttls()
            smtp.login(config_data["SMTP_USERNAME"], config_data["SMTP_PASSWORD"])
        smtp.sendmail(config_data["SMTP_USERNAME"], receiver, text)

        # Terminating the session
        smtp.quit()
        print("Email sent successfully!")
    except Exception as ex:
        print("Something went wrong....", ex)

class CustomThread(Thread):
    def __init__(
        self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None
    ):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        Thread.join(self, *args)
        return self._return

def commander(arg_list = [], inputs = None):
    # command = [f"/home/itnet/Azumaril/static/shamir2.py"]
    command = [os.path.dirname(__file__) + "/../../../static/shamir"]
    if getattr(sys, 'frozen', False):
        command[0] = f"{sys._MEIPASS}/static/shamir"
    command += arg_list
    if inputs is None:
        result = subprocess.run(
            command,
            capture_output = True,
            text = True
        )
    else:
        result = subprocess.run(
            command,
            input = inputs,
            capture_output = True,
            text = True
        )
    if result.stdout is not None and result.stdout != "":
        lines = result.stdout
        if len(arg_list) >=2:
            if arg_list[1] == "-i" and len(lines.split("\n")) >2 :
                # lines = lines.split('\n',1)[-1]
                return True, lines
            else:
                return True, lines
        else:
            return True, lines
    else:
        return False, result.stderr
 

def remove_last_line(s):
    return s[:s.rfind('\n')]

def remove_last_lines(s, n):
    for i in range(n):
        s = s[:s.rfind('\n')]
    return s

def remove_first_line(lines):
    return lines.split('\n',1)[-1]

def not_initiated():
    checker = commander(["-a"])
    lines = checker[1]
    print(lines)
    if "The app has not been initiated yet" in lines:
        return True
    else:
        return False

def loader_v2(args, in_sdd = False, break_if_done = True, inputs = None, outputs = True):
    try:
        rks = ["clear", "app", "init", "unseal", "encrypt", "decrypt", "seal"]
        for rk in rks:
            if rk not in args:
                args[rk] = None
        if args["clear"] is not None and args["clear"]:
            if inputs is None:
                mink = commander(["-mik"])[1]
                args_to_input = []
                for i in range(int(mink)):
                    args_to_input.append(getpass.getpass("Enter the key : "))
                inputs = ""
                for key in args_to_input:
                    inputs += f"{key}\n"
            checker = commander(["-cls"], inputs = inputs)
            lines = checker[1]
            lines = lines.split('\n',1)[-1]
            return lines
            # print(lines)
            # sys.exit(1)
        if args["app"] is not None and args["app"]:
            checker = commander(["-a"])
            if break_if_done:
                if outputs:
                    print(checker[1])
                sys.exit(1)
            else:
                return checker[1]
        if args["init"] is not None and args["init"]:
            checker = commander(["-a"])
            lines = checker[1]
            if len(lines.split("\n")) >2:
                if outputs:
                    print(commander(["-i"])[1])
                sys.exit(1)
            else:
                if inputs is None:
                    maxKey = input("Enter the maximum number of keys : ")
                    minKey = input("Enter the minimum number of keys for the reconstitution : ")
                    inputs = f"{maxKey}\n{minKey}"
                result = commander(["-i"], inputs = inputs)[1]
                if outputs:
                    print(result)
                if inputs is not None:
                    return result
                if break_if_done:
                    sys.exit(1)
                else:
                    return True
        if args["unseal"] is not None and args["unseal"]:
            mink = commander(["-mik"])[1]
            checker = commander(["-a"])[1]
            if not_initiated():
                if outputs:
                    print(commander(["-u"])[1])
                sys.exit(1)
            else:
                if "Seal : False" in checker:
                    if outputs:
                        print(commander(["-u"])[1])
                    sys.exit(1)
                else:
                    args_to_input = []
                    for i in range(int(mink)):
                        args_to_input.append(getpass.getpass("Enter the key : "))
                    inputs = ""
                    for key in args_to_input:
                        inputs += f"{key}\n"
                    lines = commander(["-u"], inputs = inputs)[1]
                    lines = lines.split('\n',1)[-1]
                    # mkey = lines.split("\n")[0]
                    lines = lines.split('\n',1)[-1]
                    # mkey = lines.split("\n")[len(lines.split("\n"))-1]
                    # lines = remove_last_line(lines)
                    if outputs:
                        print(lines)
                    # if outputs:
                    # print(mkey)
                    sys.exit(1)
        if args["encrypt"] is not None:
            if outputs:
                print(commander(["-e"], "Nothing")[1])
            sys.exit(1)
        if args["decrypt"] is not None:
                if outputs:
                    print(commander(["-d"], "Nothing Nothing Nothing")[1])
                sys.exit(1)
        if in_sdd:
            KEYS = os.getenv('AZUMARIL_KEYS')
            args["keys"] = KEYS.split(",")  #if the API is running into the development server
        
        if not_initiated():      #if the app was not initiated yet 
            choice = input("App not initiated, dou you want to init ? (yes/no) : ")
            inputs = f"{choice}"
            if choice == "yes":
                maxKey = input("Enter the maximum number of keys : ")
                minKey = input("Enter the minimum number of keys for the reconstitution : ")
                inputs += f"\n{maxKey}\n{minKey}\nno"
                lines = commander(inputs = inputs)[1]
                lines = remove_last_lines(lines, 3)
                lines = remove_first_line(lines)
                if outputs:
                    print(lines)
                choice = input("App sealed do you want to unseal ? (yes/no) : ")
                inputs = f"{choice}"
                if choice == "yes":
                    for i in range(int(minKey)):
                        keyy = getpass.getpass("Enter the key : ")
                        inputs += f"\n{keyy}"
                    lines = commander(inputs = inputs)[1]
                    lines = remove_first_line(lines)
                    byted_encryption_key = lines.split("\n")[0]
                    encryption_key = byted_encryption_key[2:-1] #b'fgf'
                    lines = remove_first_line(lines)
                    if outputs:
                        print(lines)
                    return encryption_key
                else:
                    lines = commander(inputs = inputs)[1]
                    lines = remove_first_line(lines)
                    if outputs:
                        print(lines)
                    sys.exit(1)
            else:
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                if outputs:
                    print(lines)
                sys.exit(1)
        else:               #if the app had already been initiated
            mink = commander(["-mik"])[1]
            if not in_sdd and args["seal"] is None:
                if inputs is not None:
                    lines = commander(inputs = inputs)[1]
                    if args["seal"]:
                        return lines
                    # if outputs:
                    # print(lines)
                    lines = remove_first_line(lines)
                    byted_encryption_key = lines.split("\n")[0]
                    encryption_key = byted_encryption_key[2:-1]
                    lines = remove_first_line(lines)
                    # if outputs:
                    # print(lines)
                    if lines.split("\n")[0] == "app not unsealed":
                        if not break_if_done:
                            return None
                        
                        sys.exit(1)
                    return encryption_key
                choice = input("App sealed do you want to unseal ? (yes/no) : ")
            else:
                choice = "yes"      #if the API is running into the development server
            inputs = f"{choice}"
            if choice == "yes":
                keys_idx = 0
                for i in range(int(mink)):
                    if not in_sdd :  
                        keyy = getpass.getpass("Enter the key : ")
                    else:
                        keyy = args["keys"][keys_idx]   #if the API is running into the development server
                    keys_idx += 1
                    inputs += f"\n{keyy}"
                lines = commander(inputs = inputs)[1]
                if args["seal"]:
                    return lines
                lines = remove_first_line(lines)
                byted_encryption_key = lines.split("\n")[0]
                encryption_key = byted_encryption_key[2:-1]
                lines = remove_first_line(lines)
                # if outputs:
                # print(lines)
                if lines.split("\n")[0] == "app not unsealed":
                    if not break_if_done:
                        return None
                    
                    sys.exit(1)
                return encryption_key
            else:
                lines = commander(inputs = inputs)[1]
                lines = remove_first_line(lines)
                if outputs:
                    print(lines)
                sys.exit(1)
    except:
        print(traceback.format_exc())
        time.sleep(80)
        sys.exit(1)

def get_default_secret(secret, secret_salt):
    try:
        if type(secret["secret"]) == type({}):
            if "$binary" in secret["secret"]:
                secret["secret"] = secret["secret"]["$binary"]
        # print(secret["secret"])
        # print(type(secret["secret"]))
        # print(secret_salt)
        # print(type(secret_salt)) String1#
        encrypted_data = jwt.decode(secret["secret"], secret_salt, algorithms=["HS256"])
        decrypted_data = decrypt(encrypted_data, encryption_key=secret_salt)
        if isinstance(decrypted_data, tuple):
            # print("tupled")
            # print(decrypted_data)
            return None
        print("default secret fetched")
        return jwt.decode(decrypted_data, secret_salt, algorithms=["HS256"])
    except:
        print(traceback.format_exc())
        return None

inputs = f"yes\n\n\n"

ecptk = loader_v2({}, AZUMARIL_KEYS is not None, False, inputs=inputs, outputs=False)


def encrypt(data = None, is_file = False, isUpdating = False, encryption_key = None):
    global ecptk
    db_manager = DBManager()
    if is_file:
        if isUpdating:         
            fsecret = db_manager.find_one("secrets", {"secret_id": data["secret_id"]}, {'_id': 0})
            safe_id = fsecret["safe_id"]
            name = fsecret["secret_name"]
            auth_token = request.headers.get('Authorization')
            auth_token = auth_token.split()[1]
            userid = data["owner_uid"]
            if isErrorKey(data, "safe_id"):
                safe_id = data["safe_id"]
            if isErrorKey(data, "secret_name"):
                name = data["secret_name"]
                
            if isErrorKey(data, "file_path"):
                commander(["-ef", "-path", data["file_path"], "-ecptk", ecptk])[1]
                print(data)
                efp = data["file_path"].replace(data["file_name"], f'{data["secret_name"]}.azumaril')
                with open(efp, mode="r") as file:
                    secret = file.read()
                    data["secret"] = secret
                    file.close()
                try:
                    fileserver = db_manager.find_one("creds", {"type":"File_Server"}, {'_id': 0})
                    file_server_url = fileserver['ip']
                    url = f"{file_server_url}?token={auth_token}&path={fsecret['file_path']}&userid={userid}"
                    requests.delete(url)
                except:
                    pass
                try:
                    with open(efp, mode="rb") as file:
                        upload_file(f"users/{data['owner_uid']}/{safe_id}", file, upload_type = "complexe")
                        file.close()
                except:
                    pass
                data["file_path"] = f"users/{data['owner_uid']}/{safe_id}/{name}.azumaril"
                secret_id = data["secret_id"]
                del data["owner_uid"]
                del data["secret_id"]
                db_manager.update_one("secrets", {"secret_id" : secret_id}, data)
                """secrets.update_one(
                    {"secret_id" : secret_id},
                    {
                        "$set" : data
                    }
                )"""
            else:
                old_file_path = fsecret['file_path']
                if isErrorKey(data, "safe_id"):
                    fsecret["file_path"] = fsecret["file_path"].replace(fsecret["safe_id"], data["safe_id"])
                    data["file_path"] = fsecret["file_path"]
                if isErrorKey(data, "secret_name"):
                    fsecret["file_name"] = fsecret["file_name"].replace(fsecret["secret_name"], data["secret_name"])
                    data["file_name"] = fsecret["file_name"]
                    fsecret["file_path"] = fsecret["file_path"].replace(fsecret["secret_name"], data["secret_name"])
                    data["file_path"] = fsecret["file_path"]
                secret_id = data["secret_id"]
                del data["owner_uid"]
                del data["secret_id"]
                if data != {}:
                    fileserver = db_manager.find_one("creds", {"type":"File_Server"}, {'_id': 0})
                    file_server_url = fileserver['ip']
                    url = f"{file_server_url}?token={auth_token}&path={old_file_path}&userid={userid}&newPath={data['file_path']}"
                    requests.put(url)
                    db_manager.update_one("secrets", {"secret_id" : secret_id}, data)
                    """secrets.update_one(
                        {"secret_id" : secret_id},
                        {
                            "$set" : data
                        }
                    )"""
        else:
            commander(["-ef", "-path", data["file_path"], "-ecptk", ecptk])[1]
            efp = data["file_path"].replace(data["file_name"], f'{data["secret_name"]}.azumaril')
            with open(efp, mode="r") as file:
                secret = file.read()
                data["secret"] = secret
                file.close()
            try:
                with open(efp, mode="rb") as file:
                    upload_file(f"users/{data['owner_uid']}/{data['safe_id']}", file, upload_type = "complexe")
                    file.close()
            except:
                pass
            data["file_path"] = f"users/{data['owner_uid']}/{data['safe_id']}/{data['secret_name']}.azumaril"
            
            fsecret = db_manager.find_one("secrets", {"file_name" : data["file_name"], "owner_uid": data["owner_uid"], "safe_id": data["safe_id"]}, {"_id":0})
            if fsecret is None:
                from bson import ObjectId

                data["secret_id"] = str(ObjectId())
                db_manager.insert_one("secrets", data)
                
        # else:
        #     secrets.find_one_and_update(
        #         {
        #             "file_name" : data["file_name"],
        #             "owner_uid": data["owner_uid"],
        #             "safe_id": data["safe_id"]
        #         },
        #         {
                    
        #         }
        #     )
    else:
        if encryption_key is None:
            encryption_key = ecptk
        lines = commander(["-e", "-data", data, "-ecptk", encryption_key])[1]
        # print(lines)
        cpt = lines.split("\n")[0][2:-1]
        tag = lines.split("\n")[1][2:-1]
        nonce = lines.split("\n")[2][2:-1]
        return cpt, tag, nonce

def decrypt(encrypted_data="", is_file=False, file_path=None, encryption_key=None):
    global ecptk
    if is_file:
        commander(["-df", "-ecptk", ecptk, "-path", file_path])[1]
        return ""
    if encryption_key is None:
        encryption_key = ecptk
    lines = commander(
        [
            "-d",
            "-ecptk",
            encryption_key,
            "-ctxt",
            encrypted_data["ciphertext"],
            "-tag",
            encrypted_data["tag"],
            "--nonce",
            encrypted_data["nonce"],
        ]
    )[1]
    decrypted_data = lines.split("\n")[1].split(":")[1]
    return decrypted_data


EC_PTK: Final[str] = ecptk
default_secret_keys = list(cd_secret_collection.find({}))
# print(default_secret_keys)
config_data = {}
for default_secret_key in default_secret_keys:
    decrypted_default_secret_key = get_default_secret(
        default_secret_key, ecptk
    )
    if decrypted_default_secret_key is not None:
        config_data.update(decrypted_default_secret_key)

def success_response(status="success", message="", code=200, data=[], **kwargs):
    response_data = {
        "status": status,
        "is_success": True,
        "message": message,
        "data": data
    }
    response_data.update(kwargs)
    return jsonify(response_data), code

def get_system_safe():
    fsafe = db_manager.find_one("safe", {"owner_uid" : "SYSTEM", "name": "SYSTEM", "type": "system"})
    # safe_info = {
    #             "owner_uid": "0000000",
    #             "safe_id": safe_id,
    #             "name": "SYSTEM",
    #             "type": "system",
    #             "date": datetime.now(),
    #         }
    #         safes.insert_one(safe_info)
    return fsafe

fapp = db_manager.find_one("applications", {"owner_uid" : "SYSTEM", "type": "kmip", "name": "kmip"})
if fapp is None:
    print("Creating kmip application ..")
    db_manager.insert_one(
        "applications",
        {
            "app_id": str(ObjectId()),
            "owner_uid": "SYSTEM",
            "app_type": "kmip",
            "type": "kmip",
            "name": "kmip",
            "fields": {
                "url": True,
                "collection": True,
                "database": True
            },
            "date": datetime.now().strftime("%d-%b-%Y %H-%M-%S"),
            "icon_path": "static/app_icons/kmip_icon.png"
        }
    )
    print("Kmip application created!")

fapp = db_manager.find_one("applications", {"owner_uid" : "SYSTEM", "type": "rdp", "name": "RDP"})
if fapp is None:
    print("Creating RDP application ..")
    db_manager.insert_one(
        "applications",
        {
            "app_id": str(ObjectId()),
            "owner_uid": "SYSTEM",
            "app_type": "rdp",
            "type": "rdp",
            "name": "RDP",
            "fields": {
                "hostname": True,
                "username": True,
                "password": True,
                "max-connections": False,
                "color_depth": False,
                "width": False,
                "height": False,
                "max-connections-per-user": False,
                "domain": False
            },
            "date": datetime.now().strftime("%d-%b-%Y %H-%M-%S"),
            "icon_path": "static/app_icons/rdp.jpg"
        }
    )
    print("RDP application created!")
    
fapp2 = db_manager.find_one("applications", {"owner_uid" : "SYSTEM", "type": "ca", "name": "ca"})
if fapp2 is None:
    # print("aaaaa")
    # db_manager.delete_one("applications", fapp2)
    # print("ok")
    
    print("Creating CA application ..")
    db_manager.insert_one(
        "applications",
        {
            "app_id": str(ObjectId()),
            "owner_uid": "SYSTEM",
            "app_type": "ca",
            "type": "ca",
            "name": "ca",
            "fields": {
            },
            "date": datetime.now().strftime("%d-%b-%Y %H-%M-%S"),
            "icon_path": "/home/AZUMARIL/static/app_icons/ca_icon.png"
        }
    )
    print("CA application created!")

def error_response(status="failed", message="", code=400, data=[], **kwargs):
    response_data = {
        "status": status,
        "is_success": False,
        "message": message,
        "data": data
    }
    response_data.update(kwargs)
    return jsonify(response_data), code

def save_icon_file(icon_dir, icon_file, save_filename):
    os.makedirs(icon_dir, exist_ok=True)
    icon_path = os.path.join(icon_dir, save_filename)
    icon_file.save(icon_path)

def isErrorKey(data, key):
    try:
        data[key]
        return True
    except KeyError:
        return False

def save_secret_file(secret_dir, secret_file, secret_name):
    temp_folder = os.path.dirname(__file__) + secret_dir
    os.makedirs(temp_folder)
    file_name = secure_filename(secret_file.filename)
    file_path = f"{temp_folder}/{file_name}"
    secret_file.save(os.path.join(file_path))
    file_type = secret_file.content_type if secret_file.content_type else ""

    # format secret name
    if secret_name is not None:
        path = Path(file_path)
        extension = path.suffix
        path.rename(Path(path.parent, f"{secret_name}{extension}"))
        file_path = f"{temp_folder}/{secret_name}{extension}"
        file_name = f"{secret_name}{extension}"

    return {
        "file_name": file_name, 
        "file_path": file_path, 
        "file_type": file_type, 
        "temp_folder": temp_folder
    }


def upload_file(path_to_upload, file, atype = "file", is_certificate = "no", certificate_path = "a", upload_type = "simple"):
    try:
        db_manager = DBManager()
        fileserver = db_manager.find_one("creds", {"type":"File_Server"}, {'_id': 0})
        file_server_url = fileserver['ip']
        dataToSend = {
            "path" : path_to_upload,
            "atype" : atype
        }
        response = requests.post(
            file_server_url, 
            # json = dataToSend,
            headers = {
                "path" : path_to_upload,
                "atype" : atype,
                "application" : "azumaril",
                "upload_type" : upload_type,
                "is_certificate" : is_certificate,
                "certificate_path" : certificate_path
            },
            files = {"form_field_name": file}
        )
        # print(response.status_code)
        return True
    except:
        # print(traceback.format_exc())
        return False


def secret_access(secret_id, owner_uid):
    db_manager = DBManager()
    secret = db_manager.find_one("secrets", {"secret_id": secret_id, "owner_uid": owner_uid})
    #secret = secrets.find_one({"secret_id": secret_id, "owner_uid": owner_uid})
    rights = {
        "read": True,
        "write": True,
        "share": True,
        "propagate": True,
        "delete": True,
        "all": False,
        "owner": True,
    }
    if secret is None:
        db_manager = DBManager()
        owner = db_manager.find_one("users", {"uid": owner_uid}, {"_id": 0, "email": 1})
        #owner = users.find_one({"uid": owner_uid}, {"_id": 0, "email": 1})
        # NOTE est-ce que le même secret peut être partager deux fois a la même personne?
        # ne faut il pas simplement mettre à jour le précédent partage?
        
        found_share = owner = db_manager.find_one(
            "shares", 
            {
                "secret_ids": {"$all": [secret_id]},
                "users_mails": {"$all": [owner["email"]]},
            }
        )

        # found_share = shares.find_one(
        #    {
        #        "secret_ids": {"$all": [secret_id]},
        #        "users_mails": {"$all": [owner["email"]]},
        #    }
        # )
        if found_share is not None:
            attempts = None
            if "attempts" in found_share:
                attempts = found_share["attempts_info"]
            
            db_manager = DBManager()
            secret = db_manager.find_one("secrets", {"secret_id": secret_id})
            rights["owner"] = False
            for k, v in rights.items():
                try:
                    if not (k in ["owner", "all"]):
                        found_share["rights"][k]
                        rights[k] = found_share["rights"][k]
                except:
                    rights[k] = False
            # rights["read"] = found_share["rights"]["read"]
            # rights["write"] = found_share["rights"]["write"]
            # rights["share"] = found_share["rights"]["share"]
            # rights["propagate"] = found_share["rights"]["propagate"]
            # rights["delete"] = found_share["rights"]["delete"]
            if (
                rights["read"]
                and rights["write"]
                and rights["share"]
                and rights["delete"]
                and rights["propagate"]
            ):
                rights["all"] = True
            return (
                True,
                secret,
                rights,
                found_share["share_ids"],
                attempts,
                found_share["share_id"],
            )
        else:
            return False, None, rights
    return True, secret, rights

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
                    db_manager = DBManager()
                    db_manager.update_one(
                        "shares",
                        {"share_id":share_id},
                        {"$set":{"attempts_info":attempts}}
                    )
                
                else:
                    return False, "secret access attempts exceeded"
                return True, ua

def encode_token(token_type, user_uid, data, exp_days, payload_data=None, oidc=False):
    db_manager = DBManager()
    tokenTmp = {
        "token": "xxxxxxxxxxxxxxxxxxxxxx",
        "user_uid": "",
        "creation_date": "",
        "expiration_date": "",
        "is_expired": "true",
    }
    try:
        creation_date_time = datetime.utcnow()
        expiration_date_time = creation_date_time + timedelta(hours=exp_days * 24)
        payload = {
            "exp": expiration_date_time,
            "iat": datetime.utcnow(),
            "sub": user_uid,
        }
        if payload_data is not None:
            payload.update(payload_data)
        credsData = db_manager.find_one("creds", {"type":"token_secret"}, {"_id":0})
        salt = credsData["salt"]
        encodejwt = jwt.encode(payload, salt, algorithm="HS256")
        # print(encodejwt)
        if isinstance(encodejwt, bytes):
            encodejwt = encodejwt.decode("utf-8")
        tokenTmp["type"] = token_type
        tokenTmp["token"] = encodejwt
        tokenTmp["user_uid"] = user_uid
        expiry_date = datetime.utcnow() + timedelta(hours=24)
        tokenTmp["expireAt"] = expiry_date
        tokenTmp["creation_date"] = creation_date_time
        tokenTmp["expiration_date"] = expiration_date_time
        tokenTmp["is_expired"] = "false"
        tokenTmp.update(data)
        if not oidc:
            db_manager.insert_one("tokens", tokenTmp)
            #token.insert_one(tokenTmp)
        return tokenTmp
    except Exception as e:
        return e

def check_keys(fields, dictionary):
    required_key = []
    for key, value in fields.items():
        if value:
            required_key.append(key)

    missing_key = []
    for key in required_key:
        if key not in dictionary:
            missing_key.append(key)

    if len(missing_key) > 0:
        response = str(missing_key)
        return False, response
    else:
        return True, []

def secret_credentials_encryption(secret):
    db_manager = DBManager()
    credsData = db_manager.find_one("creds", {"type":"token_secret"}, {"_id":0})
    salt = credsData["salt"]

    #print(secret)
    secret_jwt = jwt.encode(
        secret,
        salt,
        algorithm='HS256'
    )
    #print(secret_jwt)

    encrypted_data = encrypt(secret_jwt)

    encrypted_data_jwt = jwt.encode(
        {
            "ciphertext" : encrypted_data[0],
            "tag" : encrypted_data[1],
            "nonce" : encrypted_data[2]
        },
        salt,
        algorithm='HS256'
    )

    return encrypted_data_jwt

def reveal_secret(secret_id):
        """
            All exception in this function is: NotFoundException InsufficientRight AttemptsExceeded CustomException SomethingWentWrong
        """
        db_manager = DBManager()
        credsData = db_manager.find_one("creds", {"type":"token_secret"}, {"_id":0})
        salt = credsData["salt"]
        fsecret = db_manager.find_one("secrets", {"secret_id": secret_id})

        if not fsecret:
            raise NotFoundException('Secret not found')
            # return error_response(message=f"No secret found", code=404)
        
        access_info = secret_access(fsecret["secret_id"], fsecret["owner_uid"])
        if not access_info[2]["read"]:
            raise InsufficientRight("access denied, can't perform this action on this secret")
            # return error_response(messag="", code=403)
        
        secret = access_info[1]
        if(not access_info[2]["owner"]):
            check_result = check_attempts(access_info, fsecret["owner_uid"])
            if(not check_result[0]):
                raise AttemptsExceeded(check_result[1])
        
        if secret["secret_type"] == "file":
            random_str = str(ObjectId())
            temp_folder = os.path.dirname(__file__) + f"/temp/.temp_{random_str}"
            os.makedirs(temp_folder)

            if secret["secret"] is not None:
                if "secret_name" in secret:
                    with open(f'{temp_folder}/{secret["secret_name"]}.azumaril', 'w') as f:
                        f.write(secret["secret"])
                        f.close()
                    print("not downloading the file secret is not None")
                    decrypt(is_file = True, file_path = f'{temp_folder}/{secret["secret_name"]}.azumaril')
                elif "name" in secret:
                    with open(f'{temp_folder}/{secret["name"]}.azumaril', 'w') as f:
                        f.write(secret["secret"])
                        f.close()
                    print("not downloading the file secret is not None")
                    decrypt(is_file = True, file_path = f'{temp_folder}/{secret["name"]}.azumaril')
                
            else:
                if(not access_info[2]["owner"]):
                    auth_token = encode_token("access_token", secret["owner_uid"], {}, 1)['token']
                fileserver = db_manager.find_one("creds", {"type":"File_Server"}, {'_id': 0})
                file_server_url = fileserver['ip']
                url = file_server_url.replace("Azumaril/", f"{auth_token}/Azumaril/") + secret['file_path']
                response = requests.get(url, allow_redirects=True)
                
                if "secret_name" in secret:
                    with open(f'{temp_folder}/{secret["secret_name"]}.azumaril', 'wb') as file:
                        file.write(response.content)
                        file.close()
                    decrypt(is_file = True, file_path = f'{temp_folder}/{secret["secret_name"]}.azumaril')
                elif "name" in secret:
                    with open(f'{temp_folder}/{secret["name"]}.azumaril', 'wb') as file:
                        file.write(response.content)
                        file.close()
                    decrypt(is_file = True, file_path = f'{temp_folder}/{secret["name"]}.azumaril')

            with open(f'{temp_folder}/{secret["file_name"]}', 'rb') as file:
                data = file.read()
                file.close()
            shutil.rmtree(temp_folder)

            result = {"data": data.hex(), "name": secret["file_name"]}
            return result
        
        try:
            if type(secret["secret"]) == type({}):
                if "$binary" in secret["secret"]:
                    secret["secret"] = secret["secret"]["$binary"]
            if "app_type" in secret :
                if secret["app_type"] == "azumaril":
                    if "deletable" in secret :
                        if not secret["deletable"]:
                            salt = ecptk
            encrypted_data = jwt.decode(secret["secret"], salt, algorithms=["HS256"])
            decrypted_data = decrypt(encrypted_data)

            if isinstance(decrypted_data, tuple):
                raise CustomException(decrypted_data[1])
                # return error_response(message=, code=403)
            return jwt.decode(decrypted_data, salt, algorithms=["HS256"])
            # return success_response(message="successfully decrypted", data=)
        except:
            print(traceback.format_exc())
            raise SomethingWentWrong("Something went wrong")
            # return error_response(message=")


def check_keys_and_null_values(array, dictionary):
    missing_keys = []
    null_value_keys = []

    for key in array:
        if key not in dictionary:
            missing_keys.append(key)
        elif dictionary[key] is None:
            null_value_keys.append(key)
    
    if missing_keys or null_value_keys:
        return False, missing_keys + null_value_keys
    else:
        return True, []

# generation de cles ssh 
def generate_ssh():
    key = paramiko.RSAKey.generate(4096)
    private_key_store = io.StringIO()
    key.write_private_key(private_key_store)
    private_key_content = private_key_store.getvalue()
    #print(private_key_content)
    public_key = f'ssh-rsa {key.get_base64()}'
    with open("key.pub", "w") as f:
        f.write(public_key)
    return private_key_content, public_key

def copy_value_to_file(value_name, extension):
    with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix=extension) as temp_file:
        temp_file.write(value_name.encode())
        temp_file.close()
    return temp_file.name

def get_ssh_key(secret):
    if "private_key" and "public_key" in secret:
        return secret["private_key"], secret["public_key"]
    else:
        return None, None

def download_ssh_key(secret):
    private_key, public_key = get_ssh_key(secret)
    if private_key and public_key is not None:
        try:
            with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.pem') as temp_file:
                temp_file.write(private_key.encode())
                temp_file.write(public_key.encode())
                temp_file.close()

            print("SSH Key uploaded successfully")
            return send_file(temp_file.name, as_attachment=True, download_name='private_key.pem')
        except:
            print(traceback.print_exc())
            raise ErrorOccurred("Error occurred while writing the file")
    else:
        raise KeyMissing("Missing ssh key in dictionnary")

"""
def delete_sshpubkey(username, hostname, pub_key, private_key = None, password=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(username=username, hostname=hostname, password=password)
    elif private_key:
        ssh.connect(username=username, hostname=hostname, key_filename=private_key)
    else:
        print("Enter hostname password or add private_key")
        exit(0)

    print('Récupération de la clé à supprimer')
    if os.path.exists(pub_key):
        with open(pub_key, 'r') as f:
            sshkey = f.read()
    else:
        sshkey = pub_key
    print(sshkey)
    print('++++++++++++++++++++++++++++++++++++++1')
    stdin, stdout, stderr = ssh.exec_command('cat {}'.format("~/.ssh/authorized_keys"))
    ssh_distant= stdout.read().decode()
    print(ssh_distant)
    print('++++++++++++++++++++++++++++++++++++++2')
    new_ssh_distant = ssh_distant.replace(sshkey, ' ')
    print(new_ssh_distant)
    print('++++++++++++++++++++++++++++++++++++++3')
    # stdin, stdout, stderr = ssh.exec_command('echo {} > /root/.ssh/authorized_keys'.format(new_ssh_distant))
    stdin, stdout, stderr = ssh.exec_command('echo "{}" > {}'.format(new_ssh_distant, "~/.ssh/authorized_keys"))
    
    ssh_distant= stdout.read().decode()
    print(ssh_distant)
    ssh.close()
"""

ssh_path = "~/.ssh/authorized_keys"

def add_sshpubkey(username, hostname, pub_key, private_key = None, password=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(username=username, hostname=hostname, password=password)
    elif private_key:
        ssh.connect(username=username, hostname=hostname, key_filename=private_key)
    else:
        print("Enter hostname password or add private_key")
        exit(0)

    print('Récupération de la clé à Ajouter')
    if os.path.exists(pub_key):
        with open(pub_key, 'r') as f:
            sshkey = f.read()
    else:
       sshkey = pub_key
    stdin, stdout, stderr = ssh.exec_command('cat {} '.format(ssh_path))
    ssh_distant= stdout.read().decode()
    # print('+++++++++++++++++++++++++++++++++++4')
    # print(ssh_distant)

    if sshkey in ssh_distant:
        print ('la clé existe déjà sur le serveur distant')
        exit(0)
    print("Ajout de la clé publique sur le serveur distant ...")
    # new_ssh_distant = ssh_distant.replace(sshkey, ' ')
    # print(new_ssh_distant)
    stdin, stdout, stderr = ssh.exec_command(f'echo "{sshkey}" >> {ssh_path} ')
    ssh.close()

def ssh_auto_disconnection(username, hostname, private_key = None, password=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(username=username, hostname=hostname, password=password)
    elif private_key:
        ssh.connect(username=username, hostname=hostname, key_filename=private_key)
    else:
        print("Enter hostname password or add private_key")
        exit(0)

    ssh.exec_command('skill -kill -u {}'.format(username))
    ssh.close()

def delete_sshpubkey(username, hostname, pub_key, private_key = None, password=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(username=username, hostname=hostname, password=password)
    elif private_key:
        ssh.connect(username=username, hostname=hostname, key_filename=private_key)
    else:
        print("Enter hostname password or add private_key")
        exit(0)

    print('Récupération de la clé à supprimer')
    if os.path.exists(pub_key):
        with open(pub_key, 'r') as f:
            sshkey = f.read()
    else:
        sshkey = pub_key
    # print(sshkey)
    # print('++++++++++++++++++++++++++++++++++++++1')
    stdin, stdout, stderr = ssh.exec_command('cat {}'.format(ssh_path))
    ssh_distant= stdout.read().decode()
    # print(ssh_distant)
    # print('++++++++++++++++++++++++++++++++++++++2')
    #new_ssh_distant = ssh_distant.replace(sshkey, ' ')
    lines = ssh_distant.split('\n')
    new_lines = [line for line in lines if sshkey not in line]
    new_ssh_distant = '\n'.join(new_lines)
    # print(new_ssh_distant)
    # print('++++++++++++++++++++++++++++++++++++++3')
    # stdin, stdout, stderr = ssh.exec_command('echo {} > /root/.ssh/authorized_keys'.format(new_ssh_distant))
    stdin, stdout, stderr = ssh.exec_command('echo "{}" > {}'.format(new_ssh_distant, ssh_path))
    disconect = ssh.exec_command('skill -kill -u {}'.format(username))
    
    ssh_distant= stdout.read().decode()
    # print(ssh_distant)
    ssh.close()

def delete_expired_secret(secret_id):
    db_manager = DBManager()
    secret = db_manager.find_one("secrets", {"secret_id": secret_id})
    if secret:
        db_manager.delete_one("secrets", {"secret_id": secret_id})
    else:
        raise NotFoundException('Secret not found')

def generate_secret_name(length):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(length))

def check_expired_secrets(nothing):
    from ..modules.secret.secret_service import SecretService
    from ..modules.secret.secret_schema import SecretSshSchema

    secret_service = SecretService()
    secret_ssh_schema = SecretSshSchema()

    db_manager = DBManager()
    while True:
        secrets = db_manager.find_many("secrets", {})
        current_time = datetime.utcnow()

        for secret in secrets:
            expiration_time = secret.get('exp_time')
            secret_id = secret["secret_id"]

            found_secret = db_manager.find_one("secrets", {"secret_id": secret_id})

            if expiration_time:
                if current_time > expiration_time:

                    if secret["app_type"] == "ssh":
                        reveal = reveal_secret(secret_id)
                        public_key, private_key = reveal["public_key"], reveal["private_key"]

                        hostname = reveal["hostname"]
                        username = reveal["username"]
                        password = reveal["password"]   

                        public_file = copy_value_to_file(public_key, '.pub')
                        
                        if found_secret["auto_generate"].lower() == "true":
                        
                            if found_secret["use_password"] == "false":
                                with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.pem') as temp_file:
                                    temp_file.write(private_key.encode())
                                    temp_file.write(public_key.encode())
                                    temp_file.close()
                                
                                delete_sshpubkey(username, hostname, public_file, private_key=temp_file.name)
                                
                                secret_content = {"hostname": hostname, "username": username, "password": password}
                                secret_name = generate_secret_name(6)
                                
                                secret_data = {
                                    "exp_time": 10,
                                    "secret_name": f"{found_secret['secret_name']}_{secret_name}",
                                    "secret": secret_content,
                                    "safe_id": found_secret["safe_id"],
                                    "app_type": found_secret["app_type"],
                                    "owner_uid": found_secret["owner_uid"],
                                    "secret_type": found_secret["secret_type"],
                                    "use_password": found_secret["use_password"],
                                    "auto_generate": found_secret["auto_generate"]
                                }

                                errors = secret_ssh_schema.validate(secret_data)
                                if errors:
                                    return error_response(error=errors)
                                
                                secret_service.connect_with_ssh_key(secret_data, None)
                                
                            elif found_secret["use_password"] == "true":
                                delete_sshpubkey(username, hostname, public_file, password=password)
                                
                                secret_content = {"hostname": hostname, "username": username, "password": password}
                                secret_name = generate_secret_name(6)
                                
                                secret_data = {
                                    "exp_time": 10,
                                    "secret_name": f"{found_secret['secret_name']}_{secret_name}",
                                    "secret": secret_content,
                                    "safe_id": found_secret["safe_id"],
                                    "app_type": found_secret["app_type"],
                                    "owner_uid": found_secret["owner_uid"],
                                    "secret_type": found_secret["secret_type"],
                                    "use_password": found_secret["use_password"],
                                    "auto_generate": found_secret["auto_generate"]
                                }

                                errors = secret_ssh_schema.validate(secret_data)
                                if errors:
                                    return error_response(error=errors)
                                
                                secret_service.connect_with_ssh_key(secret_data, None)
                            else:
                                raise error_response(message="An error has occurred during deletion. Please contact admin")

                            delete_expired_secret(secret_id)
                        else:
                            delete_expired_secret(secret_id)
                    else:
                        delete_expired_secret(secret_id)
        
        time.sleep(5)

expiration_secret_thread = CustomThread(target=check_expired_secrets, args=("",))
expiration_secret_thread.start()


def generate_ssh_password():
    alphabets = string.ascii_letters
    random_string = "".join(secrets.choice(alphabets) for i in range(10))
    #print(random_string)
    return random_string

def change_ssh_password(username, hostname, private_key = None, password=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(username=username, hostname=hostname, password=password)
    elif private_key:
        ssh.connect(username=username, hostname=hostname, key_filename=private_key)
    else:
        print("Enter hostname password or add private_key")
    
    new_password = generate_ssh_password()

    #command = f"echo -e '{new_password}\n{new_password}' | passwd"
    stdin, stdout, stderr = ssh.exec_command('passwd')
    stdin.write(password + '\n')
    stdin.flush()
    stdin.write(new_password + '\n')
    stdin.flush()
    stdin.write(new_password + '\n')
    stdin.flush()

    stdout_output = stdout.read().decode()
    stderr_output = stderr.read().decode()
        
    output = stdout_output + stderr_output
    
    if "password updated successfully" in output:
        print("Mot de passe changé avec succès.")
    else:
        print("Erreur lors du changement de mot de passe.\n")
    
    ssh.close()
    
    return new_password


def generate_share_token(secret_id, receiver_email, duration):

    expiration = datetime.now() + timedelta(minutes=duration)

    data = {
        "secret_id": secret_id,
        "receveir_email": receiver_email,
        "today": str(datetime.now())
    }

    token = jwt.encode(data, config_data["TOKEN_SECRET_SALT"], algorithm="HS256")
    return token, expiration


def convert_hex_to_binary(hex_string, filename:str):

    binary_data = binascii.unhexlify(hex_string)

    if binary_data:
        with tempfile2.NamedTemporaryFile(delete=False, close=False) as temp_file:
            temp_file.write(binary_data)
            temp_file.close()
            
        print("The binary file has been written successfully")
        return send_file(temp_file.name, as_attachment=True, download_name=filename)
    else:
        raise ErrorOccurred('Error when converting from hexadecimal to binary')


if config_data["LDAP"]:
    server = Server(ldap_server["url"], get_info=ALL)
    ldap = Connection(
        server,
        user=ldap_server["value"]["default_user_dn"],
        password=ldap_server["value"]["default_password"],
    )
    ldapState = ldap.bind()
    # print(ldapState)
config = dict()
config["HOST"] = ldap_server["url"]
config["BASE_DN"] = ldap_server["value"]["base_dn"]
config["USER_DN"] = ldap_server["value"]["user_dn"]
config["GROUP_DN"] = ldap_server["value"]["group_dn"]
config["ROLE_MGR"] = ldap_server["value"]["profil_role_mgr"]
config["TECHNICAL_MGR"] = ldap_server["value"]["technical_profil_mgr"]
config["ROLE_VIEWER"] = ldap_server["value"]["profil_role_viewer"]
config["TECHNICAL_VIEWER"] = ldap_server["value"]["technical_profil_viewer"]
config["LDAP_HOST"] = ldap_server["url"]
config["LDAP_BASE_DN"] = ldap_server["value"]["base_dn"]
config["LDAP_USER_DN"] = ldap_server["value"]["user_dn"]
config["LDAP_GROUP_DN"] = ldap_server["value"]["group_dn"]

def ldap_connexion():
    ldap = Connection(
        server,
        user=ldap_server["value"]["default_user_dn"],
        password=ldap_server["value"]["default_password"],
    )
    ldapState = ldap.bind()
    if ldapState:
        return True, ldap
    else:
        return False, None


def getUserGroup(user_dn, uid=""):
    try:
        search_dn2 = config["GROUP_DN"] + "," + config["BASE_DN"]
        ldap = ldap_connexion()[1]
        ldap.search(search_dn2, f"(|(member={user_dn})(memberUid={uid}))")
        # member = config_data["LDAP_USER_ATTRIBUTES"]["groupIditenfier"]
        groups = []
        for entry in ldap.entries:
            group = ast.literal_eval(entry.entry_to_json())
            groups.append(group["dn"].split(",")[0].split("=")[1])
        ldap.unbind()
        return groups
    except:
        return ["readonly"]

def getUserDn(uid):
    DN = "uid=" + uid + "," + config["USER_DN"] + "," + config["BASE_DN"]
    return DN

def isAdmin(uid):
    if not config_data["LDAP"]:
        print("eeeee")
        db_manager = DBManager()
        fuser = db_manager.find_one("users", {"uid": uid})
        #fuser = db002.users.find_one({"uid": uid})
        return "admin" in fuser["groups"]
    print("AAAAAAA")
    user_dn = getUserDn(uid)
    groups = getUserGroup(user_dn, uid)
    return "admin" in groups


def isBlacklisted(uid):
    user = db_manager.find_one("users", {"uid": uid})
    if user:
        if "is_blacklisted" not in user:
            db_manager.update_one("users", {"uid": uid}, {"is_blacklisted": False})
            return False
        else:
            print("existing field is_blacklisted")
            return user["is_blacklisted"]
            # return True
    else:
        raise NotFoundException("user not found")

def save_ssh_response(command):
    try:
        command_str = shlex.split(command)
        # Exécuter la commande
        result = subprocess.run(command_str, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)   
        # Retourner la sortie et les erreurs
        return result.stdout, result.stderr
    except Exception as e:
        return None, str(e)


def is_date_expired(date_string):
    try:
        date_format = "%Y/%m/%d %H:%M:%S"
        date_obj = datetime.strptime(date_string, date_format)
        current_time = datetime.now()
        return date_obj < current_time
    except ValueError:
        raise ValueError("Incorrect date format. Please use 'year/month/day hour:minute:second'.")

def Blacklisted(uid, is_denied: bool = False):
    user = db_manager.find_one("users", {"uid": uid})
    if user:
       db_manager.update_one("users", {"uid": uid}, {"is_blacklisted": is_denied})
    else:
        raise NotFoundException("user not found")

def check_date_format(date_str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        return True
    except ValueError:
        return False

def send_emails_in_batches(emails, start_date, end_date, reason, batch_size=100):
    """
    Envoie des emails par lot en utilisant des threads pour chaque lot.
    Gère les exceptions pour éviter les échecs silencieux.
    """
    
    objet = "Notification de mise à jour du système"
    message = f"""Cher utilisateur,

    Nous vous informons qu'une mise à jour du système sera effectuée du {start_date} au {end_date}.
    Raison: {reason}

    Nous nous excusons pour la gêne occasionnée et vous remercions de votre compréhension.

    Cordialement,
    L'équipe technique"""
    
    for i in range(0, len(emails), batch_size):
        batch = emails[i:i + batch_size]
        threads = []

        for email in batch:
            thread = CustomThread(target=mail_sender,
                        args=(email, objet, message,),)
            threads.append(thread)
            thread.start()

        # Attendre que tous les threads du lot aient terminé
        for thread in threads:
            thread.join()

        # Pause entre les lots pour éviter de surcharger le serveur SMTP
        time.sleep(1)

def check_user(email=None, uid=None):
    # from ....modules.required_packages import search_user_info
    import modules.required_packages as package
    db_manager =  DBManager()
    query = {"$or": []}
    
    if email:
        query["$or"].append({"email": email})
    
    if uid:
        query["$or"].append({"uid": uid})
    
    if not query["$or"]:
        return False, None
    
    user = db_manager.find_one("users", query)
    # google_user = db_manager.find_one("users", {"email": user_email, "auth_type": "google"})
    # ldap_user = package.search_user_info(user_email)
    
    if user:
        # print(user)
        return True, user
    else:
        if email:
            raise NotFoundException(f"user '{email}' not found")
        else:
            raise NotFoundException(f"user '{uid}' not found")
    # elif google_user:
    #     return True, google_user
    # elif ldap_user:
    #     return True, ldap_user
    # else: 
    #     return False, None

def check_policy(police_id):
    db_manager =  DBManager()
    police = db_manager.find_one("policies", {"policie_id": police_id})

    if police is None:
        raise NotFoundException("Policy not found")
    return police

def validate_shared_safe_mode(choice, mode="user,group"):
    valid_modes = mode.split(",")
    if choice not in valid_modes:
        raise SomethingWentWrong(f"Invalid choice: '{choice}'. Choose in {valid_modes}")
    return True

def merge_rights(list_of_rights):
    final_rights = {}
    absolute = []
    
    for rights in list_of_rights:
        if len(absolute) > 0:
            for argument in absolute:
                del rights[argument]
        for key, value in rights.items():
            if value:
                absolute.append(key)
            final_rights[key] = value
            
    return final_rights


def verify_shared_safe_user(user_uid, safe_id=None, shared_safe_id=None):
    db_manager = DBManager()
    rights = []
    
    if safe_id:
        receiver_safe = db_manager.find_many("receiver_safes", {"uid": user_uid, "safe_id": safe_id})
    else:
        receiver_safe = db_manager.find_many("receiver_safes", {"uid": user_uid, "shared_safe_id": shared_safe_id})
        
    if receiver_safe is not None:        
        for safe in receiver_safe:
            rights.append(safe["rights"])
            
        merged_rights = merge_rights(rights)
        return merged_rights, receiver_safe
    else:
        raise NotFoundException("User not found in shared safe")
    
    
def apply_shared_safe_for_user(list_data=None, shared_safe_id=None, safe_id=None, owner_uid=None):
    db_manager = DBManager()
        
    for data in list_data:
        receiver_type = data["receiver_type"]
        validate_shared_safe_mode(receiver_type)
        
        police_id = data.get("police_id")
        # if police_id is not None:
        #     policy = check_policy(police_id)
        #     print(policy)
        
        if receiver_type == "group":
            found_group = db_manager.find_one("groups", {'group_name': data["receiver"], 'owner_uid': owner_uid})
            if not found_group:
                raise NotFoundException(f"group '{data['receiver']}' not found")
            
            data["receiver"] = found_group["group_name"]
                            
            group_members = found_group["group_members"]
            # print(group_members)    
            receiver_id = str(ObjectId())
            data["receiver_id"] = receiver_id
            for member in group_members:
                response, verify_user = check_user(email=member["email"], uid=member["uid"])
                data["receiver_id"] = receiver_id
                
                if police_id is not None:
                    policy = check_policy(police_id)
                    db_manager.update_one_and_create(
                        "receiver_safes",
                        {
                            "uid": verify_user["uid"],
                            "receiver_id": data["receiver_id"],
                            "safe_id": safe_id,
                            "rights": policy["rights"],
                            "shared_safe_id": shared_safe_id
                        },
                        {"old": 0}
                    )
                else:
                    db_manager.update_one_create(
                        "receiver_safes",
                        {
                            "uid": verify_user["uid"],
                            "receiver_id": data["receiver_id"],
                            "safe_id": safe_id,
                            "rights": data["rights"],
                            "shared_safe_id": shared_safe_id
                        }, 
                        {"old": 0}
                    )
                # db_manager.update_one_and_create("receiver_safes", {"uid": verify_user["uid"], "receiver_id": data["receiver_id"]}, {"shared_safes_id": shared_safe_id})
                
                # mail = verify_user["email"]
                # objet = "Azumaril safe share"
                # message = f"Un Coffre a été partagé avec vous via AZUMARIL. Connectez vous pour regarder son contenu."
                # Thread(
                #     target=mail_sender,
                #         args=(mail, objet, message,),
                #     ).start()
        
        elif receiver_type == "user":
            response, verify_user = check_user(email=data["receiver"], uid=data["receiver"])
            data["receiver_id"] = str(ObjectId())
            data["receiver"] = verify_user["email"]
            data["uid"] = verify_user["uid"]
            
            if police_id is not None:
                policy = check_policy(police_id)
                db_manager.update_one_and_create(
                    "receiver_safes",
                    {
                        "uid": verify_user["uid"],
                        "receiver_id": data["receiver_id"], 
                        "rights": policy["rights"],
                        "shared_safe_id": shared_safe_id
                    },
                    {"old": 0}
                )
            else:
                db_manager.update_one_and_create(
                    "receiver_safes",
                    {
                        "uid": verify_user["uid"],
                        "receiver_id": data["receiver_id"],
                        "rights": data["rights"],
                        "shared_safe_id": shared_safe_id
                    }, 
                    {"old": 0}
                )
            
            # db_manager.update_one_and_create("receiver_safes", {"uid": verify_user["uid"], "receiver_id": data["receiver_id"]}, {"shared_safes_id": shared_safe_id})
            
            # mail = verify_user["email"]
            # objet = "Azumaril safe share"
            # message = f"Un Coffre a été partagé avec vous via AZUMARIL. Connectez vous pour regarder son contenu."
            # Thread(
            #     target=mail_sender,
            #         args=(mail, objet, message,),
            #     ).start()
        else:
            raise SomethingWentWrong("Error with data. Please retry")


def generate_guac_base64(identifier: str, auth_provider: str = "mysql") -> str:
    """
    Generate the Base64-encoded string for a Guacamole connection URL.
    
    :param identifier: The connection ID (e.g., "2").
    :param auth_provider: The authentication provider (default: "mysql").
    :return: The Base64-encoded string.
    """
    raw_string = f"{identifier}\0c\0{auth_provider}"
    encoded_bytes = base64.b64encode(raw_string.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

KMIP_PORT = config_data["KMIP_PORT"]   
def generate_key( data):
        print(data)
        connection_client =  data.get("url")
        db = data.get("database")
        collection = data.get("collection")
        namespace = f"{db}.{collection}"
        
        print(collection,db, connection_client)
        
        #print (user_cert)
        
        if data.get("user_cert") and data.get("user_cert") :
            user_cert_bytes = base64.b64decode(data.get("user_cert"))
            user_key_bytes = base64.b64decode(data.get("user_key"))
            with tempfile.NamedTemporaryFile(delete=False, mode="wb") as temp_cert_key:
                temp_cert_key.write(user_cert_bytes)
                temp_cert_key.write(b"\n")
                temp_cert_key.write(user_key_bytes)
                temp_cert_key_path = temp_cert_key.name
        else:
            temp_cert_key_path = config_data["KMIP_CLIENT_KEY_CERT"]
            
        kms_providers = {
            "kmip": {
                "endpoint": f"localhost:{KMIP_PORT}",
            }
        }
        
        tls_options = {
            "kmip": {
                "tlsCAFile": config_data["KMIP_CA"],  # Certificat CA
                "tlsCertificateKeyFile": temp_cert_key_path,  # Certificat client + clé
            }
        }
        
        client = MongoClient(connection_client)
        # print("ici2")
        key_vault_client = MongoClient(connection_client)
        
        client1_encryption = ClientEncryption(
            kms_providers,
            namespace,
            client,
            CodecOptions(uuid_representation=UUID_SUBTYPE),
            kms_tls_options=tls_options,
        )
        master_key = {}  # PyKMIP génère une clé maître automatiquement
        data_key_id = client1_encryption.create_data_key("kmip", master_key)
        print("ici 3 ###################")
        
        dek_id = base64.b64encode(data_key_id).decode("utf-8")
        db_name, coll_name = namespace.split('.')
        key_vault_collection = key_vault_client[db_name][coll_name]
        key_document = key_vault_collection.find_one({"_id": data_key_id})
        
        key_id = key_document["masterKey"]["keyId"]
        material_key = key_document["keyMaterial"]
        material_key_base = base64.b64encode(material_key).decode("utf-8")
        key_document["keyMaterial"] = material_key_base
        key_document["_id"] = dek_id
        
        for k,v in key_document.items():
            if type(v) == type(datetime(2025, 1, 24, 11, 46, 47, 85000)):
                print("bkgkhs")
                dt_string = v.strftime("%Y-%m-%d %H:%M:%S.%f")
                v = dt_string
                key_document[k] = v
                #print(v)
        return key_document

def delete_all_shared_secrets_by_secret_id(secret_id):
    existing_count = db_manager.count_documents("shares", {"shared_secret_info.secret_id": secret_id})
    if existing_count == 0:
        print("secret_id not found in share collection")
        pass
    else:
        db_manager.update_one_and_remove("shares", {"shared_secret_info.secret_id": secret_id}, {"shared_secret_info": {"secret_id": secret_id}})
       
def pop_kmip_user_key(data, status, reveal_key=None): 
    keyId = data.get("masterKey", {}).get("keyId", None)
    if keyId is not None:
        data["status"] = status
        
    if reveal_key == "false":
        del data["user_key"]

# def check_duplicate_members(share_data, groups_data):
#     from collections import defaultdict
    
#     share_group_key, group_name_key = "receiver", "group_name"
    
#     groups_dict = {group[group_name_key]: group for group in groups_data if group_name_key in group}
#     member_groups = defaultdict(set)
    
#     for receiver in share_data:  # .get("receptors", []):
#         if receiver.get("receiver_type") == "group":
#             group_name = receiver.get(share_group_key)
#             group_data = groups_dict.get(group_name)
            
#             if group_data:
#                 for member in group_data.get("group_members", []):
#                     member_mail = member.get("email")
#                     if member_mail:
#                         member_groups[member_mail].add(group_name)
    
#     duplicates = {mail: groups for mail, groups in member_groups.items() if len(groups) > 1}  
    
#     if duplicates:
#         raise UserAlreadyExist(f"users are present in more than one group : {duplicates}")
    
#     return None

# def compare_multiple_lists(*list_key_pairs, message="The receiver is a part of share"):
#     values_set = set()  
#     for _list, key in list_key_pairs:
#         for item in _list:
#             if key in item:
#                 value = item[key]
#                 if value in values_set:
#                     raise UserAlreadyExist(message)
#                 values_set.add(value)
#     return None

# def compare_members(members_first, key_first, members_second, key_second, message="The receiver is a part of share"):
#     values_set = {item[key_first] for item in members_first if key_first in item}   
#     for item in members_second:
#         if key_second in item and item[key_second] in values_set:
#             raise UserAlreadyExist(message) 
#     return None
