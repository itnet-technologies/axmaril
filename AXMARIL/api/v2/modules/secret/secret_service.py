from .secret_model import SecretModel
from .secret_schema import SecretSchema, SecretCredentialSchema, SecretFileSchema, SecretSshSchema
from ..coffre.safe_service import CoffreService
from ..application.application_service import ApplicationService
from ..kmip.kmip_service import KmipService
#from ..guacamole.guacamole_service import GuacamoleService
from ..CA.ca_service import CaService
from ...utils.helpers import generate_ssh_password, get_system_safe, success_response, error_response, encrypt, save_secret_file, secret_access, check_keys, check_attempts, decrypt, encode_token, ecptk, secret_credentials_encryption, generate_ssh, add_sshpubkey, delete_sshpubkey, reveal_secret, copy_value_to_file, change_ssh_password, generate_share_token, mail_sender, config_data, isAdmin
from ...database.db_manager import DBManager
from datetime import datetime, timedelta
from threading import Thread
from flask import request, url_for
from bson import ObjectId
import tempfile2
import traceback
import requests
import shutil
import jwt
import os
import json
import base64
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, InsufficientRight, AttemptsExceeded, CustomException, SomethingWentWrong, KeyMissing, AttemptsExceeded, InvalidDataException, TokenInvalidError
import traceback
import binascii



safe_service = CoffreService()
application_service = ApplicationService()
kmip_service = KmipService()

ca_service = CaService()

def get_guac_service():
    from ..guacamole.guacamole_service import GuacamoleService
    return GuacamoleService()

class SecretService:
    def __init__(self):
        self.secret_model = SecretModel()
        self.secret_schema = SecretSchema()
        self.secret_file_schema = SecretFileSchema()
        self.secret_credentials_schema = SecretCredentialSchema()
        self.secret_ssh_schema = SecretSshSchema()

    def create_secret(self, data, secret_file):
        db_manager = DBManager()
        secret_type = db_manager.find_one("secret_type", {"name": data['secret_type']})
        if secret_type is None:
            raise NotFoundException('Secret type not found')
           # return error_response(message=f"the secret type {data['secret_type']} isn't defined")
        
        existing_secret = self.secret_model.find_secret_by_name(data['secret_name'])
        #print(existing_secret)
        if existing_secret:
            raise NameAlreadyExist('secret name already exists')
            #return error_response(message=f"secret {data['secret_name']} already exists")
        
        data['date'] = datetime.now()
        
        secret = data["secret"]
        
        if "safe_id" in data:
            if data["owner_uid"] == "SYSTEM":
                pass
            else:
                safe_id = safe_service.find_safe_by_id(data["owner_uid"], data['safe_id'])
                data['safe_id'] = safe_id['safe_id']

        if "exp_time" in data:
            expiration_date_time = datetime.utcnow() + timedelta(minutes = data["exp_time"])
            data['exp_time'] = expiration_date_time
        
        if 'app_type' in data:
            if data["app_type"] == "system_guacamole_account":
                pass
            else:
                application = application_service.find_application_by_type(data['app_type'])
                data['app_type'] = application.get("app_type", application.get("type", None))

                check_fields = check_keys(application['fields'], secret)

                if not check_fields[0]:
                    raise KeyMissing(f"Missing key(s) :{check_fields[1]}")
        
        if "app_type" in data:
            if data["app_type"] == "guacamole":
                db_manager = DBManager()
                fsecret = db_manager.find_one("secrets", {"owner_uid": "SYSTEM", "secret_name" : data["owner_uid"], "app_type" : "system_guacamole_account"})
                if fsecret is None:
                    print(f"Guacamole user not existing, creating a guacamole user for {data['owner_uid']}")
                    ss = get_system_safe()
                    print(ss)
                    user_creds = {
                        "password": generate_ssh_password(),
                        "username": data["owner_uid"]
                    }
                    print(user_creds)
                    guac_user_secret = {
                        "secret_name": data["owner_uid"],
                        "owner_uid": "SYSTEM",
                        "secret": user_creds,
                        "safe_id": ss["safe_id"],
                        "secret_type": "credentials",
                        "app_type": "system_guacamole_account"
                    }
                    self.create_secret(guac_user_secret, None)
                    get_guac_service().create_user(user_creds)
                    guac_user_creds = user_creds
                    print("guacamole user creation done!")
                else:
                    guac_user_creds = reveal_secret(fsecret["secret_id"])
                if data["secret"]["protocol"] == "rdp":
                    crc_response = get_guac_service().create_rdp_connexion(data, axmaril = True, guac_user_creds = guac_user_creds)
                    print("-------------- crc_response crc_response ----------")
                    print(crc_response)
                    print("-------------- crc_response crc_response ----------")
                    if crc_response[0] == 200:
                        data["secret"]["connexion_id"] = crc_response[1]
                if data["secret"]["protocol"] == "ssh":
                    
                    print("******guacamole ssh *************")
                    csc_response = get_guac_service().create_ssh_connexion(data, axmaril = True, guac_user_creds = guac_user_creds)
                    print("-------------- csc_response csc_response ----------")
                    print(csc_response)
                    print("-------------- csc_response csc_response ----------")
                    if csc_response[0] == 200:
                        data["secret"]["connexion_id"] = csc_response[1]
            if data["app_type"] in ["ssh", "rdp", "vnc"]:
                db_manager = DBManager()
                fsecret = db_manager.find_one("secrets", {"owner_uid": "SYSTEM", "secret_name" : data["owner_uid"], "app_type" : "system_guacamole_account"})
                if fsecret is None:
                    print(f"Guacamole user not existing, creating a guacamole user for {data['owner_uid']}")
                    ss = get_system_safe()
                    print(ss)
                    user_creds = {
                        "password": generate_ssh_password(),
                        "username": data["owner_uid"]
                    }
                    print(user_creds)
                    guac_user_secret = {
                        "secret_name": data["owner_uid"],
                        "owner_uid": "SYSTEM",
                        "secret": user_creds,
                        "safe_id": ss["safe_id"],
                        "secret_type": "credentials",
                        "app_type": "system_guacamole_account"
                    }
                    self.create_secret(guac_user_secret, None)
                    get_guac_service().create_user(user_creds)
                    print("guacamole user creation done!")
                else:
                    guac_user_creds = reveal_secret(fsecret["secret_id"])
                    
                if data["app_type"] == "vnc":
                    pass
                
                if data["app_type"] == "rdp":
                    crc_response = get_guac_service().create_rdp_connexion(data, axmaril = True, guac_user_creds = guac_user_creds)
                    print("-------------- crc_response crc_response ----------")
                    print(crc_response)
                    print("-------------- crc_response crc_response ----------")
                    if crc_response[0] == 200:
                        data["secret"]["connexion_id"] = crc_response[1]
                
                if data["app_type"] == "ssh":
                    if True:
                        print("******guacamole ssh *************")
                        csc_response = get_guac_service().create_ssh_connexion(data, axmaril = True, guac_user_creds = guac_user_creds)
                        print("-------------- csc_response csc_response ----------")
                        print(csc_response)
                        print("-------------- csc_response csc_response ----------")
                        if csc_response[0] == 200:
                            data["secret"]["connexion_id"] = csc_response[1]
            
                    else:
                        private_key, public_key = generate_ssh()


                        with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.pub') as temp_file:
                            temp_file.write(public_key.encode())
                            temp_file.close()
                        
                        hostname = data["secret"]["hostname"]
                        username = data["secret"]["username"]
                        password = data["secret"]["password"]

                        add_sshpubkey(username, hostname, temp_file.name, password=password)
                        
                        secret["private_key"] = private_key
                        secret["public_key"] = public_key

            if data["app_type"] == "kmip":
                #OPTION 1 utiliser tout simplement la route
                # response = requests.post("https://localhost:5001/api/v2/kmip/generate_key", json = data["secret"]).json()
                
                #OPTION 2 utiliser dirctement la fonction
                #print(data["secret"])
                response = kmip_service.generate_key(data["secret"])
                print("***********************")
                #print(response)
                for k,v in response.items():
                    print(f'{k} : type {type(v)}')
                print("***********************")
                secret.update(response)
        """
        {
            "dburl" : "",
            "dbname" : "",
            "dbcol" : "",
            "key_info" : {
            
            },
        }
        """
            
        if data["secret_type"] in ["credentials", "other"]:

            data["secret"] = secret_credentials_encryption(secret)
        
        if secret_file is not None:
            random_string = str(ObjectId())
            secret_dir = f'/temp/.temp_{random_string}'
            uploaded_file = save_secret_file(secret_dir, secret_file, data['secret_name'])

            data['file_path'] = uploaded_file['file_path']
            data['file_name'] = uploaded_file['file_name']
            data['file_type'] = uploaded_file['file_type']
            data['app_type'] = None

            encrypt(data, True)       

            shutil.rmtree(uploaded_file['temp_folder'])
            
            return True

        return self.secret_model.create_secret(data)

    def connect_with_ssh_key(self, data, ssh_key_file):
        db_manager = DBManager()
        secret_type = db_manager.find_one("secret_type", {"name": data['secret_type']})
        if secret_type is None:
            raise NotFoundException('Secret type not found')
           # return error_response(message=f"the secret type {data['secret_type']} isn't defined")
        
        existing_secret = self.secret_model.find_secret_by_name(data['secret_name'])
        if existing_secret:
            raise NameAlreadyExist('secret name already exists')
            #return error_response(message=f"secret {data['secret_name']} already exists")
        
        data['date'] = datetime.now()

        #print("secret: ", data["secret"])
        
        if "safe_id" in data:
            safe_id = safe_service.find_safe_by_id(data["owner_uid"], data['safe_id'])
            data['safe_id'] = safe_id['safe_id']

        if "exp_time" in data:
            if int(data["exp_time"]) < 10:
                raise InvalidDataException("The expiry time must be greater than or equal to 10 minutes")
            
            expiration_date_time = datetime.utcnow() + timedelta(minutes = int(data["exp_time"]))
            data['exp_time'] = expiration_date_time
        
        if 'app_type' in data:
            application = application_service.find_application_system(data['app_type'])
            data['app_type'] = application['app_type']

            check_fields = check_keys(application['fields'], data['secret'])

            if not check_fields[0]:
                raise KeyMissing(f"Missing key(s) :{check_fields[1]}")
        
        if "app_type" in data:
            if data["app_type"] == "ssh":
                private_key, public_key = generate_ssh()

                with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.pub') as temp_file:
                    temp_file.write(public_key.encode())
                    temp_file.close()
                
                hostname = data['secret']["hostname"]
                username = data['secret']["username"]
                password = data['secret']["password"]
                
                if ssh_key_file is not None:
                    random_string = str(ObjectId())
                    ssh_key_dir = f'/temp/.temp_{random_string}'
                    uploaded_file = save_secret_file(ssh_key_dir, ssh_key_file, data['secret_name'])

                    ssh_key = uploaded_file['file_path']
                else:
                    ssh_key = None
                
                # print(data["use_password"])
                   
                if data["use_password"].lower() == "true":
                    add_sshpubkey(username, hostname, temp_file.name, password=password)
                elif data["use_password"].lower() == "false":
                    add_sshpubkey(username, hostname, temp_file.name, private_key=ssh_key)
                    shutil.rmtree(uploaded_file['temp_folder'])
                else:
                    raise InvalidDataException("Define connection method")

                data['secret']["private_key"] = private_key
                data['secret']["public_key"] = public_key
                 
        if data["secret_type"] ==  "credentials" or "other":
            data['secret'] = secret_credentials_encryption(data['secret'])
        
        return self.secret_model.create_secret(data)

    def create_kmip_secret(self, data, user_cert=None, user_key=None):
        db_manager = DBManager()
        secret_type = db_manager.find_one("secret_type", {"name": data['secret_type']})
        if secret_type is None:
            raise NotFoundException('Secret type not found')
        
        existing_secret = self.secret_model.find_secret_by_name(data['secret_name'])
        if existing_secret:
            raise NameAlreadyExist('secret name already exists')
        
        secret = data["secret"]
        data['date'] = datetime.now()
        
        if "safe_id" in data:
            safe_id = safe_service.find_safe_by_id(data["owner_uid"], data['safe_id'])
            data['safe_id'] = safe_id['safe_id']
        
        if 'app_type' in data:
            application = application_service.find_application_system(data['app_type'])
            data['app_type'] = application['app_type']

            check_fields = check_keys(application['fields'], data['secret'])

            if not check_fields[0]:
                raise KeyMissing(f"Missing key(s) :{check_fields[1]}")
        
        if 'app_type' in data:
            if data["app_type"] == "kmip":
               
                if user_cert and user_key is not None:
                    user_cert_content = user_cert.read()
                    user_key_content = user_key.read()
                    
                    if not kmip_service.is_certificate(user_cert_content):
                        raise ValueError("Le fichier user_cert n'est pas un certificat valide.")
                    
                    if not kmip_service.is_private_key(user_key_content):
                        raise ValueError("Le fichier user_cert n'est pas une clé valide.")
                    
                    data["secret"]["user_cert"]= base64.b64encode(user_cert_content).decode("utf-8")
                    data["secret"]["user_key"]= base64.b64encode(user_key_content).decode("utf-8")
                    
                
                else:
                    raise SomethingWentWrong("check user_cert and user_key")
        
        response = kmip_service.generate_key(data["secret"])
        if data["secret_type"] ==  "credentials" or "other":
            secret.update(response)
            data['secret'] = secret_credentials_encryption(secret)
        
        return self.secret_model.create_secret(data)
    
    def create_kmip_secret_by_secret_id(self, data):
        db_manager = DBManager()
        secret_type = db_manager.find_one("secret_type", {"name": data['secret_type']})
        if secret_type is None:
            raise NotFoundException('Secret type not found')
        
        existing_secret = self.secret_model.find_secret_by_name(data['secret_name'])
        if existing_secret:
            raise NameAlreadyExist('secret name already exists')
        
        data['date'] = datetime.now()
        secret = data["secret"]
        
        if "safe_id" in data:
            safe_id = safe_service.find_safe_by_id(data["owner_uid"], data['safe_id'])
            data['safe_id'] = safe_id['safe_id']
        
        if 'app_type' in data:
            application = application_service.find_application_system(data['app_type'])
            data['app_type'] = application['app_type']

            check_fields = check_keys(application['fields'], data['secret'])

            if not check_fields[0]:
                raise KeyMissing(f"Missing key(s) :{check_fields[1]}")
        
        if 'app_type' in data:
            if data["app_type"] == "kmip" and data["secret_key_id"] and data["secret_cert_id"]:
                
                response_key = reveal_secret(data["secret_key_id"])
                response_cert = reveal_secret(data["secret_cert_id"])
                
                user_cert = binascii.unhexlify(response_cert["data"])
                user_key = binascii.unhexlify(response_key["data"])

                if not kmip_service.is_certificate(user_cert):
                    raise ValueError("Le fichier user_cert n'est pas un certificat valide.")
                
                if not kmip_service.is_private_key(user_key):
                    raise ValueError("Le fichier user_cert n'est pas une clé valide.")

                data["secret"]["user_cert"]= base64.b64encode(user_cert).decode("utf-8")
                data["secret"]["user_key"]= base64.b64encode(user_key).decode("utf-8")
            else:
                raise SomethingWentWrong("check user_cert and user_key")
            
        response = kmip_service.generate_key(data["secret"])
        if data["secret_type"] ==  "credentials" or "other":
            secret.update(response)
            data['secret'] = secret_credentials_encryption(data['secret'])
        
        return self.secret_model.create_secret(data)
        
    def reveal_secret(self, uid, secret_id):
        """
            All exception in this function is: NotFoundException InsufficientRight AttemptsExceeded CustomException SomethingWentWrong
        """
        db_manager = DBManager()
        credsData = db_manager.find_one("creds", {"type":"token_secret"}, {"_id":0})
        salt = credsData["salt"]
        
        fsecret = self.secret_model.find_by_id(uid, secret_id)
        print("secret_id**********")
        print(fsecret["secret_id"])
        
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
                # if secret["app_type"] == "guacamole":
                #     print("guacamole secret revealed!!!!!!!!!!!!!!!!")
            encrypted_data = jwt.decode(secret["secret"], salt, algorithms=["HS256"])
            decrypted_data = decrypt(encrypted_data)

            if isinstance(decrypted_data, tuple):
                raise CustomException(decrypted_data[1])
                # return error_response(message=, code=403)
            if secret.get("app_type", None) in ["ssh", "rdp", "vnc"]:
                secret = jwt.decode(decrypted_data, salt, algorithms=["HS256"])
                db_manager = DBManager()
                print(secret)
                fsecret2 = db_manager.find_one("secrets", {"owner_uid": "SYSTEM", "secret_name" : uid, "app_type" : "system_guacamole_account"})
                if fsecret2 is not None:
                    guac_user_creds = reveal_secret(fsecret2["secret_id"])
                    # guac_user_creds = {}
                    print(db_manager.find_many("secrets", {"secret_id" : fsecret2["secret_id"]}))
                    print("-------------guac_user_creds-------------")
                    print(guac_user_creds)
                    print("-------------guac_user_creds-------------")
                    print(secret)
                
                secret["connexion_url"] = get_guac_service().get_connexion_url(secret["connexion_id"], guac_user_creds)
                return secret
            return jwt.decode(decrypted_data, salt, algorithms=["HS256"])
            # return success_response(message="successfully decrypted", data=)
        except:
            print(traceback.format_exc())
            raise SomethingWentWrong("Something went wrong")
    
    def update_secret(self, uid, data, secret_file):
        """
            Exception: NotFoundException, InsufficientRight, NameAlreadyExist, KeyMissing
        """
        db_manager = DBManager()
        credsData = db_manager.find_one("creds", {"type":"token_secret"}, {"_id":0})
        salt = credsData["salt"]

        global config_data

        secret_id = data["secret_id"]
        is_system = False

        secret = self.secret_model.find_by_id(uid, secret_id)
        if not secret:
            raise NotFoundException(f'Secret with {secret_id} not found')
        
        if secret is not None:
            deletable = secret.get("deletable", None)
            if deletable is not None and not deletable:
                is_system = True

        access_info = secret_access(secret_id, uid)
        if not access_info[2]["write"]:
            raise InsufficientRight("access denied, can't perform this action on this secret")
        
        secret_found = access_info[1]
        if not access_info[2]["owner"]:
            check_result = check_attempts(access_info, uid)
            if(not check_result[0]):
                raise AttemptsExceeded(check_result[1])
                #return check_result[1]
        
        safe = safe_service.find_safe_by_id(uid, data["safe_id"])
        #safe = db_manager.find_one("safe-v2", {"safe_id": data["safe_id"]})
        if safe is None:
            raise NotFoundException('Safe not found')
        else:
            if is_system:
                raise InsufficientRight("You are not allowed")
        
        if 'secret_name' in data:
            check_name = self.secret_model.find_secret_by_name(data["secret_name"])
        else:
            check_name = self.secret_model.find_secret_by_name(data["name"])
        #check_name = db_manager.find_one("secret-v2", {"owner_uid": uid, "safe_id": data["safe_id"], "secret_name": data["secret_name"]})
        if check_name is not None:
            raise NameAlreadyExist('there is already a secret with this name')
        else:
            if is_system:
                raise InsufficientRight("You are not allowed")
        
        secret = data["secret"]

        if secret_found["secret_type"] == "credentials":
            if not is_system:
                application = application_service.find_application_by_type(secret_found['app_type'])
                secret_found['app_type'] = application['app_type']

                check_fields = check_keys(application['fields'], secret)

                if not check_fields[0]:
                    raise KeyMissing(f"Missing key(s) :{check_fields[1]}")
            else:
                salt = ecptk
            encrypted_data = jwt.decode(secret_found["secret"], salt, algorithms=["HS256"])
            decrypted_data = decrypt(encrypted_data)
            secret_decrypted = jwt.decode(decrypted_data, salt, algorithms=["HS256"])

            for key, value in secret.items():
                if key not in secret_decrypted:
                    raise KeyMissing(f"key {key} is not in secret value so you can't update it")
        
        data["secret"] = secret_credentials_encryption(secret)

        if is_system:
            db_manager.update_one("azumaril_app_config_data_secret", {"id": secret_id}, {"secret": data["secret"]})
            config_data = secret

        del data["secret_id"]
        
        if secret_file is not None:
            random_string = str(ObjectId())
            secret_dir = f'/temp/.temp_{random_string}'
            if 'secret_name' in data:
                uploaded_file = save_secret_file(secret_dir, secret_file, data['secret_name'])
            else:
                uploaded_file = save_secret_file(secret_dir, secret_file, data['name'])

            data['file_path'] = uploaded_file['file_path']
            data['file_name'] = uploaded_file['file_name']
            data['file_type'] = uploaded_file['file_type']
            data['app_type'] = None

            encrypt(data, True, True)         

            shutil.rmtree(uploaded_file['temp_folder'])

        return self.secret_model.update_secret(secret_id, data)
    
    def update_secret_infos(self, uid, secret_id, data):
        secret = self.secret_model.find_by_id(uid, secret_id)
        if not secret:
            raise NotFoundException(f'Secret with {secret_id} not found')
        
        self.secret_model.update_secret(secret_id, data)

    def update_ssh_password(self, uid, secret_id):
        # secrets = data["secrets"]["ids"]
        
        # for secret_id in secrets:
        #   pass
        
        existing_secret = self.secret_model.find_by_id(uid, secret_id)
        if not existing_secret:
            raise NotFoundException('Secret not found')
        
        if "app_type" in existing_secret:
            if existing_secret["app_type"] != "ssh":
                raise SomethingWentWrong("you cannot modify this secret because it's not of type ssh")
        else:
            raise SomethingWentWrong("this secret cannot be modified as it does not belong to any ssh application")
        
        reveal = reveal_secret(secret_id)
        
        public_key, private_key = reveal["public_key"], reveal["private_key"]

        hostname = reveal["hostname"]
        username = reveal["username"]
        password = reveal["password"]
        
        if existing_secret["use_password"].lower() == "false":
            with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.pem') as temp_file:
                temp_file.write(private_key.encode())
                temp_file.write(public_key.encode())
                temp_file.close()
                
            new_password = change_ssh_password(username, hostname, private_key=temp_file.name)
            
            #print(new_password)
            
            secret = {
                "hostname": hostname, 
                "username": username, 
                "password": new_password, 
                "public_key": public_key, 
                "private_key": private_key
            }
            
            secret_encrypt = secret_credentials_encryption(secret)
            
            data = {"secret": secret_encrypt}
            
            return self.secret_model.update_secret(secret_id, data)
            
        elif existing_secret["use_password"].lower() == "true":
            new_password = change_ssh_password(username, hostname, password=password)
            
            #print(new_password)
            
            secret = {
                "hostname": hostname, 
                "username": username, 
                "password": new_password, 
                "public_key": public_key, 
                "private_key": private_key
            }
            
            secret_encrypt = secret_credentials_encryption(secret)
            
            data = {"secret": secret_encrypt}
            
            return self.secret_model.update_secret(secret_id, data)
        else:
            raise SomethingWentWrong("SSH Authentication failed")
        
    def find_secret_by_id(self, uid, secret_id):
        fsecret = self.secret_model.find_by_id(uid, secret_id)
        if not fsecret:
            raise NotFoundException('Secret not found')
        return fsecret

    def find_all_secret(self):
        secrets = self.secret_model.find_all()
        if secrets is None:
            raise NotFoundException("Secret Not found")
            #return error_response(message=f"No secret found", code=404)
        return secrets

    def find_secrets_user(self, owner_uid):
        user_secrets = self.secret_model.find_secret_by_uid(owner_uid)
        if user_secrets is None:
            raise NotFoundException("Secret Not found")
            #return error_response(message=f"No secret found", code=404)
        return user_secrets

    def get_all_secrets_by_safe_id(self, uid, safe_id):
        existing_safe = safe_service.find_safe_by_id(uid, safe_id)
        if not existing_safe:
            raise NotFoundException('Safe not found')
        parameters = {
            'safe_id': safe_id,
            'owner_uid': uid
        }
        all_secrets = self.secret_model.find_all_with_parameters(parameters)
        return all_secrets

    def delete_secret(self, uid, secret_id):
        existing_secret = self.secret_model.find_by_id(uid, secret_id)
        if not existing_secret:
            raise NotFoundException('Secret not found')

        access_info = secret_access(secret_id, uid)
        if not access_info[2]["delete"]:
            raise InsufficientRight("access denied, can't perform this action on this secret")
        if not access_info[2]["owner"]:
            check_result = check_attempts(access_info, uid)
            if(not check_result[0]):
                raise AttemptsExceeded(check_result[1])
        
        if "app_type" in existing_secret and existing_secret["app_type"] == "kmip":
            #fetch the key_id by revealing the secret using the secret_id
            response_data = reveal_secret(secret_id)
            keyId = response_data.get("masterKey", {}).get("keyId", None)
            #call status_key in kmip_service to see if the key isn't active
            if keyId is None:
                raise ValueError("Key ID is missing from the revealed secret data")
            
            data =  {"key_id": keyId, "secret_id": secret_id}
            status = kmip_service.status_key(data)
            # print(f"Key ID: {keyId}")
            # print(f"Key status: {status}")

            if status == "ACTIVE":
                #print("Status is ACTIVE.")
                message = "The key is active; ensure it is revoked before deletion."
                raise SomethingWentWrong(message)
                #if key is active call revoke_key then call delete_key in kmip_service
            else:
                print("Status is NOT ACTIVE. Proceeding with deletion.")
                kmip_service.delete_key(data)  
                print("Key successfully deleted.")  
            #if key is not active then call delete_key directly in kmip_service
            
        
        if "app_type" in existing_secret and existing_secret["app_type"] == "ssh":
            reveal = reveal_secret(secret_id)
            #print("reveal: ", reveal)
            public_key, private_key = reveal["public_key"], reveal["private_key"]

            hostname = reveal["hostname"]
            username = reveal["username"]
            password = reveal["password"]

            public_file = copy_value_to_file(public_key, '.pub')

            if existing_secret["use_password"].lower() == "false":
                with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.pem') as temp_file:
                    temp_file.write(private_key.encode())
                    temp_file.write(public_key.encode())
                    temp_file.close()
                delete_sshpubkey(username, hostname, public_file, private_key=temp_file.name)
            elif existing_secret["use_password"].lower() == "true":
                delete_sshpubkey(username, hostname, public_file, password=password)
            else:
                raise SomethingWentWrong("SSH Authentication failed")

            self.secret_model.delete_secret(uid, secret_id)
        else:
            self.secret_model.delete_secret(uid, secret_id)
            
    def generate_certificate(self, data):
        db_manager = DBManager()
        secret_type = db_manager.find_one("secret_type", {"name": data['secret_type']})
        if secret_type is None:
            raise NotFoundException('Secret type not found')
        print(data)
        if "csr" in data:
            existing_secret2 = self.secret_model.find_secret_by_name(data['certificate_name'])
            if existing_secret2:
                raise NameAlreadyExist(f"secret name '{data['certificate_name']}' already exists")
        else:
            existing_secret = self.secret_model.find_secret_by_name(data['key_name'])
            print(f'{existing_secret} #############')
            if existing_secret:
                raise NameAlreadyExist(f"secret name '{data['key_name']}' already exists")
        
            existing_secret2 = self.secret_model.find_secret_by_name(data['certificate_name'])
            if existing_secret2:
                raise NameAlreadyExist(f"secret name '{data['certificate_name']}' already exists")
        
        print("UUUUUUUU")

        data['date'] = datetime.now()
        data_cert = {
            "secret_name": data['certificate_name'],
            "secret_type": data['secret_type'],
            "owner_uid": data["owner_uid"],
            "safe_id": data["safe_id"],
            "app_type": "ca",
            "identity": "cert",
            "certificate_type": data['certificate_type'],
            "secret": {}
        }
    
        data_key = None
        if "csr" not in data:
            data_key = {
                "secret_name": data['key_name'],
                "secret_type": data['secret_type'],
                "owner_uid": data["owner_uid"],
                "safe_id": data["safe_id"],
                "app_type": "ca",
                "identity": "key",
                "certificate_type": data['certificate_type'],
                "secret": {}
            }
        secret_key = {}
        secret_cert = {}
        
        if "safe_id" in data:
            safe_id = safe_service.find_safe_by_id(data["owner_uid"], data['safe_id'])
            data['safe_id'] = safe_id['safe_id']
        if 'app_type' in data:
            application = application_service.find_application_system(data['app_type'])
            data['app_type'] = application['app_type']

            check_fields = check_keys(application['fields'], data['secret'])
            if not check_fields[0]:
                raise KeyMissing(f"Missing key(s) :{check_fields[1]}")
        if data['certificate_type'] == "root_ca":
            if isAdmin (data["owner_uid"]) == True:
                ca_key, ca_cert = ca_service.create_certificate(data)
            else:
                raise ValueError("The user is not an Administraror to create a root_ca")
            
        elif data['certificate_type'] in ["intermediate_ca", "leaf_cert"]:
            key_secret_id = data.get('key_secret_id')
            cert_secret_id = data.get('cert_secret_id')
            if not key_secret_id or not cert_secret_id:
                raise NotFoundException("Key or Certificate secret ID not provided")
            
            # if not key_secret_id or not cert_secret_id:
            #     try:
            #         with open(config_data['CA_KEY'], 'rb') as f:
            #             print("11111111111111111")
            #             key = f.read()
            #         with open(config_data['CA_CERT'], 'rb') as b:
            #             cert = b.read()
            #     except FileNotFoundError:
            #         raise NotFoundException("Files CA not found")
            # else:
            response_key = reveal_secret(data.get('key_secret_id'))
            response_cert = reveal_secret(data.get('cert_secret_id'))

            if not response_key or 'key' not in response_key:
                raise NotFoundException("Signature key not found")
            if not response_cert or 'cert' not in response_cert:
                raise NotFoundException("Signature certificate not found")
            try:
                key = base64.b64decode(response_key['key'])
                #print(key)
                cert = base64.b64decode(response_cert['cert'])
            except (binascii.Error, TypeError):
                raise ValueError(" secrets are not in valid base64 format")
                
            ca_key, ca_cert = ca_service.create_certificate(data, cert, key)
        else:
            raise NotFoundException("certificate_type not found")

        if not ca_cert:
            raise NotFoundException("Certificat introuvable")
        
        data_cert['secret']['cert'] = base64.b64encode(
            ca_cert.encode() if isinstance(ca_cert, str) else ca_cert
            ).decode("utf-8")
        if data_key and ca_key:
            data_key['secret']['key'] = base64.b64encode(
            ca_key.encode() if isinstance(ca_key, str) else ca_key
            ).decode("utf-8")
            
        if data_cert["secret_type"] in ["credentials", "other"]:
            data_cert['secret'] = secret_credentials_encryption(data_cert['secret'])
            if data_key and ca_key:
                data_key['secret'] = secret_credentials_encryption(data_key['secret'])
        return self.secret_model.create_secret(data_cert), self.secret_model.create_secret(data_key) if data_key and ca_key else None
                
        # if data["secret_type"] ==  "credentials" or "other":
        #     secret_key.update(ca_key)
        #     secre_cert.update(ca_cert)
        #     data['secret'] = secret_credentials_encryption(data['secret'])
        
        # return self.secret_model.create_secret(data)
