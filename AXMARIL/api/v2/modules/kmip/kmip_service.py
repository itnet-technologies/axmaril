from .kmip_model import KmipModel
from .kmip_schema import KmipKeySchema
from ..application.application_service import ApplicationService
from ...utils.helpers import success_response, error_response, config_data, reveal_secret
from ...database.db_manager import DBManager
from datetime import datetime
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, InsufficientRight, AttemptsExceeded, CustomException, SomethingWentWrong, KeyMissing, AttemptsExceeded, InvalidDataException, TokenInvalidError
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption
from bson.codec_options import CodecOptions
from bson.binary import UUID_SUBTYPE
import base64
import tempfile
import json
from flask import request
import base64
import typing
application_service = ApplicationService()
from datetime import datetime


KMIP_PORT = config_data["KMIP_PORT"]

class KmipService:
    def __init__(self):
        self.kmip_model = KmipModel()
        self.kmip_schema = KmipKeySchema()
    
    # kms_providers = {
    # "kmip": {
    #         "endpoint": f"localhost:{KMIP_PORT}",  # Fournisseur KMIP local
    #     }
    # }
    
    # tls_options = {
    # "kmip": {
    #         "tlsCAFile": config_data["KMIP_CA"],  # Certificat CA
    #         "tlsCertificateKeyFile": config_data["KMIP_CLIENT_KEY_CERT"],  # Certificat client
    #     }
    # }
    
    def is_certificate(self ,file_content):
        """Vérifie si le fichier est un certificat X.509"""
        return (
        file_content.startswith(b"-----BEGIN CERTIFICATE-----") and
        file_content.strip().endswith(b"-----END CERTIFICATE-----")
    )
    
    def is_private_key(self ,file_content):
        """Vérifie si le fichier est une clé privée (RSA ou EC)"""
        return (
        (file_content.startswith(b"-----BEGIN PRIVATE KEY-----") and file_content.strip().endswith(b"-----END PRIVATE KEY-----")) or
        (file_content.startswith(b"-----BEGIN RSA PRIVATE KEY-----") and file_content.strip().endswith(b"-----END RSA PRIVATE KEY-----")) or
        (file_content.startswith(b"-----BEGIN EC PRIVATE KEY-----") and file_content.strip().endswith(b"-----END EC PRIVATE KEY-----"))
    )
    
    
    
    def get_kmip_client(self, data):
        response_data = reveal_secret( data.get("secret_id"))
        
        if not isinstance(response_data, dict):
            print("Erreur: response_data n'est pas un dictionnaire valide")
            return None
        
        
        user_cert_encoded = response_data.get("user_cert")
        user_key_encoded = response_data.get("user_key")
        
        if user_cert_encoded and user_key_encoded:
            try:
                user_cert = base64.b64decode(user_cert_encoded)
                user_key = base64.b64decode(user_key_encoded)
                print("Certificat et clé décodés avec succès")
            except base64.binascii.Error:
                print("Erreur: Décodage base64 échoué")
                return None
            
            cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
            key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key")

            cert_file.write(user_cert)
            key_file.write(user_key)

            cert_file.close()
            key_file.close()
            
            return ProxyKmipClient(
                hostname="localhost",
                port=KMIP_PORT,
                cert=cert_file.name,
                key=key_file.name,
                ca=config_data["KMIP_CA"],
                config={'tls_cipher_suites': 'ECDHE-RSA-AES256-GCM-SHA384'}
            )
        
        print("Aucun certificat trouvé, utilisation des certificats par défaut")
        return ProxyKmipClient(
            hostname="localhost",
            port=KMIP_PORT,
            cert=config_data["KMIP_CLIENT_CERT"],
            key=config_data["KMIP_CLIENT_KEY"],
            ca=config_data["KMIP_CA"],
            config={'tls_cipher_suites': 'ECDHE-RSA-AES256-GCM-SHA384'}
        )


        
        # return ProxyKmipClient (
        #     hostname="localhost",
        #     port= KMIP_PORT,
        #     cert=config_data["KMIP_CLIENT_CERT"],
        #     key=config_data["KMIP_CLIENT_KEY"],
        #     ca=config_data["KMIP_CA"],
        #     config={'tls_cipher_suites': 'ECDHE-RSA-AES256-GCM-SHA384'}
        # )
        
    def generate_key(self, data):
        connection_client =  data.get("url")
        db = data.get("database")
        collection = data.get("collection")
        namespace = f"{db}.{collection}"
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
                #print("bkgkhs")
                dt_string = v.strftime("%Y-%m-%d %H:%M:%S.%f")
                v = dt_string
                key_document[k] = v
                #print(v)
        return key_document
        
        # db_manager = DBManager()
        # secret_type = db_manager.find_one("secret_type", {"name": data['secret_type']})
        # if secret_type is None:
        #     raise NotFoundException('Secret type not found')
        #    # return error_response(message=f"the secret type {data['secret_type']} isn't defined")
        
        # existing_key = self.kmip_model.find_key_by_name(data['name'])
        # if existing_key:
        #     raise NameAlreadyExist('key with this name already exists')
        #     #return error_response(message=f"secret {data['secret_name']} already exists")
        
        # data['date'] = datetime.now()
        
        
        # return self.secret_model.create_secret(data)
        
    # def generate_key_by_their_certificate(self, data):
        
    #     #print(data)
    #     connection_client = data["secret"]["url"]
    #     db = data["secret"]["database"]
    #     collection = data["secret"]["collection"]
    #     namespace = f"{db}.{collection}"

    #     user_cert= data.get("user_cert")
    #     user_key = data.get("user_key")
    #     print(user_cert)
        
    #     with tempfile.NamedTemporaryFile(delete=False, mode="wb") as temp_cert_key:
    #         temp_cert_key.write(user_cert)
    #         temp_cert_key.write(b"\n")
    #         temp_cert_key.write(user_key)
    #         temp_cert_key_path = temp_cert_key.name
            
    #         print (temp_cert_key_path)
        
    #     providers = {
    #         "kmip": {
    #             "endpoint": f"localhost:{KMIP_PORT}",
    #         }
    #     }
        
    #     tls_options2 = {
    #         "kmip": {
    #             "tlsCAFile": config_data["KMIP_CA"],  # Certificat CA
    #             "tlsCertificateKeyFile": temp_cert_key_path,  # Certificat client + clé
    #         }
    #     }
        


    #     client = MongoClient(connection_client)
    #     key_vault_client = MongoClient(connection_client)
        
    #     client2_encryption = ClientEncryption(
    #         providers,
    #         namespace,
    #         client,
    #         CodecOptions(uuid_representation=UUID_SUBTYPE),
    #         kms_tls_options=tls_options2,
    #     )
    #     master_key = {}
    #     data_key_id = client2_encryption.create_data_key("kmip", master_key)
        
    #     dek_id = base64.b64encode(data_key_id).decode("utf-8")
    #     db_name, coll_name = namespace.split('.')
    #     key_vault_collection = key_vault_client[db_name][coll_name]
    #     key_document = key_vault_collection.find_one({"_id": data_key_id})
        
    #     key_id = key_document["masterKey"]["keyId"]
    #     material_key = key_document["keyMaterial"]
    #     material_key_base = base64.b64encode(material_key).decode("utf-8")
    #     key_document["keyMaterial"] = material_key_base
    #     key_document["_id"] = dek_id

    #     # Formatage des dates
    #     for k, v in key_document.items():
    #         if isinstance(v, datetime):
    #             key_document[k] = v.strftime("%Y-%m-%d %H:%M:%S.%f")

    #     return key_document 

    def status_key(self, data):
        cle_id = data.get('key_id')
        client = self.get_kmip_client(data)
        client.open()

        status = client.get_attributes(cle_id, ['State'])
        #print (status)
        client.close()
        state_value = status[1][0].attribute_value.value.name
        return state_value
    
    def revoke_key(self,data):
        #print(data)
        key_id = data.get('key_id')
        reason_str = data.get('reason', 'UNSPECIFIED')

        reason_mapping = {
            'UNSPECIFIED': enums.RevocationReasonCode.UNSPECIFIED,
            'KEY_COMPROMISE': enums.RevocationReasonCode.KEY_COMPROMISE,
            'CA_COMPROMISE': enums.RevocationReasonCode.CA_COMPROMISE,
            'AFFILIATION_CHANGED': enums.RevocationReasonCode.AFFILIATION_CHANGED,
            'SUPERSEDED': enums.RevocationReasonCode.SUPERSEDED,
            'CESSATION_OF_OPERATION': enums.RevocationReasonCode.CESSATION_OF_OPERATION,
            'PRIVILEGE_WITHDRAWN': enums.RevocationReasonCode.PRIVILEGE_WITHDRAWN
        }

        reason = reason_mapping.get(reason_str.upper(), enums.RevocationReasonCode.UNSPECIFIED)
        client = self.get_kmip_client(data)
        client.open()
        client.revoke(reason, key_id)
        client.close()
    
    
    def delete_key(self, data):
        key_id = data.get('key_id')

        if not key_id:
            message = "error : key ID required"
            return message, 400
        
        client = self.get_kmip_client(data)
        client.open()
        client.destroy(key_id)
        client.close()
        massage2 = "Key deleted"
        return massage2

    def activate_key(self, data):
        key_id = data.get('key_id')
        client = self.get_kmip_client(data)
        client.open()
        client.activate(key_id)
        client.close
    




