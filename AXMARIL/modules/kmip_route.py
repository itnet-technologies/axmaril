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
from pymongo import MongoClient
from modules.required_packages import (
    encode_token,
    get_uid_by_token,
    jwt_validation,
    leader_validator,
    validation)
from bson import ObjectId
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from pathlib import Path
import math
from pymongo import MongoClient
from bson.codec_options import CodecOptions
from bson.binary import UUID_SUBTYPE, Binary
from pymongo.encryption import ClientEncryption, AutoEncryptionOpts
import base64
import uuid
from modules.required_packages import success_response, error_response, KMIP_PORT
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums

KMIP_REQUEST = Blueprint("kmip", __name__)

# KMIP_PORT= 5690

kms_providers = {
    "kmip": {
        "endpoint": f"localhost:5690",  # Fournisseur KMIP local
        
    }
}

tls_options = {
    "kmip": {
        "tlsCAFile": "/home/python3.10/ca_1.pem",  # Certificat CA
        "tlsCertificateKeyFile": "/home/python3.10/client3.pem",  # Certificat client
    }
}


# @KMIP_REQUEST.route("/generate_key",  methods=['POST'])
# @leader_validator
# @jwt_validation
# def generate_key():
#     print("ici1#######################")
#     try:
#         req = request.get_json(force = True)
#         user_uid = get_uid_by_token()
#         connection_client = req.get("URL")
#         db = req.get("database")
#         collection = req.get("collection")
#         namespace = f"{db}.{collection}"
#         client = MongoClient(connection_client)
#         # print("ici2")
#         key_vault_client = MongoClient(connection_client)
        
#         client1_encryption = ClientEncryption(
#             kms_providers,
#             namespace,
#             client,
#             CodecOptions(uuid_representation=UUID_SUBTYPE),
#             kms_tls_options=tls_options,
#         )
#         print("ici2")
#         master_key = {}  # PyKMIP génère une clé maître automatiquement
#         data_key_id = client1_encryption.create_data_key("kmip", master_key)
#         print("ici 3 ###################")
#         dek_id = base64.b64encode(data_key_id).decode("utf-8")

#         print ("----------------------")
#         print(dek_id)
        
#         db_name, coll_name = namespace.split('.')
#         key_vault_collection = key_vault_client[db_name][coll_name]
#         key_document = key_vault_collection.find_one({"_id": data_key_id})

#         if key_document and "masterKey" in key_document and "keyId" in key_document["masterKey"]:
#             # Récupérer la valeur de `masterKey.keyId`
#             key_id = key_document["masterKey"]["keyId"]
#             material_key = key_document["keyMaterial"]
#             material_key_base = base64.b64encode(material_key).decode("utf-8")
#             key_document["keyMaterial"] = material_key_base
#             key_document["_id"] = dek_id
#             # print(f"Key ID récupéré : {key_id}")
#             # print(f"materialKey:{material_key_base}" )
#             print(key_document)

#             return jsonify({
#             "status" : "success",
#             "message" : "success",
#             "key_document" : key_document 
#             }), 200
#         else:
#             return jsonify({"message": "Key data created but keyId not found"}), 204
#     except:
#         print(traceback.format_exc())
#         return jsonify({"message":"Something went wrong", "status": "failed"}), 400

# def get_kmip_client():
#     return ProxyKmipClient (
#         hostname="localhost",
#         port=KMIP_PORT,
#         cert="/home/python3.10/client3_cert.pem",
#         key="/home/python3.10/client3_key.pem",
#         ca="/home/python3.10/ca_1.pem",
#         config={'tls_cipher_suites': 'ECDHE-RSA-AES256-GCM-SHA384'}
#     )
    
# @KMIP_REQUEST.route('/activate_key', methods=['POST'])
# @leader_validator
# @jwt_validation
# def activate_key():
#     data = request.get_json()
#     key_id = data.get('key_id')
#     try:
#         client = get_kmip_client()
#         client.open()
#         client.activate(key_id)
#         client.close
#         return jsonify({'messages': 'key activated'}), 200
#     except Exception as e:
#         return jsonify({'status': 'Failed to get status ', 'error': str(e)}), 500


# @KMIP_REQUEST.route('/status_key', methods=['POST'])
# @leader_validator
# @jwt_validation   
# def status_key():
#     data = request.get_json()
#     cle_id = data.get('key_id')
#     try:
#         client= get_kmip_client()
#         client.open()

#         status = client.get_attributes(cle_id, ['State'])
#         print (status)
#         client.close()
#         state_value = status[1][0].attribute_value.value.name
#         return jsonify({'status': state_value}), 200
#     except Exception as e:
#         print(traceback.format_exc())
#         return jsonify({'status': 'Failed to get status ', 'error': str(e)}), 500


# #status_key(cle_id="7")
# @KMIP_REQUEST.route('/revoke_key', methods=['POST'])
# @leader_validator
# @jwt_validation 
# def revoke_key():
#     try:
#         data = request.get_json()
#         key_id = data.get('key_id')
#         reason_str = data.get('reason', 'UNSPECIFIED')

#         reason_mapping = {
#             'UNSPECIFIED': enums.RevocationReasonCode.UNSPECIFIED,
#             'KEY_COMPROMISE': enums.RevocationReasonCode.KEY_COMPROMISE,
#             'CA_COMPROMISE': enums.RevocationReasonCode.CA_COMPROMISE,
#             'AFFILIATION_CHANGED': enums.RevocationReasonCode.AFFILIATION_CHANGED,
#             'SUPERSEDED': enums.RevocationReasonCode.SUPERSEDED,
#             'CESSATION_OF_OPERATION': enums.RevocationReasonCode.CESSATION_OF_OPERATION,
#             'PRIVILEGE_WITHDRAWN': enums.RevocationReasonCode.PRIVILEGE_WITHDRAWN
#         }

#         reason = reason_mapping.get(reason_str.upper(), enums.RevocationReasonCode.UNSPECIFIED)
#         client = get_kmip_client()
#         client.open()
#         client.revoke(reason, key_id)
#         client.close()

#         return jsonify({'key_id': key_id, 'status': 'Key revoked successfully', 'reason': reason_str}), 200
#     except Exception as e:
#         return jsonify({'status': 'Failed to revoke key', 'error': str(e)}), 500
    

# @KMIP_REQUEST.route('/delete_key', methods=['POST'])
# @leader_validator
# @jwt_validation    
# def delete_key():
#     try:
#         data = request.get_json()
#         key_id = data.get('key_id')

#         if not key_id:
#             return jsonify({'status': 'Failed', 'error': 'Key ID is required'}), 400
        
#         client = get_kmip_client()
#         client.open()
#         client.destroy(key_id)
#         client.close()

#         return jsonify({'key_id': key_id, 'status': 'Key destroyed successfully'}), 200
#     except Exception as e:
#         return jsonify({'status': 'Failed to destroy key', 'error': str(e)}), 500






# #generate_key(connection_client="mongodb://62.161.252.224:27017/", db="string", collection="test")


def cerate_kmip_secret():
    pass
    