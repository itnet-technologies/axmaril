from .shared_model import SharedModel
from .shared_schema import SharedSchema
from ..coffre.safe_service import CoffreService
from ..secret.secret_service import SecretService
from ...utils.helpers import config_data, generate_share_token, reveal_secret, convert_hex_to_binary, mail_sender
from datetime import datetime
from threading import Thread
from flask import url_for, send_file
from bson import ObjectId
from ...utils.custom_exception import NotFoundException, TokenExpiredError, ErrorOccurred, InsufficientRight, SomethingWentWrong
import tempfile2
import jwt
import json


secret_service = SecretService()
safe_service = CoffreService()

class SharedService:
    def __init__(self):
        self.shared_model = SharedModel()
        self.shared_schema = SharedSchema()
    
    def shared_secret(self, data):
        secret_id = data["secret_id"]
        receivers = data["receivers"]
        
        data["secret_id"] = secret_id
        data["is_valid"] = True
        
        reveal_secret(secret_id)
        
        secret_data = secret_service.find_secret_by_id(data["owner_uid"], secret_id)
        
        if "name" in secret_data:
            data["secret_infos"] = {
                "secret_id": secret_id,
                "secret_name": secret_data["name"],
                "secret_type": secret_data["secret_type"]
            }
        elif "secret_name" in secret_data:
            data["secret_infos"] = {
                "secret_id": secret_id,
                "secret_name": secret_data["secret_name"],
                "secret_type": secret_data["secret_type"]
            }

        data["duration"] = data["duration"]

        receivers_list = []

        for receiver in receivers:
            data['receiver'] = receiver
        
            if "duration" in data:
                duration = data["duration"]

                if duration is not None:
                    token, expiration = generate_share_token(secret_id, receiver, duration)
                else:
                    token, expiration = generate_share_token(secret_id, receiver, 60)
            
            data["expire_at"] = expiration
            data["shared_token"] = token

            #token = generate_share_token(secret_id, receiver, duration)
            share_link = url_for('v2_shared.download_shared_secret', token=token, _external=True)
            data["shared_link"] = share_link

            data["created_at"] = datetime.now()
            data["last_used_at"] = datetime.now()
            data["use_count"] = 0  
            
            mail = receiver
            objet = "Azumaril secret share"
            message = f"Un secret a été partagé avec vous via AZUMARIL. Télécharger le contenu via ce lien: {share_link}"
            Thread(
                target=mail_sender,
                args=(mail, objet, message,),
            ).start()

            data.pop("receivers", None)
            data.pop("secret_id", None)

            receiver_object = {
                "object_id": str(ObjectId()),
                "receiver": receiver,
                "shared_token": data["shared_token"],
                "shared_link": data["shared_link"],
                "last_used_at": data["last_used_at"],
                "is_valid": data["is_valid"],
                "use_count": data["use_count"]
            }

            receivers_list.append(receiver_object)
        
        data["receivers"] = receivers_list

        data.pop("shared_token", None)
        data.pop("shared_link", None)
        data.pop("last_used_at", None)
        data.pop("receiver", None)
        data.pop("is_valid", None)
        data.pop("use_count", None)

        self.shared_model.create_shared(data)

        #return share_link

    def download_shared(self, shared_token):

        existing_shared = self.shared_model.find_shared_by_token(shared_token)
        if not existing_shared:
            raise NotFoundException("Invalid Link")
        
        for receiver in existing_shared["receivers"]:
        
            if receiver["is_valid"] == False:
                raise InsufficientRight("You don't have sufficient access to download this secret. Please contact the owner")
            
            data = jwt.decode(shared_token, config_data["TOKEN_SECRET_SALT"], algorithms=["HS256"])
            secret_id = data.get('secret_id')
            
            today = datetime.now()

            print("expire_at: ", existing_shared["expire_at"])

            if today > existing_shared["expire_at"]:
                raise TokenExpiredError('Download link expired')
            
            receiver["use_count"] += 1
            receiver["last_used_at"] = datetime.now()


            self.shared_model.update_object(receiver["object_id"], {"receivers.$.use_count": receiver["use_count"], "receivers.$.last_used_at": receiver["last_used_at"]})

        secret_data = secret_service.find_secret_by_id(existing_shared["owner_uid"], secret_id)
        secret_content = reveal_secret(secret_id)

        if isinstance(secret_content, dict):
            secret = json.dumps(secret_content)
            
        if secret_data["secret_type"] == "file":
            return convert_hex_to_binary(secret_content["data"], secret_content["name"])
                
        elif secret_data["secret_type"] == "credentials" or "other":
                
            with tempfile2.NamedTemporaryFile(delete=False, close=False, suffix='.json') as temp_file:
                temp_file.write(secret.encode())
                temp_file.close()

            return send_file(temp_file.name, as_attachment=True, download_name='shared.json')
        else:
            raise ErrorOccurred('Error while downloading')
    
    def cancel_shared(self, object_id):
        existing_shared = self.shared_model.find_object_by_id(object_id)
        if not existing_shared:
            raise NotFoundException("Invalid Link")    
        return self.shared_model.update_object(object_id, {"receivers.$.is_valid": False})
         
    def find_all_shared(self, uid):
        all_shared = self.shared_model.find_shared_by_uid(uid)
        return all_shared
    
    def delete_secret_link_shared(self, uid, secret_id):
        secret_deleted = self.shared_model.delete_many_shared(uid, secret_id)
        if secret_deleted == False:
            print("secret_id not found in shared secret collection")
            pass
    
    
