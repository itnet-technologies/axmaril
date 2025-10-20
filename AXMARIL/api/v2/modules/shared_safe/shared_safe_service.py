from .shared_safe_model import SharedSafeModel
from .shared_safe_schema import SharedSafeSchema
from ..group.group_service import GroupService
from ..group.group_model import GroupModel
from ..coffre.safe_service import CoffreService
from ..shared.shared_service import SharedService
from ..secret.secret_service import SecretService
from ...utils.helpers import (
    mail_sender,
    delete_all_shared_secrets_by_secret_id,
    Thread,
    check_policy,
    apply_shared_safe_for_user,
    verify_shared_safe_user
    )
from datetime import datetime
from threading import Thread
from bson import ObjectId
from pprint import pprint
from ...utils.custom_exception import (
    NotFoundException,
    # UserAlreadyExist,
    # ErrorOccurred,
    InsufficientRight,
    NameAlreadyExist
    )


secret_service = SecretService()
safe_service = CoffreService()
group_service = GroupService()
group_model = GroupModel()
shared_secret_service = SharedService()

class SharedSafeService:
    def __init__(self):
        self.shared_safe_model = SharedSafeModel()
        self.shared_safe_schema = SharedSafeSchema()
    
    def create_shared_safe(self, data):
        data['shared_safe_id'] = str(ObjectId())
        
        owner_uid = data["owner_uid"]
        safe_id = data["safe_id"]
        receptors = data["receptors"]
                
        # safe_service.find_safe_by_id(owner_uid, safe_id)
        
        data["safe_id"] = safe_id
        data["created_at"] = datetime.now()

        safe = safe_service.find_safe_by_id(owner_uid, safe_id)
        data["safe_name"] = safe["name"]
                
        owner_safe = self.shared_safe_model.find_safe_by_id(safe_id, owner_uid)
        if owner_safe is not None:
            raise NameAlreadyExist("Share safe already exist. Please check and add users")
        
        apply_shared_safe_for_user(list_data=receptors, shared_safe_id=data['shared_safe_id'], safe_id=safe_id, owner_uid=owner_uid)

        self.shared_safe_model.create_shared_safe(data)
        return data['shared_safe_id']
    
    def add_users_to_share(self, owner_uid, safe_id, data):
        receptors = data["receptors"]
        
        owner_safe = self.shared_safe_model.find_safe_by_id(safe_id, owner_uid)
        if owner_safe is None:
            raise NotFoundException("share safe not found")
        
        shared_safe_id = owner_safe["shared_safe_id"]
        
        apply_shared_safe_for_user(list_data=receptors, shared_safe_id=shared_safe_id, safe_id=safe_id, owner_uid=owner_uid)
        
        self.shared_safe_model.update_safe_users(shared_safe_id, data)
                
    def update_user_rights(self, owner_uid, receiver_id, safe_id, data):
        owner_safe = self.shared_safe_model.find_safe_by_id(safe_id, owner_uid)
        if owner_safe is None:
            raise NotFoundException("shared safe note found")
        
        receiver = self.shared_safe_model.find_receiver_by_id(safe_id, receiver_id)

        if receiver is None:
            raise NotFoundException("this receiver is not part of the share")
        
        self.shared_safe_model.update_rights(receiver_id, safe_id, data)
        
        # mail = receiver["receptors"][0]["receiver"]
        # objet = "Azumaril safe share"
        # message = f"Vos droits sur le coffre {owner_safe['safe_name']} ont été mis à jour. Veuillez vous connecter pour regarder son contenu."
        # Thread(
        #     target=mail_sender,
        #     args=(mail, objet, message,),
        # ).start()
        
    def remove_safe_user(self, owner_uid, receiver_id, safe_id):
        owner_safe = self.shared_safe_model.find_safe_by_id(safe_id, owner_uid)
        if owner_safe is None:
            raise NotFoundException("shared safe not found")
        
        receiver = self.shared_safe_model.find_receiver_by_id(safe_id, receiver_id)
        if receiver is None:
            raise NotFoundException("this receiver is not part of the share")
        
        if receiver["receptors"][0]["receiver_type"] == "user":
            self.shared_safe_model.remove_user_from_safe(owner_safe["shared_safe_id"], receiver_id)
            
            # mail = receiver["receptors"][0]["receiver"]
            # objet = "Azumaril safe share"
            # message = f"Vos droits sur le coffre {owner_safe['safe_name']} ont été mis à jour. Veuillez vous connecter pour regarder son contenu."
            # Thread(
            #     target=mail_sender,
            #     args=(mail, objet, message,),
            # ).start()
            
        
        if receiver["receptors"][0]["receiver_type"] == "group":
            self.shared_safe_model.remove_group_from_safe(owner_safe["shared_safe_id"], receiver_id)
        
        # mail = receiver["receptors"][0]["receiver"]
        # objet = "Azumaril safe share"
        # message = f"Vos droits sur le coffre {owner_safe['safe_name']} ont été mis à jour. Veuillez vous connecter pour regarder son contenu."
        # Thread(
        #     target=mail_sender,
        #     args=(mail, objet, message,),
        # ).start()
    
    def read_secret_access(self, user_uid, safe_id, secret_id):
        owner_safe = self.shared_safe_model.find_with_safe_id(safe_id)
        if owner_safe is None:
            raise NotFoundException("safe not found")
           
        rights, receiver_safe = verify_shared_safe_user(user_uid, safe_id, secret_id)
        
        if rights.get("read"):
            response_data = secret_service.reveal_secret(owner_safe["owner_uid"], secret_id)
            return response_data
        else:
            raise InsufficientRight("your rights are insufficient to access this resource. Please update policy")
        
    
    # def read_secret_access(self, receiver_id, safe_id, secret_id):   
    #     receiver_safe = self.shared_safe_model.find_receiver_by_id(safe_id, receiver_id)
    #     if receiver_safe is None:
    #         raise NotFoundException("this receiver is not part of the share")
        
    #     owner_safe = self.shared_safe_model.find_with_safe_id(safe_id)
    #     if owner_safe is None:
    #         raise NotFoundException("safe not found")
        
    #     police_id = receiver_safe["receptors"][0]["police_id"]
        
    #     if police_id is not None:
    #         police = check_policy(police_id)
            
    #         rights =  police["rights"]
    #         if rights.get("read"):
    #             response_data = secret_service.reveal_secret(owner_safe["owner_uid"], secret_id)
    #             return response_data
    #         else:
    #             raise InsufficientRight("your rights are insufficient to access this resource. Please update policy")
            
    #     else:  
    #         rights = receiver_safe["receptors"][0].get("rights", {})
    #         if rights.get("read"):
    #             response_data = secret_service.reveal_secret(owner_safe["owner_uid"], secret_id)
    #             return response_data
    #         else:
    #             raise InsufficientRight("your rights are insufficient to access this resource. Please update user rights")
    
    def delete_secret_access(self, receiver_id, safe_id, secret_id):   
        receiver_safe = self.shared_safe_model.find_receiver_by_id(safe_id, receiver_id)
        if receiver_safe is None:
            raise NotFoundException("this receiver is not part of the share")
        
        owner_safe = self.shared_safe_model.find_with_safe_id(safe_id)
        if owner_safe is None:
                raise NotFoundException("safe not found")
        
        police_id = receiver_safe["receptors"][0]["police_id"]
        
        if police_id is not None:
            police = check_policy(police_id)
            
            rights =  police["rights"]
            if rights.get("delete"):
                secret_service.delete_secret(owner_safe["owner_uid"], secret_id)
                shared_secret_service.delete_secret_link_shared(owner_safe["owner_uid"], secret_id)
                Thread(target=delete_all_shared_secrets_by_secret_id, args=(secret_id,)).start()
            else:
                raise InsufficientRight("your rights are insufficient to access this resource. Please update policy")
            
        else: 
            rights = receiver_safe["receptors"][0].get("rights", {})
            if rights.get("delete"):
                secret_service.delete_secret(owner_safe["owner_uid"], secret_id)
                shared_secret_service.delete_secret_link_shared(owner_safe["owner_uid"], secret_id)
                Thread(target=delete_all_shared_secrets_by_secret_id, args=(secret_id,)).start()
                
            else:
                raise InsufficientRight("your rights are insufficient to access this resource. Please update user rights")
    
    def write_secret_access(self, receiver_id, data, value):
        receiver_safe = self.shared_safe_model.find_receiver_by_id(data["safe_id"], receiver_id)
        if receiver_safe is None:
            raise NotFoundException("this receiver is not part of the share")
        
        owner_safe = self.shared_safe_model.find_with_safe_id(data["safe_id"])
        if owner_safe is None:
                raise NotFoundException("safe not found")
        
        police_id = receiver_safe["receptors"][0]["police_id"]
        
        if police_id is not None:
            police = check_policy(police_id)
            
            rights =  police["rights"]
            if rights.get("write"):
                secret_service.update_secret(owner_safe["owner_uid"], data, value)
            else:
                raise InsufficientRight("your rights are insufficient to access this resource. Please update policy")
            
        else:
            rights = receiver_safe["receptors"][0].get("rights", {})
            if rights.get("write"):
                secret_service.update_secret(owner_safe["owner_uid"], data, value)
            else:
                raise InsufficientRight("your rights are insufficient to access this resource. Please update user rights")
        
    
    # def find_shared_safe_content(self, receiver_uid, safe_id, page, per_page):
    #     receiver_safe = self.shared_safe_model.find_receiver_by_uid(safe_id, receiver_uid)
    #     print(receiver_safe)
    #     # check if receiver is part of the share
    #     if receiver_safe is not None:
    #         # Get safe shared data
    #         owner_safe = self.shared_safe_model.find_with_safe_id(safe_id)
    #         #print(owner_safe)
    #         if owner_safe is None:
    #             raise NotFoundException("safe not found")
    #         # assign safe shared owner_uid to get content of secrets
    #         safe_content = secret_service.get_all_secrets_by_safe_id(owner_safe["owner_uid"], safe_id)
            
    #         for secret in safe_content["data"]:     
    #             del secret["secret"]
    #         return safe_content
        
    #     else:
    #         raise NotFoundException(f"the receiver {[receiver_safe['receptors'][0]['receiver']]} is not part of the share")
        
    # def find_all_shared_safe_by_me(self, owner_uid, safe_id, start, end):
    #     shared_safe = self.shared_safe_model.find_shared_by_uid(owner_uid, safe_id, start, end)
    #     if shared_safe is None:
    #         raise NotFoundException("shared safe not found")
    #     return shared_safe
    
    # def find_all_shared_safe_by_others(self, receiver_uid, page, per_page):
    #     receiver = self.shared_safe_model.find_receiver_shared_safe(receiver_uid)
    #     #print(receiver)
    #     if receiver is None:
    #         return list()
        
    #     shared_safes_id = receiver.get("shared_safes_id", [])
    #     #print(shared_safes_id)
    #     shared_safes = self.shared_safe_model.find_safe_shared_by_others(shared_safes_id, page, per_page)
    #     #print(shared_safes)
    #     return shared_safes     