from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import json_util, ObjectId
from pprint import pprint

class CoffreModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'safe'
        self.collection_shared_safe = 'shared_safe'
        self.collection_receiver_safe = 'receiver_safes'
    
    def create_safe(self, data):
        data['creation_date'] = datetime.utcnow()
        data['safe_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data['safe_id']
    
    def update_safe(self, uid, safe_id, data):
        return self.db_manager.update_one(self.collection_name, {'owner_uid': uid, 'safe_id': safe_id}, data)

    def find_by_id(self, uid, safe_id):
        return self.db_manager.find_one(self.collection_name, {'owner_uid': uid, 'safe_id': safe_id}, {'_id': 0})

    def find_many_by_name(self, uid, safe_name):
        return self.db_manager.find_many(self.collection_name, {'owner_uid': uid, 'name': safe_name}, {'_id': 0})

    def find_by_name(self, uid, safe_name):
        return self.db_manager.find_many(self.collection_name, {'owner_uid': uid, 'name': safe_name}, {'_id': 0})


    def find_all_safe(self, uid):
        return self.db_manager.find_many(self.collection_name, {'owner_uid': uid},{"_id":0})

    def find_all_safe_with_paginate(self, uid, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'owner_uid': uid}, {'_id': 0}, page, per_page)
        # all_safes = []
        # safe_ids = set()
        
        # receiver_info = self.db_manager.find_one(self.collection_receiver_safe, {'uid': uid})
        # pprint(receiver_info)
        
        # safes_shared_with_me = []
        # projection = {"created_at": 1, "owner_uid": 1, "receptors": 1, "safe_id": 1, "safe_name": 1, "_id": 0}
        
        # if receiver_info is not None:
        #     shared_safes_id = receiver_info.get("shared_safes_id", [])
        #     safes_shared_with_me_dict = self.db_manager.find_many_with_paginate(self.collection_shared_safe, {'shared_safe_id': {'$in': shared_safes_id}}, projection, page, per_page)
        #     safes_shared_with_me = safes_shared_with_me_dict.get("data", []) if safes_shared_with_me_dict and "data" in safes_shared_with_me_dict else []
            
        #     if safes_shared_with_me:
        #         for safe in safes_shared_with_me:
        #             if safe["safe_id"] not in safe_ids:
        #                 safe["date"] = safe["created_at"]
        #                 del safe["created_at"]
                        
        #                 safe["name"] = safe["safe_name"]
        #                 del safe["safe_name"]
        #                 safe["send_by"] = "others"
                    
        #                 all_safes.append(safe)
        #                 safe_ids.add(safe["safe_id"])
                  
        
        # safes_shared_by_me_dict = self.db_manager.find_many_with_paginate(self.collection_shared_safe, {'owner_uid': uid}, projection, page, per_page)
        # safes_shared_by_me = safes_shared_by_me_dict.get("data", []) if safes_shared_by_me_dict and "data" in safes_shared_by_me_dict else []
        
        # if safes_shared_by_me:
        #     for safe in safes_shared_by_me:
        #         if safe["safe_id"] not in safe_ids:
        #             safe["date"] = safe["created_at"]
        #             del safe["created_at"]
                    
        #             safe["name"] = safe["safe_name"]
        #             del safe["safe_name"]
        #             safe["send_by"] = "owner"
                
        #             all_safes.append(safe)
        #             safe_ids.add(safe["safe_id"])
                
        # owner_safe_dict = self.db_manager.find_many_with_paginate(self.collection_name, {'owner_uid': uid}, {'_id': 0}, page, per_page)
        # owner_safe = owner_safe_dict.get("data", []) if owner_safe_dict and "data" in owner_safe_dict else []
        # if owner_safe:
        #     for safe in owner_safe:
        #         if "creation_date" in safe:
        #             safe["date"] = safe["creation_date"]
        #             del safe["creation_date"]
                
        #         if safe["safe_id"] not in safe_ids:
        #             all_safes.append(safe)
        #             safe_ids.add(safe["safe_id"])
        
        # # all_safes = owner_safe + safes_shared_with_me + safes_shared_by_me
        # return all_safes
    

    def delete_safe(self, uid, safe_id):
        return self.db_manager.delete_one(self.collection_name, {'owner_uid': uid, 'safe_id': safe_id})

    def find_one_with_parameters(self, parameters):
        return self.db_manager.find_one(self.collection_name, parameters)

    
