from api.v2.database.db_manager import DBManager
from bson import ObjectId

class SharedSafeModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'shared_safe'
        self.collection_receiver_safe = 'receiver_safes'
        self.collection_policies = 'policies'
        self.collection_groups = 'groups'
    
    def create_shared_safe(self, data):
        # data['shared_safe_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data
        # for receiver in data["receptors"]:
        #     self.db_manager.update_one_and_create(self.collection_receiver_safe, {"uid": receiver["uid"]}, {"shared_safes_id": data['shared_safe_id']})
      
        # return data['shared_safe_id']

    def update_safe_users(self, shared_safe_id, data):
        for receiver in data["receptors"]:
            self.db_manager.update_one_and_save(self.collection_name, {'shared_safe_id': shared_safe_id}, {"receptors": receiver})
            # self.db_manager.update_one_and_create(self.collection_receiver_safe, {"uid": receiver["uid"]}, {'shared_safes_id': shared_safe_id})
        return shared_safe_id
    
    def update_rights(self, receiver_id, safe_id, data):
        return self.db_manager.update_one(self.collection_name, {'safe_id': safe_id, 'receptors.receiver_id': receiver_id}, {"receptors.$.rights": data["rights"], "receptors.$.police_id": data["police_id"]})
    
    def remove_user_from_safe(self, shared_safe_id, receiver_id):
        self.db_manager.update_one_and_remove(self.collection_name, {'shared_safe_id': shared_safe_id}, {'receptors':  {'receiver_id': receiver_id}})
        self.db_manager.update_one_and_remove(self.collection_receiver_safe, {'receiver_id': receiver_id}, {'shared_safes_id': shared_safe_id})
    
    def remove_group_from_safe(self, shared_safe_id, receiver_id):
        self.db_manager.update_one_and_remove(self.collection_name, {'shared_safe_id': shared_safe_id}, {'receptors':  {'receiver_id': receiver_id}})
        self.db_manager.update_many_and_remove(self.collection_receiver_safe, {'receiver_id': receiver_id}, {'shared_safes_id': shared_safe_id})
    
    def find_by_id(self, shared_safe_id):
        return self.db_manager.find_one(self.collection_name, {'shared_safe_id': shared_safe_id})
    
    def find_with_safe_id(self, safe_id):
        return self.db_manager.find_one(self.collection_name, {'safe_id': safe_id})
    
    def find_receiver_by_id(self, safe_id, receiver_id):
        return self.db_manager.find_one(self.collection_name, {'safe_id': safe_id, 'receptors.receiver_id': receiver_id}, {"receptors.$": 1})
    
    def find_receiver_by_group_name(self, safe_id, group_name):
        return self.db_manager.find_one(self.collection_groups, {'safe_id': safe_id, 'receptors.receiver': group_name}, {"receptors.$": 1})
    
    def find_receiver_by_group(self, safe_id, owner_uid):
        # query = {"$not": {"$elemMatch": {"receiver_type": {"$ne": "group"}}}}
        query = {"$elemMatch": {"receiver_type": "group"}}
        return self.db_manager.find_one(self.collection_name, {'safe_id': safe_id, "owner_uid": owner_uid, "receptors": query}, {"receptors.$": 1})
    
    def find_safe_shared_by_others(self, shared_safes_id, page = 1, per_page = 10):
        projection = {"created_at": 1, "owner_uid": 1, "receptors": 1, "safe_id": 1, "safe_name": 1, "shared_safe_id": 1, "_id": 0}
        return self.db_manager.find_many_with_paginate(self.collection_name, {'shared_safe_id': {'$in': shared_safes_id}}, projection, page, per_page)
    
    def find_safe_by_id(self, safe_id, owner_uid):
        return self.db_manager.find_one(self.collection_name, {'safe_id': safe_id, 'owner_uid': owner_uid})
    
    def find_receiver_shared_safe(self, receiver_id):
        return self.db_manager.find_one(self.collection_receiver_safe, {'receiver': receiver_id})
    
    def find_all(self, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {}, {'_id': 0}, page, per_page)
    
    def find_all_with_parameters(self, parameters):
        return self.db_manager.find_many_with_paginate(self.collection_name, parameters, {'_id': 0})
    
    def find_shared_by_uid(self, owner_uid, safe_id, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {"owner_uid": owner_uid, "safe_id": safe_id}, {'_id': 0}, page, per_page)
    
    def find_policy_by_id(self, police_id):
        return self.db_manager.find_one(self.collection_policies, {"policie_id": police_id})