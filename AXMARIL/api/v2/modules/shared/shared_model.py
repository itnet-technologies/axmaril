from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import ObjectId


class SharedModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'shared-v2'
    
    def create_shared(self, data):
        #data["_id"] = str(ObjectId())
        data['shared_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data['shared_id']

    def update_shared(self, shared_id, data):
        return self.db_manager.update_one(self.collection_name, {'shared_id': shared_id}, data)
    
    def update_object(self, object_id, data):
        return self.db_manager.update_one(self.collection_name, {'receivers.object_id': object_id}, data)

    def delete_shared(self, uid, shared_id):
        self.db_manager.delete_one(self.collection_name, {'owner_uid': uid, 'shared_id': shared_id})
    
    def delete_many_shared(self, uid, secret_id):
        existing_count = self.db_manager.count_documents(self.collection_name, {'secret_infos.secret_id': secret_id})
        if existing_count == 0:
            return False
        else:
            self.db_manager.delete_many(self.collection_name, {'owner_uid': uid, 'secret_infos.secret_id': secret_id})
    
    def find_by_id(self, shared_id):
        return self.db_manager.find_one(self.collection_name, {'shared_id': shared_id})
    
    def find_object_by_id(self, object_id):
        return self.db_manager.find_one(self.collection_name, {'receivers.object_id': object_id})
    
    def find_shared_by_token(self, value):
        return self.db_manager.find_one(self.collection_name, {"receivers.shared_token": value}, {"_id":0})
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})
    
    def find_all_with_parameters(self, parameters):
        return self.db_manager.find_many(self.collection_name, parameters, {'_id': 0})
    
    def find_shared_by_uid(self, owner_uid):
        return self.db_manager.find_many(self.collection_name, {"owner_uid": owner_uid}, {'_id': 0})
