from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import ObjectId


class BulkModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'bulk-v2'
    
    def create_bulk(self, data):
        data['bulk_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data['bulk_id']

    def update_bulk(self, bulk_id, data):
        return self.db_manager.update_one(self.collection_name, {'bulk_id': bulk_id}, data)

    def delete_bulk(self, uid, bulk_id):
        self.db_manager.delete_one(self.collection_name, {'owner_uid': uid, 'bulk_id': bulk_id})
    
    def find_by_id(self, bulk_id):
        return self.db_manager.find_one(self.collection_name, {'bulk_id': bulk_id})
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})
    
    def find_all_with_parameters(self, parameters):
        return self.db_manager.find_many(self.collection_name, parameters, {'_id': 0})

    def find_bulk_by_uid(self, owner_uid):
        return self.db_manager.find_many(self.collection_name, {"owner_uid": owner_uid}, {'_id': 0})