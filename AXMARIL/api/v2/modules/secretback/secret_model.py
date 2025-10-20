from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import ObjectId


class SecretModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'secrets'
    
    def create_secret(self, data):
        data['secret_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data['secret_id']

    def update_secret(self, secret_id, data):
        return self.db_manager.update_one(self.collection_name, {'secret_id': secret_id}, data)

    def delete_secret(self, uid, secret_id):
        self.db_manager.delete_one(self.collection_name, {'owner_uid': uid, 'secret_id': secret_id})
    
    def delete_secrets(self, scope):
        self.db_manager.delete_many(self.collection_name, scope)
        
    def find_by_id(self, uid, secret_id):
        return self.db_manager.find_one(self.collection_name, {'owner_uid': uid, 'secret_id': secret_id})
    
    def find_secret_by_name(self, name):
        return self.db_manager.find_one(self.collection_name, {"secret_name": name}, {"_id":0})
    
    def find_secret_by_safe(self, safe_id, owner_uid):
        return self.db_manager.find_one(self.collection_name, {"safe_id": safe_id, "owner_uid": owner_uid}, {"_id":0})
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})
    
    def count(self, scope):
        return self.db_manager.count_documents(self.collection_name, scope, {'_id': 0})

    def find_all_with_parameters(self, parameters, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, parameters, {'_id': 0}, page, per_page)
    
    def find_secret_by_uid(self, owner_uid):
        return self.db_manager.find_many(self.collection_name, {"owner_uid": owner_uid}, {'_id': 0})
    
    def find_root_ca_by_certificate_type(self, certificate_type):
        return self.db_manager.find_many(self.collection_name, {"certificate_type": certificate_type}, {"_id":0})
