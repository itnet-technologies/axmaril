from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import ObjectId


class SshSessionModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'sshsession'
    
    def create_ssh_session(self, data):
        data['session_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data['session_id']

    def update_ssh_session(self, session_id, data, other):
        return self.db_manager.update_other(self.collection_name, {'session_id': session_id}, data, other)

    def update_session(self, session_id, data):
        return self.db_manager.update_one(self.collection_name, {'session_id': session_id}, data)

    def delete_ssh_session(self, session_id):
        self.db_manager.delete_one(self.collection_name, {'session_id': session_id})
    
    def find_session_by_id(self, owner_uid, session_id):
        return self.db_manager.find_one(self.collection_name, {'owner_uid': owner_uid, 'session_id': session_id})
    
    def find_by_id(self, session_id):
        return self.db_manager.find_one(self.collection_name, {'session_id': session_id})
    
    def find_all_with_paginate(self, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {}, {'_id': 0}, page, per_page)
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})
    
    def find_all_with_parameters(self, parameters):
        return self.db_manager.find_many(self.collection_name, parameters, {'_id': 0})

    def find_ssh_session_by_uid(self, owner_uid):
        return self.db_manager.find_many(self.collection_name, {"owner_uid": owner_uid}, {'_id': 0})