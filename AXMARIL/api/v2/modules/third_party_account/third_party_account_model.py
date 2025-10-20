from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import json_util, ObjectId
import re

class ThirdPartyAccountModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'third_party_account'

    def create_third_party_account(self, data):
        data['creation_date'] = datetime.utcnow()
        data['updated_at'] = datetime.utcnow()
        data['account_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data

    def update_third_party(self, account_id, data):
        data['updated_at'] = datetime.utcnow()
        return self.db_manager.update_one(self.collection_name, {'account_id': account_id}, data)

    def find_by_id(self, uid, account_id):
        return self.db_manager.find_one(self.collection_name, {'owner_uid': uid, 'account_id': account_id}, {'_id': 0})
    
    def find_by_name_with_paginate(self, third_name, page = 1, per_page = 10):
        regex = re.compile('.*{}.*'.format(re.escape(third_name)), re.IGNORECASE)
        return self.db_manager.find_many_with_paginate(self.collection_name, {'name': {'$regex': regex}}, {'_id': 0}, page, per_page)

    def find_by_name(self, third_name, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'name': third_name}, {'_id': 0}, page, per_page)

    def find_one_by_name(self, third_name):
        return self.db_manager.find_one(self.collection_name, {'name': third_name}, {'_id': 0})

    def find_all_with_paginate(self, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {}, {'_id': 0}, page, per_page)
    
    def find_all_third_party_account(self, uid, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'owner_uid': uid}, {'_id': 0}, page, per_page)
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})

    def delete_third_party(self, uid, account_id):
        self.db_manager.delete_one(self.collection_name, {'owner_uid': uid, 'account_id': account_id})
    
