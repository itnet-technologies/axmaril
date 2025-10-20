from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import json_util, ObjectId
import re

class ApplicationModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'applications'

    def create_application(self, data):
        data['creation_date'] = datetime.utcnow()
        data['app_id'] = str(ObjectId())
        return self.db_manager.insert_one(self.collection_name, data)

    def update_application(self, app_id, data):
        return self.db_manager.update_one(self.collection_name, {'app_id': app_id}, data)

    def find_by_id(self, app_id):
        return self.db_manager.find_one(self.collection_name, {'app_id': app_id}, {'_id': 0})
    
    def find_by_type(self, app_type):
        return self.db_manager.find_one(self.collection_name, {"$or" : [{'app_type': app_type}, {'type': app_type}]}, {'_id': 0})

    def find_system(self, app_type):
        return self.db_manager.find_one(self.collection_name, {'app_type': app_type, "owner_uid" : "SYSTEM"}, {'_id': 0})
    
    def find_by_name_with_paginate(self, app_name, page = 1, per_page = 10):
        regex = re.compile('.*{}.*'.format(re.escape(app_name)), re.IGNORECASE)

        return self.db_manager.find_many_with_paginate(self.collection_name, {'app_name': {'$regex': regex}}, {'_id': 0}, page, per_page)

    def find_by_name(self, app_name, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'app_name': app_name}, {'_id': 0}, page, per_page)

    def find_all_with_paginate(self, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {}, {'_id': 0}, page, per_page)
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})

    def delete_application(self, app_id):
        self.db_manager.delete_one(self.collection_name, {'app_id': app_id})
    
