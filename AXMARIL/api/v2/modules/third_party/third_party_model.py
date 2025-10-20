from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import json_util, ObjectId
import re

class ThirdPartyModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'third_party'

    def create_third_party(self, data):
        data['creation_date'] = datetime.utcnow()
        data['updated_at'] = datetime.utcnow()
        data['third_id'] = str(ObjectId())
        return self.db_manager.insert_one(self.collection_name, data)

    def update_third_party(self, third_id, data):
        data['updated_at'] = datetime.utcnow()
        return self.db_manager.update_one(self.collection_name, {'third_id': third_id}, data)

    def find_by_id(self, third_id):
        return self.db_manager.find_one(self.collection_name, {'third_id': third_id}, {'_id': 0})
    
    def find_by_name_with_paginate(self, third_name, page = 1, per_page = 10):
        regex = re.compile('.*{}.*'.format(re.escape(third_name)), re.IGNORECASE)
        return self.db_manager.find_many_with_paginate(self.collection_name, {'name': {'$regex': regex}}, {'_id': 0}, page, per_page)

    def find_by_name(self, third_name, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'name': third_name}, {'_id': 0}, page, per_page)

    def find_all_with_paginate(self, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {}, {'_id': 0}, page, per_page)
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})

    def delete_third_party(self, third_id):
        self.db_manager.delete_one(self.collection_name, {'third_id': third_id})
    
