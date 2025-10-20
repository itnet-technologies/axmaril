from pymongo import MongoClient

from modules.required_packages import config_data
import math

class DBManager:
    def __init__(self, database_name='your_database'):
        self.client = None
        self.db = None
        self.database_name = database_name
        self.connect_to_database()

    def connect_to_database(self):
        self.client = MongoClient(host=config_data['DATABASE_HOST'], port=int(config_data['DATABASE_PORT']))
        self.db = self.client[config_data['DATABASE_NAME']]

    def insert_one(self, collection_name, document):
        collection = self.db[collection_name]
        return collection.insert_one(document)
    
    def insert_many(self, collection_name, document):
        collection = self.db[collection_name]
        return collection.insert_many(document, ordered=False)

    def find_one(self, collection_name, query, except_filters = {'_id': 0}):
        collection = self.db[collection_name]
        return collection.find_one(query, except_filters)

    def find_many(self, collection_name, query, except_filters = {'_id': 0}):
        collection = self.db[collection_name]
        return list(collection.find(query, except_filters))

    def update_one(self, collection_name, query, update):
        collection = self.db[collection_name]
        return collection.update_one(query, {'$set': update})
    
    def update_one_and_create(self, collection_name, query, update):
        collection = self.db[collection_name]
        return collection.update_one(query, {"$addToSet": update}, upsert=True)
    
    def update_one_and_save(self, collection_name, query, update):
        collection = self.db[collection_name]
        return collection.update_one(query, {"$addToSet": update})
    
    def update_one_and_remove(self, collection_name, query, update):
        collection = self.db[collection_name]
        return collection.update_one(query, {"$pull": update})
    
    def update_many_and_remove(self, collection_name, query, update):
        collection = self.db[collection_name]
        return collection.update_many(query, {"$pull": update})
    
    def update_other(self, collection_name, query, update, other_change):
        collection = self.db[collection_name]
        return collection.update_one(query, {'$push': other_change, '$set': update})

    def delete_one(self, collection_name, query):
        collection = self.db[collection_name]
        return collection.delete_one(query)
    
    def delete_many(self, collection_name, query):
        collection = self.db[collection_name]
        return collection.delete_many(query)

    def count_documents(self, collection_name, query):
        collection = self.db[collection_name]
        return collection.count_documents(query)

    def find_many_with_paginate(self, collection_name, query, except_filters = {'_id': 0}, page = 1, per_page = 10):

        collection = self.db[collection_name]

        skip_count = (page - 1) * per_page

        total_found = collection.count_documents(query)

        last_page = math.ceil(total_found / per_page)

        result = collection.find(query, except_filters).skip(skip_count).limit(per_page)

        to_return = {
            "data": list(result),
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "total": total_found
        }

        return to_return
