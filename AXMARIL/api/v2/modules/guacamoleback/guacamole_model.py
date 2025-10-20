from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import json_util, ObjectId
import re

class GuacamoleModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'guacamole'
        self.user_collection = 'guacamole_users' 

    def create_guacamole(self, data):
        data['creation_date'] = datetime.utcnow()
        data['app_id'] = str(ObjectId())
        return self.db_manager.insert_one(self.collection_name, data)

    def update_guacamole(self, app_id, data):
        return self.db_manager.update_one(self.collection_name, {'app_id': app_id}, data)

    def find_by_id(self, app_id):
        return self.db_manager.find_one(self.collection_name, {'app_id': app_id}, {'_id': 0})
    
    def find_by_type(self, app_type):
        return self.db_manager.find_one(self.collection_name, {'app_type': app_type}, {'_id': 0})

    def find_by_name_with_paginate(self, app_name, page = 1, per_page = 10):
        regex = re.compile('.*{}.*'.format(re.escape(app_name)), re.IGNORECASE)
        return self.db_manager.find_many_with_paginate(self.collection_name, {'app_name': {'$regex': regex}}, {'_id': 0}, page, per_page)

    def find_by_name(self, app_name, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'app_name': app_name}, {'_id': 0}, page, per_page)

    def find_all_with_paginate(self, page = 1, per_page = 10):
        return self.db_manager.find_many_with_paginate(self.collection_name, {}, {'_id': 0}, page, per_page)
    
    def find_all(self):
        return self.db_manager.find_many(self.collection_name, {}, {'_id': 0})

    def delete_guacamole(self, app_id):
        self.db_manager.delete_one(self.collection_name, {'app_id': app_id})
    
    def find_user_by_username(self, username):
        """
        Cherche un utilisateur Guacamole par son nom d'utilisateur.
        Retourne True si trouvé, False sinon.
        """
        user = self.db_manager.find_one(self.user_collection, {'username': username}, {'_id': 0})
        return bool(user)

    def create_guacamole_user(self, user_data):
        """
        Enregistre un utilisateur Guacamole dans MongoDB après sa création via l'API
        """
        user_data['creation_date'] = datetime.utcnow()
        user_data['user_id'] = str(ObjectId())
        return self.db_manager.insert_one(self.user_collection, user_data)

    def find_user_by_email(self, email):
        """
        Cherche un utilisateur Guacamole par son email
        """
        return self.db_manager.find_one(self.user_collection, {'email': email}, {'_id': 0})

    def update_user(self, username, data):
        """
        Met à jour un utilisateur Guacamole
        """
        data['last_modified'] = datetime.utcnow()
        return self.db_manager.update_one(self.user_collection, {'username': username}, data)

    def get_user_by_username(self, username):
        """
        Récupère les données complètes d'un utilisateur
        """
        return self.db_manager.find_one(self.user_collection, {'username': username}, {'_id': 0})