from datetime import datetime
from api.v2.database.db_manager import DBManager
from bson import ObjectId


class GroupModel:
    def __init__(self):
        self.db_manager = DBManager()
        self.collection_name = 'groups'
    
    def create_group(self, data):
        data['group_id'] = str(ObjectId())
        self.db_manager.insert_one(self.collection_name, data)
        return data['group_id']

    def update_group(self, group_id, owner_uid, data):
        return self.db_manager.update_one(self.collection_name, {'group_id': group_id, 'owner_uid': owner_uid}, data)
    
    def update_member_from_group(self, group_id, data):
        for member in data["group_members"]:
            self.db_manager.update_one_and_save(self.collection_name, {'group_id': group_id}, {'group_members': member})
        return group_id
        
    def remove_member_from_group(self, group_id, member_uid):
        self.db_manager.update_one_and_remove(self.collection_name, {'group_id': group_id}, {'group_members': {'uid': member_uid}})

    def delete_group(self, uid, group_id):
        self.db_manager.delete_one(self.collection_name, {'owner_uid': uid, 'group_id': group_id})
    
    def find_group_by_id(self, group_id, owner_uid):
        return self.db_manager.find_one(self.collection_name, {'group_id': group_id, 'owner_uid': owner_uid})
    
    def find_member_by_uid(self, group_id, member_uid):
        return self.db_manager.find_one(self.collection_name, {'group_id': group_id, 'group_members.uid': member_uid}, {"group_members.$": 1})
    
    def find_group_by_name(self, group_name, owner_uid):
        return self.db_manager.find_one(self.collection_name, {'group_name': group_name, 'owner_uid': owner_uid})
    
    def find_all_groups(self, owner_uid, page, per_page):
        return self.db_manager.find_many_with_paginate(self.collection_name, {'owner_uid': owner_uid}, {'_id': 0}, page, per_page)
    
    def find_groups_with_names(self, owner_uid, group_names:list):
        return self.db_manager.find_many(self.collection_name, {'owner_uid': owner_uid, 'group_name': {'$in': group_names}})