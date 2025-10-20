from .group_model import GroupModel
from .group_schema import GroupSchema, GroupSchemaUpdate
from datetime import datetime
from ...utils.helpers import check_user, mail_sender
from threading import Thread

from ...utils.custom_exception import NotFoundException, UserAlreadyExist, NameAlreadyExist

class GroupService:
    def __init__(self):
        self.group_model = GroupModel()
        self.group_schema = GroupSchema()
        self.group_schema_update = GroupSchemaUpdate()
    
    def create_group_member(self, data):
        owner_uid = data["owner_uid"]
        group_name =  data["group_name"]
        group_members = data["group_members"]
        print(group_members)
        
        data["created_at"] = datetime.now()
        
        existing_group = self.group_model.find_group_by_name(group_name, owner_uid)
        if existing_group:
            raise NameAlreadyExist("Sorry. The name of your group is already exist. Please change it.")
        
        members = []
        for member in group_members:
            
            response, found_member = check_user(email=member, uid=member)
            member_info = {"uid": found_member["uid"], "email": found_member["email"]}
            members.append(member_info)
                # mail = found_member["email"]
                # objet = "Azumaril Groupe"
                # message = f"Vous avez été ajouté au groupe '{group_name}' sur AZUMARIL. Veuillez vous connnecter pour plus de détails."
                # Thread(
                #     target=mail_sender,
                #     args=(mail, objet, message,),
                # ).start()
        
        data["group_members"] = members
        return self.group_model.create_group(data)
    
    def add_group_member(self, group_id, owner_uid, data):
        group_members = data["group_members"]
        
        owner_group = self.group_model.find_group_by_id(group_id, owner_uid)
        if owner_group is None:
            raise NotFoundException("group not found")
        
        members = []
        for member in group_members:
            response, exist_user = check_user(email=member, uid=member)
            
            found_member = self.group_model.find_member_by_uid(group_id, exist_user["uid"])
            if found_member is not None:
                raise UserAlreadyExist(f'the member(s) {[found_member["group_members"][0]["email"]]} is part of the group')
            else:
                member_info = {"uid": exist_user["uid"], "email": exist_user["email"]}
                members.append(member_info)
                # mail = found_member["group_members"][0]["email"]
                # objet = "Azumaril Groupe"
                # message = f"Vous avez été ajouté au groupe '{owner_group["group_name"]}' sur AZUMARIL. Veuillez vous connnecter pour plus de détails."
                # Thread(
                #     target=mail_sender,
                #     args=(mail, objet, message,),
                # ).start()
        
        data["group_members"] = members
        self.group_model.update_member_from_group(group_id, data)
        
    
    def remove_group_member(self, group_id, owner_uid, member_uid):
        owner_group = self.group_model.find_group_by_id(group_id, owner_uid)
        if owner_group is None:
            raise NotFoundException("group not found")
        
        member = self.group_model.find_member_by_uid(group_id, member_uid)
        print(member)
        if member is None:
            raise NotFoundException("this member is not part of the group")
        
        self.group_model.remove_member_from_group(group_id, member_uid)
        
        # mail = member["group_members"][0]["email"]
        # objet = "Azumaril Groupe"
        # message = f"Vous avez été retiré du groupe '{owner_group["group_name"]}' sur AZUMARIL. Veuillez vous connnecter pour plus de détails."
        # Thread(
        #     target=mail_sender,
        #     args=(mail, objet, message,),
        # ).start()
    
    def update_group_data(self, group_id, owner_uid, data):
        owner_group = self.group_model.find_group_by_id(group_id, owner_uid)
        if owner_group is None:
            raise NotFoundException("group not found")
        
        checK_existing_name = self.group_model.find_group_by_name(data["group_name"], owner_uid)
        if checK_existing_name:
            raise NameAlreadyExist("Group name already exist in your group list. Please change it")
        
        self.group_model.update_group(group_id, owner_uid, data)
    
    def find_group_detail(self, owner_uid, group_id):
        found_group = self.group_model.find_group_by_id(group_id, owner_uid)
        if found_group is None:
            raise NotFoundException("Sorry, your group not found.")
        return found_group
    
    def find_group_list(self, owner_uid, page, per_page):
        groups = self.group_model.find_all_groups(owner_uid, page, per_page)
        # print(groups)
        for group in groups["data"]: group.pop("group_members", None)
        return groups
