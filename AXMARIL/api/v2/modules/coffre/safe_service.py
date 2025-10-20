import traceback
from .safe_model import CoffreModel
from ..secret.secret_model import SecretModel
from ..secret.secret_schema import SecretSchema

from .safe_schema import CoffreSchema
from ...utils.helpers import url_for, error_response, save_icon_file, cd_secret_collection, datetime, math
from ...utils.custom_exception import *
from werkzeug.utils import secure_filename
import os
from bson import ObjectId

class CoffreService:
    def __init__(self):
        self.safe_model = CoffreModel()
        self.secret_model = SecretModel()
        self.safe_schema = CoffreSchema()
        self.secret_schema = SecretSchema()
        
    def create_safe(self, uid, data):
        existing_safe = self.safe_model.find_by_name(uid, data['name'])
        if existing_safe:
            raise NameAlreadyExist('An safe with the same name already exists')
        data['owner_uid'] = uid
        if 'created_by' not in data:
            data['created_by'] = 'user'
        if 'from' not in data:
            data['from'] = 'azumarill'

        return self.safe_model.create_safe(data)
    
    def v1v2(self):
        pass
    
    def safe_secret(self, args, owner_uid):
        params = args
        safe_id = params.get('safe_id', None)
        if not safe_id:
            raise KeyMissing("key safe_id not provided")
        # per_page is the number of elements per page
        per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        skip_count = (page - 1) * per_page

        safe_retrieve = self.safe_model.find_by_id(safe_id, owner_uid)
        if not safe_retrieve:
            raise NotFoundException("safe not found")
        safe_type = safe_retrieve.get("type", None)
        
        if safe_type is not None and safe_type == "system":
            self.refresh_azumaril_system_safe()

        user_safe_secrets = self.secret_model.find_secret_by_safe(safe_id, owner_uid).skip(skip_count).limit(per_page)

        total_user_secrets = self.secret_model.count({"safe_id" : safe_id, "owner_uid": owner_uid})

        last_page = math.ceil(total_user_secrets / per_page)

        # Générer l'URL de la première page
        first_page_url = url_for('secret.safe_secrets', page=1, _external=True)

        # Générer l'URL de la dernière page
        last_page_url = url_for('secret.safe_secrets', page=last_page, _external=True)  if last_page >= 1 else None

        # Générer l'URL de la page suivante (si disponible)
        next_page_url = url_for('secret.safe_secrets', page=page + 1, _external=True) if page < last_page else None

        # Générer l'URL de la page précédente (si disponible)
        prev_page_url = url_for('secret.safe_secrets', page=page - 1, _external=True) if page > 1 else None


        # list_of_secrets = []
        data = {
            "data": [],
            "per_page": per_page,
            "current_page": page,
            "last_page": last_page,
            "first_page_url": first_page_url,
            "last_page_url": last_page_url,
            "next_page_url": next_page_url,
            "prev_page_url": prev_page_url,
            "total": total_user_secrets
        }
        for secret in user_safe_secrets:
            if type(secret["date"]) == type(datetime.strptime("2022-10-1", '%Y-%m-%d')):
                secret["date"] = secret["date"].strftime('%Y-%m-%d')
            else:
                timestamp = secret["date"]["$date"] / 1000
                date_object = datetime.fromtimestamp(timestamp)
                year = date_object.year
                month = date_object.month
                day = date_object.day
                secret["date"] = f"{year}-{month}-{day}"
            data['data'].append(secret)
        return data

    def safe_secret_content(self, safe_id, owner_uid, start, end):
        # params = args
        # per_page is the number of elements per page
        # per_page = int(params.get('per_page', 10))
        # page is the number of page where you want to get
        # page = int(params.get('page', 1))
        # skip count for know how element we must skip based on per_page and page
        # skip_count = (page - 1) * per_page

        safe_retrieve = self.safe_model.find_by_id(owner_uid, safe_id)
        if not safe_retrieve:
            raise NotFoundException("safe not found")
        safe_type = safe_retrieve.get("type", None)
        
        if safe_type is not None and safe_type == "system":
            self.refresh_azumaril_system_safe()

        user_safe_secrets = self.secret_model.find_all_with_parameters({"safe_id": safe_id, "owner_uid": owner_uid}, start, end)

        # total_user_secrets = self.secret_model.count({"safe_id" : safe_id, "owner_uid": owner_uid})

        #last_page = math.ceil(total_user_secrets / per_page)

        # list_of_secrets = []
        data = {
            "data": []
        }
        
        for secret in user_safe_secrets:
            try:
                if type(secret["date"]) == type(datetime.strptime("2022-10-1", '%Y-%m-%d')):
                    secret["date"] = secret["date"].strftime('%Y-%m-%d')
                else:
                    timestamp = secret["date"]["$date"] / 1000
                    date_object = datetime.fromtimestamp(timestamp)
                    year = date_object.year
                    month = date_object.month
                    day = date_object.day
                    secret["date"] = f"{year}-{month}-{day}"
            except:
                print(traceback.format_exc())
            data['data'].append(secret)
        return data
    
    def refresh_azumaril_system_safe(self):
        fsafe = self.safe_model.find_one_with_parameters({"owner_uid": "0000000", "name": "SYSTEM", "type": "system"})
        self.secret_model.delete_secrets({"safe_id": fsafe["safe_id"], "deletable": False})
        system_secrets = list(cd_secret_collection.find({}))
        for ss in system_secrets:
            del ss["_id"]
            secret_infos = {
                "owner_uid": "0000000",
                "secret_id": ss["id"],
                "name": ss["name"],
                "secret_name": ss["name"],
                "secret": ss["secret"],
                "date": datetime.now(),
                "secret_type": "credentials",
                "deletable": False,
                "safe_id": fsafe["safe_id"],
                "app_type": "azumaril",
                "file_path": None,
                "file_name": None,
                "file_type": None,
            }
            errors = self.secret_schema.validate(secret_infos)
            if errors:
                return error_response(error=errors)
            self.secret_model.create_secret(secret_infos, None)


    def update_safe(self, uid, safe_id, data):
        existing_safe = self.safe_model.find_by_id(uid, safe_id)
        if not existing_safe:
            raise NotFoundException('Safe not found')
        if existing_safe['created_by'] == 'system':
            raise InsufficientRight('Insufficient right to delete safe created by system')
        self.safe_model.update_safe(uid, safe_id, data)

    def find_safe_by_id(self, uid, safe_id):
        existing_safe = self.safe_model.find_by_id(uid, safe_id)
        if not existing_safe:
            raise NotFoundException('Safe not found')
        return existing_safe
    
    def find_safe_by_name(self, uid, safe_name):
        existing_safe = self.safe_model.find_by_name(uid, safe_name)
        if not existing_safe:
            raise NotFoundException('Safe not found')
        return existing_safe
    
    def find_all_safe(self, uid, start, end):
        safe = self.safe_model.find_all_safe_with_paginate(uid, start, end)
        return safe
    
    def delete_safe(self, uid, safe_id):
        existing_safe = self.safe_model.find_by_id(uid, safe_id)
        if not existing_safe:
            raise NotFoundException('Safe not found')
        if existing_safe['created_by'] == 'system':
            raise InsufficientRight('Insufficient right to delete safe created by system')         
        self.safe_model.delete_safe(uid, safe_id)

    def find_safe_with_parameters(self, data):
        return self.safe_model.find_one_with_parameters(data)
