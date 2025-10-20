from .third_party_model import ThirdPartyModel
from .third_party_schema import ThirdPartySchema
from ...utils.helpers import success_response, error_response, save_icon_file
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, InvalidDataException, DatabaseUpdateException
from werkzeug.utils import secure_filename
import os
from bson import ObjectId

class ThirdPartyService:
    def __init__(self):
        self.third_party_model = ThirdPartyModel()
        self.third_party_schema = ThirdPartySchema()

    def create_third_party(self, data):
        existing_third = self.third_party_model.find_by_name(data['name'])
        print(existing_third)
        if existing_third['data']:
            raise NameAlreadyExist('An third pary with the same name already exists')

        self.third_party_model.create_third_party(data)

    def update_third_party(self, third_id, data):
        existing_third = self.third_party_model.find_by_id(third_id)
        if not existing_third:
            raise NotFoundException('Third party not found')

        self.third_party_model.update_third_party(third_id, data)

    def find_third_party_by_id(self, third_id):
        existing_third = self.third_party_model.find_by_id(third_id)
        if not existing_third:
            raise NotFoundException('Third party not found')
        return existing_third
    
    def find_third_party_by_name(self, third_name, page, per_page):
        existing_third = self.third_party_model.find_by_name_with_paginate(third_name, page, per_page)
        return existing_third
    
    def find_all_third_parties(self, page, per_page):
        third_app = self.third_party_model.find_all_with_paginate(page, per_page)
        return third_app
    
    def delete_third_party(self, third_id):
        existing_third = self.third_party_model.find_by_id(third_id)
        if not existing_third:
            raise NotFoundException('Third party not found')          
        self.third_party_model.delete_third_party(third_id)

    def get_third_party_fields_by_id(self, third_id):
        existing_third = self.third_party_model.find_by_id(third_id)
        if not existing_third:
            raise NotFoundException('Third party not found')
        return existing_third['fields']