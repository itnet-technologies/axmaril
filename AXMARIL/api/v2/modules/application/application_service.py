from .application_model import ApplicationModel
from .application_schema import ApplicationSchema
from ...utils.helpers import success_response, error_response, save_icon_file
from ...utils.custom_exception import ApplicationNotFoundException, InvalidDataException, DatabaseUpdateException
from werkzeug.utils import secure_filename
import os
from bson import ObjectId

class ApplicationService:
    def __init__(self):
        self.application_model = ApplicationModel()
        self.application_schema = ApplicationSchema()

    def create_application(self, data, app_icon):
        existing_application = self.application_model.find_by_name(data['app_name'])
        if existing_application['data']:
            raise ApplicationNotFoundException('An application with the same name already exists')

        if app_icon:
            filename = secure_filename(app_icon.filename)
            icon_dir = 'static/app_icons'
            new_filename = f"{str(ObjectId())}_{filename}"
            save_icon_file(icon_dir, app_icon, new_filename)
            icon_path = os.path.join(icon_dir, new_filename)
            data['app_icon_path'] = '/' + icon_path

        self.application_model.create_application(data)

    def update_application(self, app_id, data, app_icon):
        existing_application = self.application_model.find_by_id(app_id)
        if not existing_application:
            raise ApplicationNotFoundException('Application not found')

        if app_icon:
            icon_path = existing_application['app_icon_path'].lstrip('/')
            if os.path.exists(icon_path):
                os.remove(icon_path)

            filename = secure_filename(app_icon.filename)
            icon_dir = 'static/app_icons'
            new_filename = f"{str(ObjectId())}_{filename}"
            save_icon_file(icon_dir, app_icon, new_filename)

            icon_path = os.path.join(icon_dir, new_filename)
            app_icon.save(icon_path)
            data['app_icon_path'] = '/' + icon_path

        self.application_model.update_application(app_id, data)

    def find_application_by_id(self, app_id):
        existing_application = self.application_model.find_by_id(app_id)
        if not existing_application:
            raise ApplicationNotFoundException('Application not found')
        return existing_application
    
    def find_application_by_type(self, app_type):
        existing_application = self.application_model.find_by_type(app_type)
        if not existing_application:
            raise ApplicationNotFoundException('Application not found')
        return existing_application
    

    def find_application_system(self, app_type):
        existing_application = self.application_model.find_system(app_type)
        if not existing_application:
            raise ApplicationNotFoundException('Application not found')
        return existing_application
    
    def find_application_by_name(self, app_name, page, per_page):
        existing_application = self.application_model.find_by_name_with_paginate(app_name, page, per_page)
        return existing_application
    
    def find_all_applications(self, page, per_page):
        applications = self.application_model.find_all_with_paginate(page, per_page)
        return applications
    
    def delete_application(self, app_id):
        existing_application = self.application_model.find_by_id(app_id)
        if not existing_application:
            raise ApplicationNotFoundException('Application not found')            
        self.application_model.delete_application(app_id)
