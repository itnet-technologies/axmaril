from .third_party_account_model import ThirdPartyAccountModel
from .third_party_account_schema import ThirdPartyAccountSchema, CyberArkSafes, CyberArkSecrets
from ..third_party.third_party_service import ThirdPartyService
from ..coffre.safe_service import CoffreService
from ..secret.secret_service import SecretService
from ...utils.helpers import success_response, error_response, save_icon_file, check_keys_and_null_values
from ...utils.custom_exception import NameAlreadyExist, NotFoundException, CustomException, KeyMissing, ThirdPartyAccountNotExist, InsufficientRight
from werkzeug.utils import secure_filename
import os
from bson import ObjectId
from datetime import datetime
from .cyberark.index import CyberArk


def create_instance(name, data):
    instances = {
        'cyberark': CyberArk(data)
        # Ajoutez d'autres classes avec leurs noms correspondants ici
    }
    return instances.get(name.lower(), None)()

class ThirdPartyAccountService:
    def __init__(self):
        self.third_party_account_model = ThirdPartyAccountModel()
        self.third_party_service = ThirdPartyService()
        self.third_party_account_schema = ThirdPartyAccountSchema()
        self.safe_service = CoffreService()
        self.secret_service = SecretService()

    def _initialize_instance(self, uid, account_id):
        existing_third = self.third_party_account_model.find_by_id(uid, account_id)
        if not existing_third:
            raise NotFoundException('Third party account not found')

        third_party_infos = self.third_party_service.find_third_party_by_id(existing_third['third_party'])
        secret_id = existing_third.get('secret_id')
        third_party_name = third_party_infos.get('name', None)
        Instance = None
        secret_reveal = self.secret_service.reveal_secret(uid, secret_id)
        if third_party_name == 'cyberark':
            Instance = CyberArk(secret_reveal)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)
        return Instance

    def create_third_party_account(self, uid, data):
        third_party = self.third_party_service.find_third_party_by_id(data['third_party_id'])
        check_fields = check_keys_and_null_values(third_party['fields'], data['fields'])
        if not check_fields[0]:
            raise KeyMissing(f"Missing key or null values sent: {(', ').join(check_fields[1])}")
        
        if 'name' in data:
            existing_account = self.third_party_account_model.find_one_by_name(data['name'])
            if existing_account:
                raise NameAlreadyExist('Account with the same name exist')
                
        if 'name' not in data:
            date = datetime.utcnow()
            data['name'] = f"{third_party['name']}_{uid}_{str(date.strftime('%d-%m-%H-%M-%S'))}"
        safe = None

        try:
            safe = self.safe_service.find_safe_by_name(uid, 'third_party_accounts')
        except NotFoundException:
            self.safe_service.create_safe(uid, {'name': 'third_party_accounts', 'created_by': 'system'})
            safe = self.safe_service.find_safe_by_name(uid, 'third_party_accounts')

        secret_data = {
            "secret_name": data['name'],
            "name": data['name'],
            "secret": data['fields'],
            "safe_id": safe[0]['safe_id'],
            "owner_uid": uid,
            "secret_type": "other"
        }
        secret_id = self.secret_service.create_secret(secret_data, None)
        # secret_reveal = self.secret_service.reveal_secret(uid, secret_id)
        
        account_data = {
            'name': data['name'],
            'secret_id': secret_id,
            'third_party': data['third_party_id'],
            'owner_uid': uid
        }
        return self.third_party_account_model.create_third_party_account(account_data)

    def update_third_party_account(self, uid, data):
    
        last_third_party_accounts_data =  self.third_party_account_model.find_by_id(uid, data['account_id'])
        if not last_third_party_accounts_data: 
            raise NotFoundException(f"Third Party Account Not Found")

        third_party = self.third_party_service.find_third_party_by_id(last_third_party_accounts_data['third_party'])
        check_fields = check_keys_and_null_values(third_party['fields'], data['fields'])
        if not check_fields[0]:
            raise KeyMissing(f"Missing key or null values sent: {(', ').join(check_fields[1])}")

        if 'name' not in data or data['name'] == "":
            date = datetime.utcnow()
            data['name'] = f"{third_party['name']}_{uid}_{str(date.strftime('%d-%m-%H-%M-%S'))}"
        
        safe = self.safe_service.find_safe_by_name(uid, 'third_party_accounts')

        secret_data = {
            "secret_name": data['name'],
            "name": data['name'],
            "secret": data['fields'],
            "safe_id": safe[0]['safe_id'],
            "owner_uid": uid,
            "secret_type": "other"
        }
        #self.secret_service.delete_secret(uid, last_third_party_accounts_data['secret_id'])
        secret_id = self.secret_service.create_secret(secret_data, None)

        account_data = {
            'name': data['name'],
            'secret_id': secret_id,
            'third_party': last_third_party_accounts_data['third_party'],
            'owner_uid': uid
        }
        return self.third_party_account_model.update_third_party(data['account_id'], account_data)

    def find_all_third_party_account(self, uid):
        safe_content = self.third_party_account_model.find_all_third_party_account(uid)
        return safe_content

    def find_third_party_account_by_id(self, uid, account_id):
        the_third_party = self.third_party_account_model.find_by_id(uid, account_id)
        return the_third_party

    def delete_third_party_account_by_id(self, uid, account_id):
        the_third_party = self.third_party_account_model.find_by_id(uid, account_id)
        if not the_third_party:
            raise ThirdPartyAccountNotExist(f"Third Party Account that you want to delete Not Found")
        the_third_party = self.third_party_account_model.delete_third_party(uid, account_id)
        return the_third_party

    def check_connexion_status(self, uid, account_id):
        Instance = self._initialize_instance(uid, account_id)
        response_data = {
            'status': False,
            'error': None
        }
        response_data['status'], response_data['error'] = Instance.connect()
        return response_data

    def get_all_safe_in_cyberark_account(self, uid, account_id) -> list:
        Instance = self._initialize_instance(uid, account_id)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)
        status, response_or_errormsg = Instance.get_safes()
        Instance.disconnect()
        if not status:
            raise CustomException(response_or_errormsg)
        safes_schema = CyberArkSafes(many=True)
        return safes_schema.dump(response_or_errormsg['value'])

    def get_all_secrets_of_safe_in_cyberark_account(self, uid, account_id, safe_id):
        Instance = self._initialize_instance(uid, account_id)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)
        status, response_or_errormsg = Instance.get_safe_by_id(safe_id)
        Instance.disconnect()
        if not status:
            raise CustomException(response_or_errormsg)
        secret_schema = CyberArkSecrets()
        return secret_schema.dump(response_or_errormsg)

    def read_secret_in_cyberark_account(self, uid, account_id, secret_id):
        Instance = self._initialize_instance(uid, account_id)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)
        response = Instance.get_secret_by_id(secret_id)
        Instance.disconnect()
        return response

    def import_safe_from_cyberark(self, uid, data):
        account_id = data.get('account_id')
        cyberark_safe_id = data.get('cyberark_safe_id')
        safe_id = data.get('safe_id', None)
        safe_name = data.get('safe_name', None)
        account_id = data.get('account_id')

        Instance = self._initialize_instance(uid, account_id)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)

        status, response_or_errormsg = Instance.get_safe_by_id(cyberark_safe_id)
        if not status:
            raise CustomException(response_or_errormsg)

        existing_safe_data = self.safe_service.find_safe_with_parameters({'owner_uid': uid, 'cyberark_safe_id': cyberark_safe_id})
        if existing_safe_data:
            if 'from' in existing_safe_data and existing_safe_data['from'] == 'cyberark' and cyberark_safe_id == existing_safe_data['cyberark_safe_id']:
                raise CustomException('This safe is already exist in azumarill. Please use sync to update your data')
        
        if safe_id:
            safe_data = self.safe_service.find_safe_by_id(uid, safe_id)
        else:
            if not safe_name:
                safe_name = response_or_errormsg['safeName']
            safe_id = self.safe_service.create_safe(uid, {
                'name': safe_name,
                'created_by': 'user',
                'from': str(Instance),
                'cyberark_safe_id': cyberark_safe_id
            })

        all_secrets = response_or_errormsg['accounts']

        for secret in all_secrets:
            status, secret_data = Instance.get_secret_by_id(secret['id'])
            if status:
                to_insert = {
                    "secret_name": secret['name'],
                    "name": secret['name'],
                    "secret": secret_data,
                    "safe_id": safe_id,
                    "owner_uid": uid,
                    "secret_type": "other",
                    'from': str(Instance),
                    f'{str(Instance)}_id': secret['id']
                }
                try:
                    self.secret_service.create_secret(to_insert, None)
                except Exception as e:
                    print(str(e))
                    pass
        return safe_id
    
    def import_secret_from_cyberark_into_azumarill(self, uid, data):
        
        account_id = data.get('account_id')
        cyberark_secret_id = data.get('cyberark_secret_id')
        safe_id = data.get('safe_id', None)
        new_secret_name = data.get('new_secret_name', None)

        Instance = self._initialize_instance(uid, account_id)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)
        
        found_safe = self.safe_service.find_safe_by_id(uid, safe_id)
        if found_safe['owner_uid'] == '0000000':
            raise InsufficientRight('Insufficient right to use this safe created by system')

        status, response_or_errormsg = Instance.get_secret_by_id(cyberark_secret_id)
        if not status:
            raise CustomException(response_or_errormsg)

        final_secret_name = new_secret_name if new_secret_name is not None else response_or_errormsg['name']

        to_insert = {
            "secret_name": final_secret_name,
            "name": final_secret_name,
            "secret": response_or_errormsg,
            "safe_id": safe_id,
            "owner_uid": uid,
            "secret_type": "other",
            'from': str(Instance),
            f'{str(Instance)}_id': cyberark_secret_id
        }
        c_secret_id = self.secret_service.create_secret(to_insert, None)
        
        return c_secret_id

    def sync_azumarill_to_cyberark(self, uid, data):
        account_id = data.get('account_id')
        safe_id = data.get('safe_id')
        force = data.get('force')

        Instance = self._initialize_instance(uid, account_id)

        status, error = Instance.connect()
        if not status:
            raise CustomException(error)

        found_safe = self.safe_service.find_safe_by_id(uid, safe_id)
        if found_safe['from'] != str(Instance):
            raise CustomException('Cannot sync data from different source')

        cyberark_safe_id = found_safe['cyberark_safe_id']

        status, response_or_errormsg = Instance.get_safe_by_id(cyberark_safe_id)
        if not status:
            raise CustomException(response_or_errormsg)

        all_secrets_in_cyberark = response_or_errormsg['accounts']
        all_secrets_in_azumarill = self.secret_service.get_all_secrets_by_safe_id(uid, safe_id)
        # return {'cyberark': all_secrets_in_cyberark, 'azumarill': all_secrets_in_azumarill}

        if force == True:
            for secret in all_secrets_in_azumarill:
                self.secret_service.delete_secret(uid, secret['secret_id'])

            for secret in all_secrets_in_cyberark:
                status, secret_data = Instance.get_secret_by_id(secret['id'])
                if status:
                    to_insert = {
                        "secret_name": secret['name'],
                        "name": secret['name'],
                        "secret": secret_data,
                        "safe_id": safe_id,
                        "owner_uid": uid,
                        "secret_type": "other",
                        'from': str(Instance),
                        'cyberark_id': secret['id']
                    }
                    try:
                        self.secret_service.create_secret(to_insert, None)
                    except Exception as e:
                        print(str(e))
                        pass
        else:
            for secret in all_secrets_in_azumarill:
                if 'cyberark_id' in secret:
                    status, secret_data = Instance.get_secret_by_id(secret['cyberark_id'])
                    if status:
                        to_insert = {
                            "secret_name": secret['secret_name'],
                            "name": secret['secret_name'],
                            "secret": secret_data,
                            "safe_id": safe_id,
                            "owner_uid": uid,
                            "secret_type": "other",
                            'from': str(Instance),
                            'cyberark_id': secret_data['id']
                        }
                        try:
                            self.secret_service.delete_secret(uid, secret['secret_id'])
                            self.secret_service.create_secret(to_insert, None)
                        except Exception as e:
                            print(str(e))
                            pass