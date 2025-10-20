import os
from .required_packages import google_connexion, oidc_authorization_links, oidc_apps, generate_authorization_code, oidc_authorization_tokens, users, oidc_authorization_codes
from .required_packages import error_response, success_response, ObjectId, jwt
from .required_packages import addNewUser, connectUser, config_data, decode_auth_token
from datetime import datetime, timedelta
import shortuuid
from urllib.parse import urlencode
import traceback
import requests
import base64
import json

from flask import redirect
import secrets as sec
import string
from authlib.integrations.requests_client import OAuth2Session
import google.oauth2.credentials
import googleapiclient.discovery
from google.oauth2.credentials import Credentials
import tldextract
import validators



def validate(value, mustBe, string=False):
    if not string:
        if isinstance(value, list):
            return any(element in mustBe for element in value)
        else:
            return value in mustBe
    else:
        return value == mustBe

def validate_domain_name(domain, dev = False):
    extracted_info = tldextract.extract(domain)
    if dev == False:
        return bool(extracted_info.domain) and bool(extracted_info.suffix)
    else:
        return bool(extracted_info.domain)


def validate_url(url):
    return validators.url(url)
    
# def validate_domain(domain):
#     import re
#     # # regex = r'^(https?://)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
#     # with_sous_domaine = r'^(https?://)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(:\d+)?$'
#     # # regex = r'^(https?://)([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})?(:\d+)?$'
#     # return re.match(with_sous_domaine, domain) is not None
#     regex = r"((http|https)://)?[a-zA-Z0-9@:%._\+~#?&//=]+(\.[a-z]{2,6})?([-a-zA-Z0-9@:%._\+~#?&//=]*)"

#     p = re.compile(regex)

#     if domain is None:
#         return False

#     if re.search(p, domain):
#         return True
#     else:
#         return False

def encode_email(email):
    import base64
    encoded_email = base64.b64encode(email.encode('utf-8')).decode('utf-8')
    return encoded_email

def encode_dict_to_base64(dictionary):
    json_string = json.dumps(dictionary)
    json_bytes = json_string.encode('utf-8')
    base64_bytes = base64.b64encode(json_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string


class OAuth2:
    def __init__(self):
        self.CLIENT_ID = config_data["OIDC_CLIENT_ID"]
        self.CLIENT_SECRET = config_data["OIDC_CLIENT_SECRET"]
        self.ACCESS_TOKEN_URI = config_data["OIDC_ACCESS_TOKEN_URI"]
        self.AUTHORIZATION_URL = config_data["OIDC_AUTHORIZATION_URL"]
        self.AUTHORIZATION_SCOPE = config_data["OIDC_AUTHORIZATION_SCOPE"]
        self.REDIRECT_URL = config_data["OIDC_REDIRECT_URL_DEV"]
        self.FRONTEND_URL = config_data["OIDC_FRONTEND_URL"]
        self.parameters = {'status': "failed",'source': 'google','user_infos': {}}
        return

    def authorize(self):
        session = OAuth2Session(self.CLIENT_ID, self.CLIENT_SECRET,
                            scope=self.AUTHORIZATION_SCOPE,
                            redirect_uri=self.REDIRECT_URL)
        uri, state = session.create_authorization_url(self.AUTHORIZATION_URL)

        return success_response(data={
            "redirect_url": uri,
            "state": state
        })

    def build_credentials(self, oauth2_tokens):
        return google.oauth2.credentials.Credentials(
                    oauth2_tokens['access_token'],
                    refresh_token=oauth2_tokens['refresh_token'],
                    client_id=self.CLIENT_ID,
                    client_secret=self.CLIENT_SECRET,
                    token_uri=self.ACCESS_TOKEN_URI)

    def get_user_info_oauth2(self, oauth2_tokens):
        credentials = self.build_credentials(oauth2_tokens)

        oauth2_client = googleapiclient.discovery.build(
                            'oauth2', 'v2',
                            credentials=credentials)
        return oauth2_client.userinfo().get().execute()


    def redirect_with_params(self):
        query_params = '&'.join([f'{key}={value}' for key, value in self.parameters.items()])
        frontend_url = self.FRONTEND_URL + '?' + query_params
        return redirect(frontend_url)


    def callback(self, args, request_url):
        req_state = args["state"]
        req_code = args["code"]
        req_scope = args["scope"]

        if req_state is None:
            return self.redirect_with_params()

        session = OAuth2Session(self.CLIENT_ID, self.CLIENT_SECRET,
                                scope=req_scope,
                                state=req_state,
                                redirect_uri=self.REDIRECT_URL)

        oauth2_tokens = session.fetch_access_token(
                            self.ACCESS_TOKEN_URI,
                            authorization_response=request_url)
        user_info = self.get_user_info_oauth2(oauth2_tokens)

        fuser = users.find_one({"email" : user_info["email"]}, {"_id" : 0})
        if fuser:
            connect_user, status_code = google_connexion(fuser)
            self.parameters['user_infos'] = encode_dict_to_base64(connect_user.json)
            self.parameters['status'] = "success"
        else:
            user = {
                "firstname": user_info.get('family_name', 'None'),
                "lastname": user_info.get('given_name', 'None'),
                "email": user_info.get('email'),
                "password": str(encode_email(user_info.get('email'))),
            }
            try:
                add_new_user_response = addNewUser(user, from_google=True)
                if add_new_user_response.status_code == 200:
                    fuser = users.find_one({"email" : user_info.get('email')}, {"_id" : 0})
                    connect_user, status_code = google_connexion(fuser)
                    self.parameters['user_infos'] = encode_dict_to_base64(connect_user.json)
                    self.parameters['status'] = "success"
            except:
                pass
        return self.redirect_with_params()


class OIDCProvider:
    def __init__(self):
        self.oidc_authorization_links = oidc_authorization_links
        self.oidc_apps = oidc_apps
        self.oidc_authorization_tokens = oidc_authorization_tokens
        self.oidc_authorization_codes = oidc_authorization_codes
        self.authorization_endpoint = config_data["OIDC_OPENID_AUTHORIZATION_ENDPOINT"]
        self.salt = config_data["TOKEN_SECRET_SALT"]

    def register_client(self, request_data):
        try:
            exist_app = self.oidc_apps.find_one({"name": request_data['name']})
            if exist_app:
                return error_response(message="This name is not available !")
            encryptKey = str(datetime.now()) + "axmaril"
            client_id = shortuuid.uuid(name=encryptKey)
            client_secret = sec.token_hex(32)

            callback_urls = request_data['callback_url']
            homepage_url = request_data['homepage_url']
            authorized_domains = request_data['authorized_domains']
            dev = request_data ["dev"]

            #Validation for callback urls
            for url in callback_urls:
                if not validate_url(url):
                    return error_response(message="Bad request. Please check your callback urls", errors=str(url))

            #Validation for homepage url
            if not validate_url(homepage_url):
                return error_response(message="Bad request. Please check your homepage url")

            #Validation for authorized domain
            for authorized_url in authorized_domains:
                if not validate_domain_name(authorized_url, dev):
                    return error_response(message="Bad request. Please check your authorized_domains urls. ex: google.com, name.extension", errors=str(authorized_url))

            new_app = {
                "app_id": str(ObjectId()),
                "name": request_data['name'],
                "description": request_data['description'],
                "homepage_url": homepage_url,
                "callback_url": callback_urls,
                "developer_contact_information": request_data['developer_contact_information'],
                "authorized_domains": authorized_domains,
                "client_id": client_id,
                "client_secret": client_secret,
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "dev": dev
            }
            response_data = {key: value for key, value in new_app.items() if key not in ['created_at', 'updated_at']}
            self.oidc_apps.insert_one(new_app)
            return success_response(
                    data=response_data,
                    message="application created with success",
                    code=201
                )
        except KeyError as error:
            key = error.args[0]  # Récupérer la clé à partir des arguments de l'exception
            return error_response(message= "Something went wrong",  errors=f"KeyError occurred for key {key}", code=500)
        except Exception as error:
            print(traceback.format_exc())
            return error_response(message="Something went wrong", code=500, errors=str(error))

    def update_client(self, request_data, app_id):
        try:
            exist_app = self.oidc_apps.find_one({"app_id": app_id})
            if not exist_app:
                return error_response(message="Application not found !", code=404)
            update_data = {}
            allowed_fields = [
                'name',
                'description',
                'homepage_url',
                'callback_url',
                'developer_contact_information',
                'authorized_domains',
                'dev'
            ]
            dev = False
            if "dev" in request_data:
                
                dev = request_data["dev"]
            #Validation for homepage url
            if "homepage_url" in request_data:
                if not validate_url(request_data["homepage_url"]):
                    return error_response(message="Bad request. Please check your homepage url")
    
            if "callback_url" in request_data:
                for url in request_data["callback_url"]:
                    if not validate_url(url):
                        return error_response(message="Bad request. Please check your callback urls", errors=str(url))


            #Validation for authorized domain
            if "authorized_domains" in request_data:
                for authorized_url in request_data["authorized_domains"]:
                    if not validate_domain_name(authorized_url, dev):
                        return error_response(message="Bad request. Please check your authorized_domains urls. ex: google.com, name.extension. If dev is false, local url will not work", errors=str(authorized_url))

            for field in allowed_fields:
                if field in request_data:
                    update_data[field] = request_data[field]

            # Ajouter le champ 'updated_at'
            update_data['updated_at'] = datetime.now()

            # Mettre à jour l'application existante avec les champs de update_data
            self.oidc_apps.update_one({"app_id": app_id}, {"$set": update_data})
            return success_response(
                data=update_data, message="Information updated with success")

        except KeyError as error:
            key = error.args[0]  # Récupérer la clé à partir des arguments de l'exception
            return error_response(message= "Something went wrong",  errors=f"KeyError occurred for key {key}")
        except Exception as error:
            return error_response(message="Something went wrong", code=500, errors=str(error))

    def delete_client(self, app_id):
        try:
            exist_app = self.oidc_apps.find_one({"app_id": app_id})

            if not exist_app:
                return error_response(message="Application not found !", code=404)

            self.oidc_apps.delete_one({"app_id": app_id})

            return success_response(
                message="App deleted with success")

        except KeyError as error:
            key = error.args[0]  # Récupérer la clé à partir des arguments de l'exception
            return error_response(message= "Something went wrong",  errors=f"KeyError occurred for key {key}")

        except Exception as error:
            print(traceback.format_exc())
            return error_response(message= "Something went wrong",  errors=str(error), code=500)

    def authorize(self, data, host):
        required_fields = ['redirect_uri', 'response_type', 'client_id', 'scope', 'state']

        if not all(data.get(field) for field in required_fields):
            return error_response(message="Bad request. Please provide all required fields.")
        else:
            redirect_uri = data.get('redirect_uri', None)

            # if not validate_url(redirect_uri):
            #     return error_response(message="Bad request. Please provide a valide redirect_uri.")

            valid_scope = ['email', 'profile', 'offline_access']

            scope = data.get('scope', None)

            if not validate(scope.split(), valid_scope):
                return error_response(message="Bad request. Please provide a valide scope.")

            valid_response_type = ['token', 'code']

            response_type = data.get('response_type', None)

            if not validate(response_type, valid_response_type):
                return error_response(message="Bad request. Please provide a valide response type.")

            client_id = data.get('client_id', None)

            state = data.get('state', None)

            # print(redirect_uri)
            # print(host)

            if state is None:
                # Générer un state unique
                state = sec.token_urlsafe(16)
            client = self.oidc_apps.find_one({
                "client_id": client_id,
                "$and": [
                    {"callback_url": {"$in": [redirect_uri]}},
                    # {"authorized_domains": {"$in": [host]}}
                ]
            })
            # print(client)
            if not client:
                print("Client not found. Please provide valid client information.")
                return error_response(message="Client not found. Please provide valid client information.")

            # code = generate_authorization_code()
            
            app_name = client["name"]
            app_homepage_url = client["homepage_url"]
            created_at = datetime.utcnow()
            expired_at = created_at + timedelta(minutes=10)
            request_id = sec.token_hex(32)
            new_authorization = {
                'request_id': request_id,
                'client_id': client_id,
                'response_type': response_type,
                'scope': scope,
                'state': state,
                'redirect_uri': redirect_uri,
                'created_at': created_at,
                'expired_at': expired_at
            }
            self.oidc_authorization_links.insert_one(new_authorization)
            query_params = {
                "request_id": request_id,
                "client_id": client_id,
                "response_type": response_type,
                "scope": scope,
                "state": state,
                "redirect_uri": redirect_uri,
                "homepage_url": app_homepage_url,
                "app_name": app_name
            }

        encoded_params = urlencode(query_params)
        return success_response(data={
            'state':state,
            'redirect_uri': f"{self.authorization_endpoint}?{encoded_params}"
        })

    def generate_oidc_code(self, length=8):
        characters = string.ascii_letters + string.digits + '-._~'
        code = ''.join(sec.choice(characters) for i in range(length))
        return code

    def generate_access_token(self, user_uid, client_id, scope, expiration_time):
        # Définir les informations spécifiques pour le token
        payload = {
            'user_uid': user_uid,
            'client_id': client_id,
            'scope': scope# Date d'expiration du token
        }

        # Générer le token avec la clé secrète
        access_token = jwt.encode(payload, self.salt, algorithm='HS256')
        return access_token

    def login(self, data):
        try:
            client_id = data.get('client_id')
            state = data.get('state')
            scope = data.get('scope')
            token = data.get('token', None)
            user_uid = None
            
            if token:
                user_uid = decode_auth_token(token)
                signature_expired = user_uid == 'Signature expired. Please log in again.'
                invalid_token = user_uid == 'Invalid token. Please log in again.'
                if signature_expired or invalid_token:
                    return error_response(message=user_uid)
            else:
                user_uid = data.get('user_uid', None)
                password = data.get('password', None)
                response, status_code = connectUser({
                    "uid": user_uid,
                    "password": password
                })
                if status_code != 200:
                    return error_response(message="Authentication failed. Bad email or password")

            request_id = data.get('request_id')
            redirect_uri = data.get('redirect_uri')
            #Vérifier les champs obligatoir&es
            if not client_id or not state or not request_id or not user_uid:
                return error_response(message="Bad request. Please provide all required fields.")

            if not redirect_uri:
                return error_response(message='Login failed. Invalid redirect_uri.')

            request_exist = self.oidc_authorization_links.find_one({'request_id': request_id, 'client_id': client_id, 'state': state})
            if not request_exist:
                return error_response(message='Login failed. Please try again.')
            exp_at = datetime.now() + timedelta(hours=1)
            REDIRECT_URL = None

            #Get response type for request
            response_type = request_exist.get('response_type')
            if response_type == "token":
                access_token = self.generate_access_token(user_uid, client_id, scope, exp_at)
                created_at = datetime.utcnow()
                expired_at = created_at + timedelta(hours=1)
                new_access_token = {
                    'access_token': access_token,
                    'exp_at': exp_at,
                    'client_id': client_id,
                    'scope': scope,
                    'user_uid': user_uid,
                    'created_at': created_at,
                    'expired_at': expired_at
                }
                self.oidc_authorization_tokens.insert_one(new_access_token)
                self.oidc_authorization_links.delete_one({'request_id': request_exist['request_id']})
                REDIRECT_URL = f"{request_exist['redirect_uri']}?access_token={access_token}&state={state}"
            elif response_type == "code":
                code = self.generate_oidc_code()
                created_at = datetime.utcnow()
                expired_at = created_at + timedelta(minutes=5)
                new_code = {
                    'code': str(code),
                    'exp_at': exp_at,
                    'client_id': client_id,
                    'scope': scope,
                    'user_uid': user_uid,
                    'created_at': created_at,
                    'expired_at': expired_at
                }
                self.oidc_authorization_codes.insert_one(new_code)
                self.oidc_authorization_links.delete_one({'request_id': request_exist['request_id']})
                REDIRECT_URL = f"{request_exist['redirect_uri']}?code={code}&state={state}"
            return success_response(data={'REDIRECT_URL': REDIRECT_URL})
        except KeyError as error:
            key = error.args[0]  # Récupérer la clé à partir des arguments de l'exception
            return error_response(message= "Something went wrong",  errors=f"KeyError occurred for key {key}", code=500)
        except Exception as error:
            print(traceback.format_exc())
            return error_response(message="Something went wrong", code=500, errors=str(error))

    def get_token_with_code(self, client_id, code):
        try:
            code_request = self.oidc_authorization_codes.find_one({"code": code, "client_id": client_id})
            if not code_request:
                return error_response(message="Bad code. Please try again")
            user_uid = code_request.get('user_uid')
            scope = code_request.get('scope')
            created_at = datetime.utcnow()
            expired_at = created_at + timedelta(hours=1)

            access_token = self.generate_access_token(user_uid, client_id, scope, expired_at)
            new_access_token = {
                'access_token': access_token,
                'client_id': client_id,
                'scope': scope,
                'user_uid': user_uid,
                'created_at': created_at,
                'expired_at': expired_at
            }
            self.oidc_authorization_tokens.insert_one(new_access_token)
            self.oidc_authorization_codes.delete_one({'_id': code_request['_id']})
            return success_response(data={
                'access_token': access_token,
                'expiration_date': expired_at
            })
        except KeyError as error:
            key = error.args[0]  # Récupérer la clé à partir des arguments de l'exception
            return error_response(message= "Something went wrong",  errors=f"KeyError occurred for key {key}", code=500)
        except Exception as error:
            print(traceback.format_exc())
            return error_response(message="Something went wrong", code=500, errors=str(error))

    def validate_access_token(self, access_token):
        try:
            return True, jwt.decode(access_token, self.salt, algorithms="HS256")
        except Exception as error:
            # Gérer les erreurs de token invalide
            return False, error_response(message=str(error))

    def userinfo(self, client_id, access_token):
        # Vérifier si le token est valide
        validated_access_token = self.validate_access_token(access_token)
        if not validated_access_token[0]:
            return validated_access_token[1]

        # Vérifier si le token est valide et correspond au client ID
        get_access_token = self.oidc_authorization_tokens.find_one({'client_id': client_id, 'access_token': access_token})
        if not get_access_token:
            return error_response(message='Bad request. The token is expired or you provided incorrect information')

        if validated_access_token[1].get('user_uid') != get_access_token['user_uid']:
            return error_response(message='Unauthorized access. The token does not belong to the specified user.', code=403)

        user = users.find_one({'uid': get_access_token.get('user_uid')})
        if not user:
            user = users.find_one({'email': get_access_token.get('user_uid')})
            if not user:
                return error_response(message='Something went wrong. Please re login')

        # Obtenir le scope du token
        scope = get_access_token.get('scope').split()

        # Vérifier si le scope demandé inclut "profile" et/ou "email"
        if "profile" in scope:
            # Obtenir les informations de profil de l'utilisateur
            profile_info = {
                "firstname": user.get('firstname'),
                "lastname": user.get('lastname'),
                "email": user.get('email')
            }
        else:
            profile_info = {}

        if "email" in scope:
            # Obtenir l'adresse e-mail de l'utilisateur
            email_info = {
                "email": user.get('email'),
            }
        else:
            email_info = {}

        # Combiner les informations de profil et d'e-mail
        user_info = {**profile_info, **email_info}

        return success_response(data=user_info)

    def validate_refresh_token(self, refresh_token):
        # Implémentez ici la logique de validation d'un token de rafraîchissement
        # Vous devez vérifier la validité du token, sa signature et sa validité temporelle, et retourner les informations d'identification de l'utilisateur associé au token
        return