import json
import os
import shutil
import requests
import traceback
from base64 import b64encode
from json import dumps
from threading import Thread
# from turtle import right
from flask import jsonify, Blueprint,request
from modules.required_packages import (
    admin_middleware, success_response, error_response, 
    secrets, users, shares, decrypt, encrypt, get_userid_by_token, isErrorKey, run_dag,
    validation, salt, jwt, client, oidc_apps, file_server_url, delete_safe_util, tokens
)
# import shortuuid
from urllib.parse import urlparse
from bson import ObjectId
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from pathlib import Path
import secrets as sec
from flask import current_app
from flask import jsonify
from flask.helpers import make_response
from flask.templating import render_template

from http.client import HTTPResponse
import urllib.parse
import pprint

from .oic import OIDCProvider, OAuth2

OIDC = Blueprint("oidc", __name__)

# @OIDC.route('/google/login', methods=['GET'])
# def google_login():
#     return OAuth2().authorize()


# @OIDC.route('/google/callback', methods=['GET'])
# def google_auth_redirect(): 
#     try:
#         args = request.args.to_dict()
#         return OAuth2().callback(args, request.url)
#     except Exception as error:
#         print(traceback.format_exc())
#         return error_response(errors=str(error), message= "Something went wrong. Please try again")

@OIDC.route('/list/app', methods=['GET'])
@admin_middleware
def list_user_apps():
    try:
        user_apps = oidc_apps.find({}, {"_id": 0})
        return success_response(data=list(user_apps))
    except:
        print(traceback.format_exc())
        return error_response(message="Something went wrong but it's not your fault.")

@OIDC.route('/create/app', methods=['POST'])
@admin_middleware
def create_app():
    req = request.get_json(force = True)
    client = OIDCProvider()
    return client.register_client(req)

     
@OIDC.route('/update/app/<app_id>', methods=['PUT'])
@admin_middleware
def update_app(app_id):
    req = request.get_json(force = True)
    client = OIDCProvider()
    return client.update_client(req, app_id)
    

@OIDC.route('/delete/app/<app_id>', methods=['DELETE'])
@admin_middleware
def delete_app(app_id):
    client = OIDCProvider()
    return client.delete_client(app_id)

@OIDC.route('/authorization', methods=['POST'])
def authorization_endpoint():
    try:
        data = request.get_json(force=True)
        # print(data)
        client = OIDCProvider()
        host_request = request.remote_addr
        # server_ip = request.__dict__['gunicorn.socket']
        # print(server_ip)
        # print(request.__dict__['environ'].get('REMOTE_ADDR'))

        # print(f"Real IP {request.remote_addr}")
        # parsed_url = urlparse(request.url)
        # prefix = f"{parsed_url.scheme}://{parsed_url.netloc}"
        return client.authorize(data, host_request)
    except:
        print("Cannot do this")
        print(traceback.format_exc())
        return error_response(message="Cannot do this")

@OIDC.route('/login', methods=['POST'])
def login():
    #client_id #state #scope #user_uid #request_id #redirect_uri
    data = request.get_json(force=True)
    client = OIDCProvider()
    return client.login(data)

@OIDC.route('/token', methods=['POST'])
def token():
    #client_id #access_token
    data = request.get_json(force=True)
    client_id = data.get('client_id')
    code = data.get('code')
    client = OIDCProvider()
    return client.get_token_with_code(client_id, code)


@OIDC.route('/userinfo', methods=['GET'])
def userinfo():
    try:
        data = request.args.to_dict()   
        client_id = data.get('client_id', None)
        access_token = data.get('access_token', None)
        if client_id is None or access_token is None:
            return error_response(message="Please send access_token and client_id in params")
        client = OIDCProvider()
        return client.userinfo(client_id, access_token)
    except:
        return error_response(message="Cannot get you infos. Please retry")
