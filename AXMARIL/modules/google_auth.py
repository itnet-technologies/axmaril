import json
import os
import shutil
import requests
import traceback
from base64 import b64encode
from json import dumps
from threading import Thread
# from turtle import right
from flask import jsonify, Blueprint,request, make_response
# from pymongo import MongoClient
from modules.required_packages import success_response, error_response
from modules.required_packages import (
    encode_token, has_role, mail_sender, parse_json, safe_access, secret_access, 
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

from .oic import OAuth2

GOOGLE_AUTH = Blueprint("google_auth", __name__)

@GOOGLE_AUTH.route('/google/login', methods=['GET'])
def google_login():
    # allow_redirect_domains = ['https://azumarill.axe-tag.com/google/login', 'http://localhost:5173/google/login']
    # params = request.args.to_dict()
    # redirect_domain = "https://azumarill.axe-tag.com"
    # if 'redirect_domain' in params:
    #     redirect_domain_retrieve = params.get('redirect_domain')
    #     allow_redirect_domains = ['https://azumarill.axe-tag.com', 'http://localhost:5173']
    #     if redirect_domain_retrieve in allow_redirect_domains:
    #         redirect_domain = redirect_domain_retrieve
    return OAuth2().authorize()


@GOOGLE_AUTH.route('/google/callback', methods=['GET'])
def google_auth_redirect(): 
    try:
        args = request.args.to_dict()
        return OAuth2().callback(args, request.url)
    except Exception as error:
        print(traceback.format_exc())
        return OAuth2().redirect_with_params()
        #return error_response(errors=str(error), message= "Something went wrong. Please try again")