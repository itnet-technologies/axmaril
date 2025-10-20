from functools import wraps
from flask import request, jsonify, abort
import traceback
from .helpers import success_response, error_response
from api.v2.database.db_manager import DBManager
from .custom_exception import TokenDecodeError, TokenExpiredError, TokenInvalidError
import jwt
import sys, os


def get_python_version():
    version_info = sys.version_info
    if version_info.major == 3 and version_info.minor > 6:
        return "new"
    else:
        return "old"

def decode_auth_token(auth_token):
    """
    Decode the authentication token.
    :param auth_token: The authentication token to decode.
    :return: The subject (often the user's ID) contained in the token.
    """
    try:
        db_manager = DBManager()
        creds_data = db_manager.find_one("creds", {"type":"token_secret"}, {'_id': 0})
        salt = creds_data["salt"]

        py_version = get_python_version()
        if py_version == "old":
            payload = jwt.decode(auth_token, salt)
        else:
            payload = jwt.decode(auth_token, salt, algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError('Signature expired. Please log in again.')
    except jwt.InvalidTokenError:
        raise TokenInvalidError('Invalid token. Please log in again.')

def jwt_validation(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        db_manager = DBManager()
        tokens_collection = "tokens"
        auth_token = request.headers.get('Authorization')

        if auth_token is None:
            return error_response(message="Missing token", code=401)

        try:
            auth_token = auth_token.split()[1]
            user_token_info = db_manager.find_one(tokens_collection, {"token":auth_token, "type": "auth_token"}, {'_id': 0})
            if user_token_info is None:
                return error_response(message="Missing token", code=401)
            user_id_from_token = decode_auth_token(auth_token)
            user_id_from_db = user_token_info["user_uid"]
            user_infos = db_manager.find_one("users", {"uid": user_id_from_db})
            user_data = {
                'uid': user_id_from_db,
                'email': user_infos['email']
            }
            if user_id_from_token != user_id_from_db:
                return error_response(message="Please log in again", code=401)

            return f(user_data, *args, **kwargs)

        except TokenExpiredError as e:
            return error_response(message=str(e), code=401)
        except TokenInvalidError as e:
            return error_response(message=str(e), code=401)
        except Exception as e:
            print(traceback.format_exc())
            return abort(401)
    return decorator

def license_validation(feature):
    def decorator_factory(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            LICENSE_INFO = os.environ["AXMARIL_LICENSE_INFO"]
            if LICENSE_INFO is None:
                return jsonify({
                    "status" : "failed",
                    "message" : "This premium feature is not allowed in the current version, please add a valid license to unlock it",
                }), 403
            if LICENSE_INFO["features"][feature]:
                return f(*args, **kwargs)
            else:
                return jsonify({
                    "status" : "failed",
                    "message" : "This premium feature is not allowed in the current version, please add a valid license to unlock it",
                }), 403
        return decorator
    return decorator_factory

def ws_jwt_validation(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        db_manager = DBManager()
        tokens_collection = "tokens"
        args = dict(request.args)
        auth_token = args.get("token", None)

        if auth_token is None:
            return error_response(message="Missing token", code=401)
        try:
            user_token_info = db_manager.find_one(tokens_collection, {"token":auth_token, "type": "auth_token"}, {'_id': 0})
            if user_token_info is None:
                return error_response(message="Missing token", code=401)
            user_id_from_token = decode_auth_token(auth_token)
            user_id_from_db = user_token_info["user_uid"]
            user_infos = db_manager.find_one("users", {"uid": user_id_from_db})
            user_data = {
                'uid': user_id_from_db,
                'email': user_infos['email']
            }
            if user_id_from_token != user_id_from_db:
                return error_response(message="Please log in again", code=401)

            return f(user_data, *args, **kwargs)

        except TokenExpiredError as e:
            return error_response(message=str(e), code=401)
        except TokenInvalidError as e:
            return error_response(message=str(e), code=401)
        except Exception as e:
            print(traceback.format_exc())
            return abort(401)
    return decorator

def get_user_data_by_token(token):
    db_manager = DBManager()
    user_id_from_token = decode_auth_token(token)
    user_token_info = db_manager.find_one("tokens", {"token":token, "type": "auth_token"}, {'_id': 0})
    user_id_from_db = user_token_info["user_uid"]
    user_infos = db_manager.find_one("users", {"uid": user_id_from_db})
    user_data = {
        'uid': user_id_from_db,
        'email': user_infos['email']
    }
    if user_id_from_token != user_id_from_db:
        raise error_response(message="Please log in again", code=401)
    return user_data