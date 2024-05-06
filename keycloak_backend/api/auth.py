import os
import jwt
import httpx
import pathlib
import logging
from flask import abort
from flask import request
from functools import wraps
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

__author__ = "Florian SIPP"
__email__ = "florian.sipp@chuv.ch"

auth = HTTPBasicAuth()

# get relative path of env files
ENV_PATH = pathlib.Path(__file__).parent.parent

def get_domain():
  return str(os.getenv('BACKEND_DOMAIN'))

def get_credentials():
  if os.getenv("KEYCLOAK_BACKEND_USER") is not None and os.getenv("KEYCLOAK_BACKEND_PASSWORD") is not None:
    username = os.getenv("KEYCLOAK_BACKEND_USER")
    password = generate_password_hash(os.getenv("KEYCLOAK_BACKEND_PASSWORD"))
    return {username: password}
    
  with open(ENV_PATH.joinpath("keycloak_backend.secret"), mode='r') as secret:
    username, password = secret.read().split('@')
  return {username: password}

@auth.verify_password
def verify_password(username, password):
  if username in users:
    return check_password_hash(users.get(username), password)
  return False

def decode_access_token(authorisation_token, realm):
    # authorisation_token=str.replace(str(authorisation_token), 'Bearer ', '')
    # user_info = jwt.decode(authorisation_token, options={"verify_signature": False})

    # get public key 
    response = httpx.get(url= get_domain()+'/realms/'+realm)
    keys = response.json()

    #format authorization token
    chosen_key=keys['public_key']
    chosen_key = '''-----BEGIN PUBLIC KEY-----\n''' + chosen_key + '''\n-----END PUBLIC KEY-----'''
    chosen_key = chosen_key.encode('ascii')

    authorisation_token2 = str.replace(str(authorisation_token), 'Bearer ', '')

    #decode
    user_info = jwt.decode(jwt=authorisation_token2,
                        key=chosen_key,
                        algorithms=["RS256"],
                        options={"verify_aud": False})
    return user_info

def role_required(role_name):
    def decorator(func):
        @wraps(func)
        def authorize(*args, **kwargs):
            hd = request.headers.get('Authorization')
            realm = request.args.get('realm')
            user_info = decode_access_token(hd,realm)
            #print(user_info)
            if 'groups' not in user_info:
               logging.exception("User " + user_info['preferred_username'] + " does not have groups")
               abort(401)
            if role_name not in user_info['groups']:
               logging.exception("User " + user_info['preferred_username'] + " is not authorized to access this ressource")
               abort(401) # not authorized
            return func(*args, **kwargs)
        return authorize
    return decorator

users = get_credentials()
