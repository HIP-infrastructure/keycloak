from flask import Flask
from flask import request
from flask import jsonify
from flask import abort
from flask_httpauth import HTTPBasicAuth
import pathlib
import yaml
from werkzeug.security import generate_password_hash, check_password_hash
import json
import subprocess
import socket
import os
from dotenv import load_dotenv

from hipcloak import Hipcloak

from keycloak.exceptions import raise_error_from_response, KeycloakGetError
from keycloak.urls_patterns import URL_ADMIN_CLIENT_ROLE
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

__author__ = "Florian SIPP"
__email__ = "florian.sipp@chuv.ch"

app = Flask(__name__)
auth = HTTPBasicAuth()

# get relative path of env files
ENV_PATH = pathlib.Path(__file__).parent

# get relative path of docker-compose file
DOCKER_PATH = pathlib.Path(__file__).parent.parent

load_dotenv(ENV_PATH.joinpath("keycloak_backend.env"))

def get_domain():
  return str(os.getenv('BACKEND_DOMAIN'))

# load necessary var for keycloak connection
load_dotenv(ENV_PATH.joinpath("../.env"))

server_url=get_domain()
admin_username=os.getenv("KEYCLOAK_ADMIN")
admin_password=os.getenv("KEYCLOAK_ADMIN_PASSWORD")
keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')

def get_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8", 80))
  return s.getsockname()[0]

def get_credentials():
  with open(ENV_PATH.joinpath("keycloak_backend.secret"), mode='r') as secret:
    username, password = secret.read().split('@')
  return {username: password}

users = get_credentials()

class InvalidUsage(Exception):
  status_code = 400

  def __init__(self, message, status_code=None, payload=None):
    Exception.__init__(self)
    self.message = message
    if status_code is not None:
      self.status_code = status_code
    self.payload = payload

  def to_dict(self):
    rv = dict(self.payload or ())
    rv['message'] = self.message
    return rv

@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
  response = jsonify(error.to_dict())
  response.status_code = error.status_code
  return response

@auth.verify_password
def verify_password(username, password):
  if username in users:
    return check_password_hash(users.get(username), password)
  return False

@app.route('/')
@auth.login_required
def index():
  return "Hello, %s!" % auth.username()

@app.route('/ok')
@auth.login_required
def health_check():
  return "Keycloak Backend currently running on %s" % get_domain()

# Json structure to create a new user
# {
#     "User Name": "keyfloak",
#     "First Name": "Florian",
#     "Last Name": "SIPP",
#     "Password": "tutu",
#     "Email": "florian.sipp@chuv.ch"
# }
# @app.route('/identity/users', methods=['POST'])
# @auth.login_required
# def create_user():
#   realm_name = request.args.get('realm')

#   content = request.get_json()
#   user_name=content['User Name']
#   user_to_add_first_name = content['First Name']
#   user_to_add_last_name = content['Last Name']
#   user_to_add_password = content['Password']
#   user_to_add_email = content['Email']

#   keycloak_adm.switch_realm(realm_name)

#   add_user_id = keycloak_adm.create_user(user_name=user_name, 
#                                         first_name=user_to_add_first_name, 
#                                         last_name=user_to_add_last_name, 
#                                         user_password=user_to_add_password, 
#                                         email=user_to_add_email)
                                        
#   if add_user_id is not None:
#       return 'User <%s> created' %(user_name)
#   else:
#       return 'User was not created'

# @app.route('/identity/users/<string:user_name>', methods=['DELETE'])
# @auth.login_required
# def delete_user(user_name):
#   realm_name = request.args.get('realm')
#   keycloak_adm.switch_realm(realm_name)

#   delete_user_id = keycloak_adm.delete_user(user_name=user_name)
#   if delete_user_id is not None:
#       return 'User <%s> deleted' %(user_name)
#   else:
#       return 'User <%s> was not deleted' %(user_name)

# # Json structure to create a new group (role under keycloak naming)
# # {
# #     "name": "group-HIP-dev-CHUV",
# #     "description": "group-HIP-dev-CHUV"
# # }
# @app.route('/identity/groups', methods=['POST'])
# @auth.login_required
# def add_group_to_realm():
#   print('a')
#   realm_name = request.args.get('realm')
#   print('a')
#   content = request.get_json()
#   role_name=content['name']
#   role_description = content['description']
#   print('a')
#   keycloak_adm.switch_realm(realm_name)
#   print('a')
#   wanted_role = keycloak_adm.add_role_to_realm(role_name,role_description)
#   if wanted_role is not None:
#       return 'Role ' + role_name + ' created in realm ' + realm_name
#   else:
#       return 'Role ' + role_name + ' already exist in realm ' + realm_name

# @app.route('/identity/groups/<string:role_name>', methods=['DELETE'])
# @auth.login_required
# def remove_group_from_realm(role_name):
#   realm_name = request.args.get('realm')
#   keycloak_adm.switch_realm(realm_name)

#   delete_wanted_role = keycloak_adm.delete_role_from_realm(role_name)
#   if delete_wanted_role is not None:
#       return 'Role ' + role_name + ' deleted from realm ' + realm_name
#   else:
#       return 'Role ' + role_name + ' does not exist in realm ' + realm_name

# @app.route('/identity/groups/<string:role_name>/users/<string:user_name>', methods=['PUT'])
# @auth.login_required
# def add_user_to_group(user_name, role_name):
#   print('username : ' + user_name)
#   print('rolename :' + role_name)

#   realm_name = request.args.get('realm')
#   keycloak_adm.switch_realm(realm_name)

#   wanted_user_id = keycloak_adm.add_role_to_user(user_name, role_name)
#   print('role added')
#   return 'Role <%s> added to user <%s>' %(role_name, user_name)

# @app.route('/identity/groups/<string:role_name>/users/<string:user_name>', methods=['DELETE'])
# @auth.login_required
# def remove_user_from_group(user_name, role_name):
#   realm_name = request.args.get('realm')
#   keycloak_adm.switch_realm(realm_name)

#   wanted_user_id = keycloak_adm.remove_role_from_user(user_name, role_name)
#   return 'Role <%s> removed from user <%s>' %(role_name, user_name)

#Beginning of work with manu
@app.route('/projects/users/<string:user_name>', methods=['GET'])
@auth.login_required
def get_user_groups(user_name):
  realm_name = request.args.get('realm')
  query_type = request.args.get('type')
  keycloak_adm.switch_realm(realm_name)

  users_from_group = []
  group_to_check = []
  group_list = keycloak_adm.get_group_for_user(user_name)

  group_info = {}
  for current_group in group_list:
    if '/HIP-dev-projects' in current_group['path'] and not '/administrators' in current_group['path']:
        group_info = {}
        group_info['type'] = query_type
        group_members = keycloak_adm.get_members_from_group(current_group['id'])

        group_info['name'] = current_group['name']
        group_info['description'] = ""
        group_info['members'] = []
        for member in group_members:
          group_info['members'] += [member['username']]

        group_info['admins'] = []
        
        users_from_group += [group_info]
    elif '/HIP-dev-projects' in current_group['path'] and '/administrators' in current_group['path']:
      group_members = keycloak_adm.get_members_from_group(current_group['id'])
      for member in group_members:
          group_info['admins'] += [member['username']]
        
  return jsonify(users_from_group)

@app.route('/identity/users/<string:user_name>', methods=['GET'])
@auth.login_required
def get_user(user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        wanted_user = keycloak_adm.get_user(user_name)
        
        # Check if the user is in the "Projects Administrators" group
        group_id_admin = keycloak_adm.get_group_id_from_path("/Projects Administrators")
        group_members = keycloak_adm.get_members_from_group(group_id_admin.get('id', ''))
        isAdmin = any(member.get('username') == wanted_user.get('username') for member in group_members)

        user_info = {
            'id': wanted_user.get('username', ''),
            'displayName': f"{wanted_user.get('firstName', '')} {wanted_user.get('lastName', '')}",
            'email': wanted_user.get('email', ''),
            'groups': keycloak_adm.get_group_for_user(wanted_user.get('username', '')),
            'enabled': wanted_user.get('enabled', False),
            'hasProjectsAdminRole': isAdmin
        }

        return jsonify(user_info)
    except KeyError as e:
        return jsonify({'error': f'Missing key in user data: {e}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/identity/groups', methods=['POST'])
@auth.login_required
def create_group():
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        content = request.get_json()
        admin_name = content['adminId']
        role_name = content['name']
        role_description = content.get('description', '')  # Provide a default value if description is missing

        # Create the main role and the administrators role
        wanted_role = keycloak_adm.create_group(role_name)
        wanted_role_admin = keycloak_adm.create_group("administrators", role_name)

        # Add the admin to both groups
        keycloak_adm.add_user_to_group(admin_name, wanted_role)
        keycloak_adm.add_user_to_group(admin_name, wanted_role_admin)

        return '', 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/identity/groups2', methods=['POST'])
def create_group2():
    return 'coucou'

@app.route('/identity/groups/<string:group_name>', methods=['DELETE'])
@auth.login_required
def delete_group(group_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        group_path = f"/HIP-dev-projects/{group_name}"
        group_id = keycloak_adm.get_group_id_from_path(group_path)
        print('a')
        if group_id:
            keycloak_adm.delete_group(group_id['id'])
            print('b')
            return '', 204
        else:
            print('c')
            return jsonify({'error': 'Group not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/identity/groups', methods=['GET'])
@auth.login_required
def get_all_groups():
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        group_path = "/HIP-dev-projects"
        all_groups = keycloak_adm.get_group_id_from_path(group_path)

        groups_info = []

        for current_group in all_groups.get('subGroups', []):
            if '/HIP-dev-projects' in current_group.get('path', '') and '/administrators' not in current_group.get('path', ''):
                group_info = {
                    'name': current_group.get('name', ''),
                    'description': '',
                    'members': [member.get('username', '') for member in keycloak_adm.get_members_from_group(current_group.get('id', ''))],
                    'admins': []
                }

                # Check for administrators sub-group
                for current_group_admin in current_group.get('subGroups', []):
                    if current_group_admin.get('name', '') == 'administrators':
                        group_info['admins'] = [member_admin.get('username', '') for member_admin in keycloak_adm.get_members_from_group(current_group_admin.get('id', ''))]

                groups_info.append(group_info)

        return jsonify(groups_info)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/identity/groups/<string:group_name>/<string:role_name>/users/<string:user_name>', methods=['PUT'])
@auth.login_required
def add_user_to_group(group_name, role_name, user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        match role_name:
            case 'member':
                group_path = f"/HIP-dev-projects/{group_name}"
            case 'admin':
                group_path = f"/HIP-dev-projects/{group_name}/administrators"
            case _:
                return jsonify({'error': 'Role not found, not doing anything'}), 400

        group_id = keycloak_adm.get_group_id_from_path(group_path)
        keycloak_adm.add_user_to_group(user_name, group_id['id'])

        return '', 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/identity/groups/<string:group_name>/<string:role_name>/users/<string:user_name>', methods=['DELETE'])
def remove_user_from_group(group_name, role_name, user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        match role_name:
            case 'member':
                group_path = f"/HIP-dev-projects/{group_name}"
            case 'admin':
                group_path = f"/HIP-dev-projects/{group_name}/administrators"
            case _:
                return jsonify({'error': 'Role not found, not doing anything'}), 400

        group_id = keycloak_adm.get_group_id_from_path(group_path)
        keycloak_adm.remove_user_from_group(user_name, group_id['id'])

        return '', 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500
  
@app.route('/identity/groups/<string:group_name>', methods=['GET'])
def get_group_info(group_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm.switch_realm(realm_name)

        group_path = f"/HIP-dev-projects/{group_name}"
        group_id = keycloak_adm.get_group_id_from_path(group_path)
        group_id_admin = keycloak_adm.get_group_id_from_path(f"{group_path}/administrators")

        if group_id is None:
            return jsonify({'error': 'Group not found'}), 404

        group_info = {
            'title': group_id['name'],
            'description': '',
            'members': [member['username'] for member in keycloak_adm.get_members_from_group(group_id['id'])],
            'admins': [],
        }

        if group_id_admin:
            group_info['admins'] = [member['username'] for member in keycloak_adm.get_members_from_group(group_id_admin['id'])]

        return jsonify(group_info)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
  app.run(port=8060)
