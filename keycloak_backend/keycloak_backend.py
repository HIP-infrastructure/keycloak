import os
import pathlib
from flask import Flask
from flask import request
from flask import jsonify
from dotenv import load_dotenv
from api.auth import *
from api.hipcloak import Hipcloak

__author__ = "Florian SIPP"
__email__ = "florian.sipp@chuv.ch"

app = Flask(__name__)

# get relative path of env files
ENV_PATH = pathlib.Path(__file__).parent

# get relative path of docker-compose file
DOCKER_PATH = pathlib.Path(__file__).parent.parent

# load necessary env vars (keycloak connection and else)
load_dotenv(ENV_PATH.joinpath("keycloak_backend.env"))
load_dotenv(ENV_PATH.joinpath("../.env"))

#master login
server_url=get_domain()
admin_username=os.getenv("KEYCLOAK_ADMIN")
admin_password=os.getenv("KEYCLOAK_ADMIN_PASSWORD")
#keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')

@app.route('/')
@auth.login_required
def index():
  return "Hello, %s!" % auth.username()

@app.route('/ok')
@auth.login_required
def health_check():
  return "Keycloak Backend currently running on %s" % get_domain()

"""
Create a new user account in the Keycloak identity and access management system within a specified realm.

Endpoint:
POST /identity/users

Parameters:
- JSON Request Body (dict): A JSON object containing user information:
  - 'User Name' (str): The username of the new user (required).
  - 'First Name' (str): The first name of the new user.
  - 'Last Name' (str): The last name of the new user.
  - 'Password' (str): The password for the new user (required).
  - 'Email' (str): The email address of the new user.

Returns:
- str: A success message indicating that the user was created.
- tuple (str, int): An error message and HTTP status code (400 for bad request or 500 for server error) in case of failure.

Description:
This endpoint allows administrators to create a new user account within a Keycloak realm. The provided user information is used to create the user in the specified realm.

- Ensure that the 'auth.login_required' decorator is applied to restrict access to authenticated users only.

- The 'realm' query parameter specifies the Keycloak realm in which the user should be created.

- The function retrieves user information from the JSON request body and validates that the required fields ('User Name' and 'Password') are provided.

- It then creates the user using the provided information and checks if the user was successfully created.

Example Usage:
```http
POST /identity/users?realm=my_realm
{
    "User Name": "john_doe",
    "First Name": "John",
    "Last Name": "Doe",
    "Password": "secretpassword",
    "Email": "john.doe@example.com"
}
"""
@app.route('/identity/users', methods=['POST'])
@role_required('app-admin')
def create_user():
    try:
        realm_name = request.args.get('realm')

        # Retrieve user information from the JSON request
        content = request.get_json()
        user_name = content.get('User Name', '')
        user_to_add_first_name = content.get('First Name', '')
        user_to_add_last_name = content.get('Last Name', '')
        user_to_add_password = content.get('Password', '')
        user_to_add_email = content.get('Email', '')

        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        # Create the user
        add_user_id = keycloak_adm.create_user(
            user_name=user_name,
            first_name=user_to_add_first_name,
            last_name=user_to_add_last_name,
            user_password=user_to_add_password,
            email=user_to_add_email
        )

        if add_user_id:
            return f'User {user_name} created'
        else:
            return 'User was not created', 500

    except KeyError as e:
        return jsonify({'error': f'Missing key in user data: {e}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

"""
Delete a user account from the Keycloak identity and access management system within a specified realm.

Endpoint:
DELETE /identity/users/<string:user_name>

Parameters:
- user_name (str): The username of the user to be deleted.
- realm (str, query parameter): The name of the Keycloak realm in which the user should be deleted.

Returns:
- str: A success message indicating that the user was deleted.
- tuple (str, int): An error message and HTTP status code (500 for server error) in case of failure.

Description:
This endpoint allows administrators to delete a user account from a Keycloak realm. The specified user account associated with 'user_name' will be permanently removed from the realm.

- Ensure that the 'auth.login_required' decorator is applied to restrict access to authenticated users only.

- The 'realm' query parameter specifies the Keycloak realm in which the user should be deleted.

- The function handles the deletion process and checks if the user was successfully removed. It returns an appropriate success message or an error message with a 500 status code if the deletion fails.

Example Usage:
```http
DELETE /identity/users/john_doe?realm=my_realm
"""
@app.route('/identity/users/<string:user_name>', methods=['DELETE'])
@role_required('app-admin')
def delete_user(user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        # Delete the user
        delete_user_id = keycloak_adm.delete_user(user_name=user_name)

        # Check if the user was successfully deleted
        if delete_user_id:
            return f'User {user_name} deleted'
        else:
            return f'User {user_name} was not deleted', 500

    except Exception as e:
        # Handle exceptions with a generic error message and a 500 Internal Server Error status code
        return jsonify({'error': str(e)}), 500

"""
Retrieve a user's group membership information within a specified Keycloak realm.

Endpoint:
GET /projects/users/<string:user_name>

Parameters:
- user_name (str): The username of the user for whom group membership information is requested.
- realm (str, query parameter): The name of the Keycloak realm in which to perform the query.
- type (str, query parameter): The type of group membership query (e.g., 'projects', 'administrators').

Returns:
- JSON Response: A JSON representation of the user's group membership information, including group names, descriptions, members, and administrators.

Description:
This endpoint allows you to retrieve detailed information about a user's group memberships within a Keycloak realm. It provides the flexibility to query for different types of group memberships, such as 'projects' or 'administrators,' based on the 'type' query parameter.

- 'projects': Retrieves information about the user's memberships in project-related groups.
- 'administrators': Retrieves information about the user's memberships in administrative groups.

The function iterates through the user's group memberships and compiles a JSON response with the following structure for each group:

{
    'type': <query_type>,
    'name': <group_name>,
    'description': <group_description>,
    'members': [<member_username_1>, <member_username_2>, ...],
    'admins': [<admin_username_1>, <admin_username_2>, ...]
}

- 'type': Indicates the type of group membership query (e.g., 'projects', 'administrators').
- 'name': The name of the group.
- 'description': A brief description of the group.
- 'members': A list of usernames of members in the group.
- 'admins': A list of usernames of administrators in the group.

Example Usage:
```http
GET /projects/users/john_doe?realm=my_realm&type=projects
"""
@app.route('/projects/<string:root_path>/users/<string:user_name>', methods=['GET'])
#@role_required('app-admin')
def get_user_groups(root_path, user_name):
  realm_name = request.args.get('realm')
  #query_type = request.args.get('type')
  keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
  keycloak_adm.switch_realm(realm_name)
  
  users_from_group = []
  group_list = keycloak_adm.get_groups_for_user(user_name)
  
  if group_list is None: return []
  
  group_info = {}
  for current_group in group_list:
    if root_path in current_group['path'] and not '/administrators' in current_group['path'] and not '-administrators' in current_group['path']:
    #if '/HIP-dev-projects' in current_group['path'] and not '/administrators' in current_group['path']:
        group_info = {}
        #group_info['type'] = query_type
        group_members = keycloak_adm.get_members_from_group(current_group['id'])

        group_info = {
            "name": current_group['name'],
            "isPublic": current_group['attributes'].get('isPublic', ['False'])[0].lower() == 'true',
            "description": "",
            "members": [],
            "admins":[]
        }

        for member in group_members:
          group_info['members'] += [member['username']]
        
        users_from_group += [group_info]
    #elif '/HIP-dev-projects' in current_group['path'] and '/administrators' in current_group['path']:
    elif root_path in current_group['path'] and '/administrators' in current_group['path']:
      group_members = keycloak_adm.get_members_from_group(current_group['id'])
      for member in group_members:
          group_info['admins'] += [member['username']]
        
  return jsonify(users_from_group)

"""
Retrieve detailed information about a user account in the Keycloak identity and access management system within a specified realm.

Endpoint:
GET /identity/users/<string:user_name>

Parameters:
- user_name (str): The username of the user for whom information is requested.
- realm (str, query parameter): The name of the Keycloak realm in which the user's information should be retrieved.

Returns:
- JSON Response: A JSON representation of the user's account information, including username, display name, email, group memberships, and administrator role status.

Description:
This endpoint allows administrators with the 'app-admin' role to retrieve detailed information about a user account within a Keycloak realm. The requested user's information, such as username, display name, email address, group memberships, and administrator role status, is returned in a structured JSON format.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm in which the user's information should be retrieved.

- The function retrieves the user's information using the Keycloak Admin API and checks if the user is a member of the "Projects Administrators" group.

- It then compiles the user's account information into a JSON response for client consumption.

Example Usage:
```http
GET /identity/users/john_doe?realm=my_realm
"""
@app.route('/identity/projects/<string:root_path>/users/<string:user_name>', methods=['GET'])
@role_required('app-admin')
def get_user(root_path, user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        wanted_user = keycloak_adm.get_user(user_name)
        # Check if the user is in the "root_path" group , ie "HIP-dip-dev-projects-administrators"
        group_id_admin = keycloak_adm.get_group_details_from_path(root_path)
        group_members = keycloak_adm.get_members_from_group(group_id_admin.get('id', ''))
        
        isAdmin = any(member.get('username') == wanted_user.get('username') for member in group_members)

        user_info = {
            'id': wanted_user.get('username', ''),
            'displayName': f"{wanted_user.get('firstName', '')} {wanted_user.get('lastName', '')}",
            'email': wanted_user.get('email', ''),
            'groups': keycloak_adm.get_groups_for_user(wanted_user.get('username', '')),
            'enabled': wanted_user.get('enabled', False),
            'hasProjectsAdminRole': isAdmin
        }

        return jsonify(user_info)
    except KeyError as e:
        return jsonify({'error': f'Missing key in user data: {e}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/identity/groupsroot', methods=['POST'])
@role_required('app-admin')
def create_root_collab():
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        content = request.get_json()
        role_name = content['name']
        role_description = content.get('description', '')  # Provide a default value if description is missing

        wanted_role = keycloak_adm.create_root_group(role_name)

        return '', 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
"""
Create a new group in the Keycloak identity and access management system within a specified realm, including an 'administrators' sub-group.

Endpoint:
POST /identity/groups

Parameters:
- JSON Request Body (dict): A JSON object containing group information:
  - 'adminId' (str): The username of the group administrator (required).
  - 'name' (str): The name of the new group (required).
  - 'description' (str, optional): A brief description of the new group (optional).

Returns:
- HTTP Status Code: 201 Created if the group is successfully created.
- JSON Response with Error: An error message and HTTP status code (400 for bad request) in case of failure.

Description:
This endpoint allows administrators with the 'app-admin' role to create a new group within a Keycloak realm. The new group is created with a specified name and, optionally, a brief description.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm in which the group should be created.

- The function retrieves group information from the JSON request body, including the administrator's username, group name, and an optional group description.

- It creates two groups: the main group and an 'administrators' sub-group. The main group is intended for regular members, while the 'administrators' sub-group is for group administrators.

- The administrator specified by 'adminId' is added to both the main group and the 'administrators' sub-group.

Example Usage:
```http
POST /identity/groups?realm=my_realm
{
    "adminId": "admin_user",
    "name": "My Group",
    "description": "A group for project XYZ"
}
"""
@app.route('/identity/groups', methods=['POST'])
@role_required('app-admin')
def create_group():
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        content = request.get_json()
        admin_name = content['adminId']
        role_name = content['name']
        root_name = content['root']
         # Provide a default value if description is missing
        role_description = content.get('description', '')
        # Provide a default value if isPublic is missing
        is_public_space = content.get('isPublic', False)

        # Create the main role and the administrators role
        wanted_role = keycloak_adm.create_group(role_name, root_name, is_public_space)
        wanted_role_admin = keycloak_adm.create_group("administrators", root_name + "/" + role_name)

        # Create corresponding role for the collab : needs to be prefixed with "group-"" at the moment 
        role_name = "group-" + role_name
        role_for_group = keycloak_adm.add_role_to_realm(role_name)

        # Add the admin to both groups
        keycloak_adm.add_user_to_group(admin_name, wanted_role)
        keycloak_adm.add_user_to_group(admin_name, wanted_role_admin)

        #Add role mapping to the group
        keycloak_adm.add_role_to_group(wanted_role, role_for_group)

        return '', 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

"""
Delete a group and its associated 'administrators' sub-group in the Keycloak identity and access management system within a specified realm.

Endpoint:
DELETE /identity/groups/<string:group_name>

Parameters:
- group_name (str): The name of the group to be deleted.
- realm (str, query parameter): The name of the Keycloak realm in which the group should be deleted.

Returns:
- HTTP Status Code: 204 No Content if the group is successfully deleted.
- JSON Response with Error: An error message and HTTP status code (404 for not found or 500 for server error) in case of failure.

Description:
This endpoint allows administrators with the 'app-admin' role to delete a group and its associated 'administrators' sub-group within a Keycloak realm. The specified group and its sub-group are permanently removed from the realm.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm in which the group should be deleted.

- The function constructs the group's path and retrieves its ID using the Keycloak Admin API. It checks if the group exists.

- If the group exists, it is deleted, including its 'administrators' sub-group. The function returns a 204 No Content status code upon successful deletion.

- If the group does not exist, a 404 Not Found status code is returned with an error message.

Example Usage:
```http
DELETE /identity/groups/my_group?realm=my_realm
"""
@app.route('/identity/groups/<string:root_path>/<string:group_name>', methods=['DELETE'])
@role_required('app-admin')
def delete_group(root_path, group_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        role_name = "group-" + group_name
        group_path = f"{root_path}/{group_name}"
        group_id = keycloak_adm.get_group_details_from_path(group_path)
        
        # Unassign role from group
        keycloak_adm.remove_role_from_group(group_id, role_name)

        # Delete corresponding roles
        keycloak_adm.delete_role_from_realm(role_name)
        
        # Delete group
        if group_id:
            keycloak_adm.delete_group(group_id['id'])
            return '', 204
        else:
            return jsonify({'error': 'Group not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

"""
Retrieve information about all groups and their members within a specified Keycloak realm.

Endpoint:
GET /identity/groups

Parameters:
- realm (str, query parameter): The name of the Keycloak realm for which group information is requested.

Returns:
- JSON Response: A JSON representation of all groups, including their names, descriptions, members, and administrators.

Description:
This endpoint allows administrators with the 'app-admin' role to retrieve information about all groups within a Keycloak realm. It provides details about each group, including group names, descriptions, group members, and administrators.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm for which group information should be retrieved.

- The function constructs a list of groups and their details by querying the Keycloak Admin API. It iterates through the groups and their sub-groups, compiling information about each group, including members and administrators.

- Groups are structured as follows in the JSON response:
  {
      'name': <group_name>,
      'description': <group_description>,
      'members': [<member_username_1>, <member_username_2>, ...],
      'admins': [<admin_username_1>, <admin_username_2>, ...]
  }

- The 'admins' field contains the usernames of group administrators, including those in the 'administrators' sub-group.

Example Usage:
```http
GET /identity/groups?realm=my_realm
"""
@app.route('/identity/groups/<string:root_path>', methods=['GET'])
@role_required('app-admin')
def get_all_groups(root_path):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        #group_path = "/HIP-dev-projects"
        all_groups = keycloak_adm.get_group_details_from_path(root_path, full_hierarchy=True)

        groups_info = []

        for current_group in all_groups.get('subGroups', []):
            #if '/HIP-dev-projects' in current_group.get('path', '') and '/administrators' not in current_group.get('path', ''):
            if root_path in current_group.get('path', '') and '/administrators' not in current_group.get('path', ''):
                group_info = {
                    'name': current_group.get('name', ''),
                    'isPublic': current_group['attributes'].get('isPublic', ['False'])[0].lower() == 'true',
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

@app.route('/identity/groups/<string:root_path>/users/<string:user_name>', methods=['PUT'])
@role_required('app-admin')
def add_user_to_admin_group(root_path, user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        group_id = keycloak_adm.get_group_details_from_path(root_path)
        keycloak_adm.add_user_to_group(user_name, group_id['id'])

        return '', 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
"""
Add a user to a specified group or its 'administrators' sub-group within a Keycloak realm.

Endpoint:
PUT /identity/groups/<string:group_name>/<string:role_name>/users/<string:user_name>

Parameters:
- group_name (str): The name of the group to which the user should be added.
- role_name (str): The role specifying whether to add the user as a 'member' or an 'admin' of the group.
- user_name (str): The username of the user to be added.
- realm (str, query parameter): The name of the Keycloak realm in which the operation should occur.

Returns:
- HTTP Status Code: 201 Created if the user is successfully added to the group.
- JSON Response with Error: An error message and HTTP status code (400 for bad request or 500 for server error) in case of failure.

Description:

This endpoint allows administrators with the 'app-admin' role to add a user to a specified group or its 'administrators' sub-group within a Keycloak realm. The 'role_name' parameter specifies whether the user should be added as a 'member' or an 'admin' of the group.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm in which the operation should occur.

- The function determines the group's path based on the 'role_name':
  - If 'role_name' is 'member', the user is added to the main group.
  - If 'role_name' is 'admin', the user is added to the 'administrators' sub-group of the specified group.
  - If 'role_name' is neither 'member' nor 'admin', an error response is returned.

- The user is added to the group using the Keycloak Admin API, and a 201 Created status code is returned upon successful addition.

Example Usage:
```http
PUT /identity/groups/my_group/member/users/john_doe?realm=my_realm
"""
@app.route('/identity/groups/<string:root_path>/<string:group_name>/<string:role_name>/users/<string:user_name>', methods=['PUT'])
@role_required('app-admin')
def add_user_to_group(root_path, group_name, role_name, user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        match role_name:
            case 'member':
                group_path = f"{root_path}/{group_name}"
            case 'admin':
                group_path = f"{root_path}/{group_name}/administrators"
            case _:
                return jsonify({'error': 'Role not found, not doing anything'}), 400

        group_id = keycloak_adm.get_group_details_from_path(group_path)
        keycloak_adm.add_user_to_group(user_name, group_id['id'])

        return '', 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

"""
Remove a user from a specified group or its 'administrators' sub-group within a Keycloak realm.

Endpoint:
DELETE /identity/groups/<string:group_name>/<string:role_name>/users/<string:user_name>

Parameters:
- group_name (str): The name of the group from which the user should be removed.
- role_name (str): The role specifying whether to remove the user as a 'member' or an 'admin' of the group.
- user_name (str): The username of the user to be removed.
- realm (str, query parameter): The name of the Keycloak realm in which the operation should occur.

Returns:
- HTTP Status Code: 204 No Content if the user is successfully removed from the group.
- JSON Response with Error: An error message and HTTP status code (400 for bad request or 500 for server error) in case of failure.

Description:
This endpoint allows administrators with the 'app-admin' role to remove a user from a specified group or its 'administrators' sub-group within a Keycloak realm. The 'role_name' parameter specifies whether the user should be removed as a 'member' or an 'admin' of the group.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm in which the operation should occur.

- The function determines the group's path based on the 'role_name':
  - If 'role_name' is 'member', the user is removed from the main group.
  - If 'role_name' is 'admin', the user is removed from the 'administrators' sub-group of the specified group.
  - If 'role_name' is neither 'member' nor 'admin', an error response is returned.

- The user is removed from the group using the Keycloak Admin API, and a 204 No Content status code is returned upon successful removal.

Example Usage:
```http
DELETE /identity/groups/my_group/member/users/john_doe?realm=my_realm
"""
@app.route('/identity/groups/<string:root_path>/<string:group_name>/<string:role_name>/users/<string:user_name>', methods=['DELETE'])
@role_required('app-admin')
def remove_user_from_group(root_path, group_name, role_name, user_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        match role_name:
            case 'member':
                group_path = f"{root_path}/{group_name}"
            case 'admin':
                group_path = f"{root_path}/{group_name}/administrators"
            case _:
                return jsonify({'error': 'Role not found, not doing anything'}), 400

        group_id = keycloak_adm.get_group_details_from_path(group_path)
        keycloak_adm.remove_user_from_group(user_name, group_id['id'])

        return '', 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500
  
"""
Retrieve information about a specific group, including its members and administrators, within a Keycloak realm.

Endpoint:
GET /identity/groups/<string:group_name>

Parameters:
- group_name (str): The name of the group for which information is requested.
- realm (str, query parameter): The name of the Keycloak realm in which the group's information should be retrieved.

Returns:
- JSON Response: A JSON representation of the group's details, including name, description, members, and administrators.

Description:
This endpoint allows administrators with the 'app-admin' role to retrieve detailed information about a specific group within a Keycloak realm. The requested group's information, such as its name, description, group members, and administrators, is returned in a structured JSON format.

- Ensure that the 'role_required' decorator with the 'app-admin' role restriction is applied to limit access to authorized users.

- The 'realm' query parameter specifies the Keycloak realm in which the group's information should be retrieved.

- The function constructs the group's path based on the 'group_name' parameter and retrieves its ID using the Keycloak Admin API.

- If the group is found, its details, including the names of members and administrators, are compiled into a JSON response.

- The 'admins' field contains the usernames of group administrators, including those in the 'administrators' sub-group.

Example Usage:
```http
GET /identity/groups/my_group?realm=my_realm
"""
@app.route('/identity/groups/<string:root_path>/<string:group_name>', methods=['GET'])
@role_required('app-admin')
def get_group_info(root_path, group_name):
    try:
        realm_name = request.args.get('realm')
        keycloak_adm = Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')
        keycloak_adm.switch_realm(realm_name)

        group_path = root_path + f"/{group_name}"
        group_id = keycloak_adm.get_group_details_from_path(group_path)
        group_id_admin = keycloak_adm.get_group_details_from_path(f"{group_path}/administrators")

        if group_id is None:
            return jsonify({'error': 'Group not found'}), 404

        group_info = {
            'title': group_id['name'],
            "isPublic": group_id['attributes'].get('isPublic', ['False'])[0].lower() == 'true',
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
