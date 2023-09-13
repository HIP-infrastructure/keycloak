import pprint
pp = pprint.PrettyPrinter(indent=4)
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

__author__ = "Florian SIPP"
__email__ = "florian.sipp@chuv.ch"

class Hipcloak:
    _kc_admin = None
    
    def __init__(self, server_url=None, username=None, password=None, realm_name='master'):
        keycloak_connection = KeycloakOpenIDConnection(
            server_url=server_url,
            username=username,
            password=password.strip("'"),
            realm_name=realm_name
        )
        self._kc_admin = KeycloakAdmin(connection=keycloak_connection)
        print('Connected to Keycloak server <%s> with realm <%s>' %(server_url, realm_name))

    def switch_realm(self, realm_name):
        self._kc_admin.connection.realm_name = realm_name
        print('Switched to realm <%s>' %(realm_name))

    def create_user(self, user_name, first_name, last_name, user_password, email):
        exists = self._kc_admin.get_user_id(username=user_name)
        if exists is not None:
            #print('User <%s> already exists' %(user_name))
            return None
    
        new_user_id = self._kc_admin.create_user(payload={"username": user_name,
                                                          "enabled": True,
                                                          "emailVerified": True,
                                                          "firstName": first_name,
                                                          "lastName": last_name,
                                                          "email": email,
                                                          "credentials": [{"type": "password", "value": user_password, "temporary": True}]})
        #print('Created user with name <%s>' %(user_name))
        return new_user_id
    
    def delete_user(self, user_name):
        wanted_user_id = self._kc_admin.get_user_id(user_name)
        if wanted_user_id is None:
            #print('User <%s> does not exist' %(user_name))
            return None
        else:
            self._kc_admin.delete_user(user_id=wanted_user_id)
            #print('User <%s> deleted' %(user_name))
            return wanted_user_id

    def get_user(self, user_name):
        wanted_user_id = self._kc_admin.get_user_id(user_name)
        if wanted_user_id is None:
            return None
        else:
            return self._kc_admin.get_user(wanted_user_id)
        
    def add_role_to_realm(self, name, description=''):
        try:
            return self._kc_admin.create_realm_role(payload={"name": name, "description": description})
            #print('Role <%s> created in realm <%s>' %(name, description))
        except Exception as e:
            return None
            #sys.exit('Role <%s> already exist in realm <%s>' %(name, description))

    def delete_role_from_realm(self, name):
        try:
            return self._kc_admin.delete_realm_role(name)
            #print('Role <%s> deleted from realm <%s>' %(name, description))
        except Exception as e:
            return None
            #sys.exit('Role <%s> does not exist in realm <%s>' %(name, description))

    def add_role_to_user(self, user_name, user_role, force_creation=False):
        #Try to get role and if it does not exist, create it if the flag is set to true
        try:
            wanted_role=self._kc_admin.get_realm_role(role_name=user_role)
        except Exception as e:
            if force_creation:
                wanted_role = self._kc_admin.create_realm_role(payload={"name": user_role, "description": ""})
                #print('Role <%s> created' %(user_role))
            else:
                return None
                #sys.exit('Role <%s> does not exist' %(user_role))

        #Try to get user
        try:
            wanted_user_id=self._kc_admin.get_user_id(user_name)
        except Exception as e:
            return None
            #sys.exit('User <%s> does not exist' %(user_name))

        return self._kc_admin.assign_realm_roles(user_id=wanted_user_id, roles=[{"id": wanted_role['id'], "name": wanted_role['name']}])
        #print('Role <%s> added to user <%s>' %(user_role, user_name))

    def remove_role_from_user(self, user_name, user_role):
        #Try to get role and if it does not exist, exit
        try:
            wanted_role=self._kc_admin.get_realm_role(role_name=user_role)
        except Exception as e:
            return None
            #sys.exit('Role <%s> does not exist' %(args['user_role']))

        try:
            wanted_user_id=self._kc_admin.get_user_id(user_name)
            #print('Role <%s> removed from user <%s>' %(args['user_role'], args['user_name']))
        except Exception as e:
            return None
            #sys.exit('User <%s> does not exist' %(args['user_name']))

        return self._kc_admin.delete_realm_roles_of_user(user_id=wanted_user_id, roles=[wanted_role])

    def get_group_for_user(self, user_name):
        try:
            wanted_user_id=self._kc_admin.get_user_id(user_name)
            #print('Role <%s> removed from user <%s>' %(args['user_role'], args['user_name']))
            return self._kc_admin.get_user_groups(wanted_user_id,brief_representation=False)
        except Exception as e:
            return None
            #sys.exit('User <%s> does not exist' %(args['user_name']))

    def get_members_from_group(self, group_id):
        try:
            return self._kc_admin.get_group_members(group_id)
        except Exception as e:
            return None
            #sys.exit('User <%s> does not exist' %(args['user_name']))
    
    def get_group_id_from_path(self, group_path):
        try:
            return self._kc_admin.get_group_by_path(group_path)
        except Exception as e:
            return None
            #sys.exit('User <%s> does not exist' %(args['user_name']))

    #Return group_id for created group or None for an existing froup
    def create_group(self, group_title, parent_name="", isCollab=True):
        payload = {"name": group_title}
        if isCollab:
            if parent_name is "":
                parent_id = self.get_group_id_from_path("/HIP-dev-projects")
            else:
                parent_id = self.get_group_id_from_path("/HIP-dev-projects/" + parent_name)

            return self._kc_admin.create_group(payload, parent_id['id'], True)
        else:
            return self._kc_admin.create_group(payload, None, True)

    def delete_group(self, group_id):
        try:
            return self._kc_admin.delete_group(group_id)
        except Exception as e:
            return None

    def add_user_to_group(self, user_name, group_id):
        user_id = self._kc_admin.get_user_id(user_name)
        return self._kc_admin.group_user_add(user_id, group_id)
    
    def remove_user_from_group(self, user_name, group_id):
        user_id = self._kc_admin.get_user_id(user_name)
        return self._kc_admin.group_user_remove(user_id, group_id)