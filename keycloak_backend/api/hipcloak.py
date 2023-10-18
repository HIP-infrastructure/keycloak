import pprint
pp = pprint.PrettyPrinter(indent=4)
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

__author__ = "Florian SIPP"
__email__ = "florian.sipp@chuv.ch"

class Hipcloak:
    _kc_admin = None
    
    def __init__(self, server_url=None, username=None, password=None, realm_name='master'):
        """
        Initialize the Hipcloak class with a connection to Keycloak.

        Args:
            server_url (str): The Keycloak server URL.
            username (str): The username for authentication.
            password (str): The password for authentication.
            realm_name (str): The name of the realm to work with (default is 'master').

        Returns:
            None
        """
        keycloak_connection = KeycloakOpenIDConnection(
            server_url=server_url,
            username=username,
            password=password.strip("'"),
            realm_name=realm_name
        )
        self._kc_admin = KeycloakAdmin(connection=keycloak_connection)
        print('Connected to Keycloak server <%s> with realm <%s>' %(server_url, realm_name))

    def switch_realm(self, realm_name):
        """
        Switch the current realm for the Keycloak Admin connection.

        Args:
            realm_name (str): The name of the realm to switch to.

        Returns:
            None
        """
        try:
            realms = self._kc_admin.get_realms()
            if realm_name not in [realm['realm'] for realm in realms]:
                raise ValueError(f"Realm '{realm_name}' does not exist.")

            self._kc_admin.connection.realm_name = realm_name
            print(f'Switched to realm: {realm_name}')
        except KeyError as e:
            print(f"Error: Missing 'realm_name' parameter.")
        except ValueError as e:
            print(str(e))
        except Exception as e:
            print(f"Error while switching realm: {str(e)}")

    def create_user(self, user_name, first_name, last_name, user_password, email):
        """
        Create a new user in the Keycloak realm with the provided information.

        Args:
            user_name (str): The username for the new user.
            first_name (str): The first name of the new user.
            last_name (str): The last name of the new user.
            user_password (str): The initial password for the new user.
            email (str): The email address of the new user.

        Returns:
            str or None: The ID of the newly created user if successful, or None if an error occurs.

        Note:
            This function checks if a user with the same username already exists in the realm.
            If the user already exists, it prints a message and returns None.
            If the user does not exist, it creates a new user with the provided information and returns the user's ID.
            Passwords are initially set as temporary, and users will be prompted to change them upon login.
        """
        try:
            existing_user_id = self._kc_admin.get_user_id(username=user_name)
            if existing_user_id is not None:
                print(f"User '{user_name}' already exists.")
                return None
        
            new_user_payload={
                "username": user_name,
                "enabled": True,
                "emailVerified": True,
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "credentials": [{"type": "password", "value": user_password, "temporary": True}]}
            
            new_user_id = self._kc_admin.create_user(payload=new_user_payload)
            return new_user_id
        except Exception as e:
            print(f"Error creating user '{user_name}': {str(e)}")
            return None
    
    def delete_user(self, user_name):
        """
        Delete a user from the Keycloak realm by their username.

        Args:
            user_name (str): The username of the user to be deleted.

        Returns:
            str or None: The ID of the deleted user if successful, or None if the user does not exist or an error occurs.

        Note:
            This function first checks if a user with the provided username exists in the realm.
            If the user exists, it deletes the user and returns the user's ID.
            If the user does not exist, it prints a message and returns None.
        """
        try:
            wanted_user_id = self._kc_admin.get_user_id(user_name)
            if wanted_user_id is None:
                print(f"User '{user_name}' does not exist.")
                return None

            self._kc_admin.delete_user(user_id=wanted_user_id)
            print(f"User '{user_name}' deleted.")
            return wanted_user_id
        except Exception as e:
            print(f"Error deleting user '{user_name}': {str(e)}")
            return None

    def get_user(self, user_name):
        """
        Retrieve user details from the Keycloak realm by their username.

        Args:
            user_name (str): The username of the user whose details are to be retrieved.

        Returns:
            dict or None: A dictionary containing user details if the user exists, or None if the user does not exist or an error occurs.

        Note:
            This function retrieves the ID of the user by their username and then fetches their details.
            If the user exists, it returns a dictionary with user details.
            If the user does not exist, it prints a message and returns None.
        """
        try:
            wanted_user_id = self._kc_admin.get_user_id(user_name)
            
            if wanted_user_id is None:
                print(f"User '{user_name}' does not exist.")
                return None

            user_details = self._kc_admin.get_user(wanted_user_id)
            return user_details
        except Exception as e:
            print(f"Error retrieving user '{user_name}' details: {str(e)}")
            return None

    def get_groups_for_user(self, user_name):
        """
        Retrieve the groups to which a user belongs in the Keycloak realm by their username.

        Args:
            user_name (str): The username of the user whose groups are to be retrieved.

        Returns:
            list or None: A list of groups that the user belongs to if the user exists, or None if the user does not exist or an error occurs.

        Note:
            This function retrieves the ID of the user by their username and then fetches the groups they belong to.
            If the user exists, it returns a list of groups.
            If the user does not exist, it prints a message and returns None.
        """
        try:
            wanted_user_id = self._kc_admin.get_user_id(user_name)
            
            if wanted_user_id is None:
                print(f"User '{user_name}' does not exist.")
                return None

            user_groups = self._kc_admin.get_user_groups(wanted_user_id, brief_representation=False)
            return user_groups
        except Exception as e:
            print(f"Error retrieving groups for user '{user_name}': {str(e)}")
            return None

    def get_members_from_group(self, group_id):
        """
        Retrieve the members of a group in the Keycloak realm by the group's ID.

        Args:
            group_id (str): The ID of the group whose members are to be retrieved.

        Returns:
            list or None: A list of group members if the group exists, or None if the group does not exist or an error occurs.

        Note:
            This function retrieves the members of a group in the Keycloak realm using the group's ID.
            If the group exists, it returns a list of group members.
            If the group does not exist, it prints a message and returns None.
        """
        try:
            group_members = self._kc_admin.get_group_members(group_id)
            return group_members
        except Exception as e:
            print(f"Error retrieving members for group '{group_id}': {str(e)}")
            return None
    
    def get_group_details_from_path(self, group_path):
        """
        Retrieve details of a group in the Keycloak realm by its path.

        Args:
            group_path (str): The path of the group whose details are to be retrieved.

        Returns:
            dict or None: A dictionary containing group details if the group exists, or None if the group does not exist or an error occurs.

        Note:
            This function retrieves the details of a group in the Keycloak realm using its path.
            If the group exists, it returns a dictionary with group details.
            If the group does not exist, it prints a message and returns None.
        """
        try:
            group_info = self._kc_admin.get_group_by_path(group_path)
            if group_info:
                return group_info
            else:
                print(f"Group not found at path '{group_path}'.")
                return None
        except Exception as e:
            print(f"Error retrieving group details from path '{group_path}': {str(e)}")
            return None

    def create_group(self, group_title, parent_name="", isCollab=True):
        """
        Create a new group in the Keycloak realm with the provided information.

        Args:
            group_title (str): The title or name of the new group.
            parent_name (str, optional): The name of the parent group (if any) where the new group will be created. Default is an empty string.
            isCollab (bool, optional): A flag indicating whether the group is a collaborative group. Default is True.

        Returns:
            dict or None: A dictionary containing group details if the group is successfully created, or None if an error occurs.
        """
        try:
            payload = {"name": group_title}

            if isCollab:
                if not parent_name:
                    parent_id = self.get_group_details_from_path("/HIP-dev-projects")
                else:
                    parent_id = self.get_group_details_from_path("/HIP-dev-projects/" + parent_name)
                if parent_id:
                    return self._kc_admin.create_group(payload, parent_id['id'], True)
                else:
                    print(f"Parent group '{parent_name}' not found.")
                    return None
            else:
                return self._kc_admin.create_group(payload, None, True)
        except Exception as e:
            print(f"Error creating group '{group_title}': {str(e)}")
            return None

    def delete_group(self, group_id):
        """
        Delete a group from the Keycloak realm by its ID.

        Args:
            group_id (str): The ID of the group to be deleted.

        Returns:
            bool: True if the group is successfully deleted, False otherwise.
        """
        try:
            delete_result = self._kc_admin.delete_group(group_id)
            print(delete_result)
            if delete_result:
                print(f"Group with ID '{group_id}' deleted successfully.")
                return True
            else:
                print(f"Failed to delete group with ID '{group_id}'.")
                return False
        except Exception as e:
            print(f"Error deleting group with ID '{group_id}': {str(e)}")
            return False

    def add_user_to_group(self, user_name, group_id):
        """
        Add a user to a group in the Keycloak realm by their username and the group's ID.

        Args:
            user_name (str): The username of the user to be added to the group.
            group_id (str): The ID of the group where the user will be added.

        Returns:
            bool: True if the user is successfully added to the group, False otherwise.
        """
        try:
            user_id = self._kc_admin.get_user_id(user_name)
            
            if user_id is None:
                print(f"User '{user_name}' does not exist.")
                return False

            self._kc_admin.group_user_add(user_id, group_id)
            print(f"User '{user_name}' added to group with ID '{group_id}'.")
            return True
        except Exception as e:
            print(f"Error adding user '{user_name}' to group with ID '{group_id}': {str(e)}")
            return False
    
    def remove_user_from_group(self, user_name, group_id):
        """
        Remove a user from a group in the Keycloak realm by their username and the group's ID.

        Args:
            user_name (str): The username of the user to be removed from the group.
            group_id (str): The ID of the group from which the user will be removed.

        Returns:
            bool: True if the user is successfully removed from the group, False if the user or group does not exist or an error occurs.

        Note:
            This function removes a user from a group in the Keycloak realm using their username and the group's ID.
            If the user and group both exist, and the user is successfully removed, it returns True.
            If the user or group does not exist or an error occurs during the operation, it prints a message and returns False.
        """
        try:
            user_id = self._kc_admin.get_user_id(user_name)
            
            if user_id is None:
                print(f"User '{user_name}' does not exist.")
                return False

            success = self._kc_admin.group_user_remove(user_id, group_id)
            if success:
                print(f"User '{user_name}' removed from group with ID '{group_id}'.")
            else:
                print(f"Failed to remove user '{user_name}' from group with ID '{group_id}'.")

            return success
        except Exception as e:
            print(f"Error removing user '{user_name}' from group with ID '{group_id}': {str(e)}")
            return False
    
    def add_role_to_realm(self, name, description=''):
        """
        Add a realm role to the Keycloak realm by its name and optional description.

        Args:
            name (str): The name of the realm role to be added.
            description (str, optional): A description for the realm role. Default is an empty string.

        Returns:
            dict or None: A dictionary containing the created realm role details if the role is successfully added,
            or None if the role already exists or an error occurs.
        """
        try:
            role = None
            try:
                role = self._kc_admin.get_realm_role(role_name=name)
            except Exception as e:
                if role:
                    print(f"Realm role '{name}' already exists.")
                    return None
        
            role_data = {"name": name, "description": description}
            created_role = self._kc_admin.create_realm_role(payload=role_data)

            if created_role:
                print(f"Realm role '{name}' added successfully.")
                return created_role
            else:
                print(f"Failed to add realm role '{name}'.")
                return None

        except Exception as e:
            print(f'An error occurred: {e}')
            return None

    def delete_role_from_realm(self, name):
        """
        Delete a realm role from the Keycloak realm by its name.

        Args:
            name (str): The name of the realm role to be deleted.

        Returns:
            bool or None: True if the realm role is successfully deleted, None if the role does not exist or an error occurs.
        """
        try:
            self._kc_admin.delete_realm_role(name)            
            print(f'Role "{name}" deleted from the realm.')
            return True
        except Exception as e:
            print(f'An error occurred: {e}')
            return None

    def add_role_to_user(self, user_name, user_role, force_creation=False):
        """
        Add a realm role to a user in the Keycloak realm by their username.

        Args:
            user_name (str): The username of the user to whom the realm role will be added.
            user_role (str): The name of the realm role to be added.
            force_creation (bool, optional): A flag indicating whether to create the realm role if it does not exist. Default is False.

        Returns:
            dict or None: A dictionary containing the result if the role is successfully added to the user, or None if an error occurs.
        """
        try:
            wanted_role = self._kc_admin.get_realm_role(role_name=user_role)

            if not wanted_role and force_creation:
                wanted_role = self._kc_admin.create_realm_role(payload={"name": user_role, "description": ""})
                print(f'Realm role "{user_role}" created.')

            if not wanted_role:
                print(f'Realm role "{user_role}" does not exist.')
                return None

            wanted_user_id = self._kc_admin.get_user_id(user_name)

            if not wanted_user_id:
                print(f'User "{user_name}" does not exist.')
                return None

            result = self._kc_admin.assign_realm_roles(user_id=wanted_user_id, roles=[{"id": wanted_role['id']}])
            print(f'Realm role "{user_role}" added to user "{user_name}".')
            return result

        except Exception as e:
            error_message = f'An error occurred: {e}'
            print(error_message)
            return None

    def remove_role_from_user(self, user_name, user_role):
        """
        Remove a realm role from a user in the Keycloak realm by their username.

        Args:
            user_name (str): The username of the user from whom the realm role will be removed.
            user_role (str): The name of the realm role to be removed.

        Returns:
            bool or None: True if the realm role is successfully removed from the user, False if the role was not assigned to the user, None if the user or role does not exist or an error occurs.
        """
        try:
            wanted_role = self._kc_admin.get_realm_role(role_name=user_role)
            wanted_user_id = self._kc_admin.get_user_id(user_name)

            if not wanted_role:
                print(f'Realm role "{user_role}" does not exist.')
                return None

            if not wanted_user_id:
                print(f'User "{user_name}" does not exist.')
                return None

            result = self._kc_admin.delete_realm_roles_of_user(user_id=wanted_user_id, roles=[wanted_role])

            if result:
                print(f'Realm role "{user_role}" removed from user "{user_name}".')
            else:
                print(f'Realm role "{user_role}" was not assigned to user "{user_name}".')
            
            return result

        except Exception as e:
            error_message = f'An error occurred: {e}'
            print(error_message)
            return None

    def add_role_to_group(self, grouppp_id, role):
        try:
            roleeeee = self._kc_admin.get_realm_role(role_name=role)
            result = self._kc_admin.assign_group_realm_roles(group_id=grouppp_id, roles=roleeeee)
            print(result)
            return result
        
        except Exception as e:
            error_message = f'An error occurred: {e}'
            print(error_message)
            return None
        
    def remove_role_from_group(self, group_id, role):
        wanted_role = self._kc_admin.get_realm_role(role_name=role)
        if not wanted_role:
            print(f'Realm role "{role}" does not exist.')
            return None
        else:
            result = self._kc_admin.delete_group_realm_roles(group_id=group_id['id'], roles=wanted_role)
            return result
    