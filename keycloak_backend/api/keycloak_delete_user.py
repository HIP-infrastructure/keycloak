import os
import sys
import json
import select
import pprint
import argparse

pp = pprint.PrettyPrinter(indent=4)

from keycloak.exceptions import raise_error_from_response, KeycloakGetError
from keycloak.urls_patterns import URL_ADMIN_CLIENT_ROLE
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

_author_ = "Florian SIPP"
_email_ = "florian.sipp@chuv.ch"

def main():
    argsparser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    argsparser.add_argument('-l', '--server-url', dest='server_url', default='https://keycloak.thehip.app', help='Keycloak server base URL', type=str)
    argsparser.add_argument('-u', '--admin-username', dest='admin_username', default='admin', help='Keycloak Realm Administrator username', type=str)
    argsparser.add_argument('-p', '--admin-password', dest='admin_password', help='Keycloak Realm Administrator password', type=str)
    argsparser.add_argument('-r', '--realm-name', dest='realm_name', default='hip', help='Keycloak Realm name to target', type=str)
    argsparser.add_argument('-k', '--user-name', dest='user_name', help='Username for the user', type=str)
    argsparser.add_argument('-v', dest='verbose_level', action='count', default=0, help='Verbose level')

    args = argsparser.parse_args()
    args = vars(args)

    params_keys = []
    for key in args.keys():
        params_keys.append(key)
    for key in params_keys:
        if args[key] is None or args[key] == '':
            args.pop(key)

    for arg in ['server_url', 'realm_name', 'admin_username', 'admin_password']:
        if arg not in args:
            sys.exit('Missing required argument: <%s>' %(arg))

    try:
        keycloak_connection = KeycloakOpenIDConnection(
                                server_url=args['server_url'], 
                                username=args['admin_username'], 
                                password=args['admin_password'], 
                                realm_name='master', 
                                verify=True)       
        keycloak_adm = KeycloakAdmin(connection=keycloak_connection)

        keycloak_adm.connection.realm_name = args['realm_name'] # Change to wanted realm
        print('Connected to Keycloak server <%s> with realm <%s>' %(args['server_url'], args['realm_name']))

        wanted_user_id = keycloak_adm.get_user_id(args['user_name'])
        if wanted_user_id==None:
            sys.exit('User <%s> does not exist' %(args['user_name']))
        else:
            keycloak_adm.delete_user(user_id=wanted_user_id)
            print('User <%s> deleted' %(args['user_name']))

    except Exception as e:
        sys.exit(e)

if __name__ == '__main__':
    main()