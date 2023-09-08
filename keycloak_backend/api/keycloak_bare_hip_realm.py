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
        print('Connected to Keycloak server <%s> with realm <%s>' %(args['server_url'], 'master'))

        payload={"realm": args['realm_name'], "displayName": args['realm_name'], 
                 "displayNameHtml": "<div class=\"kc-logo-text\"><span>" + args['realm_name'] + "</span></div>", 
                 "enabled": True, "sslRequired": "all"}

        #Create realm:
        try:
            new_realm=keycloak_adm.create_realm(payload=payload)
            print('Realm <%s> created' %(args['realm_name']))
        except Exception as e:
            sys.exit('Realm <%s> already exists' %(args['realm_name']))

        #Change to wanted realm
        keycloak_adm.connection.realm_name = args['realm_name'] 
        print('Switching to realm <%s>' %(args['realm_name']))

        #Create client scopes :        
        group_clientScope_id = keycloak_adm.create_client_scope(payload={"name": "group",
                                                                            "description":"",
                                                                            "protocol":"openid-connect",
                                                                            "attributes":{
                                                                                "include.in.token.scope":"true",
                                                                                "display.on.consent.screen":"true",
                                                                                "consent.screen.text":""
                                                                            },
                                                                            "protocolMappers":[
                                                                            {
                                                                                "name":"username",
                                                                                "protocol":"openid-connect",
                                                                                "protocolMapper":"oidc-usermodel-attribute-mapper",
                                                                                "consentRequired": False,
                                                                                "config":{
                                                                                    "aggregate.attrs": "true",
                                                                                    "userinfo.token.claim": "true",
                                                                                    "multivalued": "false",
                                                                                    "user.attribute": "username",
                                                                                    "id.token.claim": "true",
                                                                                    "access.token.claim": "true",
                                                                                    "claim.name": "preferred_username",
                                                                                    "jsonType.label": "String"
                                                                                }
                                                                            },
                                                                            {
                                                                                "name":"groups",
                                                                                "protocol":"openid-connect",
                                                                                "protocolMapper":"oidc-usermodel-realm-role-mapper",
                                                                                "consentRequired": False,
                                                                                'config': {
                                                                                    "multivalued": "true",
                                                                                    "userinfo.token.claim": "true",
                                                                                    "id.token.claim": "true",
                                                                                    "access.token.claim": "true",
                                                                                    "claim.name": "roles.group",
                                                                                    "jsonType.label": "String"
                                                                                }
                                                                            }]})
        
        team_clientScope_id = keycloak_adm.create_client_scope(payload={"name": "team",
                                                                        "description":"",
                                                                        "protocol":"openid-connect",
                                                                        "attributes":{
                                                                            "include.in.token.scope":"true",
                                                                            "display.on.consent.screen":"true",
                                                                            "consent.screen.text":""
                                                                        }})
        
        print('Client scopes group and team created')
        
        #Set assigned type for group scope to default 
        keycloak_adm.add_default_default_client_scope(group_clientScope_id)
        print('Client scope group assigned type set as default')

        #Create client :        
        new_client_id = keycloak_adm.create_client(payload={"clientId": "hip_dev",
                                                            "name": "${client_hip_dev}",
                                                            "description": "",
                                                            "rootUrl": "",
                                                            "adminUrl": "",
                                                            "baseUrl": "https://dev.thehip.app/",
                                                            "surrogateAuthRequired": False,
                                                            "enabled": True,
                                                            "alwaysDisplayInConsole": False,
                                                            "clientAuthenticatorType": "client-secret",
                                                            "secret": "nHJmP0EByjSOQmqsHhgY5zxJhxHig6Sh",
                                                            "redirectUris": [
                                                                "https://dev.thehip.app/*",
                                                                "https://cpu1.thehip.app/*",
                                                                "https://dev.thehip.app/apps/sociallogin/custom_oidc/keycloak3.thehip.app"
                                                            ],
                                                            "webOrigins": [
                                                                "https://dev.thehip.app",
                                                                "https://cpu1.thehip.app"
                                                            ],
                                                            "notBefore": 0,
                                                            "bearerOnly": False,
                                                            "consentRequired": False,
                                                            "standardFlowEnabled": True,
                                                            "implicitFlowEnabled": False,
                                                            "directAccessGrantsEnabled": True,
                                                            "serviceAccountsEnabled": True,
                                                            "authorizationServicesEnabled": True,
                                                            "publicClient": False,
                                                            "frontchannelLogout": True,
                                                            "protocol": "openid-connect",
                                                            "defaultClientScopes": [
                                                                "web-origins",
                                                                "acr",
                                                                "profile",
                                                                "roles",
                                                                "team",
                                                                "email",
                                                                "group"
                                                            ],
                                                            "optionalClientScopes": [
                                                                "address",
                                                                "phone",
                                                                "offline_access",
                                                                "microprofile-jwt"
                                                            ]})
        print('Client hip_dev created')
    
        #add group scope as default client scope for the hip client
        keycloak_adm.add_client_default_client_scope(client_id=new_client_id, 
                                                     client_scope_id=group_clientScope_id, 
                                                     payload={
                                                        "realm":args['realm_name'],
                                                        "client":new_client_id,
                                                        "clientScopeId":group_clientScope_id
                                                    })

    except Exception as e:
        sys.exit(e)

if __name__ == '__main__':
    main()