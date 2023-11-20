import os
import sys
import json
import yaml
import pathlib
import argparse

from dotenv import load_dotenv
from hipcloak import Hipcloak
from auth import *

def read_config_file(file_path):
    with open(file_path, 'r') as file:
        config_data = yaml.safe_load(file)
    return config_data

def connect_to_master_realm():
    server_url = get_domain()
    admin_username = os.getenv("KEYCLOAK_ADMIN")
    admin_password = os.getenv("KEYCLOAK_ADMIN_PASSWORD")

    return Hipcloak(server_url=server_url, username=admin_username, password=admin_password, realm_name='master')

def create_client_scope(keycloak_adm, scope_payload):
    scope_id = keycloak_adm._kc_admin.create_client_scope(scope_payload)
    keycloak_adm._kc_admin.add_default_default_client_scope(scope_id)
    return scope_id

def add_default_client_scope(keycloak_adm, client_id, client_scope_id, realm_name):
    keycloak_adm._kc_admin.add_client_default_client_scope(client_id=client_id,
                                                          client_scope_id=client_scope_id,
                                                          payload={
                                                              "realm": realm_name,
                                                              "client": client_id,
                                                              "clientScopeId": client_scope_id
                                                          })

def generate_idp_payload(config_data):
    idp_payload = {
        "alias": config_data['identity_provider']['alias'],
        "displayName": config_data['identity_provider']['displayName'],
        "providerId": "keycloak-oidc",
        "enabled": True,
        "updateProfileFirstLoginMode": "on",
        "trustEmail": False,
        "storeToken": True,
        "addReadTokenRoleOnCreate": True,
        "authenticateByDefault": False,
        "linkOnly": False,
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {
            "userInfoUrl": config_data['identity_provider']['userInfoUrl'],
            "validateSignature": "true",
            "hideOnLoginPage": "false",
            "tokenUrl": config_data['identity_provider']['tokenUrl'],
            "acceptsPromptNoneForwardFromClient": "false",
            "clientId": config_data['identity_provider']['clientId'],
            "uiLocales": "false",
            "jwksUrl": config_data['identity_provider']['jwksUrl'],
            "backchannelSupported": "false",
            "issuer": config_data['identity_provider']['issuer'],
            "useJwksUrl": "true",
            "loginHint": "false",
            "pkceEnabled": "false",
            "clientAuthMethod": "client_secret_post",
            "authorizationUrl": config_data['identity_provider']['authorizationUrl'],
            "disableUserInfo": "false",
            "logoutUrl": config_data['identity_provider']['logoutUrl'],
            "syncMode": "FORCE",
            "clientSecret": config_data['identity_provider']['clientSecret'],
            "passMaxAge": "false",
            "allowedClockSkew": "0",
            "defaultScope": "openid email profile group roles team",
            "guiOrder": "",
            "clientAssertionSigningAlg": "",
            "prompt": "",
            "forwardParameters": ""
        },
        "postBrokerLoginFlowAlias": ""
    }
    return idp_payload

def generate_client_payload(yaml_data):
    # Extracting parameters from the YAML data
    realm_name = yaml_data['realm']['name']
    client_data = yaml_data['client']

    # Creating the client payload
    client_creation_payload = {
        "clientId": client_data['clientId'],
        "name": client_data['name'],
        "description": "",
        "rootUrl": "",
        "adminUrl": "",
        "baseUrl": client_data['baseUrl'],
        "surrogateAuthRequired": False,
        "enabled": client_data['enabled'],
        "alwaysDisplayInConsole": False,
        "clientAuthenticatorType": "client-secret",
        "secret": client_data['secret'],
        "redirectUris": client_data['redirectUris'],
        "webOrigins": client_data['webOrigins'],
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
        "attributes": {
            "post.logout.redirect.uris": "+",
            "oauth2.device.authorization.grant.enabled": "false",
            "backchannel.logout.revoke.offline.tokens": "false",
            "use.refresh.tokens": "false",
            "oidc.ciba.grant.enabled": "false",
            "backchannel.logout.session.required": "true",
            "client_credentials.use_refresh_token": "false",
            "tls.client.certificate.bound.access.tokens": "false",
            "require.pushed.authorization.requests": "false",
            "acr.loa.map": "{}",
            "display.on.consent.screen": "false",
            "token.response.type.bearer.lower-case": "false",
            "login_theme": "",
            "frontchannel.logout.url": "",
            "backchannel.logout.url": ""
        },
        "authenticationFlowBindingOverrides": {},
        "fullScopeAllowed": True,
        "nodeReRegistrationTimeout": -1,
        "protocolMappers": [
            {
                "name": "Client IP Address",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "consentRequired": False,
                "config": {
                    "user.session.note": "clientAddress",
                    "userinfo.token.claim": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "clientAddress",
                    "jsonType.label": "String"
                }
            },
            {
                "name": "Client Host",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "consentRequired": False,
                "config": {
                    "user.session.note": "clientHost",
                    "userinfo.token.claim": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "clientHost",
                    "jsonType.label": "String"
                }
            },
            {
                "name": "Client ID",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "consentRequired": False,
                "config": {
                    "user.session.note": "client_id",
                    "userinfo.token.claim": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "client_id",
                    "jsonType.label": "String"
                }
            }
        ],
        "defaultClientScopes": [
            "web-origins",
            "acr",
            "address",
            "phone",
            "offline_access",
            "profile",
            "roles",
            "team",
            "microprofile-jwt",
            "email",
            "group"
        ],
        "optionalClientScopes": [],
        "access": {
            "view": True,
            "configure": True,
            "manage": True
        }
    }

    return client_creation_payload

def create_service_client_payload(yaml_data):
    # Extracting parameters from the YAML data
    realm_name = yaml_data['realm']['name']
    service_client_data = yaml_data['service_client']

    # Creating the service client payload
    service_client_creation_payload = {
        "clientId": service_client_data['clientId'],
        "name": service_client_data['name'],
        "description": "",
        "rootUrl": service_client_data['rootUrl'],
        "adminUrl": "",
        "baseUrl": "",
        "surrogateAuthRequired": False,
        "enabled": service_client_data['enabled'],
        "alwaysDisplayInConsole": False,
        "clientAuthenticatorType": "client-secret",
        "secret": service_client_data['secret'],
        "redirectUris": service_client_data['redirectUris'],
        "webOrigins": service_client_data['webOrigins'],
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
        "attributes": {
            "oauth2.device.authorization.grant.enabled": "false",
            "backchannel.logout.revoke.offline.tokens": "false",
            "use.refresh.tokens": "false",
            "oidc.ciba.grant.enabled": "false",
            "backchannel.logout.session.required": "true",
            "client_credentials.use_refresh_token": "false",
            "tls.client.certificate.bound.access.tokens": "false",
            "require.pushed.authorization.requests": "false",
            "acr.loa.map": "{}",
            "display.on.consent.screen": "false",
            "token.response.type.bearer.lower-case": "false",
            "login_theme": "",
            "frontchannel.logout.url": "",
            "backchannel.logout.url": ""
        },
        "authenticationFlowBindingOverrides": {},
        "fullScopeAllowed": True,
        "nodeReRegistrationTimeout": -1,
        "protocolMappers": [
            {
                "name": "Client ID",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "consentRequired": False,
                "config": {
                    "user.session.note": "client_id",
                    "userinfo.token.claim": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "client_id",
                    "jsonType.label": "String"
                }
            },
            {
                "name": "Client IP Address",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "consentRequired": False,
                "config": {
                    "user.session.note": "clientAddress",
                    "userinfo.token.claim": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "clientAddress",
                    "jsonType.label": "String"
                }
            },
            {
                "name": "Client Host",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "consentRequired": False,
                "config": {
                    "user.session.note": "clientHost",
                    "userinfo.token.claim": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "clientHost",
                    "jsonType.label": "String"
                }
            }
        ],
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
        ],
        "access": {
            "view": True,
            "configure": True,
            "manage": True
        }
    }

    return service_client_creation_payload

def add_idp_to_realm(yaml_file):
    print('Add_idp_to_realm :')
    print('')
    config_data = read_config_file(yaml_file)
    realm_name = config_data['realm']['name']

    keycloak_adm = connect_to_master_realm()
    keycloak_adm.switch_realm(realm_name)

    idp_payload=generate_idp_payload(config_data)
    keycloak_adm._kc_admin.create_idp(idp_payload)
    print('')

def create_center(keycloak_adm, center_name):
    # Check and create group
    group_id = None
    groups = keycloak_adm._kc_admin.get_groups()
    for group in groups:
        if group['name'] == center_name:
            group_id = group['id']
            break

    if not group_id:
        group_id = keycloak_adm._kc_admin.create_group({'name': center_name})

    # Check and create role
    roles = keycloak_adm._kc_admin.get_realm_roles()
    role_exists = any(role['name'] == center_name for role in roles)

    if not role_exists:
        keycloak_adm._kc_admin.create_realm_role({'name': center_name, 'clientRole': False})

    # Add role to group
    role = keycloak_adm._kc_admin.get_realm_role(center_name)
    keycloak_adm._kc_admin.assign_group_realm_roles(group_id, [role])

    print(f"Group '{center_name}' and role '{center_name}' created and role assigned to the group.")

def create_center_mapper_idp(keycloak_adm, center_name, idp_alias):
    mapper_payload={
        "name": center_name,
        "config": {
            "group": "/" + center_name,
            "claim": "roles.group",
            "claim.value": center_name,
            "jsonType.label": "String",
            "syncMode": "INHERIT",
            "are.claim.values.regex": False,
            "claims": "[{\"key\":\"roles.group\",\"value\":\""+center_name+"\"}]"
        },
        "identityProviderMapper": "oidc-advanced-group-idp-mapper",
        "identityProviderAlias": idp_alias
    }

    keycloak_adm._kc_admin.add_mapper_to_idp(idp_alias, mapper_payload)
    print(f"Mapper '{center_name}' created and added to idp")

def add_center_to_realm(values):
    print("Add_center_to_realm :")
    print('')
    realm, center = values
    keycloak_adm = connect_to_master_realm()
    keycloak_adm.switch_realm(realm)
    create_center(keycloak_adm, center)
    print('')

def redeploy_full_realm(yaml_file):
    print("Redeploy_full_realm :")
    print('')
    config_data = read_config_file(yaml_file)
    realm_name =config_data['realm']['name']

    #Connect to master realm
    keycloak_adm = connect_to_master_realm()

    #Create and switch to realm:
    keycloak_adm.create_realm(realm_name)
    keycloak_adm.switch_realm(realm_name)

    #Create group client scope :
    group_client_scope_payload={"name": "group",
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
                                },
                                {
                                    "name":"groups2",
                                    "protocol":"openid-connect",
                                    "protocolMapper":"oidc-group-membership-mapper",
                                    "consentRequired": False,
                                    'config': {
                                        "access.token.claim": "true",
                                        "claim.name": "group",
                                        "full.path": "false",
                                        "id.token.claim": "true",
                                        "userinfo.token.claim": "true"
                                    }
                                }]}                       
    group_clientScope_id = create_client_scope(keycloak_adm, group_client_scope_payload)

    #Create team client scope :
    team_client_scope_payload={"name": "team",
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
                                    "name":"client roles",
                                    "protocol":"openid-connect",
                                    "protocolMapper":"oidc-usermodel-client-role-mapper",
                                    "consentRequired": False,
                                    "config":{
                                        "access.token.claim": "true",
                                        "claim.name": "resource_access.${client_id}.roles",
                                        "id.token.claim": "true",
                                        "jsonType.label": "String",
                                        "multivalued": "true",
                                        "userinfo.token.claim": "true",
                                        "usermodel.clientRoleMapping.clientId": "",
                                        "usermodel.clientRoleMapping.rolePrefix": ""
                                    }
                                },
                                {
                                    "name": "groups",
                                    "protocol": "openid-connect",
                                    "protocolMapper": "oidc-usermodel-realm-role-mapper",
                                    "consentRequired": False,
                                    "config": {
                                        "multivalued": "true",
                                        "userinfo.token.claim": "true",
                                        "id.token.claim": "true",
                                        "access.token.claim": "true",
                                        "claim.name": "groups",
                                        "jsonType.label": "String"
                                    }
                                },
                                {
                                    "name": "realm roles",
                                    "protocol": "openid-connect",
                                    "protocolMapper": "oidc-usermodel-realm-role-mapper",
                                    "consentRequired": False,
                                    "config": {
                                        "multivalued": "true",
                                        "userinfo.token.claim": "true",
                                        "id.token.claim": "true",
                                        "access.token.claim": "true",
                                        "claim.name": "realm_access.roles",
                                        "jsonType.label": "String"
                                    }
                                }]}
    team_clientScope_id = create_client_scope(keycloak_adm, team_client_scope_payload)
    print('Client scopes group and team created')

    #create client for private and public spaces (hip_dev and hip_service_dev for instance) and attribute role 
    #app-admin to the service accounts roles of the service client (hip_service_dev)
    client_creation_payload=generate_client_payload(config_data)
    new_client_id = keycloak_adm._kc_admin.create_client(client_creation_payload)

    service_client_creation_payload=create_service_client_payload(config_data)
    new_service_client_id = keycloak_adm._kc_admin.create_client(service_client_creation_payload)
    print('Client and service client created')

    #Add app-admin role to service account role
    service_account_name="service-account-"+config_data['service_client']['clientId']
    keycloak_adm.add_role_to_user(user_name=service_account_name, user_role="app-admin", force_creation=True)
    print("Should have added app-admin to service account")

    #add group scope as default client scope for the hip client
    add_default_client_scope(keycloak_adm, client_id=new_client_id, client_scope_id=group_clientScope_id, realm_name=realm_name)
    add_default_client_scope(keycloak_adm, client_id=new_service_client_id, client_scope_id=team_clientScope_id, realm_name=realm_name)

    #Create the centers 
    for group_config in config_data['groups']:
        group_name = group_config['name']
        create_center(keycloak_adm, group_name)

    #create an identity provider
    idp_payload=generate_idp_payload(config_data)
    keycloak_adm._kc_admin.create_idp(idp_payload)

    for group_config in config_data['groups']:
        group_name = group_config['name']
        create_center_mapper_idp(keycloak_adm, group_name, config_data['identity_provider']['alias'])

    print("new realm has been installed")
    print('')

def main():
    argsparser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    argsparser.add_argument('-r', '--redeploy', help='Redeploy a full realm with everything from yaml file')
    argsparser.add_argument('-i', '--idp', help='Add an identity provider according to info in yaml file')
    argsparser.add_argument('-c', '--center', nargs=2, type=str, help="Add a center to a realm. 2 Parameters, realm then center.")
    
    args = argsparser.parse_args()

    #load env vars
    ENV_PATH = pathlib.Path(__file__).parent.parent
    load_dotenv(ENV_PATH.joinpath("keycloak_backend.env"))
    load_dotenv(ENV_PATH.joinpath("../.env"))

    if args.redeploy:
        redeploy_full_realm(args.redeploy)
    elif args.idp:
        add_idp_to_realm(args.idp)
    elif args.center:
        add_center_to_realm(args.center)

if __name__ == '__main__':
    main()