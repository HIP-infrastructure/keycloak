# Keycloak

Keycloak install and backend API to manage groups CRUD in Keycloak

## Keycloak Install

- Copy the .env.template to .env
- `docker-compose up -d`

## Keycloak Backend Flask Application

### Install

- `install_keycloak_backend.sh`

### Overview

This Flask application serves as a backend service for managing user accounts, groups, and group memberships in a Keycloak identity and access management system. It provides a RESTful API for creating, deleting, and retrieving user and group information within specified Keycloak realms.

### Features

- **User Management**: Create and delete user accounts in Keycloak.
- **Group Management**: Create and delete groups, including 'administrators' sub-groups.
- **Group Membership Retrieval**: Retrieve detailed information about user group memberships.
- **User Information Retrieval**: Get detailed information about user accounts, including group memberships and administrator status.
- **Health Check**: Endpoint to check the health of the backend service.

### Endpoints

1. **User Creation**: `POST /identity/users` - Create a new user account in Keycloak.
2. **User Deletion**: `DELETE /identity/users/<user_name>` - Delete a user account from Keycloak.
3. **User Group Membership Retrieval**: `GET /projects/users/<user_name>` - Retrieve a user's group membership information.
4. **User Information Retrieval**: `GET /identity/users/<user_name>` - Get detailed information about a user account.
5. **Group Creation**: `POST /identity/groups` - Create a new group in Keycloak.
6. **Group Deletion**: `DELETE /identity/groups/<group_name>` - Delete a group from Keycloak.
7. **Group Information Retrieval**: `GET /identity/groups` - Retrieve information about all groups in Keycloak.
8. **Health Check**: `GET /ok` - Check the health of the Keycloak Backend service.

### Authentication and Authorization

- The application uses Flask's authentication mechanisms.
- Role-based access control is implemented using `@role_required` decorators to restrict certain actions to users with specific roles, such as 'app-admin'.

### Environment Configuration

- The application loads environment variables from `.env` files for configuration, including Keycloak connection details.

### Error Handling

- The application handles various exceptions and returns appropriate HTTP status codes and error messages.

### Author

- Florian SIPP

### Contact

- Email: florian.sipp@chuv.ch

### Usage

To use the application, ensure that the required environment variables are set and that the Keycloak server is accessible. The application can be started as a standard Flask application and provides a RESTful API accessible over HTTP.

### Example Usage

```http
POST /identity/users?realm=my_realm
{
    "User Name": "john_doe",
    "First Name": "John",
    "Last Name": "Doe",
    "Password": "secretpassword",
    "Email": "john.doe@example.com"
}
```

This README provides a basic overview of the application's functionality and usage. For detailed API documentation, refer to the inline comments in the code.

## Acknowledgement

This research was supported by the EBRAINS research infrastructure, funded from the European Union’s Horizon 2020 Framework Programme for Research and Innovation under the Specific Grant Agreement No. 945539 (Human Brain Project SGA3).
