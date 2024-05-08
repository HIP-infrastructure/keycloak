#!/bin/bash

if [ -f ./keycloak_backend/keycloak_backend.secret ]; then
    echo "./keycloak_backend/keycloak_backend.secret exists, exiting."
    exit 1
fi

echo -n "Enter keycloak_backend username: "
read -r keycloak_backend_username
echo -n "Enter keycloak_backend password: "
read -rs keycloak_backend_password
echo

keycloak_backend_hash=`python3 -c "from werkzeug.security import generate_password_hash as g; print(g('$keycloak_backend_password', method='pbkdf2:sha256:600000'), end='');"`

echo -n "$keycloak_backend_username@$keycloak_backend_hash" > ./keycloak_backend/keycloak_backend.secret
