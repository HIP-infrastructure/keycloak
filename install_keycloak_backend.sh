#!/bin/bash

if ! command -v jq &> /dev/null
then
    echo "jq could not be found, installing..."
    sudo apt-get update && sudo apt-get install -y jq
    echo "jq installed."
fi

if ! python3 -c "import ensurepip" &> /dev/null
then
    echo "python3-venv could not be found, installing..."
    sudo apt-get update && sudo apt-get install -y python3-venv
    echo "python3-venv installed."
fi

python3 -m venv keycloak_backend/venv
./keycloak_backend/venv/bin/pip install -r keycloak_backend/requirements.txt

if ! command -v caddy &> /dev/null
then
    echo "caddy could not be found, installing..."
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
    sudo apt-get update && sudo apt-get install -y caddy
    sudo systemctl stop caddy
    sudo systemctl disable caddy
    echo "caddy installed."
fi

if ! command -v npm &> /dev/null
then
    echo "npm could not be found, installing..."
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    NODE_MAJOR=20
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
    sudo apt-get update
    sudo apt-get install nodejs -y
    echo "npm installed."
fi

if ! command -v pm2 &> /dev/null
then
    echo "pm2 could not be found, installing..."
    sudo npm install pm2 -g
    echo "pm2 installed."
fi

# generate keycloak_backend credentials if needed
./gencreds.py

cd pm2 && npm i && cd ..
sudo pm2 start pm2/ecosystem.config.js
sudo pm2 save
sudo pm2 startup
sudo systemctl start pm2-root
sudo systemctl enable pm2-root
