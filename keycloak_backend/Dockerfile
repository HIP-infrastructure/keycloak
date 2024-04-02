FROM ubuntu:22.04

RUN mkdir -p /root/keycloak_backend
WORKDIR /root/keycloak_backend
RUN cd /root/keycloak_backend

COPY caddy /root/keycloak_backend/caddy
COPY keycloak_backend /root/keycloak_backend/keycloak_backend
COPY pm2 /root/keycloak_backend/pm2
COPY install_keycloak_backend.sh /root/keycloak_backend/

RUN /root/keycloak_backend/install_keycloak_backend.sh --docker-install

ENTRYPOINT [ "pm2-runtime", "resurrect" ]