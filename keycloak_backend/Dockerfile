FROM ubuntu:22.04

RUN mkdir -p /root/keycloak_backend
WORKDIR /root/keycloak_backend
RUN cd /root/keycloak_backend

COPY install_keycloak_backend.sh /root/keycloak_backend/
COPY caddy /root/keycloak_backend/caddy
COPY keycloak_backend /root/keycloak_backend/keycloak_backend
COPY pm2 /root/keycloak_backend/pm2

RUN /root/keycloak_backend/install_keycloak_backend.sh --docker-install

ENV KEYCLOAK_CADDY_URL=keycloak:8080

ENTRYPOINT [ "pm2-runtime", "pm2/ecosystem.config.js" ]