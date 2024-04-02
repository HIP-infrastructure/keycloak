FROM ubuntu:22.04

RUN mkdir -p /root/keycloak_backend
WORKDIR /root/keycloak_backend
RUN cd /root/keycloak_backend

COPY caddy keycloak_backend pm2 install_keycloak_backend.sh /root/keycloak_backend/

RUN /root/keycloak_backend/install_keycloak_backend.sh --docker-install

ENTRYPOINT [ "pm2", "resurrect" ]