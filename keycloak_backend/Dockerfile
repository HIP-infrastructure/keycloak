FROM ubuntu:22.04

RUN mkdir -p /root/keycload_backend
WORKDIR /root/keycload_backend
RUN cd /root/keycload_backend

COPY caddy keycload_backend pm2 install_keycloak_backend.sh /root/keycload_backend/

RUN /root/keycload_backend/install_keycloak_backend.sh --docker-install

ENTRYPOINT [ "pm2", "resurrect" ]