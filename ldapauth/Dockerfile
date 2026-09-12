ARG BUILD_FROM
FROM $BUILD_FROM
RUN apk add --no-cache python3 py3-pip py3-flask py3-ldap3 py3-waitress
COPY ldap_server.py /usr/bin/ldap_server.py
RUN chmod +x /usr/bin/ldap_server.py
COPY rootfs /
