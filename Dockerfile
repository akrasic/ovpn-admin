# Combined OpenVPN Server + ovpn-admin Dockerfile
# Runs both OpenVPN and the web admin interface in a single container

FROM golang:1.24.6-bullseye AS builder
COPY . /app
ARG TARGETARCH
RUN cd /app && env CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} go build -a -tags netgo -ldflags '-linkmode external -extldflags -static -s -w' -o ovpn-admin

FROM alpine:3.23
WORKDIR /app

ARG TARGETARCH

# Install OpenVPN, Easy-RSA, and dependencies
RUN apk add --update --no-cache \
    bash \
    openvpn \
    easy-rsa \
    iptables \
    openssl \
    coreutils \
    supervisor \
    && ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin \
    && wget https://github.com/pashcovich/openvpn-user/releases/download/v1.0.4/openvpn-user-linux-${TARGETARCH}.tar.gz -O - | tar xz -C /usr/local/bin \
    && rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

# Link openvpn-user binary if arch-specific version exists
RUN if [ -f "/usr/local/bin/openvpn-user-${TARGETARCH}" ]; then \
    ln -s /usr/local/bin/openvpn-user-${TARGETARCH} /usr/local/bin/openvpn-user; \
    fi

# Copy ovpn-admin binary
COPY --from=builder /app/ovpn-admin /app/ovpn-admin

# Copy setup scripts
COPY setup/ /etc/openvpn/setup/
RUN chmod +x /etc/openvpn/setup/*.sh

# Copy entrypoint
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy supervisord config
COPY supervisord.conf /etc/supervisord.conf

# Create necessary directories
RUN mkdir -p /etc/openvpn/ccd /etc/openvpn/easyrsa /var/log/supervisor

# Expose ports
# 1194 - OpenVPN
# 8080 - ovpn-admin web interface
EXPOSE 1194/tcp 1194/udp 8080/tcp

# Environment defaults
ENV OVPN_SERVER_NET=172.16.100.0 \
    OVPN_SERVER_MASK=255.255.255.0 \
    OVPN_NETWORK=172.16.100.0/24 \
    OVPN_PASSWD_AUTH=false \
    OVPN_CCD=true \
    OVPN_CCD_PATH=/etc/openvpn/ccd \
    EASYRSA_PATH=/etc/openvpn/easyrsa \
    OVPN_INDEX_PATH=/etc/openvpn/easyrsa/pki/index.txt \
    OVPN_AUTH_DB_PATH=/etc/openvpn/easyrsa/pki/users.db \
    OVPN_MGMT=main=127.0.0.1:8989 \
    OVPN_SERVER=127.0.0.1:1194:tcp \
    LOG_LEVEL=info

ENTRYPOINT ["/entrypoint.sh"]
