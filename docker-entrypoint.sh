#!/bin/bash
set -e

EASY_RSA_LOC="${EASYRSA_PATH:-/etc/openvpn/easyrsa}"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"
CCD_PATH="${OVPN_CCD_PATH:-/etc/openvpn/ccd}"

OVPN_SRV_NET=${OVPN_SERVER_NET:-172.16.100.0}
OVPN_SRV_MASK=${OVPN_SERVER_MASK:-255.255.255.0}

echo "==> Starting OpenVPN + ovpn-admin combined container"

# Initialize PKI if not exists
cd $EASY_RSA_LOC

if [ -e "$SERVER_CERT" ]; then
    echo "==> Found existing certificates - reusing"
else
    if [ "${OVPN_ROLE:-master}" = "slave" ]; then
        echo "==> Slave mode: Waiting for initial sync from master"
        while [ $(wget -q localhost:8080/api/sync/last/try -O - 2>/dev/null | wc -m) -lt 1 ]; do
            sleep 5
        done
    else
        echo "==> Generating new PKI and certificates"
        easyrsa --batch init-pki
        cp -R /usr/share/easy-rsa/* $EASY_RSA_LOC/pki
        echo "ca" | easyrsa build-ca nopass
        easyrsa --batch build-server-full server nopass
        easyrsa gen-dh
        openvpn --genkey secret ./pki/ta.key
    fi
fi

# Generate CRL
easyrsa gen-crl

# Setup NAT for VPN traffic
iptables -t nat -D POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} ! -d ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} ! -d ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -j MASQUERADE

# Create TUN device if not exists
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

# Copy OpenVPN config
cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf

# Setup password authentication if enabled
if [ "${OVPN_PASSWD_AUTH}" = "true" ]; then
    echo "==> Enabling password authentication"
    mkdir -p /etc/openvpn/scripts/
    cp -f /etc/openvpn/setup/auth.sh /etc/openvpn/scripts/auth.sh
    chmod +x /etc/openvpn/scripts/auth.sh
    echo "auth-user-pass-verify /etc/openvpn/scripts/auth.sh via-file" >> /etc/openvpn/openvpn.conf
    echo "script-security 2" >> /etc/openvpn/openvpn.conf
    echo "verify-client-cert require" >> /etc/openvpn/openvpn.conf

    # Initialize user database
    openvpn-user db-init --db.path=$EASY_RSA_LOC/pki/users.db 2>/dev/null || true
    openvpn-user db-migrate --db.path=$EASY_RSA_LOC/pki/users.db 2>/dev/null || true
fi

# Fix permissions
[ -d $EASY_RSA_LOC/pki ] && chmod 755 $EASY_RSA_LOC/pki
[ -f $EASY_RSA_LOC/pki/crl.pem ] && chmod 644 $EASY_RSA_LOC/pki/crl.pem

# Create CCD directory
mkdir -p $CCD_PATH

echo "==> Starting services with supervisord"

# Start supervisord (manages both OpenVPN and ovpn-admin)
exec /usr/bin/supervisord -c /etc/supervisord.conf
