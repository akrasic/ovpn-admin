#!/usr/bin/env bash
set -ex

EASY_RSA_LOC="/etc/openvpn/easyrsa"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"

OVPN_SRV_NET="${OVPN_SERVER_NET:-172.16.100.0}"
OVPN_SRV_MASK="${OVPN_SERVER_MASK:-255.255.255.0}"

cd "$EASY_RSA_LOC"

if [ -e "$SERVER_CERT" ]; then
  echo "Found existing certs - reusing"
else
  if [[ "${OVPN_ROLE:-master}" == "slave" ]]; then
    echo "Waiting for initial sync data from master"
    while [ "$(wget -q --timeout=10 localhost/api/sync/last/try -O - | wc -m)" -lt 1 ]
    do
      sleep 5
    done
  else
    echo "Generating new certs"
    easyrsa --batch init-pki
    cp -R /usr/share/easy-rsa/* "$EASY_RSA_LOC/pki"
    echo "ca" | easyrsa build-ca nopass
    easyrsa --batch build-server-full server nopass
    easyrsa gen-dh
    openvpn --genkey secret ./pki/ta.key
  fi
fi
easyrsa gen-crl

# Enable IP forwarding (may fail if read-only, set via docker-compose sysctls instead)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "Note: ip_forward is read-only, ensure sysctls is set in docker-compose"

# Setup NAT for VPN clients
iptables -t nat -D POSTROUTING -s "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" ! -d "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" -j MASQUERADE || true
iptables -t nat -A POSTROUTING -s "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" ! -d "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" -j MASQUERADE

# Create TUN device if needed
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf

# Add DNS servers if configured (comma-separated list, e.g., "1.1.1.1,8.8.8.8")
if [[ -n "${OVPN_DNS:-}" ]]; then
  IFS=',' read -ra DNS_SERVERS <<< "$OVPN_DNS"
  for dns in "${DNS_SERVERS[@]}"; do
    echo "push \"dhcp-option DNS $dns\"" >> /etc/openvpn/openvpn.conf
  done
fi

# Add routes if configured (comma-separated CIDR, e.g., "10.0.0.0/8,172.16.0.0/12")
if [[ -n "${OVPN_ROUTES:-}" ]]; then
  IFS=',' read -ra ROUTES <<< "$OVPN_ROUTES"
  for route in "${ROUTES[@]}"; do
    # Convert CIDR to network + netmask
    network=$(echo "$route" | cut -d'/' -f1)
    cidr=$(echo "$route" | cut -d'/' -f2)
    # Convert CIDR to netmask
    case $cidr in
      8)  netmask="255.0.0.0" ;;
      12) netmask="255.240.0.0" ;;
      16) netmask="255.255.0.0" ;;
      20) netmask="255.255.240.0" ;;
      24) netmask="255.255.255.0" ;;
      28) netmask="255.255.255.240" ;;
      32) netmask="255.255.255.255" ;;
      *)  netmask="255.255.255.0" ;;
    esac
    echo "push \"route $network $netmask\"" >> /etc/openvpn/openvpn.conf
  done
fi

# Password authentication setup
if [[ "${OVPN_PASSWD_AUTH:-false}" == "true" ]]; then
  mkdir -p /etc/openvpn/scripts/
  cp -f /etc/openvpn/setup/auth.sh /etc/openvpn/scripts/auth.sh
  chmod +x /etc/openvpn/scripts/auth.sh
  echo "auth-user-pass-verify /etc/openvpn/scripts/auth.sh via-file" >> /etc/openvpn/openvpn.conf
  echo "script-security 2" >> /etc/openvpn/openvpn.conf
  echo "verify-client-cert require" >> /etc/openvpn/openvpn.conf
  openvpn-user db-init --db.path="$EASY_RSA_LOC/pki/users.db" && openvpn-user db-migrate --db.path="$EASY_RSA_LOC/pki/users.db"
fi

# Set permissions
[ -d "$EASY_RSA_LOC/pki" ] && chmod 755 "$EASY_RSA_LOC/pki"
[ -f "$EASY_RSA_LOC/pki/crl.pem" ] && chmod 644 "$EASY_RSA_LOC/pki/crl.pem"

mkdir -p /etc/openvpn/ccd

# Start OpenVPN
exec openvpn --config /etc/openvpn/openvpn.conf \
  --client-config-dir /etc/openvpn/ccd \
  --port 1194 \
  --proto tcp \
  --management 127.0.0.1 8989 \
  --dev tun0 \
  --server "${OVPN_SRV_NET}" "${OVPN_SRV_MASK}"
