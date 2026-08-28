#!/usr/bin/env sh
#
# OpenVPN auth-user-pass-verify handler, "via-file" mode.
#
# $1 names a temporary file holding the username on line 1 and the password on line 2.
#
# Every expansion below is quoted. An unquoted password is subject to word splitting
# and pathname expansion, which silently truncates any password containing a space and
# rewrites one containing glob characters, so the account cannot log in even though the
# password was set correctly.

PATH="$PATH:/usr/local/bin"
set -eu

AUTH_DB="/etc/openvpn/easyrsa/pki/users.db"

creds_file="${1:-}"
if [ -z "$creds_file" ] || [ ! -r "$creds_file" ]; then
  echo "auth: credentials file missing or unreadable" >&2
  exit 1
fi

# "IFS= read -r" preserves each line byte for byte, including leading and trailing
# whitespace. $(head -1) and $(tail -1) strip trailing whitespace, and on a
# single-line file both return the same line, making the username double as the
# password.
auth_usr=''
auth_passwd=''
{
  IFS= read -r auth_usr || true
  IFS= read -r auth_passwd || true
} < "$creds_file"

if [ -z "$auth_usr" ] || [ -z "$auth_passwd" ]; then
  echo "auth: empty username or password" >&2
  exit 1
fi

# The certificate CN must match the username being presented.
if [ "${common_name:-}" != "$auth_usr" ]; then
  echo "auth: common_name does not match the supplied username" >&2
  exit 1
fi

exec openvpn-user auth --db.path "$AUTH_DB" --user "$auth_usr" --password "$auth_passwd"
