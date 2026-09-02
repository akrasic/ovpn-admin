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
#
# Every attempt is appended to AUTH_LOG as one tab-separated line:
#
#   <UTC timestamp>\t<outcome>\t<username>\t<common_name>\t<ip:port>
#
# outcome is success, bad-password, cn-mismatch or empty-creds. The password is
# never written. The log lives beside the PKI but outside pki/ itself, so an
# easyrsa re-init cannot take the history with it. Logging is best effort: a
# full disk or missing directory must never turn into an authentication outage.

PATH="$PATH:/usr/local/bin"
set -eu

AUTH_DB="${AUTH_DB:-/etc/openvpn/easyrsa/pki/users.db}"
AUTH_LOG="${AUTH_LOG:-/etc/openvpn/easyrsa/auth.log}"
AUTH_LOG_MAX_BYTES="${AUTH_LOG_MAX_BYTES:-5242880}"

auth_usr=''

log_attempt() {
  {
    # One rotation generation keeps the file bounded without a logrotate dependency.
    if [ -f "$AUTH_LOG" ] && [ "$(wc -c < "$AUTH_LOG")" -gt "$AUTH_LOG_MAX_BYTES" ]; then
      mv -f "$AUTH_LOG" "$AUTH_LOG.1"
    fi
    # The username is client input: strip control characters (a tab or newline
    # would let a client forge log lines) and cap the length.
    safe_usr="$(printf '%s' "${auth_usr:-}" | tr -d '\000-\037\177' | cut -c1-64)"
    safe_cn="$(printf '%s' "${common_name:-}" | tr -d '\000-\037\177' | cut -c1-64)"
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$safe_usr" "$safe_cn" \
      "${untrusted_ip:-}:${untrusted_port:-}" >> "$AUTH_LOG"
  } 2>/dev/null || true
}

creds_file="${1:-}"
if [ -z "$creds_file" ] || [ ! -r "$creds_file" ]; then
  echo "auth: credentials file missing or unreadable" >&2
  exit 1
fi

# "IFS= read -r" preserves each line byte for byte, including leading and trailing
# whitespace. $(head -1) and $(tail -1) strip trailing whitespace, and on a
# single-line file both return the same line, making the username double as the
# password.
auth_passwd=''
{
  IFS= read -r auth_usr || true
  IFS= read -r auth_passwd || true
} < "$creds_file"

if [ -z "$auth_usr" ] || [ -z "$auth_passwd" ]; then
  log_attempt empty-creds
  echo "auth: empty username or password" >&2
  exit 1
fi

# The certificate CN must match the username being presented. A mismatch means a
# valid certificate holder tried another account's credentials, which is the most
# interesting line this log can carry.
if [ "${common_name:-}" != "$auth_usr" ]; then
  log_attempt cn-mismatch
  echo "auth: common_name does not match the supplied username" >&2
  exit 1
fi

if openvpn-user auth --db.path "$AUTH_DB" --user "$auth_usr" --password "$auth_passwd"; then
  log_attempt success
  exit 0
fi

log_attempt bad-password
exit 1
