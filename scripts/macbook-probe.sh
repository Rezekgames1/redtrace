set -eu
ROOT="$HOME/.local/share/redtrace-network-validation-20261013"
mkdir -p "$ROOT"
chmod 700 "$ROOT"
umask 077
/usr/bin/log show --last 2m --style ndjson --info --predicate 'process == "sshd" OR process == "sshd-session" OR process == "sudo" OR process == "authd"' > "$ROOT/unified-sample.ndjson"
printf 'Unified records: '
wc -l < "$ROOT/unified-sample.ndjson"
/usr/sbin/auditconfig -getcond || true
/bin/launchctl print system/com.apple.auditd || true
/usr/bin/man audit | /usr/bin/col -b | /usr/bin/head -50
/usr/bin/pgrep -x auditd || true
if test -e /etc/security/audit_control; then ls -l /etc/security/audit_control; fi
/usr/bin/tail -25 "$ROOT/cargo-tests.log"
