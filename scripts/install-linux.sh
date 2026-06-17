#!/bin/sh
# Compatibility shim. install-linux.sh has been superseded by alighieri.sh,
# which manages the full lifecycle (install, upgrade, uninstall, status).
#
# This forwards to alighieri.sh so existing instructions keep working. With no
# arguments it runs `install` (the historical behaviour) rather than opening
# the interactive menu, so automation that called this script does not block.
set -eu

# Resolve the script's directory portably. Prefix ./ when $0 begins with a dash
# so neither dirname nor cd parses the path as an option, without depending on
# `--` (kept for the leading-dash hardening without that portability question).
self="$0"
case "$self" in -*) self="./$self" ;; esac
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$self")" && pwd)
MANAGER="$SCRIPT_DIR/alighieri.sh"

# Require a regular file (-x would also accept a searchable directory); the exec
# below uses bash, so the manager doesn't need the executable bit.
[ -f "$MANAGER" ] ||
    { echo "install-linux.sh: $MANAGER not found (expected a file)" >&2; exit 1; }

# alighieri.sh requires bash; invoke it explicitly so this shim works even
# without the executable bit set on the manager script. Check it is present so a
# missing bash produces clear guidance rather than a bare "exec: bash: not found".
command -v bash >/dev/null 2>&1 ||
    { echo "install-linux.sh: bash is required to run alighieri.sh; please install bash" >&2; exit 1; }

# `--` terminates bash option parsing so a manager path starting with `-` is
# treated as a script, not an option.
if [ $# -eq 0 ]; then
    exec bash -- "$MANAGER" install
fi
exec bash -- "$MANAGER" "$@"
