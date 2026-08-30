#!/usr/bin/env bash
# alighieri.sh — install, upgrade, and uninstall Alighieri as a systemd service.
#
# A single entry point for managing an Alighieri SOCKS5 proxy deployment:
#
#   sudo ./scripts/alighieri.sh                 Install, or open a menu if installed
#   sudo ./scripts/alighieri.sh install         Install / reconfigure (unit + config)
#   sudo ./scripts/alighieri.sh upgrade         Replace the binary and restart
#   sudo ./scripts/alighieri.sh uninstall       Remove the service and binary
#   sudo ./scripts/alighieri.sh status          Show deployment status
#   sudo ./scripts/alighieri.sh help            Detailed help
#
# Run it from a repository checkout, or from a Linux release archive, which
# bundles this helper, the matching prebuilt binary, and the default config.
# In a complete release archive the helper automatically selects the bundled
# ./alighieri binary. A checkout without a prebuilt binary builds with Cargo and
# may fetch its locked dependencies, but the helper never clones a mutable
# repository branch or downloads a replacement lifecycle script.
#
# Configuration constants are intentionally NOT read from the environment:
# this script runs as root, and honouring env overrides would widen the attack
# surface for privilege escalation via environment injection. Use the
# documented flags instead.
#
# https://github.com/wiresock/alighieri
set -euo pipefail

SERVICE_NAME="alighieri"
SERVICE_USER="alighieri"
CONFIG_DIR="/etc/alighieri"
LOG_DIR="/var/log/alighieri"
# systemd StateDirectory: created on start, owned by the service user, and kept
# writable under ProtectSystem=strict. Holds the ACME certificate cache.
STATE_DIR="/var/lib/${SERVICE_NAME}"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_FILE="${CONFIG_DIR}/${SERVICE_NAME}.conf"

# Defaults overridable by flags.
PREFIX="/usr/local"
PREFIX_EXPLICIT=0
BINARY=""
BINARY_EXPLICIT=0
INSTALL_CONFIG=""
CONFIG_EXPLICIT=0
RESTART_ON_UPGRADE=1
START_ON_INSTALL=1
PURGE_CONFIG=0
PURGE_LOGS=0
PURGE_STATE=0
PURGE_USER=0
ACTION="auto"
COMMAND_SEEN=0
STAGED_BIN=""
STAGED_UNIT=""
UNIT_CANDIDATE_SNAPSHOT=""
UNIT_BACKUP=""
UNIT_TRANSACTION_DIR=""
UNIT_RETAINED_BACKUP=""
UNIT_TRANSACTION_ACTIVE=0
UNIT_HAD_ORIGINAL=0
UNIT_TRANSACTION_USES_STAGED_LINK=0
UNIT_ROLLBACK_CONFLICT_COPY=""
UNIT_ROLLBACK_RELOAD_FAILED=0
BINARY_COMMIT_IN_PROGRESS=0
UPGRADE_LEGACY_UNIT_KIND=""
LIFECYCLE_LOCK_FILE="/run/alighieri-management.lock"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# ── Output helpers ────────────────────────────────────────────────────────────
# Colour only when writing to a terminal so journald/pipes stay clean.
if [ -t 2 ]; then
    C_RED=$'\033[0;31m'
    C_YELLOW=$'\033[0;33m'
    C_GREEN=$'\033[0;32m'
    C_RESET=$'\033[0m'
else
    C_RED='' C_YELLOW='' C_GREEN='' C_RESET=''
fi

info() { printf '%s\n' "$*" >&2; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
ok()   { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET" >&2; }
die()  { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# systemd parses ExecStart itself rather than passing it through a shell. These
# characters introduce specifier/environment expansion or quoting/escaping, so
# the simple whitespace-delimited unit format below cannot represent them as
# literal path bytes. Reject them instead of validating one path and launching
# another.
validate_exec_start_path() {
    local option="$1" value="$2"
    case "$value" in
        *%*|*'$'*|*'"'*|*"'"*|*\\*)
            die "$option must not contain systemd ExecStart metacharacters (%, $, quotes, or backslash): $value"
            ;;
    esac
}

# Lexically normalise a path — collapse `.`, `..`, and redundant `/` — using only
# shell parameter expansion, with no external command. Symlinks are deliberately
# NOT resolved: callers compare declared paths and need identical behaviour on
# GNU and BusyBox systems (which may lack `realpath -m`). A leading `/` is
# preserved; the result has no trailing slash except for the root itself.
normalize_path() {
    local path="$1" abs='' out='' rest comp
    case "$path" in
        /*) abs=1 ;;
    esac
    rest="$path"
    while [ -n "$rest" ]; do
        case "$rest" in
            /*) rest="${rest#/}"; continue ;; # collapse leading / and // runs
        esac
        comp="${rest%%/*}"                     # next component, up to the slash
        case "$rest" in
            */*) rest="${rest#*/}" ;;
            *) rest='' ;;
        esac
        case "$comp" in
            '' | '.') ;;                       # drop empty and `.` segments
            '..')
                case "$out" in
                    '') [ -n "$abs" ] || out='..' ;; # absolute: `..` at root is a no-op
                    '..' | *'/..') out="$out/.." ;;  # relative escape: cannot pop a `..`
                    */*) out="${out%/*}" ;;          # pop the last segment
                    *) out='' ;;                     # pop the only segment
                esac
                ;;
            *) if [ -z "$out" ]; then out="$comp"; else out="$out/$comp"; fi ;;
        esac
    done
    if [ -n "$abs" ]; then
        printf '%s\n' "/$out"
    elif [ -n "$out" ]; then
        printf '%s\n' "$out"
    else
        printf '%s\n' "."
    fi
}

install_bin_dir_for_prefix() {
    local prefix="$1"
    [ "$(normalize_path "$prefix")" = "$prefix" ] || return 1
    join_path_child "$prefix" bin
}

join_path_child() {
    local directory="$1" child="$2"
    # `${directory%/}` is empty only for `/`, yielding `/child` instead of
    # `//child`. Every other accepted managed directory is already canonical.
    printf '%s/%s' "${directory%/}" "$child"
}

validate_existing_install_directory() {
    local directory="$1"
    case "$directory" in
        /*) ;;
        *) die "the existing unit's install directory is not absolute ($directory); fix ExecStart or pass --prefix with an absolute path" ;;
    esac
    case "$directory" in
        *[[:space:]]*)
            die "the existing unit's install directory contains whitespace ($directory); pass --prefix with a whitespace-free path" ;;
    esac
    validate_exec_start_path "the existing unit's install directory" "$directory"
    [ "$(normalize_path "$directory")" = "$directory" ] ||
        die "the existing unit's install directory is not canonical ($directory); fix ExecStart or pass --prefix with a canonical path"
}

existing_install_directory_for_binary() {
    local binary="$1" directory
    case "$binary" in
        /*) ;;
        *) die "the existing unit's executable path is not absolute ($binary); fix ExecStart or pass --prefix with an absolute path" ;;
    esac
    [ "$(normalize_path "$binary")" = "$binary" ] ||
        die "the existing unit's executable path is not canonical ($binary); fix ExecStart or pass --prefix with a canonical path"
    directory="$(dirname -- "$binary")" ||
        die "could not derive the existing unit's install directory from $binary"
    validate_existing_install_directory "$directory"
    printf '%s' "$directory"
}

usage() {
    cat <<EOF
alighieri.sh — install, upgrade, and uninstall Alighieri as a systemd service.

Usage:
  sudo $0 [COMMAND] [OPTIONS]

Commands:
  install            Build (or use) the binary, create a dedicated system user,
                     install a default config under ${CONFIG_DIR} (kept if
                     present), write a hardened systemd unit, then enable and
                     (re)start the service. Re-run to reconfigure.
  upgrade            Replace the installed binary with a newer build and restart
                     the service. Preserves the config; exact unmodified legacy
                     units are migrated transactionally when required.
  uninstall          Stop and disable the service and remove the unit and binary.
  status             Show the installed version, binary, service, and config state.
  help               Show this help.

  With no command: open a management menu if Alighieri is already installed,
  otherwise run install.

Options:
  --binary PATH      Use this prebuilt alighieri binary instead of building.
  --prefix DIR       Install prefix for the binary (default: ${PREFIX}).
  --config PATH      (install) Use this config in the systemd unit. Without it,
                     reconfiguration preserves the unit's current config path.
                     A custom path must already be root:${SERVICE_USER} mode 640
                     beneath a physical, root-controlled directory chain.
  --no-restart       (upgrade) Replace the binary but do not restart the service.
  --no-start         (install) Prepare files and the unit without enabling or
                     starting it. Re-run install after creating credentials.
  --purge-config     (uninstall) Also remove ${CONFIG_DIR} (userlist, TLS keys!).
  --purge-logs       (uninstall) Also remove ${LOG_DIR}.
  --purge-state      (uninstall) Also remove ${STATE_DIR} (ACME certs/account!).
  --purge-user       (uninstall) Also remove the ${SERVICE_USER} system user.
  --purge-all        (uninstall) --purge-config --purge-logs --purge-state --purge-user.
  -h, --help         Show this help.

Examples:
  sudo $0                                   # install, or manage if installed
  sudo $0 install                            # use the bundled release binary, or build
  sudo $0 install --binary ./alighieri      # explicitly select a prebuilt binary
  sudo $0 install --config /etc/alighieri/alighieri.conf
                                             # explicitly select the unit config
  sudo $0 upgrade                            # use bundled binary, or rebuild, and restart
  sudo $0 upgrade --binary ./alighieri      # swap in a prebuilt binary
  sudo $0 uninstall --purge-all             # remove everything
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        install | upgrade | uninstall | status | __selftest)
            # __selftest is hidden (CI self-tests, no root); it is still a command,
            # so it obeys the same one-command mutual-exclusivity rule as the rest.
            [ "$COMMAND_SEEN" -eq 0 ] || die "only one command may be given (already '$ACTION'): $1"
            ACTION="$1"; COMMAND_SEEN=1 ;;
        help | -h | --help) usage; exit 0 ;; # help always wins, immediately
        --binary) shift; [ $# -gt 0 ] || die "--binary requires a path"; BINARY="$1"; BINARY_EXPLICIT=1 ;;
        --prefix) shift; [ $# -gt 0 ] || die "--prefix requires a path"; PREFIX="$1"; PREFIX_EXPLICIT=1 ;;
        --config) shift; [ $# -gt 0 ] || die "--config requires a path"; INSTALL_CONFIG="$1"; CONFIG_EXPLICIT=1 ;;
        --config=*) INSTALL_CONFIG="${1#--config=}"; [ -n "$INSTALL_CONFIG" ] || die "--config requires a path"; CONFIG_EXPLICIT=1 ;;
        --no-restart) RESTART_ON_UPGRADE=0 ;;
        --no-start) START_ON_INSTALL=0 ;;
        --purge-config) PURGE_CONFIG=1 ;;
        --purge-logs) PURGE_LOGS=1 ;;
        --purge-state) PURGE_STATE=1 ;;
        --purge-user) PURGE_USER=1 ;;
        --purge-all) PURGE_CONFIG=1; PURGE_LOGS=1; PURGE_STATE=1; PURGE_USER=1 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
done

# systemd requires an absolute, whitespace-free ExecStart, and the install
# prefix forms that path, so reject anything that would produce an invalid one.
case "$PREFIX" in
    /*) ;;
    *) die "--prefix must be an absolute path: $PREFIX" ;;
esac
case "$PREFIX" in
    *[[:space:]]*) die "--prefix must not contain whitespace: $PREFIX" ;;
esac
validate_exec_start_path "--prefix" "$PREFIX"
# Do not silently normalize: `/opt/link/..` is not necessarily `/opt` when
# `link` is a symlink. Requiring the canonical lexical spelling keeps both the
# kernel target and systemd's loaded path/argv comparison unambiguous.
[ "$(normalize_path "$PREFIX")" = "$PREFIX" ] ||
    die "--prefix must use a canonical path without trailing/repeated slashes, . or .. components: $PREFIX"
if [ "$CONFIG_EXPLICIT" -eq 1 ]; then
    [ "$ACTION" = "install" ] || die "--config is valid only with the install command"
    case "$INSTALL_CONFIG" in
        /*) ;;
        *) die "--config must be an absolute path: $INSTALL_CONFIG" ;;
    esac
    case "$INSTALL_CONFIG" in
        *[[:space:]]*) die "--config must not contain whitespace: $INSTALL_CONFIG" ;;
    esac
    validate_exec_start_path "--config" "$INSTALL_CONFIG"
fi

BIN_DIR="$(install_bin_dir_for_prefix "$PREFIX")" ||
    die "could not derive an install directory from --prefix: $PREFIX"

# ── Helpers ───────────────────────────────────────────────────────────────────
require_root() {
    [ "$(id -u)" -eq 0 ] && return
    local hint="sudo $0"
    [ "$ACTION" = "auto" ] || hint="$hint $ACTION"
    die "must run as root (try: $hint)"
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 ||
        die "systemctl not found; this installer requires systemd"
}

flock_command() { command flock "$@"; }

# Serialize recovery and every mutating lifecycle command. Without one lock, a
# second invocation could mistake the first invocation's live migration journal
# for an interrupted transaction and roll it back underneath the binary commit.
acquire_lifecycle_lock() {
    local previous_umask
    command -v flock >/dev/null 2>&1 ||
        die "flock not found (required to serialize privileged lifecycle commands)"
    if [ -e "$LIFECYCLE_LOCK_FILE" ] || [ -L "$LIFECYCLE_LOCK_FILE" ]; then
        if [ ! -f "$LIFECYCLE_LOCK_FILE" ] || [ -L "$LIFECYCLE_LOCK_FILE" ]; then
            die "lifecycle lock path is not a physical regular file: $LIFECYCLE_LOCK_FILE"
        fi
    fi
    previous_umask="$(umask)"
    umask 077
    if ! { exec 9>"$LIFECYCLE_LOCK_FILE"; }; then
        umask "$previous_umask"
        die "could not open lifecycle lock $LIFECYCLE_LOCK_FILE"
    fi
    umask "$previous_umask"
    flock_command -n 9 ||
        die "another Alighieri lifecycle command is already running (lock: $LIFECYCLE_LOCK_FILE)"
}

release_lifecycle_lock() {
    flock_command -u 9 2>/dev/null || true
    exec 9>&-
}

prepare_mutating_lifecycle_command() {
    acquire_lifecycle_lock
    recover_interrupted_legacy_unit_transaction
}

require_service_sandbox() {
    command -v systemd-run >/dev/null 2>&1 ||
        die "systemd-run not found; this installer requires it for service-sandbox preflight"
    command -v busctl >/dev/null 2>&1 ||
        die "busctl not found; this installer requires it for effective service-sandbox checks"
    command -v readlink >/dev/null 2>&1 ||
        die "readlink not found; this installer requires it for canonical service-path preflight"
}

nologin_shell() {
    for candidate in /usr/sbin/nologin /sbin/nologin /bin/false; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return
        fi
    done
    printf '%s' /bin/false
}

# ExecStart payload from the base unit file only. Empty when absent.
unit_file_exec_start_payload() {
    local line=""
    if [ -f "$UNIT_FILE" ]; then
        line="$(grep '^[[:space:]]*ExecStart=' "$UNIT_FILE" 2>/dev/null | tail -n1 || true)"
    fi
    [ -n "$line" ] && printf '%s' "${line#*=}"
    return 0
}

# Resolve the D-Bus object for the service unit, loading a freshly written unit
# when it is not already referenced or active. Manager.GetUnit only works for an
# already-loaded unit, which breaks a first install (especially --no-start).
service_unit_object_path() {
    local response type object extra
    response="$(busctl call \
        org.freedesktop.systemd1 \
        /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager \
        LoadUnit s "${SERVICE_NAME}.service" 2>/dev/null)" || return 1
    read -r type object extra <<<"$response"
    [ "$type" = "o" ] && [ -z "$extra" ] || return 1
    object="${object#\"}"
    object="${object%\"}"
    case "$object" in
        /org/freedesktop/systemd1/unit/*) printf '%s' "$object" ;;
        *) return 1 ;;
    esac
}

systemd_manager_version() {
    local version
    version="$(systemctl show --property=Version --value 2>/dev/null)" || return 1
    version="${version%%[!0-9]*}"
    case "$version" in
        '' | *[!0-9]*) return 1 ;;
    esac
    printf '%s' "$version"
}

decode_busctl_simple_string() {
    local value="$1"
    case "$value" in
        \"*\")
            value="${value#\"}"
            value="${value%\"}"
            ;;
        *) return 1 ;;
    esac
    # Supported unit paths/arguments contain neither whitespace nor quoting
    # escapes. Refuse a busctl-escaped value rather than decoding it differently
    # from systemd. Dollar and percent markers are also unsafe here: systemd can
    # expand them only when the service starts, after this manager-loaded value
    # has been inspected, so preflighting the literal would validate a different
    # path from the one used on restart.
    case "$value" in
        *\\* | *\"* | *'$'* | *%*) return 1 ;;
    esac
    printf '%s' "$value"
}

legacy_effective_exec_start_is_unmodified() {
    # ExecStartEx (v243+) exposes every command prefix. The legacy D-Bus
    # property exposes only `-`, so on older managers conservatively require
    # each physical ExecStart assignment to be empty (a reset) or start with the
    # managed unquoted absolute executable form. Reject includes, BOMs, and line
    # continuations that could hide a privileged `+`/`!`/`:` prefix.
    systemctl cat --no-pager -- "${SERVICE_NAME}.service" 2>/dev/null |
        LC_ALL=C awk '
    BEGIN { bom = "\357\273\277" }
    /^[[:space:]]*[#;]/ { next }
    index($0, bom) == 1 { exit 1 }
    {
        line = $0
        sub(/^[[:space:]]*/, "", line)
        if (line ~ /^\.include([[:space:]]|$)/) exit 1
        if (line ~ /\\[[:space:]]*$/) exit 1
        if (line !~ /^ExecStart[[:space:]]*=/) next
        sub(/^ExecStart[[:space:]]*=[[:space:]]*/, "", line)
        if (line != "" && substr(line, 1, 1) != "/") exit 1
    }
    '
}

# Canonical whitespace-delimited argv for the single manager-loaded ExecStart.
# Reading D-Bus rather than `systemctl cat` includes legacy `.include` files,
# continuations, and the exact post-daemon-reload command. The managed service
# uses simple, whitespace-free arguments, so reject shapes that cannot be
# represented by the installer's deliberately narrow parser.
loaded_exec_start_payload() {
    local object output command_count executable argc flags token value payload="" \
          i version property
    local -a fields=() argv=()
    object="$(service_unit_object_path)" || return 1
    version="$(systemd_manager_version)" || return 1
    if [ "$version" -ge 243 ]; then
        property="ExecStartEx"
    else
        property="ExecStart"
        legacy_effective_exec_start_is_unmodified || return 1
    fi
    output="$(busctl get-property \
        org.freedesktop.systemd1 "$object" \
        org.freedesktop.systemd1.Service "$property" 2>/dev/null)" || return 1
    read -ra fields <<<"$output"
    [ "${#fields[@]}" -ge 6 ] || return 1
    command_count="${fields[1]}"
    executable="$(decode_busctl_simple_string "${fields[2]}")" || return 1
    argc="${fields[3]}"
    case "$argc" in
        '' | *[!0-9]*) return 1 ;;
    esac
    [ "$command_count" = "1" ] && [ "$argc" -ge 1 ] &&
        [ "${#fields[@]}" -ge $((argc + 5)) ] || return 1
    flags="${fields[$((argc + 4))]}"
    if [ "$version" -ge 243 ]; then
        [ "$flags" = "0" ] || return 1
    else
        [ "$flags" = "false" ] || return 1
    fi
    for ((i = 0; i < argc; i++)); do
        token="${fields[$((i + 4))]}"
        value="$(decode_busctl_simple_string "$token")" || return 1
        argv+=("$value")
        payload="${payload}${payload:+ }$value"
    done
    [ "${argv[0]}" = "$executable" ] || return 1
    printf '%s' "$payload"
}

# Effective ExecStart payload (everything after its first '=') for the service.
# Prefer the manager-loaded D-Bus argv so includes/continuations and drop-ins are
# honoured; fall back to merged/on-disk text for non-mutating status/uninstall
# lookups when the manager or busctl is unavailable. Empty when none is found.
exec_start_payload() {
    local line="" loaded=""
    if command -v busctl >/dev/null 2>&1 &&
        loaded="$(loaded_exec_start_payload 2>/dev/null)"; then
        printf '%s' "$loaded"
        return 0
    fi
    if command -v systemctl >/dev/null 2>&1; then
        line="$(systemctl cat -- "${SERVICE_NAME}.service" 2>/dev/null |
            grep '^[[:space:]]*ExecStart=' | tail -n1 || true)"
    fi
    if [ -z "$line" ]; then
        unit_file_exec_start_payload
    else
        printf '%s' "${line#*=}"
    fi
    return 0
}

# True when systemd's merged ExecStart differs from the base unit we manage,
# which means a drop-in will survive rewriting that base file.
effective_exec_start_overrides_base() {
    local base effective
    base="$(unit_file_exec_start_payload)"
    effective="$(exec_start_payload)"
    [ "$effective" != "$base" ]
}

# Resolve where the binary actually lives, from the effective ExecStart (so a
# custom --prefix install — or a drop-in override — is found on upgrade and
# uninstall); fall back to the default prefix when it can't be parsed/validated.
installed_binary_path() {
    local payload bin_path
    payload="$(exec_start_payload)"
    # Split on any whitespace (space or tab); the first field is the binary.
    read -r bin_path _ <<<"$payload"
    # Only trust an absolute path whose name matches the service; a malformed or
    # hand-edited unit with a relative path must not make upgrade/uninstall mv or
    # rm a path relative to the caller's CWD as root.
    case "$bin_path" in
        /*)
            if [ "$(basename -- "$bin_path")" = "$SERVICE_NAME" ]; then
                printf '%s' "$bin_path"
                return
            fi
            ;;
    esac
    join_path_child "$BIN_DIR" "$SERVICE_NAME"
}

# Resolve the config path the installed unit actually launches with. An explicit
# --config / --config=PATH flag (also supported by the binary) wins; otherwise
# the positional second token of ExecStart (the first is the binary). Only an
# absolute path is trusted, so a malformed or hand-edited unit with a relative
# token falls back to the default rather than pointing upgrade/status at a path
# relative to the caller's CWD.
installed_config_path() {
    local payload cfg=""
    payload="$(exec_start_payload)"
    # read -ra splits on shell whitespace (space, tab) without glob-expanding;
    # unit paths are whitespace-free.
    local -a tokens=()
    read -ra tokens <<<"$payload"
    local i=0 n=${#tokens[@]}
    while [ "$i" -lt "$n" ]; do
        case "${tokens[$i]}" in
            --config=*) cfg="${tokens[$i]#--config=}" ;;
            --config)
                if [ $((i + 1)) -lt "$n" ]; then cfg="${tokens[$((i + 1))]}"; fi
                ;;
        esac
        i=$((i + 1))
    done
    if [ -z "$cfg" ] && [ "$n" -ge 2 ]; then
        cfg="${tokens[1]}" # positional config (binary is tokens[0])
    fi
    case "$cfg" in
        /*) printf '%s' "$cfg"; return ;;
    esac
    printf '%s' "$CONFIG_FILE"
}

effective_install_matches() {
    local expected_binary="$1" expected_config="$2" effective
    # This is a post-daemon-reload safety check, not a status-path lookup. Match
    # the exact payload we just wrote instead of using installed_*_path, whose
    # deliberately conservative fallbacks would turn an empty/malformed
    # surviving drop-in into the expected defaults and allow a stale service to
    # start. Paths accepted by the installer contain neither whitespace nor
    # systemd expansion/quoting characters, so this canonical form is exact.
    effective="$(loaded_exec_start_payload)" || return 1
    [ "$effective" = "$expected_binary $expected_config" ]
}

# Historical generated units are accepted for automatic migration only when
# their complete base-unit bytes still match a released template. This narrow
# fingerprint distinguishes an untouched old Alighieri install from a hand-
# edited unit whose operational intent the helper must not overwrite.
render_legacy_unit_v0_1() {
    local install_bin="$1" config_file="$2"
    cat <<UNIT
[Unit]
Description=Alighieri SOCKS5 proxy server
Documentation=https://github.com/wiresock/alighieri
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$install_bin $config_file
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

# Hardening. The default config listens on an unprivileged port; to bind a
# port below 1024, add CAP_NET_BIND_SERVICE to AmbientCapabilities and
# CapabilityBoundingSet.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
UNIT
}

render_legacy_unit_v0_2_to_v0_4() {
    local install_bin="$1" config_file="$2" caps="$3"
    case "$caps" in '' | CAP_NET_BIND_SERVICE) ;; *) return 1 ;; esac
    cat <<UNIT
[Unit]
Description=Alighieri SOCKS5 proxy server
Documentation=https://github.com/wiresock/alighieri
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$install_bin $config_file
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

# Hardening. CAP_NET_BIND_SERVICE is granted (below) only when the config needs
# a privileged port — an internal: port under 1024, or ACME, whose TLS-ALPN-01
# challenge is answered on :443; otherwise all capabilities are dropped.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=$caps
AmbientCapabilities=$caps
ReadWritePaths=$LOG_DIR
# StateDirectory keeps /var/lib/${SERVICE_NAME} writable under
# ProtectSystem=strict (created on start, owned by the service user); it holds
# the ACME certificate cache (tls.acme.cache).
StateDirectory=${SERVICE_NAME}
StateDirectoryMode=0750

[Install]
WantedBy=multi-user.target
UNIT
}

unit_file_is_safe_for_legacy_migration() {
    local path="${1:-$UNIT_FILE}"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    local metadata owner mode extra permissions
    metadata="$(stat -Lc '%u %a' -- "$path" 2>/dev/null)" || return 1
    read -r owner mode extra <<<"$metadata"
    [ "$owner" = 0 ] && [ -n "$mode" ] && [ -z "${extra:-}" ] || return 1
    case "$mode" in *[!0-7]* | '') return 1 ;; esac
    permissions=$((8#$mode))
    [ $((permissions & 0022)) -eq 0 ]
}

loaded_unit_source_is_unoverridden() {
    local properties
    properties="$(systemctl show --no-pager \
        --property=FragmentPath --property=DropInPaths \
        -- "${SERVICE_NAME}.service" 2>/dev/null)" || return 1
    printf '%s\n' "$properties" | grep -Fqx -- "FragmentPath=$UNIT_FILE" &&
        printf '%s\n' "$properties" | grep -Fqx -- 'DropInPaths='
}

legacy_unit_file_matches_kind() {
    local path="$1" kind="$2" install_bin="$3" config_file="$4" caps
    case "$kind" in
        v0.1.x)
            cmp -s -- "$path" \
                <(render_legacy_unit_v0_1 "$install_bin" "$config_file")
            ;;
        v0.2.0-v0.4.0)
            for caps in '' CAP_NET_BIND_SERVICE; do
                if cmp -s -- "$path" \
                    <(render_legacy_unit_v0_2_to_v0_4 \
                        "$install_bin" "$config_file" "$caps"); then
                    return 0
                fi
            done
            return 1
            ;;
        *) return 1 ;;
    esac
}

# Print the recognized legacy family. Failure means the loaded service is not
# backed by an exact, unmodified released template and must remain fail-closed.
legacy_generated_unit_kind() {
    command -v cmp >/dev/null 2>&1 || return 2
    unit_file_is_safe_for_legacy_migration || return 1
    loaded_unit_source_is_unoverridden || return 1

    local payload value
    local -a argv=()
    payload="$(loaded_exec_start_payload 2>/dev/null)" || return 1
    read -ra argv <<<"$payload"
    [ "${#argv[@]}" -eq 2 ] || return 1
    for value in "${argv[@]}"; do
        case "$value" in
            /*) ;;
            *) return 1 ;;
        esac
        case "$value" in *[[:space:]%\$\"\'\\]*) return 1 ;; esac
        [ "$(normalize_path "$value")" = "$value" ] || return 1
    done
    [ "$(basename -- "${argv[0]}")" = "$SERVICE_NAME" ] || return 1

    if legacy_unit_file_matches_kind \
        "$UNIT_FILE" v0.1.x "${argv[0]}" "${argv[1]}"; then
        printf '%s' 'v0.1.x'
        return 0
    fi
    if legacy_unit_file_matches_kind \
        "$UNIT_FILE" v0.2.0-v0.4.0 "${argv[0]}" "${argv[1]}"; then
        printf '%s' 'v0.2.0-v0.4.0'
        return 0
    fi
    return 1
}

# Decide whether upgrade can keep the current unit or should migrate a released
# legacy template. Exact legacy recognition comes first so semantically compatible
# v0.2-v0.4 units are refreshed too; every edited unit and every drop-in remains
# subject to the normal effective-sandbox guard.
prepare_upgrade_unit_migration() {
    local install_bin="$1" config_file="$2" expected_exec_start="$3" \
          kind status description
    UPGRADE_LEGACY_UNIT_KIND=""

    if kind="$(legacy_generated_unit_kind 2>/dev/null)"; then
        [ "$expected_exec_start" = "$install_bin $config_file" ] ||
            die "effective systemd ExecStart changed while identifying the legacy unit; review the unit/drop-ins, then retry"
        UPGRADE_LEGACY_UNIT_KIND="$kind"
        case "$kind" in
            v0.1.x) description="v0.1-era" ;;
            v0.2.0-v0.4.0) description="v0.2-v0.4-era" ;;
            *) description="legacy" ;;
        esac
        info "recognized an untouched Alighieri $description systemd unit template; upgrade will migrate it to the current hardened unit"
        return 0
    else
        status=$?
        [ "$status" -ne 2 ] ||
            die "cmp not found; install a coreutils-compatible cmp command before checking or migrating a legacy systemd unit"
    fi

    effective_service_sandbox_matches && return 0
    die "effective systemd service settings differ from the managed unit, and the base unit is not an exact unmodified Alighieri legacy template. Inspect it with: systemctl show ${SERVICE_NAME}.service --no-pager -p FragmentPath -p DropInPaths; systemctl cat ${SERVICE_NAME}.service. After reviewing any deliberate customization, use 'sudo $0 install' to regenerate the managed unit."
}

# Effective identity and filesystem-view properties after systemd merges the
# managed unit with all surviving drop-ins. These must match the transient
# preflight exactly: an overridden WorkingDirectory would resolve relative
# userlists differently, while identity or namespace overrides could make paths
# readable during validation but unavailable after restart (or vice versa).
effective_service_sandbox_properties() {
    systemctl show --no-pager \
        --property=User \
        --property=Group \
        --property=WorkingDirectory \
        --property=ProtectSystem \
        --property=ProtectHome \
        --property=PrivateTmp \
        --property=PrivateDevices \
        --property=ProtectKernelTunables \
        --property=ProtectKernelModules \
        --property=ProtectControlGroups \
        --property=DynamicUser \
        --property=PrivateUsers \
        --property=SupplementaryGroups \
        --property=RootDirectory \
        --property=RootImage \
        -- "${SERVICE_NAME}.service"
}

# True when the manager-loaded unit has no additive path-namespace directives.
# systemctl before v247 renders some of these complex arrays as `[unprintable]`
# even when empty. Read their stable raw D-Bus representation instead: its first
# value after the type signature is the top-level element count. This also sees
# legacy `.include` files, continuations, BOM-prefixed fragments, and the exact
# state the next restart will use without reimplementing systemd's unit parser.
effective_service_path_namespace_matches() {
    local object version property output signature count value extra
    local -a properties=(ReadOnlyPaths InaccessiblePaths BindPaths BindReadOnlyPaths)

    object="$(service_unit_object_path)" || return 1

    version="$(systemd_manager_version)" || return 1
    if [ "$version" -ge 238 ]; then
        properties+=(TemporaryFileSystem)
    fi
    if [ "$version" -ge 247 ]; then
        properties+=(MountImages)
    fi
    if [ "$version" -ge 248 ]; then
        properties+=(ExtensionImages NoExecPaths ExecPaths)
    fi
    if [ "$version" -ge 251 ]; then
        properties+=(ExtensionDirectories)
    fi

    for property in "${properties[@]}"; do
        output="$(busctl get-property \
            org.freedesktop.systemd1 "$object" \
            org.freedesktop.systemd1.Service "$property" 2>/dev/null)" || return 1
        read -r signature count _ <<<"$output"
        [ -n "$signature" ] && [ "$count" = "0" ] || return 1
    done
    # v260's RootMStack is another complete alternate root (overlay-backed),
    # analogous to RootDirectory/RootImage, but is not present on older managers.
    if [ "$version" -ge 260 ]; then
        output="$(busctl get-property \
            org.freedesktop.systemd1 "$object" \
            org.freedesktop.systemd1.Service RootMStack 2>/dev/null)" || return 1
        read -r signature value extra <<<"$output"
        [ "$signature" = "s" ] && [ "$value" = '""' ] &&
            [ -z "$extra" ] || return 1
    fi
}

loaded_service_property() {
    local object="$1" property="$2"
    busctl get-property \
        org.freedesktop.systemd1 "$object" \
        org.freedesktop.systemd1.Service "$property" 2>/dev/null
}

loaded_single_string_array_equals() {
    local raw="$1" expected="$2" signature count encoded extra decoded
    read -r signature count encoded extra <<<"$raw"
    [ "$signature" = as ] && [ "$count" = 1 ] && [ -n "$encoded" ] &&
        [ -z "${extra:-}" ] || return 1
    decoded="$(decode_busctl_simple_string "$encoded")" || return 1
    [ "$decoded" = "$expected" ]
}

loaded_empty_string_array() {
    local raw="$1" signature count extra
    read -r signature count extra <<<"$raw"
    [ "$signature" = as ] && [ "$count" = 0 ] && [ -z "${extra:-}" ]
}

loaded_unsigned_equals() {
    local raw="$1" expected_signature="$2" expected="$3" signature value extra
    read -r signature value extra <<<"$raw"
    [ "$signature" = "$expected_signature" ] && [ -z "${extra:-}" ] || return 1
    case "$value" in
        '' | *[!0-9]*) return 1 ;;
    esac
    [ "$value" = "$expected" ]
}

# StateDirectorySymlink was added in systemd 250. Older implementations expose
# only actual destination mappings, while newer ones expose the ordinary
# `StateDirectory=alighieri` entry with an empty destination as well. Either
# exact representation is safe; every non-empty destination or flag is not.
loaded_state_directory_mapping_matches() {
    local raw="$1" signature count source destination flags extra
    read -r signature count source destination flags extra <<<"$raw"
    [ "$signature" = 'a(sst)' ] || return 1
    if [ "$count" = 0 ]; then
        [ -z "${source:-}" ]
        return
    fi
    [ "$count" = 1 ] && [ -n "${source:-}" ] &&
        [ -n "${destination:-}" ] && [ -n "${flags:-}" ] &&
        [ -z "${extra:-}" ] || return 1
    source="$(decode_busctl_simple_string "$source")" || return 1
    destination="$(decode_busctl_simple_string "$destination")" || return 1
    [ "$source" = "$SERVICE_NAME" ] && [ -z "$destination" ] && [ "$flags" = 0 ]
}

# Verify the manager-loaded writable locations, not just the base unit text.
# List-valued drop-ins can reset StateDirectory/ReadWritePaths or add broader
# paths while leaving the scalar namespace properties above unchanged.
effective_service_managed_storage_matches() {
    local object version property raw
    object="$(service_unit_object_path)" || return 1

    raw="$(loaded_service_property "$object" StateDirectory)" || return 1
    loaded_single_string_array_equals "$raw" "$SERVICE_NAME" || return 1

    raw="$(loaded_service_property "$object" StateDirectoryMode)" || return 1
    # 0750 expressed as the unsigned decimal D-Bus value.
    loaded_unsigned_equals "$raw" u 488 || return 1

    raw="$(loaded_service_property "$object" ReadWritePaths)" || return 1
    loaded_single_string_array_equals "$raw" "$LOG_DIR" || return 1

    # These managed-directory directives create additional service-writable
    # roots despite ProtectSystem=strict. The generated unit uses none of them,
    # so a surviving drop-in must not be allowed to add one.
    for property in RuntimeDirectory CacheDirectory LogsDirectory ConfigurationDirectory; do
        raw="$(loaded_service_property "$object" "$property")" || return 1
        loaded_empty_string_array "$raw" || return 1
    done

    version="$(systemd_manager_version)" || return 1
    if [ "$version" -ge 250 ]; then
        raw="$(loaded_service_property "$object" StateDirectorySymlink)" || return 1
        loaded_state_directory_mapping_matches "$raw" || return 1
    fi
}

effective_service_capability_sets_match() {
    local expected="$1" object raw
    case "$expected" in 0 | 1024) ;; *) return 1 ;; esac
    object="$(service_unit_object_path)" || return 1

    raw="$(loaded_service_property "$object" CapabilityBoundingSet)" || return 1
    loaded_unsigned_equals "$raw" t "$expected" || return 1
    raw="$(loaded_service_property "$object" AmbientCapabilities)" || return 1
    loaded_unsigned_equals "$raw" t "$expected"
}

effective_service_sandbox_matches() {
    local properties expected
    properties="$(effective_service_sandbox_properties 2>/dev/null)" || return 1
    for expected in \
        "User=$SERVICE_USER" \
        "Group=$SERVICE_USER" \
        'ProtectSystem=strict' \
        'ProtectHome=yes' \
        'PrivateTmp=yes' \
        'PrivateDevices=yes' \
        'ProtectKernelTunables=yes' \
        'ProtectKernelModules=yes' \
        'ProtectControlGroups=yes' \
        'DynamicUser=no' \
        'PrivateUsers=no' \
        'SupplementaryGroups=' \
        'RootDirectory=' \
        'RootImage='; do
        printf '%s\n' "$properties" | grep -Fqx -- "$expected" || return 1
    done
    # An unset WorkingDirectory is systemd's system-service default `/`, so an
    # older generated unit without the explicit directive is semantically equal.
    printf '%s\n' "$properties" |
        grep -Eq '^WorkingDirectory=(/)?$' || return 1

    # Additive namespace directives can still shadow otherwise identical paths.
    effective_service_path_namespace_matches || return 1
    effective_service_managed_storage_matches || return 1
    if [ "$#" -gt 0 ]; then
        effective_service_capability_sets_match "$1" || return 1
    fi
}

require_effective_service_sandbox() {
    if [ "$#" -gt 0 ]; then
        effective_service_sandbox_matches "$1"
    else
        effective_service_sandbox_matches
    fi || die "effective systemd service identity, WorkingDirectory, filesystem namespace, writable paths, or capabilities differ from the managed unit; remove or update the overriding drop-in, then retry"
}

# Select the config for an install/reconfigure. Passing the installed unit's
# effective path keeps this helper pure and self-testable; an explicit --config
# is the only way to override that preserved path.
select_install_config_path() {
    local installed_path="${1:-}"
    if [ "$CONFIG_EXPLICIT" -eq 1 ]; then
        printf '%s' "$INSTALL_CONFIG"
    elif [ -n "$installed_path" ]; then
        printf '%s' "$installed_path"
    else
        printf '%s' "$CONFIG_FILE"
    fi
}

# BusyBox applet builds do not consistently implement GNU's destination-as-file
# option. Keep the same exact-path semantics with explicit pre/postcondition
# checks: candidates may be regular files only, an absent staging/backup path may
# not be repurposed as a directory, and a replacement must consume its source and
# leave a regular non-symlink at the requested destination. Binary parent
# directories are verified as root-controlled before staging, so the checks and
# following operation cannot be raced by the unprivileged service account.
install_file_command() { command install "$@"; }
copy_file_command() { command cp "$@"; }
move_file_command() { command mv "$@"; }
link_file_command() { command link "$@"; }

hardlink_utility_available() {
    command -v link >/dev/null 2>&1
}

require_hardlink_utility() {
    hardlink_utility_available ||
        die "legacy-unit migration requires the coreutils-compatible 'link' utility; install it before retrying"
}

stage_executable_copy() {
    local source="$1" destination="$2"
    [ -f "$source" ] || return 1
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 1
    install_file_command -m 755 -- "$source" "$destination" || return 1
    [ -f "$destination" ] && [ ! -L "$destination" ] || return 1
}

copy_regular_file_to_absent_path() {
    local source="$1" destination="$2"
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 1
    copy_file_command -p -- "$source" "$destination" || return 1
    [ -f "$destination" ] && [ ! -L "$destination" ] || return 1
}

# `link SOURCE DESTINATION` maps directly to link(2): unlike `ln` it never
# treats an existing directory as a container, and the kernel creates
# DESTINATION only if that exact path is absent. Keep SOURCE so a transaction
# can later identify its published candidate by inode.
link_regular_file_to_absent_path() {
    local source="$1" destination="$2"
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 1
    link_file_command "$source" "$destination" || return 1
    [ -f "$source" ] && [ ! -L "$source" ] &&
        [ -f "$destination" ] && [ ! -L "$destination" ] &&
        [ "$source" -ef "$destination" ]
}

binary_directory_metadata_is_safe() {
    local owner="$1" mode="$2"
    [ "$owner" = 0 ] || return 1
    case "$mode" in
        '' | *[!0-7]*) return 1 ;;
    esac
    # Special bits are harmless here; only group/other write permission lets an
    # unprivileged process replace the staged/final child between our checks.
    [ $((8#$mode & 8#22)) -eq 0 ]
}

binary_directory_path_metadata() {
    command stat -L -c '%u %a' -- "$1"
}

physical_directory_path() {
    CDPATH='' cd -- "$1" 2>/dev/null && pwd -P
}

binary_directory_exists() {
    [ -d "$1" ]
}

binary_path_is_symlink() {
    [ -L "$1" ]
}

binary_path_symlink_target() {
    readlink -- "$1"
}

binary_path_kind() {
    if binary_path_is_symlink "$1"; then
        if [ -d "$1" ]; then
            printf '%s' directory-symlink
        else
            printf '%s' invalid-symlink
        fi
    elif [ -d "$1" ]; then
        printf '%s' directory
    elif [ -e "$1" ]; then
        printf '%s' other
    else
        printf '%s' missing
    fi
}

require_safe_directory_chain() {
    local path="$1" description="$2" remediation="$3" current='/' rest component \
          owner mode extra metadata symlink_target
    case "$path" in
        /) rest='' ;;
        /*) rest="${path#/}" ;;
        *) die "$description is not absolute: $path" ;;
    esac

    while :; do
        if binary_path_is_symlink "$current"; then
            symlink_target="$(binary_path_symlink_target "$current" 2>/dev/null)" ||
                die "could not inspect $description symlink $current"
            # Conservatively reject custom symlink ancestry: even when its final
            # physical destination is safe, a nested target may pass through an
            # attacker-writable hop that `pwd -P` no longer exposes. The standard
            # merged-/usr root link is the sole narrow exception; `/` is already
            # validated and its direct, canonical target is checked below too.
            if [ "$current" != /bin ] ||
                { [ "$symlink_target" != usr/bin ] &&
                    [ "$symlink_target" != /usr/bin ]; }; then
                die "$description contains symlink $current -> $symlink_target; use a physical root-controlled path (only the standard /bin -> usr/bin merged-/usr link is accepted)"
            fi
        fi
        metadata="$(binary_directory_path_metadata "$current" 2>/dev/null)" ||
            die "could not inspect $description ancestor $current"
        read -r owner mode extra <<<"$metadata"
        if [ -n "${extra:-}" ] ||
            ! binary_directory_metadata_is_safe "$owner" "$mode"; then
            die "$description ancestor $current must resolve to a root-owned directory that is not group- or world-writable; $remediation"
        fi
        [ -n "$rest" ] || break
        component="${rest%%/*}"
        case "$rest" in
            */*) rest="${rest#*/}" ;;
            *) rest='' ;;
        esac
        current="$(join_path_child "$current" "$component")"
    done
}

require_safe_binary_directory_chain() {
    require_safe_directory_chain "$1" "$2" \
        "fix its ownership/mode or choose a safe --prefix"
}

require_safe_binary_directory() {
    local directory="$1" physical
    case "$directory" in
        /*) ;;
        *) die "binary install directory is not absolute: $directory" ;;
    esac
    [ "$(normalize_path "$directory")" = "$directory" ] ||
        die "binary install directory is not canonical: $directory"
    binary_directory_exists "$directory" ||
        die "binary install directory $directory is missing or is not a directory"

    # Validate both spellings. The lexical chain protects every pathname entry
    # used during staging; the physical chain catches an intermediate symlink
    # whose target lives below a user-controlled ancestor. `/bin` remains valid
    # on merged-/usr systems when both `/bin` and `/usr/bin` chains are trusted.
    physical="$(physical_directory_path "$directory")" ||
        die "could not resolve binary install directory $directory"
    require_safe_binary_directory_chain "$directory" "binary install path"
    if [ "$physical" != "$directory" ]; then
        require_safe_binary_directory_chain "$physical" \
            "resolved binary install path for $directory"
    fi
}

# Status is intentionally available before the root/systemd gates, so never run
# a binary merely because a hand-edited unit names it. Query --version only for
# the same physical, root-controlled shape the installer itself maintains.
installed_binary_is_safe_for_status() {
    local path="$1" directory metadata owner mode extra
    case "$path" in /*) ;; *) return 1 ;; esac
    [ "$(normalize_path "$path")" = "$path" ] || return 1
    [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] || return 1
    directory="$(dirname -- "$path")" || return 1
    (require_safe_binary_directory "$directory") >/dev/null 2>&1 || return 1
    metadata="$(stat -Lc '%u %a' -- "$path" 2>/dev/null)" || return 1
    read -r owner mode extra <<<"$metadata"
    [ -z "${extra:-}" ] || return 1
    binary_directory_metadata_is_safe "$owner" "$mode" || return 1
    # The installer writes 0755 binaries. Reject set-ID/sticky variants so a
    # privileged status query cannot regain credentials inside its sandbox.
    [ $((8#$mode & 8#7000)) -eq 0 ]
}

status_effective_uid() {
    case "${EUID:-}" in
        '' | *[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "$EUID"
}

# Status is dispatched before the root/systemd gates. A root invocation must
# never execute an installed payload as root, while an ordinary caller can query
# the root-controlled binary as itself. If the transient sandbox is unavailable,
# fail closed and let do_status report an unknown version.
query_installed_binary_version() {
    local path="$1" effective_uid
    effective_uid="$(status_effective_uid)" || return 1
    case "$effective_uid" in
        0) run_in_service_sandbox "$path" --version ;;
        '' | *[!0-9]*) return 1 ;;
        *) "$path" --version ;;
    esac
}

require_safe_service_file_directory() {
    local directory="$1" description="$2" remediation="$3" physical
    case "$directory" in
        /*) ;;
        *) die "$description directory is not absolute: $directory" ;;
    esac
    [ "$(normalize_path "$directory")" = "$directory" ] ||
        die "$description directory is not canonical: $directory"
    binary_directory_exists "$directory" ||
        die "$description directory $directory is missing or is not a directory"

    physical="$(physical_directory_path "$directory")" ||
        die "could not resolve $description directory $directory"
    require_safe_directory_chain "$directory" "$description path" "$remediation"
    if [ "$physical" != "$directory" ]; then
        require_safe_directory_chain "$physical" \
            "resolved $description path for $directory" "$remediation"
    fi
}

require_safe_service_config_directory() {
    require_safe_service_file_directory "$1" "service config" \
        "fix its ownership/mode or choose a config under $CONFIG_DIR"
}

require_safe_service_userlist_directory() {
    require_safe_service_file_directory "$1" "service userlist" \
        "fix its ownership/mode or choose a userlist under $CONFIG_DIR"
}

service_config_metadata_is_safe() {
    local owner="$1" group="$2" mode="$3" expected_group="$4"
    [ "$owner" = 0 ] && [ "$group" = "$expected_group" ] && [ "$mode" = 640 ]
}

service_config_path_metadata() {
    command stat -L -c '%u %g %a' -- "$1"
}

service_group_record() {
    getent group "$SERVICE_USER"
}

service_group_id() {
    local record name fields group_id
    record="$(service_group_record 2>/dev/null)" || return 1
    name="${record%%:*}"
    fields="${record#*:}"
    [ "$fields" != "$record" ] && [ "$name" = "$SERVICE_USER" ] || return 1
    case "$fields" in *:*) fields="${fields#*:}" ;; *) return 1 ;; esac
    case "$fields" in *:*) group_id="${fields%%:*}" ;; *) return 1 ;; esac
    case "$group_id" in
        '' | *[!0-9]*) return 1 ;;
    esac
    printf '%s' "$group_id"
}

require_secure_service_config_file() {
    local path="$1" metadata owner group mode extra expected_group quoted_path
    metadata="$(service_config_path_metadata "$path" 2>/dev/null)" ||
        die "could not inspect service config metadata at $path"
    read -r owner group mode extra <<<"$metadata"
    expected_group="$(service_group_id)" ||
        die "could not resolve group id for service group $SERVICE_USER"
    if [ -n "${extra:-}" ] ||
        ! service_config_metadata_is_safe "$owner" "$group" "$mode" "$expected_group"; then
        printf -v quoted_path '%q' "$path"
        die "service config $path must be owned by root:$SERVICE_USER with mode 640; run: chown root:$SERVICE_USER -- $quoted_path && chmod 640 -- $quoted_path, then retry"
    fi
}

require_secure_service_userlist_file() {
    local path="$1" metadata owner group mode extra expected_group quoted_path
    [ "$(service_userlist_path_kind "$path")" = regular ] ||
        die "configured userlist $path changed while it was being validated; it must be a physical regular file"
    metadata="$(service_config_path_metadata "$path" 2>/dev/null)" ||
        die "could not inspect service userlist metadata at $path"
    read -r owner group mode extra <<<"$metadata"
    expected_group="$(service_group_id)" ||
        die "could not resolve group id for service group $SERVICE_USER"
    if [ -n "${extra:-}" ] ||
        ! service_config_metadata_is_safe "$owner" "$group" "$mode" "$expected_group"; then
        printf -v quoted_path '%q' "$path"
        die "service userlist $path must be owned by root:$SERVICE_USER with mode 640; run: chown root:$SERVICE_USER -- $quoted_path && chmod 640 -- $quoted_path, then retry"
    fi
}

require_safe_binary_directory_parent_for_creation() {
    local directory="$1" current kind parent
    case "$directory" in
        /*) ;;
        *) die "binary install directory is not absolute: $directory" ;;
    esac
    [ "$(normalize_path "$directory")" = "$directory" ] ||
        die "binary install directory is not canonical: $directory"
    current="$directory"
    while :; do
        kind="$(binary_path_kind "$current")" ||
            die "could not inspect prospective binary install path $current"
        case "$kind" in
            directory | directory-symlink) break ;;
            missing)
                parent="$(dirname -- "$current")" ||
                    die "could not inspect prospective binary install path $current"
                [ "$parent" != "$current" ] ||
                    die "could not find an existing parent for binary install directory $directory"
                current="$parent"
                ;;
            invalid-symlink)
                die "prospective binary install path $current is a dangling or non-directory symlink; remove it or choose a safe --prefix"
                ;;
            *)
                die "prospective binary install path $current exists but is not a directory; remove it or choose a safe --prefix"
                ;;
        esac
    done
    require_safe_binary_directory "$current"
}

prepare_binary_directory() {
    local directory="$1"
    # Validate the nearest existing parent before creating a missing tail, then
    # revalidate the completed lexical and physical chains before staging bytes.
    require_safe_binary_directory_parent_for_creation "$directory"
    install_file_command -d -m 755 -- "$directory" ||
        die "could not create binary install directory $directory"
    require_safe_binary_directory "$directory"
}

replace_file_atomically() {
    local source="$1" destination="$2"
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    # Plain `mv SOURCE DEST` treats an existing directory (including a symlink
    # to one) as a container. Reject that shape before the same-filesystem rename.
    [ ! -d "$destination" ] || return 1
    move_file_command -f -- "$source" "$destination" || return 1
    [ ! -e "$source" ] && [ ! -L "$source" ] &&
        [ -f "$destination" ] && [ ! -L "$destination" ]
}

# "Installed" means this script's systemd unit is present. A bare binary at the
# default path (e.g. from `cargo install`) is not treated as an install, so the
# menu and uninstall never act on something we did not deploy.
is_installed() {
    [ -f "$UNIT_FILE" ]
}

regular_files_match_for_rollback() {
    local left="$1" right="$2" left_metadata right_metadata
    [ -f "$left" ] && [ ! -L "$left" ] &&
        [ -f "$right" ] && [ ! -L "$right" ] || return 1
    command cmp -s "$left" "$right" || return 1
    left_metadata="$(stat -Lc '%u %g %a' -- "$left" 2>/dev/null)" || return 1
    right_metadata="$(stat -Lc '%u %g %a' -- "$right" 2>/dev/null)" || return 1
    [ "$left_metadata" = "$right_metadata" ]
}

remove_retained_backup_if_expected() {
    local expected="$1"
    [ -n "$UNIT_RETAINED_BACKUP" ] || return 0
    if [ ! -e "$UNIT_RETAINED_BACKUP" ] && [ ! -L "$UNIT_RETAINED_BACKUP" ]; then
        return 0
    fi
    if [ -f "$UNIT_RETAINED_BACKUP" ] && [ ! -L "$UNIT_RETAINED_BACKUP" ] &&
        [ -f "$expected" ] && [ ! -L "$expected" ] &&
        [ "$UNIT_RETAINED_BACKUP" -ef "$expected" ]; then
        command rm -f -- "$UNIT_RETAINED_BACKUP" 2>/dev/null ||
            warn "could not remove obsolete migration recovery link $UNIT_RETAINED_BACKUP"
        return 0
    fi
    warn "preserved concurrently changed migration backup $UNIT_RETAINED_BACKUP"
}

# Restore the exact displaced legacy unit without ever force-renaming over the
# live pathname. If a file is present, first move that exact object into the
# deterministic same-filesystem journal, classify it there, then hard-link
# either it or the backup into the absent live name. Every publication is link(2)
# create-if-absent, so another operator always wins a concurrent pathname race.
# Return 0 when restored, 2 when a concurrent unit was preserved, and 1 when
# recovery failed with all available copies left in place.
rollback_linked_unit_transaction() {
    local rollback_live displaced_is_candidate=0
    UNIT_ROLLBACK_CONFLICT_COPY=""

    [ -n "$UNIT_TRANSACTION_DIR" ] || return 1
    rollback_live="${UNIT_TRANSACTION_DIR}/rollback.displaced"

    if [ -z "$UNIT_BACKUP" ] || [ ! -f "$UNIT_BACKUP" ] || [ -L "$UNIT_BACKUP" ]; then
        # The guard is armed before detach. If the backup is still absent and
        # the live file is not the staged candidate, no move occurred.
        if [ -e "$rollback_live" ] || [ -L "$rollback_live" ]; then
            UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
            return 1
        fi
        if [ -f "$UNIT_FILE" ] && [ ! -L "$UNIT_FILE" ] &&
            { [ -z "$STAGED_UNIT" ] || [ ! -f "$STAGED_UNIT" ] ||
                [ -L "$STAGED_UNIT" ] || [ ! "$STAGED_UNIT" -ef "$UNIT_FILE" ]; }; then
            return 0
        fi
        return 1
    fi

    if [ -e "$rollback_live" ] || [ -L "$rollback_live" ]; then
        if [ ! -f "$rollback_live" ] || [ -L "$rollback_live" ]; then
            UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
            return 1
        fi
        if [ -n "$STAGED_UNIT" ] && [ -f "$STAGED_UNIT" ] &&
            [ ! -L "$STAGED_UNIT" ] && [ "$rollback_live" -ef "$STAGED_UNIT" ] &&
            [ -n "$UNIT_CANDIDATE_SNAPSHOT" ] &&
            regular_files_match_for_rollback \
                "$rollback_live" "$UNIT_CANDIDATE_SNAPSHOT"; then
            displaced_is_candidate=1
        fi
    fi

    # A previous recovery may already have linked the old unit back before it
    # was interrupted. Finish that exact rollback instead of classifying the old
    # inode as a concurrent replacement on the next invocation.
    if [ -f "$UNIT_FILE" ] && [ ! -L "$UNIT_FILE" ] &&
        [ "$UNIT_FILE" -ef "$UNIT_BACKUP" ]; then
        if [ -e "$rollback_live" ] || [ -L "$rollback_live" ]; then
            if [ "$displaced_is_candidate" -eq 1 ] ||
                { [ -f "$rollback_live" ] && [ ! -L "$rollback_live" ] &&
                    [ "$rollback_live" -ef "$UNIT_BACKUP" ]; }; then
                command rm -f -- "$rollback_live" 2>/dev/null || {
                    UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
                    return 1
                }
            else
                UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
                return 2
            fi
        fi
        command rm -f -- "$UNIT_BACKUP" 2>/dev/null || return 1
        return 0
    fi

    # Resume an interruption after the exact live pathname was moved into the
    # deterministic journal. The displaced inode is either our unchanged
    # candidate or an operator's unit, and publication remains no-replace.
    if [ -e "$rollback_live" ] || [ -L "$rollback_live" ]; then
        if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
            if [ -f "$UNIT_FILE" ] && [ ! -L "$UNIT_FILE" ] &&
                [ "$UNIT_FILE" -ef "$rollback_live" ]; then
                command rm -f -- "$rollback_live" 2>/dev/null ||
                    UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
                return 2
            fi
            if [ "$displaced_is_candidate" -eq 1 ]; then
                command rm -f -- "$rollback_live" 2>/dev/null ||
                    UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
            else
                UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
            fi
            return 2
        fi

        if [ "$displaced_is_candidate" -eq 1 ]; then
            if link_regular_file_to_absent_path "$UNIT_BACKUP" "$UNIT_FILE"; then
                command rm -f -- "$rollback_live" 2>/dev/null || {
                    UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
                    return 1
                }
                command rm -f -- "$UNIT_BACKUP" 2>/dev/null || return 1
                return 0
            fi
            if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
                UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
                return 2
            fi
            UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
            return 1
        fi

        if link_regular_file_to_absent_path "$rollback_live" "$UNIT_FILE"; then
            command rm -f -- "$rollback_live" 2>/dev/null ||
                UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
            return 2
        fi
        UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
        if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then return 2; fi
        return 1
    fi

    if [ ! -e "$UNIT_FILE" ] && [ ! -L "$UNIT_FILE" ]; then
        if link_regular_file_to_absent_path "$UNIT_BACKUP" "$UNIT_FILE"; then
            command rm -f -- "$UNIT_BACKUP" 2>/dev/null || return 1
            return 0
        fi
        if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then return 2; fi
        return 1
    fi

    # Non-regular concurrent objects cannot be hard-linked and must stay exactly
    # where the operator placed them.
    if [ ! -f "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then return 2; fi

    if [ -e "$rollback_live" ] || [ -L "$rollback_live" ]; then
        UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
        return 1
    fi
    if ! replace_file_atomically "$UNIT_FILE" "$rollback_live" 2>/dev/null; then
        if [ -e "$rollback_live" ] || [ -L "$rollback_live" ]; then
            UNIT_ROLLBACK_CONFLICT_COPY="$rollback_live"
        fi
        if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then return 2; fi
        return 1
    fi
    rollback_linked_unit_transaction
}

# Restore the previous base unit while an install validation transaction is
# active. This is intentionally best-effort and safe under the EXIT trap: leave
# the backup in place if restoration itself fails so an operator can recover it.
rollback_unit_transaction() {
    [ "$UNIT_TRANSACTION_ACTIVE" -eq 1 ] || return 0

    local restored=0 conflict=0 rollback_result=0 \
          linked_transaction="$UNIT_TRANSACTION_USES_STAGED_LINK"
    UNIT_ROLLBACK_RELOAD_FAILED=0
    if [ "$UNIT_HAD_ORIGINAL" -eq 1 ]; then
        if [ "$UNIT_TRANSACTION_USES_STAGED_LINK" -eq 1 ]; then
            rollback_linked_unit_transaction || rollback_result=$?
            case "$rollback_result" in
                0) restored=1 ;;
                2) conflict=1 ;;
            esac
            # The helper can change the live pathname even when its final
            # cleanup reports failure. Refresh PID 1 before interpreting any
            # result so it never keeps the rejected candidate silently loaded.
            if ! systemctl daemon-reload >/dev/null 2>&1; then
                UNIT_ROLLBACK_RELOAD_FAILED=1
                warn "daemon-reload failed after the linked-unit rollback attempt; PID 1 may not match $UNIT_FILE (run: systemctl daemon-reload)"
            fi
        elif [ -n "$UNIT_BACKUP" ] && [ -f "$UNIT_BACKUP" ] &&
            replace_file_atomically "$UNIT_BACKUP" "$UNIT_FILE" 2>/dev/null; then
            restored=1
        fi
    elif command rm -f -- "$UNIT_FILE" 2>/dev/null; then
        restored=1
    fi

    if [ "$restored" -eq 1 ]; then
        remove_retained_backup_if_expected "$UNIT_FILE"
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        UNIT_TRANSACTION_USES_STAGED_LINK=0
        UNIT_BACKUP=""
        UNIT_RETAINED_BACKUP=""
        # Synchronise the manager with the restored/removed unit. A failure here
        # must not hide the original install error or make the EXIT trap recurse,
        # but it is safety-relevant because PID 1 may retain the rejected unit.
        if [ "$linked_transaction" -eq 0 ] &&
            ! systemctl daemon-reload >/dev/null 2>&1; then
            warn "the previous systemd unit was restored on disk, but daemon-reload failed; PID 1 may still retain the rejected candidate (run: systemctl daemon-reload)"
        fi
    elif [ "$conflict" -eq 1 ]; then
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        UNIT_TRANSACTION_USES_STAGED_LINK=0
        warn "did not overwrite the concurrently changed systemd unit at $UNIT_FILE; recovery copy kept at $UNIT_BACKUP"
        if [ -n "$UNIT_RETAINED_BACKUP" ] && [ -f "$UNIT_RETAINED_BACKUP" ]; then
            warn "the same displaced legacy unit is also retained at $UNIT_RETAINED_BACKUP"
        fi
        if [ -n "$UNIT_ROLLBACK_CONFLICT_COPY" ]; then
            warn "an additional concurrent unit copy was kept at $UNIT_ROLLBACK_CONFLICT_COPY"
        fi
        if [ "$linked_transaction" -eq 0 ] &&
            ! systemctl daemon-reload >/dev/null 2>&1; then
            warn "daemon-reload failed after the unit publication conflict; PID 1 may not match $UNIT_FILE (run: systemctl daemon-reload)"
        fi
    elif [ "$UNIT_HAD_ORIGINAL" -eq 1 ]; then
        warn "could not restore the previous systemd unit; recovery copy kept at $UNIT_BACKUP"
    else
        warn "could not remove the rejected systemd unit at $UNIT_FILE; remove it and run systemctl daemon-reload before starting the service"
    fi
    return 0
}

begin_unit_transaction() {
    if [ -z "$STAGED_UNIT" ] || [ ! -f "$STAGED_UNIT" ]; then
        die "staged systemd unit is missing; refusing to modify $UNIT_FILE"
    fi

    UNIT_BACKUP="${UNIT_FILE}.previous.$$"
    UNIT_HAD_ORIGINAL=0
    UNIT_TRANSACTION_USES_STAGED_LINK=0
    UNIT_CANDIDATE_SNAPSHOT=""
    UNIT_TRANSACTION_DIR=""
    UNIT_RETAINED_BACKUP=""
    if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
        if [ ! -f "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
            die "systemd unit path $UNIT_FILE is not a regular file; refusing to replace it"
        fi
        if [ -e "$UNIT_BACKUP" ] || [ -L "$UNIT_BACKUP" ]; then
            die "temporary unit backup path already exists: $UNIT_BACKUP"
        fi
        copy_regular_file_to_absent_path "$UNIT_FILE" "$UNIT_BACKUP" ||
            die "could not preserve the existing systemd unit at $UNIT_BACKUP"
        UNIT_HAD_ORIGINAL=1
    else
        UNIT_BACKUP=""
    fi

    # Set the guard before the atomic replacement so cleanup also handles an
    # interrupted/failed move. The old unit remains recoverable in UNIT_BACKUP.
    UNIT_TRANSACTION_ACTIVE=1
    if ! replace_file_atomically "$STAGED_UNIT" "$UNIT_FILE"; then
        rollback_unit_transaction
        die "could not stage the new systemd unit at $UNIT_FILE"
    fi
    STAGED_UNIT=""
}

# A recognized legacy unit is operator-customizable, so migration must not copy
# it and later overwrite a newer pathname. Detach the exact live inode first,
# validate that displaced file, then publish with link(2)'s atomic create-if-
# absent semantics. The staged hard link remains as an inode guard until commit
# or rollback; if another unit appears, rollback preserves both files.
begin_legacy_unit_transaction() {
    local expected_kind="$1" install_bin="$2" config_file="$3" concurrent_unit=0 \
          transaction_candidate link_probe
    if [ -z "$STAGED_UNIT" ] || [ ! -f "$STAGED_UNIT" ] || [ -L "$STAGED_UNIT" ]; then
        die "staged systemd unit is missing; refusing to modify $UNIT_FILE"
    fi
    if [ ! -f "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
        die "systemd unit path $UNIT_FILE is not a regular file; refusing to migrate it"
    fi
    require_hardlink_utility

    UNIT_TRANSACTION_DIR="${UNIT_FILE}.migration"
    UNIT_RETAINED_BACKUP="${UNIT_FILE}.pre-migration"
    if [ -e "$UNIT_TRANSACTION_DIR" ] || [ -L "$UNIT_TRANSACTION_DIR" ]; then
        die "an unfinished legacy-unit transaction exists at $UNIT_TRANSACTION_DIR; rerun the installer to recover it before retrying"
    fi
    if [ -e "$UNIT_RETAINED_BACKUP" ] || [ -L "$UNIT_RETAINED_BACKUP" ]; then
        die "a retained legacy-unit backup already exists at $UNIT_RETAINED_BACKUP; preserve or remove it before retrying migration"
    fi
    command mkdir -m 700 -- "$UNIT_TRANSACTION_DIR" ||
        die "could not create legacy-unit transaction directory $UNIT_TRANSACTION_DIR"

    # Keep every transaction artifact under one deterministic directory so the
    # next privileged invocation can recover after an untrappable process exit.
    transaction_candidate="${UNIT_TRANSACTION_DIR}/candidate"
    replace_file_atomically "$STAGED_UNIT" "$transaction_candidate" ||
        die "could not journal the staged unit at $transaction_candidate"
    STAGED_UNIT="$transaction_candidate"
    UNIT_CANDIDATE_SNAPSHOT="${UNIT_TRANSACTION_DIR}/candidate.snapshot"
    copy_regular_file_to_absent_path \
        "$STAGED_UNIT" "$UNIT_CANDIDATE_SNAPSHOT" ||
        die "could not preserve the staged unit snapshot at $UNIT_CANDIDATE_SNAPSHOT"
    # Exercise the exact hard-link primitive on the unit filesystem before the
    # live legacy pathname is detached. BusyBox-only hosts commonly lack `link`.
    link_probe="${UNIT_TRANSACTION_DIR}/link.probe"
    link_regular_file_to_absent_path "$STAGED_UNIT" "$link_probe" ||
        die "could not create a hard link in $(dirname -- "$UNIT_FILE"); legacy-unit migration was not started"
    command rm -f -- "$link_probe" ||
        die "could not remove legacy-unit hard-link probe $link_probe"
    UNIT_BACKUP="${UNIT_TRANSACTION_DIR}/previous"

    UNIT_HAD_ORIGINAL=1
    UNIT_TRANSACTION_USES_STAGED_LINK=1
    UNIT_TRANSACTION_ACTIVE=1
    if ! replace_file_atomically "$UNIT_FILE" "$UNIT_BACKUP"; then
        rollback_unit_transaction
        die "could not detach the legacy systemd unit to $UNIT_BACKUP"
    fi

    if ! unit_file_is_safe_for_legacy_migration "$UNIT_BACKUP" ||
        ! legacy_unit_file_matches_kind "$UNIT_BACKUP" \
            "$expected_kind" "$install_bin" "$config_file"; then
        die "the legacy systemd unit content or metadata changed while it was being staged; the exact displaced unit will be restored"
    fi
    link_regular_file_to_absent_path "$UNIT_BACKUP" "$UNIT_RETAINED_BACKUP" ||
        die "could not retain the displaced legacy unit at $UNIT_RETAINED_BACKUP"

    if ! link_regular_file_to_absent_path "$STAGED_UNIT" "$UNIT_FILE"; then
        if [ -e "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
            if [ ! -f "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ] ||
                [ ! -f "$STAGED_UNIT" ] || [ -L "$STAGED_UNIT" ] ||
                [ ! "$STAGED_UNIT" -ef "$UNIT_FILE" ]; then
                concurrent_unit=1
            fi
        fi
        rollback_unit_transaction
        if [ "$concurrent_unit" -eq 1 ]; then
            die "the systemd unit changed during migration publication; no binary was replaced; review $UNIT_FILE and the recovery copy at $UNIT_BACKUP"
        fi
        die "could not publish the migrated systemd unit at $UNIT_FILE; the previous unit was restored and no binary was replaced"
    fi
}

create_unit_commit_marker() {
    local marker="$1"
    if [ -e "$marker" ] || [ -L "$marker" ]; then
        [ -f "$marker" ] && [ ! -L "$marker" ]
        return
    fi
    # noclobber asks bash to create the marker with O_EXCL semantics. The marker
    # is written only after the binary rename, and recovery treats it as the
    # persistent decision never to roll the unit back around the committed binary.
    (umask 077; set -o noclobber; : >"$marker") 2>/dev/null
}

journal_binary_commit_intent() {
    local staged_binary="$1" intent staged_intent
    [ "$UNIT_TRANSACTION_USES_STAGED_LINK" -eq 1 ] || return 0
    intent="${UNIT_TRANSACTION_DIR}/binary-commit-intent"
    staged_intent="${intent}.staged"
    if [ -e "$intent" ] || [ -L "$intent" ] ||
        [ -e "$staged_intent" ] || [ -L "$staged_intent" ]; then
        return 1
    fi
    (umask 077; printf '%s\n%s\n' "$staged_binary" complete >"$staged_intent") ||
        return 1
    chmod 600 -- "$staged_intent" || return 1
    replace_file_atomically "$staged_intent" "$intent"
}

staged_binary_recovery_path_has_managed_shape() {
    local path="$1" suffix base
    case "$path" in /*.new.*) ;; *) return 1 ;; esac
    suffix="${path##*.new.}"
    case "$suffix" in '' | *[!0-9]*) return 1 ;; esac
    base="${path%".new.$suffix"}"
    [ -n "$base" ] && [ "$base" != "$path" ] &&
        [ "$(normalize_path "$path")" = "$path" ] &&
        [ "$(normalize_path "$base")" = "$base" ]
}

mark_binary_transaction_for_rollback() {
    local intent rollback untrusted_rollback staged_intent source="" destination
    [ "$UNIT_TRANSACTION_USES_STAGED_LINK" -eq 1 ] || return 0
    intent="${UNIT_TRANSACTION_DIR}/binary-commit-intent"
    rollback="${UNIT_TRANSACTION_DIR}/binary-rollback"
    untrusted_rollback="${UNIT_TRANSACTION_DIR}/binary-rollback-untrusted"
    staged_intent="${intent}.staged"
    if [ -e "$untrusted_rollback" ] || [ -L "$untrusted_rollback" ]; then
        [ -f "$untrusted_rollback" ] && [ ! -L "$untrusted_rollback" ]
        return
    fi
    if [ -e "$rollback" ] || [ -L "$rollback" ]; then
        [ -f "$rollback" ] && [ ! -L "$rollback" ]
        return
    fi
    if [ -e "$intent" ] || [ -L "$intent" ]; then
        source="$intent"
        destination="$rollback"
    elif [ -e "$staged_intent" ] || [ -L "$staged_intent" ]; then
        source="$staged_intent"
        destination="$untrusted_rollback"
    else
        return 0
    fi
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 1
    replace_file_atomically "$source" "$destination"
}

finalize_committed_legacy_unit_transaction() {
    local marker="${UNIT_TRANSACTION_DIR}/committed" artifact cleanup_ok=1
    for artifact in "$UNIT_BACKUP" "$UNIT_CANDIDATE_SNAPSHOT" "$STAGED_UNIT" \
        "${UNIT_TRANSACTION_DIR}/rollback.displaced" \
        "${UNIT_TRANSACTION_DIR}/link.probe" \
        "${UNIT_TRANSACTION_DIR}/binary-commit-intent" \
        "${UNIT_TRANSACTION_DIR}/binary-commit-intent.staged" \
        "${UNIT_TRANSACTION_DIR}/binary-rollback" \
        "${UNIT_TRANSACTION_DIR}/binary-rollback-untrusted"; do
        [ -n "$artifact" ] || continue
        if [ -e "$artifact" ] || [ -L "$artifact" ]; then
            if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
                warn "preserved unsafe committed-transaction artifact $artifact"
                cleanup_ok=0
            elif ! command rm -f -- "$artifact" 2>/dev/null; then
                warn "could not remove committed-transaction artifact $artifact"
                cleanup_ok=0
            fi
        fi
    done
    if [ "$cleanup_ok" -eq 1 ]; then
        if ! command rm -f -- "$marker" 2>/dev/null; then
            warn "could not remove committed transaction marker $marker"
            cleanup_ok=0
        elif ! command rmdir -- "$UNIT_TRANSACTION_DIR" 2>/dev/null; then
            warn "could not remove committed transaction directory $UNIT_TRANSACTION_DIR"
            cleanup_ok=0
        fi
    fi
    [ "$cleanup_ok" -eq 1 ]
}

commit_unit_transaction() {
    if [ "$UNIT_TRANSACTION_USES_STAGED_LINK" -eq 1 ]; then
        local marker="${UNIT_TRANSACTION_DIR}/committed"
        if ! create_unit_commit_marker "$marker"; then
            warn "the binary was replaced, but the migration commit marker could not be created at $marker"
            return 1
        fi
        finalize_committed_legacy_unit_transaction ||
            warn "the migration is committed; its journal will be finalized by the next privileged lifecycle command"
    else
        if [ -n "$UNIT_BACKUP" ]; then
            command rm -f -- "$UNIT_BACKUP" 2>/dev/null ||
                warn "could not remove obsolete unit backup $UNIT_BACKUP"
        fi
        if [ -n "$UNIT_CANDIDATE_SNAPSHOT" ]; then
            command rm -f -- "$UNIT_CANDIDATE_SNAPSHOT" 2>/dev/null ||
                warn "could not remove obsolete staged unit snapshot $UNIT_CANDIDATE_SNAPSHOT"
        fi
        if [ -n "$STAGED_UNIT" ]; then
            command rm -f -- "$STAGED_UNIT" 2>/dev/null ||
                warn "could not remove obsolete staged unit link $STAGED_UNIT"
        fi
        if [ -n "$UNIT_TRANSACTION_DIR" ]; then
            command rmdir -- "$UNIT_TRANSACTION_DIR" 2>/dev/null ||
                warn "could not remove obsolete unit transaction directory $UNIT_TRANSACTION_DIR"
        fi
    fi
    if [ -n "$UNIT_RETAINED_BACKUP" ] && [ -f "$UNIT_RETAINED_BACKUP" ]; then
        info "retained the exact pre-migration systemd unit at $UNIT_RETAINED_BACKUP"
    fi
    UNIT_TRANSACTION_ACTIVE=0
    UNIT_HAD_ORIGINAL=0
    UNIT_TRANSACTION_USES_STAGED_LINK=0
    UNIT_BACKUP=""
    UNIT_CANDIDATE_SNAPSHOT=""
    STAGED_UNIT=""
    UNIT_TRANSACTION_DIR=""
    UNIT_RETAINED_BACKUP=""
    return 0
}

# Remove any staged install/upgrade artifacts and roll back an uncommitted unit.
cleanup() {
    local preserve_journal=0
    # Best-effort: a failing rm must not abort the EXIT trap (under errexit) or
    # change the script's original exit status, so swallow any error.
    # The staged binary lives beside its destination, so mv uses one atomic
    # rename. If a signal lands after that rename but before the following shell
    # instruction, its source is gone: retain the already-validated unit rather
    # than rolling it back around the newly installed binary.
    if [ "$UNIT_TRANSACTION_ACTIVE" -eq 1 ] &&
        [ "$BINARY_COMMIT_IN_PROGRESS" -eq 1 ] && [ -n "$STAGED_BIN" ] &&
        [ ! -e "$STAGED_BIN" ] && [ ! -L "$STAGED_BIN" ]; then
        if ! commit_unit_transaction; then
            warn "could not finalize the committed legacy-unit transaction"
            preserve_journal=1
        fi
    else
        if [ "$UNIT_TRANSACTION_ACTIVE" -eq 1 ] &&
            [ "$UNIT_TRANSACTION_USES_STAGED_LINK" -eq 1 ] &&
            ! mark_binary_transaction_for_rollback; then
            warn "could not journal the binary rollback decision; preserving the transaction without further mutation"
            preserve_journal=1
        fi
        if [ "$preserve_journal" -eq 0 ]; then
            rollback_unit_transaction
        fi
    fi
    if [ -n "$UNIT_BACKUP" ] &&
        { [ -e "$UNIT_BACKUP" ] || [ -L "$UNIT_BACKUP" ]; }; then
        preserve_journal=1
    fi
    if [ "$UNIT_ROLLBACK_RELOAD_FAILED" -eq 1 ]; then
        preserve_journal=1
    fi
    if [ "$preserve_journal" -eq 0 ] && [ -n "$STAGED_BIN" ]; then
        if ! rm -f -- "$STAGED_BIN" 2>/dev/null ||
            [ -e "$STAGED_BIN" ] || [ -L "$STAGED_BIN" ]; then
            warn "could not remove the rolled-back staged binary; preserving its rollback journal"
            preserve_journal=1
        fi
    fi
    if [ "$preserve_journal" -eq 0 ] && [ -n "$UNIT_TRANSACTION_DIR" ]; then
        # The persistent rollback decision is removed only after its staged
        # source. Every interruption prefix therefore remains distinguishable
        # from a completed binary rename.
        if ! rm -f -- "${UNIT_TRANSACTION_DIR}/binary-rollback" \
            "${UNIT_TRANSACTION_DIR}/binary-rollback-untrusted" \
            "${UNIT_TRANSACTION_DIR}/binary-commit-intent" \
            "${UNIT_TRANSACTION_DIR}/binary-commit-intent.staged" 2>/dev/null ||
            [ -e "${UNIT_TRANSACTION_DIR}/binary-rollback" ] ||
            [ -L "${UNIT_TRANSACTION_DIR}/binary-rollback" ] ||
            [ -e "${UNIT_TRANSACTION_DIR}/binary-rollback-untrusted" ] ||
            [ -L "${UNIT_TRANSACTION_DIR}/binary-rollback-untrusted" ] ||
            [ -e "${UNIT_TRANSACTION_DIR}/binary-commit-intent" ] ||
            [ -L "${UNIT_TRANSACTION_DIR}/binary-commit-intent" ] ||
            [ -e "${UNIT_TRANSACTION_DIR}/binary-commit-intent.staged" ] ||
            [ -L "${UNIT_TRANSACTION_DIR}/binary-commit-intent.staged" ]; then
            warn "could not clear the binary rollback decision; preserving its journal"
            preserve_journal=1
        fi
    fi
    if [ "$preserve_journal" -eq 0 ]; then
        if [ -n "$STAGED_UNIT" ]; then rm -f -- "$STAGED_UNIT" 2>/dev/null || true; fi
        if [ -n "$UNIT_CANDIDATE_SNAPSHOT" ]; then
            rm -f -- "$UNIT_CANDIDATE_SNAPSHOT" 2>/dev/null || true
        fi
        if [ -n "$UNIT_TRANSACTION_DIR" ]; then
            if command rmdir -- "$UNIT_TRANSACTION_DIR" 2>/dev/null; then
                UNIT_TRANSACTION_DIR=""
            fi
        fi
    fi
    return 0
}
trap cleanup EXIT

legacy_transaction_directory_is_safe() {
    local directory="$1" metadata owner mode extra
    [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
    metadata="$(stat -Lc '%u %a' -- "$directory" 2>/dev/null)" || return 1
    read -r owner mode extra <<<"$metadata"
    [ -z "${extra:-}" ] && [ "$owner" = 0 ] && [ "$mode" = 700 ]
}

# A persistent `.migration` directory makes the detach/publish sequence
# recoverable when process traps cannot run. Before any privileged lifecycle
# action, roll an incomplete migration back with the same no-replace logic.
recover_interrupted_legacy_unit_transaction() {
    local transaction_dir="${UNIT_FILE}.migration" candidate snapshot backup \
          displaced marker intent staged_intent binary_rollback artifact \
          untrusted_rollback decision_file="" decision_kind="" \
          decision_record_trusted=0 recovery_staged_bin="" recovery_result=0
    local -a intent_lines=()
    [ ! -e "$transaction_dir" ] && [ ! -L "$transaction_dir" ] && return 0
    legacy_transaction_directory_is_safe "$transaction_dir" ||
        die "unfinished legacy-unit transaction directory is unsafe: $transaction_dir"

    candidate="${transaction_dir}/candidate"
    snapshot="${transaction_dir}/candidate.snapshot"
    backup="${transaction_dir}/previous"
    displaced="${transaction_dir}/rollback.displaced"
    marker="${transaction_dir}/committed"
    intent="${transaction_dir}/binary-commit-intent"
    staged_intent="${intent}.staged"
    binary_rollback="${transaction_dir}/binary-rollback"
    untrusted_rollback="${transaction_dir}/binary-rollback-untrusted"

    if [ -e "$marker" ] || [ -L "$marker" ]; then
        if [ ! -f "$marker" ] || [ -L "$marker" ]; then
            die "legacy-unit transaction commit marker is unsafe: $marker"
        fi
        STAGED_UNIT=""
        UNIT_CANDIDATE_SNAPSHOT=""
        if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then STAGED_UNIT="$candidate"; fi
        if [ -f "$snapshot" ] && [ ! -L "$snapshot" ]; then
            UNIT_CANDIDATE_SNAPSHOT="$snapshot"
        fi
        UNIT_BACKUP="$backup"
        UNIT_TRANSACTION_DIR="$transaction_dir"
        UNIT_RETAINED_BACKUP="${UNIT_FILE}.pre-migration"
        UNIT_TRANSACTION_USES_STAGED_LINK=1
        finalize_committed_legacy_unit_transaction ||
            die "could not finalize committed legacy-unit transaction $transaction_dir"
        STAGED_UNIT=""
        UNIT_CANDIDATE_SNAPSHOT=""
        UNIT_BACKUP=""
        UNIT_TRANSACTION_DIR=""
        UNIT_RETAINED_BACKUP=""
        UNIT_TRANSACTION_USES_STAGED_LINK=0
        ok "Finalized the committed legacy systemd unit migration journal."
        warn "service activation may have been interrupted; if the upgrade was meant to restart Alighieri, run: systemctl restart $SERVICE_NAME"
        return 0
    fi

    if [ -e "$untrusted_rollback" ] || [ -L "$untrusted_rollback" ]; then
        decision_file="$untrusted_rollback"
        decision_kind=rollback
        if [ -e "$binary_rollback" ] || [ -L "$binary_rollback" ] ||
            [ -e "$intent" ] || [ -L "$intent" ] ||
            [ -e "$staged_intent" ] || [ -L "$staged_intent" ]; then
            die "legacy-unit journal contains conflicting binary decisions: $transaction_dir"
        fi
    elif [ -e "$binary_rollback" ] || [ -L "$binary_rollback" ]; then
        decision_file="$binary_rollback"
        decision_kind=rollback
        if [ -e "$intent" ] || [ -L "$intent" ] ||
            [ -e "$staged_intent" ] || [ -L "$staged_intent" ]; then
            die "legacy-unit journal contains conflicting binary decisions: $transaction_dir"
        fi
    elif [ -e "$intent" ] || [ -L "$intent" ]; then
        decision_file="$intent"
        decision_kind=intent
        if [ -e "$staged_intent" ] || [ -L "$staged_intent" ]; then
            die "legacy-unit journal contains both staged and published binary intents: $transaction_dir"
        fi
    elif [ -e "$staged_intent" ] || [ -L "$staged_intent" ]; then
        decision_file="$staged_intent"
        decision_kind=rollback
    fi

    if [ -n "$decision_file" ]; then
        if [ ! -f "$decision_file" ] || [ -L "$decision_file" ]; then
            die "legacy-unit binary decision is unsafe: $decision_file"
        fi
        if [ "$decision_file" != "$staged_intent" ] &&
            [ "$decision_file" != "$untrusted_rollback" ]; then
            mapfile -t intent_lines <"$decision_file" || intent_lines=()
            if [ "${#intent_lines[@]}" -eq 2 ] &&
                [ "${intent_lines[1]}" = complete ] &&
                staged_binary_recovery_path_has_managed_shape "${intent_lines[0]}"; then
                recovery_staged_bin="${intent_lines[0]}"
                decision_record_trusted=1
            else
                warn "binary decision record is incomplete; rolling the unit back without deleting an external staged path"
            fi
        fi
        if [ "$decision_record_trusted" -eq 1 ] &&
            { [ -L "$recovery_staged_bin" ] ||
                { [ -e "$recovery_staged_bin" ] && [ ! -f "$recovery_staged_bin" ]; }; }; then
            warn "binary decision source is unsafe; rolling the unit back without deleting $recovery_staged_bin"
            recovery_staged_bin=""
            decision_record_trusted=0
        fi
        if [ "$decision_record_trusted" -eq 1 ] &&
            [ "$decision_kind" = intent ] && [ ! -e "$recovery_staged_bin" ]; then
            # The intent is published immediately before one atomic binary
            # rename. An absent source therefore means the validated binary is
            # committed even if SIGKILL prevented the post-rename marker.
            STAGED_UNIT=""
            UNIT_CANDIDATE_SNAPSHOT=""
            if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then STAGED_UNIT="$candidate"; fi
            if [ -f "$snapshot" ] && [ ! -L "$snapshot" ]; then
                UNIT_CANDIDATE_SNAPSHOT="$snapshot"
            fi
            UNIT_BACKUP="$backup"
            UNIT_TRANSACTION_DIR="$transaction_dir"
            UNIT_RETAINED_BACKUP="${UNIT_FILE}.pre-migration"
            UNIT_TRANSACTION_USES_STAGED_LINK=1
            create_unit_commit_marker "$marker" ||
                die "could not record the recovered binary commit at $marker"
            finalize_committed_legacy_unit_transaction ||
                die "could not finalize recovered committed transaction $transaction_dir"
            STAGED_UNIT=""
            UNIT_CANDIDATE_SNAPSHOT=""
            UNIT_BACKUP=""
            UNIT_TRANSACTION_DIR=""
            UNIT_RETAINED_BACKUP=""
            UNIT_TRANSACTION_USES_STAGED_LINK=0
            ok "Recovered the committed binary and finalized its systemd unit migration."
            warn "service activation may have been interrupted; if the upgrade was meant to restart Alighieri, run: systemctl restart $SERVICE_NAME"
            return 0
        fi
        if [ "$decision_record_trusted" -eq 0 ]; then
            if [ "$decision_file" != "$untrusted_rollback" ]; then
                if [ -e "$untrusted_rollback" ] || [ -L "$untrusted_rollback" ]; then
                    die "legacy-unit untrusted rollback marker already exists: $untrusted_rollback"
                fi
                replace_file_atomically "$decision_file" "$untrusted_rollback" ||
                    die "could not persist the untrusted binary rollback decision at $untrusted_rollback"
                decision_file="$untrusted_rollback"
            fi
        elif [ "$decision_file" != "$binary_rollback" ]; then
            if [ -e "$binary_rollback" ] || [ -L "$binary_rollback" ]; then
                die "legacy-unit binary rollback marker already exists: $binary_rollback"
            fi
            replace_file_atomically "$decision_file" "$binary_rollback" ||
                die "could not persist the binary rollback decision at $binary_rollback"
            decision_file="$binary_rollback"
            decision_kind=rollback
        fi
    fi

    require_hardlink_utility
    if [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
        if [ -e "$displaced" ] || [ -L "$displaced" ]; then
            die "unfinished legacy-unit transaction has a displaced unit at $displaced but no recovery unit at $backup; preserve both paths for manual recovery"
        fi
        if [ ! -f "$UNIT_FILE" ] || [ -L "$UNIT_FILE" ]; then
            die "unfinished legacy-unit transaction has no recovery unit at $backup and $UNIT_FILE is not a physical regular file"
        fi
        if ! systemctl daemon-reload; then
            UNIT_ROLLBACK_RELOAD_FAILED=1
            die "could not reload systemd while finalizing a rolled-back legacy-unit migration"
        fi
        UNIT_RETAINED_BACKUP="${UNIT_FILE}.pre-migration"
        remove_retained_backup_if_expected "$UNIT_FILE"
        if [ -n "$recovery_staged_bin" ] &&
            { [ -e "$recovery_staged_bin" ] || [ -L "$recovery_staged_bin" ]; }; then
            if [ ! -f "$recovery_staged_bin" ] || [ -L "$recovery_staged_bin" ]; then
                die "incomplete transaction staged binary is unsafe: $recovery_staged_bin"
            fi
            command rm -f -- "$recovery_staged_bin" ||
                die "could not remove incomplete staged binary $recovery_staged_bin"
        fi
        for artifact in "$candidate" "$snapshot" "${transaction_dir}/link.probe" \
            "$intent" "$staged_intent" "$binary_rollback" "$untrusted_rollback"; do
            if [ -e "$artifact" ] || [ -L "$artifact" ]; then
                if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
                    die "unfinished legacy-unit transaction contains an unsafe artifact: $artifact"
                fi
                command rm -f -- "$artifact" ||
                    die "could not remove incomplete transaction artifact $artifact"
            fi
        done
        command rmdir -- "$transaction_dir" ||
            die "could not remove incomplete transaction directory $transaction_dir"
        UNIT_RETAINED_BACKUP=""
        UNIT_ROLLBACK_RELOAD_FAILED=0
        warn "cleared an interrupted legacy-unit journal with no displaced unit pending recovery"
        return 0
    fi
    if [ ! -f "$backup" ] || [ -L "$backup" ]; then
        die "unfinished legacy-unit transaction recovery path is unsafe: $backup"
    fi

    STAGED_UNIT=""
    UNIT_CANDIDATE_SNAPSHOT=""
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then STAGED_UNIT="$candidate"; fi
    if [ -f "$snapshot" ] && [ ! -L "$snapshot" ]; then
        UNIT_CANDIDATE_SNAPSHOT="$snapshot"
    fi
    UNIT_BACKUP="$backup"
    UNIT_TRANSACTION_DIR="$transaction_dir"
    UNIT_RETAINED_BACKUP="${UNIT_FILE}.pre-migration"
    UNIT_HAD_ORIGINAL=1
    UNIT_TRANSACTION_USES_STAGED_LINK=1
    UNIT_TRANSACTION_ACTIVE=1

    rollback_linked_unit_transaction || recovery_result=$?
    if ! systemctl daemon-reload; then
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        UNIT_TRANSACTION_USES_STAGED_LINK=0
        UNIT_ROLLBACK_RELOAD_FAILED=1
        die "legacy-unit recovery changed or inspected the live unit but daemon-reload failed; the recovery journal was preserved"
    fi
    UNIT_ROLLBACK_RELOAD_FAILED=0
    if [ "$recovery_result" -ne 0 ]; then
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        UNIT_TRANSACTION_USES_STAGED_LINK=0
        if [ "$recovery_result" -eq 2 ]; then
            if [ -n "$UNIT_ROLLBACK_CONFLICT_COPY" ]; then
                warn "an additional concurrent unit copy was kept at $UNIT_ROLLBACK_CONFLICT_COPY"
            fi
            die "a concurrent systemd unit was preserved while recovering $transaction_dir; review $UNIT_FILE and $UNIT_BACKUP before retrying"
        fi
        die "could not recover interrupted legacy-unit transaction $transaction_dir; recovery unit remains at $UNIT_BACKUP"
    fi

    remove_retained_backup_if_expected "$UNIT_FILE"
    if [ -n "$recovery_staged_bin" ] &&
        { [ -e "$recovery_staged_bin" ] || [ -L "$recovery_staged_bin" ]; }; then
        if [ ! -f "$recovery_staged_bin" ] || [ -L "$recovery_staged_bin" ]; then
            die "restored $UNIT_FILE but preserved unsafe staged binary $recovery_staged_bin"
        fi
        command rm -f -- "$recovery_staged_bin" ||
            die "restored $UNIT_FILE but could not remove staged binary $recovery_staged_bin"
    fi
    for artifact in "$binary_rollback" "$untrusted_rollback" "$intent" "$staged_intent" \
        "${transaction_dir}/link.probe"; do
        if [ -e "$artifact" ] || [ -L "$artifact" ]; then
            if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
                die "restored $UNIT_FILE but preserved unsafe journal artifact $artifact"
            fi
            command rm -f -- "$artifact" ||
                die "restored $UNIT_FILE but could not remove journal artifact $artifact"
        fi
    done
    if [ -n "$STAGED_UNIT" ]; then command rm -f -- "$STAGED_UNIT" 2>/dev/null || true; fi
    if [ -n "$UNIT_CANDIDATE_SNAPSHOT" ]; then
        command rm -f -- "$UNIT_CANDIDATE_SNAPSHOT" 2>/dev/null || true
    fi
    command rmdir -- "$transaction_dir" ||
        die "restored $UNIT_FILE but could not remove transaction directory $transaction_dir"
    UNIT_TRANSACTION_ACTIVE=0
    UNIT_HAD_ORIGINAL=0
    UNIT_TRANSACTION_USES_STAGED_LINK=0
    STAGED_UNIT=""
    UNIT_CANDIDATE_SNAPSHOT=""
    UNIT_BACKUP=""
    UNIT_TRANSACTION_DIR=""
    UNIT_RETAINED_BACKUP=""
    ok "Recovered the interrupted legacy systemd unit migration."
}

# True when REPO_ROOT is an Alighieri checkout we can build and configure from.
in_checkout() {
    [ -f "${REPO_ROOT}/Cargo.toml" ] && [ -f "${REPO_ROOT}/doc/alighieri.conf" ]
}

# True when this helper is running from the root layout produced by the Linux
# release workflow. Keeping the binary, helper, and default config together is
# the archive's provenance boundary; unlike the retired standalone mode, this
# never fetches executable content while running as root.
in_release_archive() {
    [ ! -f "${REPO_ROOT}/Cargo.toml" ] &&
        [ -f "${REPO_ROOT}/${SERVICE_NAME}" ] &&
        [ -f "${REPO_ROOT}/doc/alighieri.conf" ] &&
        [ -f "${REPO_ROOT}/README.md" ] &&
        [ -f "${REPO_ROOT}/CHANGELOG.md" ]
}

# Refuse to obtain executable source dynamically in a root process. Source
# builds must come from the checkout containing this script; Linux release
# archives instead carry a matching binary and default config.
require_checkout() {
    in_checkout ||
        die "no matching binary found; extract the complete Linux release archive, run from an Alighieri checkout, or pass --binary PATH"
}

# Locate the binary to install/upgrade from: an explicit --binary, the binary
# bundled beside this helper in a release archive, a prebuilt checkout binary,
# or a fresh Cargo build from the checkout.
resolve_source_binary() {
    if [ -n "$BINARY" ]; then
        # A regular file is enough; install sets mode 755 on the destination, so
        # the source need not already carry the exec bit (e.g. unzipped artifact).
        [ -f "$BINARY" ] || die "binary not found: $BINARY"
        return
    fi
    if in_release_archive; then
        BINARY="${REPO_ROOT}/${SERVICE_NAME}"
        info "using bundled release binary $BINARY"
        return
    fi
    if [ -x "${REPO_ROOT}/target/release/${SERVICE_NAME}" ]; then
        BINARY="${REPO_ROOT}/target/release/${SERVICE_NAME}"
        return
    fi
    require_checkout
    build_from_source
    BINARY="${REPO_ROOT}/target/release/${SERVICE_NAME}"
}

# Build the release binary in REPO_ROOT. cargo runs dependency build scripts and
# proc-macros, so when invoked via sudo we build as the original unprivileged
# user (via runuser) instead of executing that third-party code as root, without
# changing ownership of the checkout. Building as the invoking user also picks
# up their per-user Rust toolchain, which root's PATH often lacks. Otherwise
# build as the current user, warning when that user is root.
build_from_source() {
    local build_user="" invoker="${SUDO_USER:-}"
    if [ "$(id -u)" -eq 0 ] && [ -n "$invoker" ] && [ "$invoker" != "root" ] &&
        command -v runuser >/dev/null 2>&1; then
        build_user="$invoker"
    fi

    if [ -n "$build_user" ]; then
        info "building release binary as $build_user (not root)..."
        # Pass REPO_ROOT as a positional parameter to a login shell rather than
        # interpolating it into the command string, so a path with spaces or
        # quotes is handled safely; set HOME explicitly so the build user's Rust
        # toolchain (rustup installs on PATH via their profile) is found.
        # `|| true` so a missing/failing getent (minimal distro, NSS quirks)
        # leaves user_home empty under `set -euo pipefail` rather than aborting,
        # letting the /home/<user> fallback apply.
        local user_home
        user_home="$(getent passwd "$build_user" 2>/dev/null | cut -d: -f6 || true)"
        [ -n "$user_home" ] || user_home="/home/$build_user"
        # shellcheck disable=SC2016  # $1 is expanded by the inner login shell, not here
        runuser -u "$build_user" -- env "HOME=$user_home" \
            bash -lc 'cd -- "$1" && cargo build --release --locked' alighieri-build "$REPO_ROOT" ||
            die "cargo build failed as $build_user; ensure they have a Rust toolchain, or pass --binary"
        return
    fi

    command -v cargo >/dev/null 2>&1 ||
        die "no --binary given, ${REPO_ROOT}/target/release/${SERVICE_NAME} not built, and cargo not found; install a Rust toolchain or pass --binary"
    if [ "$(id -u)" -eq 0 ]; then
        warn "building from source as root; cargo runs third-party build scripts — prefer a prebuilt binary via --binary"
    fi
    info "building release binary with cargo..."
    ( cd -- "$REPO_ROOT" && cargo build --release --locked )
}

ensure_user() {
    if ! getent group "$SERVICE_USER" >/dev/null 2>&1; then
        info "creating system group $SERVICE_USER"
        groupadd --system "$SERVICE_USER"
    fi
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        info "creating system user $SERVICE_USER"
        useradd --system --gid "$SERVICE_USER" --no-create-home \
            --shell "$(nologin_shell)" "$SERVICE_USER"
    fi
}

# Run a read-only preflight with the same identity and path-hiding controls as
# the managed service. `runuser`/`su` would catch ordinary DAC traversal but not
# ProtectHome, PrivateTmp, or PrivateDevices; a transient unit exercises the
# real systemd mount namespace before the active unit is rewritten or restarted.
# WorkingDirectory is explicit here and in the generated unit so relative config
# values resolve identically.
run_in_service_sandbox() {
    local arg manager_version
    local -a escaped_args=()
    local -a run_options=(--quiet --wait --pipe)
    # systemd-run expands $VAR and ${VAR} in command arguments by default.
    # Doubling every dollar is the portable escape (including on releases
    # older than --expand-environment=no) and makes the transient process see
    # the exact parser-reported path that the long-running service will use.
    for arg in "$@"; do
        escaped_args+=("${arg//\$/\$\$}")
    done
    manager_version="$(systemd_manager_version)" || return 1
    # --collect was added in systemd 236. It only controls garbage collection
    # of the completed transient unit, so omit it on v235 while preserving the
    # same synchronous, piped preflight and propagated command exit status.
    if [ "$manager_version" -ge 236 ]; then
        run_options+=(--collect)
    fi
    systemd-run "${run_options[@]}" \
        --property="User=$SERVICE_USER" \
        --property="Group=$SERVICE_USER" \
        --property=NoNewPrivileges=true \
        --property=WorkingDirectory=/ \
        --property=ProtectSystem=strict \
        --property=ProtectHome=true \
        --property=PrivateTmp=true \
        --property=PrivateDevices=true \
        --property=ProtectKernelTunables=true \
        --property=ProtectKernelModules=true \
        --property=ProtectControlGroups=true \
        -- "${escaped_args[@]}"
}

# Whether the service needs CAP_NET_BIND_SERVICE to start, decided from a
# `--check --json` summary (the caller runs it once and passes it in). Rather than
# reparse the config — its keywords are case-insensitive, `include:` files expand
# inline, and `internal:` is last-wins — the binary loads it with the real parser
# and reports the effective `listen` address and whether `acme` is enabled. ACME
# forces the TLS-ALPN-01 challenge onto :443; a listener port in 1..1023 is
# privileged. A binary too old to emit those fields yields neither match, so the
# capability stays unset.
needs_net_bind_capability() {
    local summary="$1" listen port
    # ACME forces the TLS-ALPN-01 challenge onto the privileged :443.
    if printf '%s\n' "$summary" | json_bool_is_true acme; then
        return 0
    fi
    # Deriving the port needs "listen" reported as a non-empty string. An absent
    # field, or a non-string value, means the installed binary predates these
    # fields (e.g. an older --binary) or cannot be verified — warn rather than
    # silently emit a unit that may fail to start. (Basing this on the extracted
    # string, not mere presence, covers a non-string `"listen":` too.)
    listen="$(printf '%s\n' "$summary" | json_string_field listen)"
    if [ -z "$listen" ]; then
        warn "installed alighieri does not report listener details in --check --json;" \
             "if the config binds a port below 1024 or uses ACME, add CAP_NET_BIND_SERVICE" \
             "to $UNIT_FILE or upgrade the binary"
        return 1
    fi
    port="${listen##*:}"   # strip host, keep the trailing port (handles [ipv6]:port)
    case "$port" in
        '' | *[!0-9]*) return 1 ;;
    esac
    port=$((10#$port))   # force base-10 so a leading zero is never read as octal
    [ "$port" -gt 0 ] && [ "$port" -lt 1024 ]
}

# CapabilityBoundingSet/AmbientCapabilities are unsigned 64-bit masks on the
# systemd D-Bus API. CAP_NET_BIND_SERVICE is Linux capability bit 10.
service_capability_mask() {
    if needs_net_bind_capability "$1"; then
        printf '%s' 1024
    else
        printf '%s' 0
    fi
}

# Extract a JSON string field's value from the flat `--check --json` output,
# honouring JSON string escapes. Reads the JSON on stdin and the field name as
# $1; prints the unescaped value (no trailing newline), or nothing if the field
# is absent or not a string. Unlike a plain `sed` capture (`"\([^"]*\)"`), a path
# containing an escaped quote (`\"`) is read in full rather than truncated, and
# `\\`/`\"`/`\/`/`\n`/`\r`/`\t` are unescaped to their real characters so the
# prefix checks below see the actual path. `\uXXXX` (emitted by the binary only
# for control characters, which never appear in a real config path) is left
# as-is. `awk` is a POSIX base utility, so this adds no new dependency.
json_string_field() {
    awk -v key="$1" '
    { json = json $0 }
    END {
        marker = "\"" key "\""
        mlen = length(marker)
        # Scan every occurrence of "key" and accept only the one that is a real
        # field: its opening quote is not escaped (so it is not inside a string
        # value like a path containing the key name) and it is followed by `:` (a
        # value occurrence is followed by `,`/`}`). [[:space:]] rather than
        # \t/\r/\n, whose meaning inside a regex literal is not portable across
        # POSIX awk implementations.
        start = 1
        while ((at = index(substr(json, start), marker)) > 0) {
            pos = start + at - 1
            start = pos + 1
            if (pos > 1 && substr(json, pos - 1, 1) == "\\") continue
            rest = substr(json, pos + mlen)
            sub(/^[[:space:]]*/, "", rest)
            if (substr(rest, 1, 1) != ":") continue
            rest = substr(rest, 2)
            sub(/^[[:space:]]*/, "", rest)
            if (substr(rest, 1, 1) != "\"") exit   # value is not a string
            rest = substr(rest, 2)
            n = length(rest)
            out = ""
            i = 1
            while (i <= n) {
                c = substr(rest, i, 1)
                if (c == "\\") {
                    e = substr(rest, i + 1, 1)
                    if (e == "\"") out = out "\""
                    else if (e == "\\") out = out "\\"
                    else if (e == "/") out = out "/"
                    else if (e == "n") out = out "\n"
                    else if (e == "r") out = out "\r"
                    else if (e == "t") out = out "\t"
                    else out = out "\\" e          # unknown escape (e.g. \uXXXX): keep literal
                    i += 2
                } else if (c == "\"") {
                    break                          # unescaped closing quote
                } else {
                    out = out c
                    i += 1
                }
            }
            printf "%s", out
            exit
        }
    }
    '
}

# Extract a JSON array of strings from the `--check --json` output. Each decoded
# value is printed on its own line, so callers must consume it with
# `IFS= read -r` to preserve spaces and backslashes. Configuration paths cannot
# contain control characters; reject their JSON escapes (and every unsupported
# escape) rather than turning one path into multiple records. Returns non-zero
# when the field is absent, is not an array of strings, or is malformed.
json_string_array_field() {
    awk -v key="$1" '
    function quote_is_escaped(text, pos,    i, slashes) {
        slashes = 0
        for (i = pos - 1; i > 0 && substr(text, i, 1) == "\\"; i--) slashes++
        return (slashes % 2) == 1
    }
    function trim_left(text) {
        sub(/^[[:space:]]*/, "", text)
        return text
    }
    { json = json $0 }
    END {
        marker = "\"" key "\""
        mlen = length(marker)
        start = 1
        while ((at = index(substr(json, start), marker)) > 0) {
            pos = start + at - 1
            start = pos + 1
            if (quote_is_escaped(json, pos)) continue
            rest = trim_left(substr(json, pos + mlen))
            if (substr(rest, 1, 1) != ":") continue
            rest = trim_left(substr(rest, 2))
            if (substr(rest, 1, 1) != "[") exit 1
            rest = trim_left(substr(rest, 2))
            if (substr(rest, 1, 1) == "]") exit 0

            while (length(rest) > 0) {
                if (substr(rest, 1, 1) != "\"") exit 1
                rest = substr(rest, 2)
                out = ""
                closed = 0
                i = 1
                while (i <= length(rest)) {
                    c = substr(rest, i, 1)
                    if (c == "\\") {
                        e = substr(rest, i + 1, 1)
                        if (e == "\"") out = out "\""
                        else if (e == "\\") out = out "\\"
                        else if (e == "/") out = out "/"
                        else exit 1
                        i += 2
                    } else if (c == "\"") {
                        closed = 1
                        rest = trim_left(substr(rest, i + 1))
                        break
                    } else {
                        if (c ~ /[[:cntrl:]]/) exit 1
                        out = out c
                        i++
                    }
                }
                if (!closed) exit 1
                printf "%s\n", out
                if (substr(rest, 1, 1) == "]") exit 0
                if (substr(rest, 1, 1) != ",") exit 1
                rest = trim_left(substr(rest, 2))
            }
            exit 1
        }
        exit 1
    }
    '
}

# Whether a JSON field named $1 is present in the flat `--check --json` object,
# escape- and key-aware to match `json_string_field`. A plain `case`/glob on
# `"<key>"` would also match
# the key name appearing as another field's *value* (e.g. `"message":"log_file"`)
# and so wrongly report the field present. Reads the JSON on stdin; returns 0 if
# a real `"<key>":` exists, 1 otherwise.
json_has_field() {
    awk -v key="$1" '
    { json = json $0 }
    END {
        marker = "\"" key "\""
        mlen = length(marker)
        start = 1
        while ((at = index(substr(json, start), marker)) > 0) {
            pos = start + at - 1
            start = pos + 1
            if (pos > 1 && substr(json, pos - 1, 1) == "\\") continue
            rest = substr(json, pos + mlen)
            sub(/^[[:space:]]*/, "", rest)
            if (substr(rest, 1, 1) == ":") exit 0   # a real key
        }
        exit 1
    }
    '
}

# Whether a JSON boolean field named $1 is present and `true`, in the flat
# `--check --json` object. Escape- and key-aware like `json_has_field`, and
# tolerant of whitespace after the colon, unlike a raw `*'"key":true'*` glob —
# which also fails to match if the value is ever rendered as `"key": true`,
# silently treating the field as false. Reads the JSON on stdin; returns 0 if a
# real `"<key>":` has the literal value `true`, 1 otherwise.
json_bool_is_true() {
    awk -v key="$1" '
    { json = json $0 }
    END {
        marker = "\"" key "\""
        mlen = length(marker)
        start = 1
        while ((at = index(substr(json, start), marker)) > 0) {
            pos = start + at - 1
            start = pos + 1
            if (pos > 1 && substr(json, pos - 1, 1) == "\\") continue
            rest = substr(json, pos + mlen)
            sub(/^[[:space:]]*/, "", rest)
            if (substr(rest, 1, 1) != ":") continue   # not a key here
            rest = substr(rest, 2)
            sub(/^[[:space:]]*/, "", rest)
            # The value must be the JSON literal `true` (terminated by a
            # separator or end of input), not a string or another literal.
            if (rest ~ /^true([[:space:],}]|$)/) exit 0
            exit 1                                     # present but not true
        }
        exit 1                                         # absent
    }
    '
}

# True when an already-normalised absolute path is hidden by the unit.
normalized_service_path_is_hidden() {
    case "$1" in
        /home | /home/* | /root | /root/* | /run/user | /run/user/* | \
        /tmp | /tmp/* | /var/tmp | /var/tmp/* | /dev | /dev/*)
            return 0
            ;;
    esac
    return 1
}

# Resolve as much of an absolute path as currently exists, then append the
# unresolved suffix. GNU `readlink -f` fails when a non-final component is
# missing, which is normal during `--no-start` credential bootstrap; walking up
# prevents an existing parent symlink into a hidden namespace from bypassing the
# lexical prefix check merely because two later components do not exist yet.
resolve_existing_service_path() {
    local candidate="$1" suffix='' resolved base
    while :; do
        resolved="$(readlink -f -- "$candidate" 2>/dev/null || true)"
        if [ -n "$resolved" ]; then
            normalize_path "$resolved$suffix"
            return 0
        fi
        # `readlink -f` cannot canonicalise a symlink whose target itself has
        # multiple missing components. Detect the symlink with plain readlink
        # and fail closed instead of peeling past it and losing the redirect.
        if readlink -- "$candidate" >/dev/null 2>&1; then
            return 1
        fi
        [ "$candidate" != "/" ] || return 1
        base="${candidate##*/}"
        candidate="${candidate%/*}"
        [ -n "$candidate" ] || candidate="/"
        suffix="/$base$suffix"
    done
}

# True when a path is hidden from the managed service even if root can access
# it: ProtectHome masks /home, /root, and /run/user, PrivateTmp replaces the
# host's /tmp and /var/tmp, and PrivateDevices replaces /dev. Relative service
# paths resolve from `/`. Check a canonical form too when available so an existing
# parent symlink cannot disguise a protected target (GNU/busybox readlink is
# present on systemd Linux hosts; the transient-unit preflight remains
# authoritative if it is unavailable).
service_path_is_hidden() {
    local path="$1" absolute normalized resolved=""
    case "$path" in
        /*) absolute="$path" ;;
        *) absolute="/$path" ;;
    esac
    normalized="$(normalize_path "$absolute")"
    normalized_service_path_is_hidden "$normalized" && return 0
    if command -v readlink >/dev/null 2>&1; then
        # Use the original spelling here rather than the lexically normalised
        # one: `symlink/../file` follows the symlink before applying `..`.
        if ! resolved="$(resolve_existing_service_path "$absolute")"; then
            return 0 # unresolved/dangling symlink: reject the path fail-closed
        fi
        normalized_service_path_is_hidden "$resolved" && return 0
    fi
    return 1
}

reject_hidden_service_path() {
    local label="$1" path="$2"
    if service_path_is_hidden "$path"; then
        die "$label $path is hidden by the service's filesystem sandbox; use a service-readable durable path (configuration and userlists normally belong under $CONFIG_DIR)"
    fi
}

# Convert an effective config path to the spelling used by the generated unit,
# whose WorkingDirectory is `/`. Keep absolute paths verbatim and only prefix a
# relative value; lexical normalisation could change kernel path resolution when
# a preceding component is a symlink.
service_runtime_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '/%s\n' "$1" ;;
    esac
}

service_userlist_path_kind() {
    if [ -L "$1" ]; then
        printf '%s' symlink
    elif [ -f "$1" ]; then
        printf '%s' regular
    elif [ -e "$1" ]; then
        printf '%s' other
    else
        printf '%s' missing
    fi
}

service_config_source_path_kind() {
    if [ -L "$1" ]; then
        printf '%s' symlink
    elif [ -f "$1" ]; then
        printf '%s' regular
    elif [ -e "$1" ]; then
        printf '%s' other
    else
        printf '%s' missing
    fi
}

validate_service_config_source_path() {
    local label="$1" path="$2" kind directory
    case "$path" in
        /*) ;;
        *) die "$label $path is not absolute; refusing an ambiguous configuration source" ;;
    esac
    [ "$(normalize_path "$path")" = "$path" ] ||
        die "$label $path is not lexically canonical; remove redundant '.', '..', or repeated separators from the include path"
    reject_hidden_service_path "$label" "$path"

    kind="$(service_config_source_path_kind "$path")"
    case "$kind" in
        regular) ;;
        symlink)
            die "$label $path is a symlink; use a physical, root-controlled configuration file"
            ;;
        missing)
            die "$label $path disappeared after configuration validation"
            ;;
        *)
            die "$label $path is not a regular file"
            ;;
    esac

    directory="$(dirname -- "$path")"
    require_safe_service_config_directory "$directory"
    # Check the leaf again after walking both the lexical and physical parent
    # chains. This makes a concurrent redirect beneath an unsafe writable
    # parent fail before metadata is trusted.
    [ "$(service_config_source_path_kind "$path")" = regular ] ||
        die "$label $path changed while its parent path was being validated"
    require_secure_service_config_file "$path"
}

validate_service_config_include_pattern() {
    local label="$1" pattern="$2" directory file_pattern
    case "$pattern" in
        /*) ;;
        *) die "$label $pattern is not absolute; refusing an ambiguous include pattern" ;;
    esac
    [ "$(normalize_path "$pattern")" = "$pattern" ] ||
        die "$label $pattern is not lexically canonical; remove redundant '.', '..', or repeated separators from the include path"
    directory="$(dirname -- "$pattern")"
    file_pattern="${pattern##*/}"
    case "$file_pattern" in
        *'*'* | *'?'*) ;;
        *) die "$label $pattern does not contain a filename wildcard" ;;
    esac
    reject_hidden_service_path "$label parent" "$directory"
    require_safe_service_config_directory "$directory"
}

# Validate every file and wildcard directory consumed by Config::load, not only
# the unit entrypoint. The binary reports parallel arrays because both spellings
# are security relevant: declared paths expose writable ancestry and leaf links,
# while canonical paths identify parsed files and physical wildcard parents.
# Fail closed with an old/malformed binary rather than silently leaving includes
# or future reload matches outside the config integrity boundary.
validate_service_config_sources() {
    local summary="$1" declared_sources canonical_sources declared_count canonical_count source \
          declared_patterns canonical_patterns declared_pattern_count canonical_pattern_count pattern
    if ! declared_sources="$(printf '%s\n' "$summary" |
        json_string_array_field declared_config_sources)"; then
        die "installed alighieri does not report declared configuration sources in --check --json; use the helper with its matching current binary"
    fi
    if ! canonical_sources="$(printf '%s\n' "$summary" |
        json_string_array_field canonical_config_sources)"; then
        die "installed alighieri does not report canonical configuration sources in --check --json; use the helper with its matching current binary"
    fi
    if ! declared_patterns="$(printf '%s\n' "$summary" |
        json_string_array_field declared_config_include_patterns)"; then
        die "installed alighieri does not report declared configuration include patterns in --check --json; use the helper with its matching current binary"
    fi
    if ! canonical_patterns="$(printf '%s\n' "$summary" |
        json_string_array_field canonical_config_include_patterns)"; then
        die "installed alighieri does not report canonical configuration include patterns in --check --json; use the helper with its matching current binary"
    fi
    if [ -z "$declared_sources" ] || [ -z "$canonical_sources" ]; then
        die "installed alighieri reported an empty configuration source set"
    fi

    declared_count="$(printf '%s\n' "$declared_sources" | awk 'END { print NR }')"
    canonical_count="$(printf '%s\n' "$canonical_sources" | awk 'END { print NR }')"
    [ "$declared_count" -eq "$canonical_count" ] ||
        die "installed alighieri reported inconsistent declared and canonical configuration source sets"
    if [ -n "$declared_patterns" ]; then
        declared_pattern_count="$(printf '%s\n' "$declared_patterns" | awk 'END { print NR }')"
    else
        declared_pattern_count=0
    fi
    if [ -n "$canonical_patterns" ]; then
        canonical_pattern_count="$(printf '%s\n' "$canonical_patterns" | awk 'END { print NR }')"
    else
        canonical_pattern_count=0
    fi
    [ "$declared_pattern_count" -eq "$canonical_pattern_count" ] ||
        die "installed alighieri reported inconsistent declared and canonical configuration include pattern sets"

    while IFS= read -r source; do
        [ -n "$source" ] || die "installed alighieri reported an empty declared configuration source"
        validate_service_config_source_path "declared configuration source" "$source"
    done <<<"$declared_sources"
    while IFS= read -r source; do
        [ -n "$source" ] || die "installed alighieri reported an empty canonical configuration source"
        validate_service_config_source_path "canonical configuration source" "$source"
    done <<<"$canonical_sources"
    if [ -n "$declared_patterns" ]; then
        while IFS= read -r pattern; do
            [ -n "$pattern" ] || die "installed alighieri reported an empty declared configuration include pattern"
            validate_service_config_include_pattern \
                "declared configuration include pattern" "$pattern"
        done <<<"$declared_patterns"
    fi
    if [ -n "$canonical_patterns" ]; then
        while IFS= read -r pattern; do
            [ -n "$pattern" ] || die "installed alighieri reported an empty canonical configuration include pattern"
            validate_service_config_include_pattern \
                "canonical configuration include pattern" "$pattern"
        done <<<"$canonical_patterns"
    fi
}

# Validate the parser-selected userlist as an integrity boundary before loading
# it as the service account. A physical, root-owned 0640 leaf beneath trusted
# parents prevents the service or another local user from changing credentials
# after this root process accepts them; `user list` then exercises the same
# UserDb loader as startup. `--no-start` permits only a genuinely missing file
# for first-user bootstrap. An absent JSON field means an older binary cannot
# safely report an include-aware/last-wins path, so fail closed rather than
# silently skip it.
validate_service_userlist() {
    local install_bin="$1" summary="$2" will_start="${3:-1}" userlist runtime_path \
          userlist_kind userlist_dir
    if ! printf '%s\n' "$summary" | json_has_field userlist; then
        die "installed alighieri does not report the effective userlist in --check --json; use the helper with its matching current binary before installing the hardened service"
    fi
    userlist="$(printf '%s\n' "$summary" | json_string_field userlist)"
    [ -n "$userlist" ] || return 0
    reject_hidden_service_path "configured userlist path" "$userlist"

    runtime_path="$(service_runtime_path "$userlist")"
    userlist_kind="$(service_userlist_path_kind "$runtime_path")"
    if [ "$will_start" -eq 0 ] && [ "$userlist_kind" = missing ]; then
        warn "configured userlist $userlist does not exist yet; --no-start leaves the service stopped so credentials can be created before the final install"
        return 0
    fi
    case "$userlist_kind" in
        regular) ;;
        symlink)
            die "configured userlist $userlist is a symlink; replace it with a physical, root-controlled file before installing the service"
            ;;
        missing)
            die "configured userlist $userlist does not exist; create it with root:$SERVICE_USER ownership and mode 640, or use --no-start for first-user bootstrap"
            ;;
        *)
            die "configured userlist $userlist exists but is not a regular file"
            ;;
    esac

    userlist_dir="$(dirname -- "$runtime_path")"
    require_safe_service_userlist_directory "$userlist_dir"
    require_secure_service_userlist_file "$runtime_path"
    if ! run_in_service_sandbox \
        "$install_bin" user list --userlist "$userlist" >/dev/null; then
        die "configured userlist $userlist cannot be loaded by $SERVICE_USER inside the hardened systemd sandbox; fix its contents and every parent directory's access, then re-run install"
    fi
}

# Warn when the ACME cache is outside the unit's StateDirectory. The hardened
# unit runs with ProtectSystem=strict, which leaves the filesystem read-only
# except for StateDirectory (${STATE_DIR}); an ACME cache anywhere else cannot be
# written, so certificate issuance/renewal fails at runtime. Reads the resolved
# cache path from the caller's `--check --json` summary rather than reparsing the
# config (case-insensitive keywords, include: files).
warn_acme_cache_outside_state_dir() {
    local summary="$1" cache
    # Only relevant when ACME is enabled.
    if ! printf '%s\n' "$summary" | json_bool_is_true acme; then
        return 0
    fi
    # Tolerate optional whitespace around the JSON colon. An empty result means
    # the binary reported "acme":true but no acme_cache field — i.e. an older
    # --binary that predates it — so warn that the path could not be verified
    # rather than silently skipping (the footgun may still apply).
    cache="$(printf '%s\n' "$summary" | json_string_field acme_cache)"
    if [ -z "$cache" ]; then
        warn "this alighieri does not report the ACME cache path (older --binary?);" \
             "ensure tls.acme.cache is under the writable StateDirectory $STATE_DIR, or the" \
             "hardened unit (ProtectSystem=strict) will be unable to write certificates."
        return 0
    fi
    # Normalise `..`/redundant separators first so a path like
    # $STATE_DIR/../elsewhere does not look like it is under the StateDirectory.
    case "$(normalize_path "$cache")" in
        "$STATE_DIR" | "$STATE_DIR"/*) return 0 ;; # under the writable StateDirectory
    esac
    warn "tls.acme.cache ($cache) is outside the service StateDirectory $STATE_DIR;" \
         "the hardened unit's ProtectSystem=strict makes it read-only, so ACME certificate" \
         "writes will fail at runtime. Put the cache under $STATE_DIR/ (e.g. $STATE_DIR/acme)" \
         "or grant the unit write access to that path."
}

# Warn when the configured logfile is outside the unit's writable log directory.
# Same hardening trap as the ACME cache: ProtectSystem=strict leaves the
# filesystem read-only except ReadWritePaths=$LOG_DIR, so a logfile elsewhere
# cannot be written and file logging fails at runtime. Reads the resolved path
# from the caller's `--check --json` summary rather than reparsing the config.
warn_logfile_outside_log_dir() {
    local summary="$1" logfile
    # An older --binary may not emit log_file at all. Unlike a present-but-empty
    # field (file logging off), an absent field means the path can't be verified,
    # so warn rather than silently skip the footgun.
    if ! printf '%s\n' "$summary" | json_has_field log_file; then
        warn "this alighieri does not report the logfile path (older --binary?);" \
             "if the config uses file logging, put the logfile under $LOG_DIR, or the" \
             "hardened unit (ProtectSystem=strict) will be unable to write it."
        return 0
    fi
    logfile="$(printf '%s\n' "$summary" | json_string_field log_file)"
    [ -n "$logfile" ] || return 0   # field present but empty: file logging not configured
    # Normalise `..`/redundant separators first so $LOG_DIR/../elsewhere does not
    # look like it is under the writable log directory.
    case "$(normalize_path "$logfile")" in
        "$LOG_DIR"/*) return 0 ;; # under the writable log directory
    esac
    warn "logfile ($logfile) is outside the writable log directory $LOG_DIR;" \
         "the hardened unit's ProtectSystem=strict makes it read-only, so file logging" \
         "will fail at runtime. Put the logfile under $LOG_DIR/ or grant the unit write access."
}

# Commands printed after installation run back in the invoking shell. Preserve
# the privilege mechanism when this script was entered through sudo, but avoid
# suggesting sudo to an operator already working directly as root.
followup_elevation() {
    local invoking_user="${SUDO_USER:-}"
    if [ -n "$invoking_user" ] && [ "$invoking_user" != "root" ]; then
        printf 'sudo'
    fi
}

# Re-running install after creating credentials must retain an explicit
# prebuilt source and config override. Quote every path for safe copy/paste when
# the script, binary, or config path contains shell metacharacters.
followup_install_command() {
    local script_path elevation quoted_script quoted_binary quoted_config
    script_path="${1:-${SCRIPT_DIR}/$(basename -- "${BASH_SOURCE[0]}")}"
    elevation="$(followup_elevation)"
    printf -v quoted_script '%q' "$script_path"
    printf '%s%s%s install' "$elevation" "${elevation:+ }" "$quoted_script"
    if [ "$BINARY_EXPLICIT" -eq 1 ]; then
        printf -v quoted_binary '%q' "$BINARY"
        printf ' --binary %s' "$quoted_binary"
    fi
    if [ "$CONFIG_EXPLICIT" -eq 1 ]; then
        printf -v quoted_config '%q' "$INSTALL_CONFIG"
        printf ' --config %s' "$quoted_config"
    fi
}

# Hidden, test-only entry point: exercise path normalization, hardened service
# preflight helpers, and warnings against fixed cases. Run by CI (`bash
# scripts/alighieri.sh __selftest`) and intentionally kept off the operator-facing
# command surface.
# Needs neither root nor systemd. Exits nonzero if any case is wrong.
run_selftest() {
    local failures=0 sandbox_call hidden_path visible_path expected_arg

    _check_norm() { # input expected
        local got
        got="$(normalize_path "$1")"
        if [ "$got" = "$2" ]; then
            printf 'ok   normalize_path %-34s -> %s\n' "$1" "$got"
        else
            printf 'FAIL normalize_path %-34s -> %s (want %s)\n' "$1" "$got" "$2"
            failures=$((failures + 1))
        fi
    }

    # Plain paths, `.`/redundant-slash collapse, `..` popping, root collapse, and
    # relative escapes (which must be preserved, not silently dropped).
    _check_norm "/var/lib/alighieri/acme" "/var/lib/alighieri/acme"
    _check_norm "/var/lib/alighieri/" "/var/lib/alighieri"
    _check_norm "/var/lib/alighieri/./acme" "/var/lib/alighieri/acme"
    _check_norm "//var//lib//alighieri" "/var/lib/alighieri"
    _check_norm "/a/../b" "/b"
    _check_norm "/var/lib/alighieri/../../etc/passwd" "/var/etc/passwd"
    _check_norm "/var/lib/alighieri/../../../etc" "/etc"
    _check_norm "/var/lib/alighieri/../alighieri-evil" "/var/lib/alighieri-evil"
    _check_norm "/" "/"
    _check_norm "/.." "/"
    _check_norm "/../" "/"
    _check_norm "foo/../bar" "bar"
    _check_norm "../../x" "../../x"
    _check_norm ".." ".."

    _check_prefix_dir() { # prefix want(accept|reject) expected-dir
        local prefix="$1" want="$2" expected="${3:-}" got='' result=reject
        if got="$(install_bin_dir_for_prefix "$prefix")"; then result=accept; fi
        if [ "$result" = "$want" ] &&
            { [ "$want" = reject ] || [ "$got" = "$expected" ]; }; then
            printf 'ok   install prefix %-30s -> %s%s\n' \
                "$prefix" "$result" "${got:+ ($got)}"
        else
            printf 'FAIL install prefix %-30s -> %s [%s] (want %s [%s])\n' \
                "$prefix" "$result" "$got" "$want" "$expected"
            failures=$((failures + 1))
        fi
    }

    # systemd simplifies the executable path but retains the original argv[0].
    # Accept only spellings that round-trip exactly; root remains valid and must
    # join to `/bin`, never `//bin`.
    _check_prefix_dir "/usr/local" accept "/usr/local/bin"
    _check_prefix_dir "/" accept "/bin"
    _check_prefix_dir "/usr/local/" reject
    _check_prefix_dir "//usr/local" reject
    _check_prefix_dir "/usr/./local" reject
    _check_prefix_dir "/usr/lib/../local" reject

    _check_reused_install_location() { # binary want(accept|reject) expected-binary
        local binary="$1" want="$2" expected="${3:-}" got='' directory='' result=reject
        if got="$({
            directory="$(existing_install_directory_for_binary "$binary")" &&
                join_path_child "$directory" "$SERVICE_NAME"
        } 2>/dev/null)"; then
            result=accept
        fi
        if [ "$result" = "$want" ] &&
            { [ "$want" = reject ] || [ "$got" = "$expected" ]; }; then
            printf 'ok   reused executable %-28s -> %s%s\n' \
                "$binary" "$result" "${got:+ ($got)}"
        else
            printf 'FAIL reused executable %-28s -> %s [%s] (want %s [%s])\n' \
                "$binary" "$result" "$got" "$want" "$expected"
            failures=$((failures + 1))
        fi
    }

    _check_reused_install_location "/alighieri" accept "/alighieri"
    _check_reused_install_location "/bin/alighieri" accept "/bin/alighieri"
    _check_reused_install_location "/bin//alighieri" reject
    _check_reused_install_location "/opt/alighieri//bin/alighieri" reject
    _check_reused_install_location "/opt/link/../bin/alighieri" reject

    _check_binary_directory_metadata() { # owner mode want(safe|unsafe)
        local owner="$1" mode="$2" want="$3" got=unsafe
        if binary_directory_metadata_is_safe "$owner" "$mode"; then got=safe; fi
        if [ "$got" = "$want" ]; then
            printf 'ok   binary directory owner/mode %s:%s -> %s\n' "$owner" "$mode" "$got"
        else
            printf 'FAIL binary directory owner/mode %s:%s -> %s (want %s)\n' \
                "$owner" "$mode" "$got" "$want"
            failures=$((failures + 1))
        fi
    }

    _check_binary_directory_metadata 0 755 safe
    _check_binary_directory_metadata 0 700 safe
    _check_binary_directory_metadata 0 2755 safe
    _check_binary_directory_metadata 0 775 unsafe
    _check_binary_directory_metadata 0 757 unsafe
    _check_binary_directory_metadata 1000 755 unsafe
    _check_binary_directory_metadata 0 invalid unsafe

    _check_binary_directory_chain() { # description path physical unsafe want [link target ...]
        local description="$1" path="$2" simulated_physical="$3" unsafe_path="$4" \
              want="$5" link_one="${6:-}" target_one="${7:-}" \
              link_two="${8:-}" target_two="${9:-}" got=unsafe
        if (
            physical_directory_path() { printf '%s' "$simulated_physical"; }
            binary_directory_path_metadata() {
                if [ -n "$unsafe_path" ] && [ "$1" = "$unsafe_path" ]; then
                    printf '%s\n' '1000 755'
                else
                    printf '%s\n' '0 755'
                fi
            }
            binary_path_is_symlink() {
                [ -n "$link_one" ] &&
                    { [ "$1" = "$link_one" ] ||
                        { [ -n "$link_two" ] && [ "$1" = "$link_two" ]; }; }
            }
            binary_path_symlink_target() {
                if [ "$1" = "$link_one" ]; then
                    printf '%s' "$target_one"
                elif [ -n "$link_two" ] && [ "$1" = "$link_two" ]; then
                    printf '%s' "$target_two"
                else
                    return 1
                fi
            }
            # Paths are simulated; bypass only the real filesystem shape check
            # while exercising both lexical and physical ancestor walks.
            binary_directory_exists() { return 0; }
            require_safe_binary_directory "$path"
        ) 2>/dev/null; then
            got=safe
        fi
        if [ "$got" = "$want" ]; then
            printf 'ok   binary directory chain %s -> %s\n' "$description" "$got"
        else
            printf 'FAIL binary directory chain %s -> %s (want %s)\n' \
                "$description" "$got" "$want"
            failures=$((failures + 1))
        fi
    }

    _check_binary_directory_chain "safe /usr/local/bin" \
        /usr/local/bin /usr/local/bin '' safe
    _check_binary_directory_chain "unsafe lexical parent" \
        /opt/alighieri/bin /opt/alighieri/bin /opt unsafe
    _check_binary_directory_chain "unsafe intermediate symlink target parent" \
        /srv/alighieri/bin /home/alice/bin /home unsafe
    _check_binary_directory_chain "nested symlink via unsafe parent" \
        /opt/alighieri/bin /usr/local/bin /tmp/attacker unsafe \
        /opt/alighieri /tmp/attacker/hop /tmp/attacker/hop /usr/local
    _check_binary_directory_chain "trusted merged-/usr /bin" \
        /bin /usr/bin '' safe /bin usr/bin

    _check_custom_config_directory_chain() { # unsafe-ancestor want(safe|unsafe)
        local unsafe_path="$1" want="$2" got=unsafe
        if (
            binary_directory_exists() { return 0; }
            physical_directory_path() { printf '%s' "$1"; }
            binary_directory_path_metadata() {
                if [ -n "$unsafe_path" ] && [ "$1" = "$unsafe_path" ]; then
                    printf '%s\n' '1000 777'
                else
                    printf '%s\n' '0 755'
                fi
            }
            binary_path_is_symlink() { return 1; }
            require_safe_service_config_directory /srv/alighieri
        ) 2>/dev/null; then
            got=safe
        fi
        if [ "$got" = "$want" ]; then
            printf 'ok   custom config parent chain -> %s\n' "$got"
        else
            printf 'FAIL custom config parent chain -> %s (want %s)\n' "$got" "$want"
            failures=$((failures + 1))
        fi
    }

    _check_custom_config_directory_chain '' safe
    _check_custom_config_directory_chain /srv unsafe

    _check_custom_config_metadata() { # owner group mode expected-group want(safe|unsafe)
        local owner="$1" group="$2" mode="$3" expected_group="$4" want="$5" got=unsafe
        if service_config_metadata_is_safe "$owner" "$group" "$mode" "$expected_group"; then
            got=safe
        fi
        if [ "$got" = "$want" ]; then
            printf 'ok   custom config metadata %s:%s:%s -> %s\n' \
                "$owner" "$group" "$mode" "$got"
        else
            printf 'FAIL custom config metadata %s:%s:%s -> %s (want %s)\n' \
                "$owner" "$group" "$mode" "$got" "$want"
            failures=$((failures + 1))
        fi
    }

    _check_custom_config_metadata 0 991 640 991 safe
    _check_custom_config_metadata 0 991 600 991 unsafe
    _check_custom_config_metadata 0 0 640 991 unsafe
    _check_custom_config_metadata 1000 991 640 991 unsafe
    _check_custom_config_metadata 0 991 1640 991 unsafe

    _check_service_userlist_metadata() { # description kind metadata want(safe|unsafe)
        local description="$1" kind="$2" mock_metadata="$3" want="$4" got=unsafe
        if (
            service_userlist_path_kind() { printf '%s' "$kind"; }
            service_config_path_metadata() { printf '%s\n' "$mock_metadata"; }
            service_group_id() { printf '%s' 991; }
            require_secure_service_userlist_file /etc/alighieri/users
        ) 2>/dev/null; then
            got=safe
        fi
        if [ "$got" = "$want" ]; then
            printf 'ok   service userlist metadata %s -> %s\n' "$description" "$got"
        else
            printf 'FAIL service userlist metadata %s -> %s (want %s)\n' \
                "$description" "$got" "$want"
            failures=$((failures + 1))
        fi
    }

    _check_service_userlist_metadata "root:service 640 regular file" \
        regular '0 991 640' safe
    _check_service_userlist_metadata "service-owned file" \
        regular '991 991 640' unsafe
    _check_service_userlist_metadata "wrong group" \
        regular '0 0 640' unsafe
    _check_service_userlist_metadata "owner-only mode" \
        regular '0 991 600' unsafe
    _check_service_userlist_metadata "world-readable mode" \
        regular '0 991 644' unsafe
    _check_service_userlist_metadata "group-writable file" \
        regular '0 991 660' unsafe
    _check_service_userlist_metadata "special permission bits" \
        regular '0 991 1640' unsafe
    _check_service_userlist_metadata "symlink after parent validation" \
        symlink '0 991 640' unsafe
    _check_service_userlist_metadata "non-regular file after parent validation" \
        other '0 991 640' unsafe

    _check_named_service_group_id() { # group-record expected-or-reject
        local simulated_record="$1" expected="$2" got=reject
        got="$(
            service_group_record() { printf '%s\n' "$simulated_record"; }
            # Resolve the explicit Group= name; the service user's unrelated
            # primary group is deliberately absent from this test and helper.
            service_group_id
        )" || got=reject
        if [ "$got" = "$expected" ]; then
            printf 'ok   named service group id -> %s\n' "$got"
        else
            printf 'FAIL named service group id -> %s (want %s)\n' "$got" "$expected"
            failures=$((failures + 1))
        fi
    }

    _check_named_service_group_id 'alighieri:x:991:' 991
    _check_named_service_group_id 'alighieri:x:991:alice,bob' 991
    _check_named_service_group_id 'other:x:991:' reject
    _check_named_service_group_id 'alighieri:x:not-a-gid:' reject

    _check_binary_directory_prepare() { # description target existing unsafe want install
        local description="$1" target="$2" existing="$3" unsafe_path="$4" \
              want="$5" want_install="$6" got=unsafe installed=no out=''
        if out="$(
            (
                local created=0
                binary_path_kind() {
                    if [ "$created" -eq 1 ] && [ "$1" = "$target" ]; then
                        printf '%s' directory
                    elif [ "$1" = "$existing" ]; then
                        printf '%s' directory
                    else
                        printf '%s' missing
                    fi
                }
                binary_directory_exists() {
                    [ "$1" = "$existing" ] ||
                        { [ "$created" -eq 1 ] && [ "$1" = "$target" ]; }
                }
                physical_directory_path() { printf '%s' "$1"; }
                binary_directory_path_metadata() {
                    if [ -n "$unsafe_path" ] && [ "$1" = "$unsafe_path" ]; then
                        printf '%s\n' '1000 755'
                    else
                        printf '%s\n' '0 755'
                    fi
                }
                install_file_command() {
                    [ "$*" = "-d -m 755 -- $target" ] || return 98
                    created=1
                    printf '%s\n' INSTALL
                }
                prepare_binary_directory "$target"
            ) 2>/dev/null
        )"; then
            got=safe
        fi
        case "$out" in *INSTALL*) installed=yes ;; esac
        if [ "$got" = "$want" ] && [ "$installed" = "$want_install" ]; then
            printf 'ok   binary directory prepare %s -> %s, install %s\n' \
                "$description" "$got" "$installed"
        else
            printf 'FAIL binary directory prepare %s -> %s, install %s (want %s/%s)\n' \
                "$description" "$got" "$installed" "$want" "$want_install"
            failures=$((failures + 1))
        fi
    }

    _check_binary_directory_prepare "missing tail under safe parent" \
        /usr/local/alighieri/bin /usr/local '' safe yes
    _check_binary_directory_prepare "unsafe existing parent is rejected first" \
        /opt/alighieri/bin /opt /opt unsafe no

    _check_portable_file_helpers() {
        local helper_tmp source staged installed backup linked blocked destination_dir \
              symlink_path mode_probe symlink_suffix='' symlink_checked=0 \
              mode_checked=0 result=0
        helper_tmp="$(mktemp -d)"
        source="$helper_tmp/source"
        staged="$helper_tmp/staged"
        installed="$helper_tmp/installed"
        backup="$helper_tmp/backup"
        linked="$helper_tmp/linked"
        blocked="$helper_tmp/blocked"
        destination_dir="$helper_tmp/destination-dir"
        symlink_path="$helper_tmp/staged-link"
        mode_probe="$helper_tmp/mode-probe"
        printf '%s\n' candidate >"$source"
        printf '%s\n' previous >"$installed"
        printf '%s\n' blocked >"$blocked"
        printf '%s\n' probe >"$mode_probe"
        command mkdir -- "$destination_dir"
        if command chmod 700 -- "$mode_probe" 2>/dev/null &&
            [ "$(command stat -c '%a' -- "$mode_probe")" = 700 ]; then
            mode_checked=1
        fi

        # Model an applet set that rejects any destination-as-file option. The
        # real helpers must succeed using only the common BusyBox argument set.
        install_file_command() {
            local arg
            for arg in "$@"; do case "$arg" in -*T*) return 97 ;; esac; done
            command install "$@"
        }
        copy_file_command() {
            local arg
            for arg in "$@"; do case "$arg" in -*T*) return 97 ;; esac; done
            command cp "$@"
        }
        move_file_command() {
            local arg
            for arg in "$@"; do case "$arg" in -*T*) return 97 ;; esac; done
            command mv "$@"
        }

        stage_executable_copy "$source" "$staged" || result=1
        if [ "$mode_checked" -eq 1 ]; then
            [ "$(command stat -c '%a' -- "$staged")" = 755 ] || result=1
        fi
        copy_regular_file_to_absent_path "$source" "$backup" || result=1
        link_regular_file_to_absent_path "$source" "$linked" || result=1
        replace_file_atomically "$staged" "$installed" || result=1
        [ "$(<"$installed")" = candidate ] &&
            [ "$(<"$backup")" = candidate ] && [ "$(<"$linked")" = candidate ] &&
            [ "$source" -ef "$linked" ] && [ ! -e "$staged" ] || result=1

        # None of the helpers may reinterpret a directory as a destination
        # container, and a rejected atomic replacement must retain its source.
        if stage_executable_copy "$source" "$destination_dir" ||
            copy_regular_file_to_absent_path "$source" "$destination_dir" ||
            link_regular_file_to_absent_path "$source" "$blocked" ||
            replace_file_atomically "$blocked" "$destination_dir"; then
            result=1
        fi
        [ -f "$blocked" ] && [ "$(<"$blocked")" = blocked ] &&
            [ ! -e "$destination_dir/$(basename -- "$source")" ] &&
            [ ! -e "$destination_dir/$(basename -- "$blocked")" ] || result=1

        # Destination symlinks are never followed while staging. Some Windows
        # Git Bash environments cannot create symlinks; Linux CI exercises it.
        if command ln -s -- "$source" "$symlink_path" 2>/dev/null &&
            [ -L "$symlink_path" ]; then
            symlink_checked=1
            if stage_executable_copy "$source" "$symlink_path"; then result=1; fi
            [ -L "$symlink_path" ] && [ "$(<"$source")" = candidate ] || result=1
        fi

        # Restore the production wrappers after these dynamically-scoped mocks.
        install_file_command() { command install "$@"; }
        copy_file_command() { command cp "$@"; }
        move_file_command() { command mv "$@"; }
        command rm -f -- "$source" "$staged" "$installed" "$backup" "$linked" "$blocked" "$mode_probe" \
            "$symlink_path" "$destination_dir/$(basename -- "$source")" \
            "$destination_dir/$(basename -- "$blocked")"
        command rmdir -- "$destination_dir" "$helper_tmp"
        if [ "$result" -eq 0 ]; then
            if [ "$symlink_checked" -eq 1 ]; then
                symlink_suffix=' (including symlinks)'
            fi
            printf 'ok   portable file helpers preserve exact-path and atomic replacement semantics%s\n' \
                "$symlink_suffix"
        else
            printf 'FAIL portable file helper exact-path/atomic replacement checks\n'
            return 1
        fi
    }

    if ! _check_portable_file_helpers; then failures=$((failures + 1)); fi
    unset -f _check_portable_file_helpers

    _check_lifecycle_lock() {
        local lock_tmp lock ready release output holder second_rejected=0
        lock_tmp="$(mktemp -d)"
        lock="$lock_tmp/management.lock"
        ready="$lock_tmp/ready"
        release="$lock_tmp/release"
        output="$lock_tmp/output"
        command mkfifo -- "$ready" "$release"
        (
            LIFECYCLE_LOCK_FILE="$lock"
            acquire_lifecycle_lock
            printf '%s\n' ready >"$ready"
            IFS= read -r _ <"$release"
            release_lifecycle_lock
        ) &
        holder=$!
        IFS= read -r _ <"$ready"
        if (LIFECYCLE_LOCK_FILE="$lock"; acquire_lifecycle_lock) >"$output" 2>&1; then
            second_rejected=0
        else
            second_rejected=1
        fi
        printf '%s\n' release >"$release"
        wait "$holder"
        if [ "$second_rejected" -eq 1 ] &&
            grep -Fq -- 'another Alighieri lifecycle command is already running' "$output" &&
            (LIFECYCLE_LOCK_FILE="$lock"; acquire_lifecycle_lock; release_lifecycle_lock); then
            printf 'ok   lifecycle lock serializes mutating helper invocations without stale locks\n'
        else
            printf 'FAIL lifecycle lock serialization\n'
            failures=$((failures + 1))
        fi
        command rm -f -- "$lock" "$ready" "$release" "$output"
        command rmdir -- "$lock_tmp"
    }
    _check_lifecycle_lock
    unset -f _check_lifecycle_lock

    _check_hidden() { # path want(hidden|visible)
        local got
        if service_path_is_hidden "$1"; then got=hidden; else got=visible; fi
        if [ "$got" = "$2" ]; then
            printf 'ok   service sandbox path %-30s -> %s\n' "$1" "$got"
        else
            printf 'FAIL service sandbox path %-30s -> %s (want %s)\n' "$1" "$got" "$2"
            failures=$((failures + 1))
        fi
    }

    # ProtectHome, PrivateTmp, and PrivateDevices paths are impossible durable
    # service locations even when root can read them. Normalisation must catch
    # traversal spellings but must not reject innocent near-prefixes.
    for hidden_path in \
        /home/alice/users /root/users /run/user/1000/users \
        /tmp/users /var/tmp/users /dev/shm/users \
        /opt/../home/alice/users tmp/users; do
        _check_hidden "$hidden_path" hidden
    done
    for visible_path in \
        /etc/alighieri/users /home2/users /rooted/users /run/users /var/tmp2/users; do
        _check_hidden "$visible_path" visible
    done

    # A missing bootstrap tail must not hide the fact that an existing parent
    # symlink redirects into ProtectHome. Mock only canonicalisation so this
    # stays portable to Git Bash and so the lexical `/opt` spelling itself is
    # definitely visible; the helper must walk up to the mocked existing prefix.
    readlink() {
        if [ "${1:-}" = "-f" ]; then
            case "${3:-}" in
                /opt/users-root/newdir/users | /opt/users-root/newdir) return 1 ;;
                /opt/users-root) printf '%s\n' /home/alice; return 0 ;;
                /opt/dangling-root/users | /opt/dangling-root) return 1 ;;
            esac
        elif [ "${1:-}" = "--" ] && [ "${2:-}" = "/opt/dangling-root" ]; then
            printf '%s\n' /home/new1/new2
            return 0
        fi
        return 1
    }
    _check_hidden /opt/users-root/newdir/users hidden
    _check_hidden /opt/dangling-root/users hidden
    unset -f readlink

    # The transient command must carry every path-affecting property from the
    # generated unit and preserve argv without a shell string.
    sandbox_call="$(
        systemd_manager_version() { printf '%s' 255; }
        systemd-run() { printf '%s' "$*"; }
        run_in_service_sandbox \
            /usr/local/bin/alighieri --check --json /etc/alighieri/alighieri.conf
    )"
    for expected_arg in \
        '--property=User=alighieri' '--property=Group=alighieri' \
        '--property=NoNewPrivileges=true' \
        '--property=WorkingDirectory=/' '--property=ProtectSystem=strict' \
        '--property=ProtectHome=true' '--property=PrivateTmp=true' \
        '--property=PrivateDevices=true' '--property=ProtectKernelTunables=true' \
        '--property=ProtectKernelModules=true' '--property=ProtectControlGroups=true' \
        '/usr/local/bin/alighieri --check --json /etc/alighieri/alighieri.conf'; do
        if [[ "$sandbox_call" == *"$expected_arg"* ]]; then
            printf 'ok   service sandbox command includes %s\n' "$expected_arg"
        else
            printf 'FAIL service sandbox command missing %s: [%s]\n' \
                "$expected_arg" "$sandbox_call"
            failures=$((failures + 1))
        fi
    done

    _check_sandbox_collect_version() { # version want(present|absent)
        local version="$1" want="$2" got
        got="$(
            systemd_manager_version() { printf '%s' "$version"; }
            systemd-run() { printf '%s' "$*"; }
            run_in_service_sandbox /usr/local/bin/alighieri --check \
                /etc/alighieri/alighieri.conf
        )"
        if { [ "$want" = present ] && [[ " $got " == *' --collect '* ]]; } ||
            { [ "$want" = absent ] && [[ " $got " != *' --collect '* ]]; }; then
            printf 'ok   systemd %s sandbox --collect -> %s\n' "$version" "$want"
        else
            printf 'FAIL systemd %s sandbox --collect: got [%s], want %s\n' \
                "$version" "$got" "$want"
            failures=$((failures + 1))
        fi
    }

    _check_sandbox_collect_version 235 absent
    _check_sandbox_collect_version 236 present

    # systemd-run performs environment expansion in its ExecStart argv even
    # without invoking a shell. The helper must escape every literal dollar so
    # a config value such as `${SUDO_USER}/users-$$` is checked verbatim rather
    # than against the transient service manager's environment/PID spelling.
    sandbox_call="$(
        systemd_manager_version() { printf '%s' 255; }
        systemd-run() { printf '%s' "$*"; }
        run_in_service_sandbox \
            /usr/local/bin/alighieri user list --userlist \
            "\${SUDO_USER}/users-\$\$"
    )"
    expected_arg="user list --userlist \$\${SUDO_USER}/users-\$\$\$\$"
    if [[ "$sandbox_call" == *"$expected_arg"* ]]; then
        printf 'ok   service sandbox command escapes literal dollar arguments\n'
    else
        printf 'FAIL service sandbox dollar escaping: got [%s], want [%s]\n' \
            "$sandbox_call" "$expected_arg"
        failures=$((failures + 1))
    fi

    if [ "$(service_runtime_path /srv/alighieri/users)" = "/srv/alighieri/users" ] &&
        [ "$(service_runtime_path 'relative users')" = "/relative users" ]; then
        printf 'ok   service runtime path preserves absolute and resolves relative values\n'
    else
        printf 'FAIL service runtime path resolution\n'
        failures=$((failures + 1))
    fi

    _check_userlist_preflight() { # description summary will-start sandbox-status want expected [command kind parent-status metadata-status]
        local desc="$1" summary="$2" will_start="$3" mock_status="$4" \
              want="$5" expected="$6" expected_command="${7:-}" \
              mock_kind="${8:-regular}" mock_parent_status="${9:-0}" \
              mock_metadata_status="${10:-0}" out got
        if out="$(
            service_userlist_path_kind() { printf '%s' "$mock_kind"; }
            require_safe_service_userlist_directory() {
                printf 'PARENT:%s|' "$1" >&2
                [ "$mock_parent_status" -eq 0 ] || die "mock unsafe userlist parent"
            }
            require_secure_service_userlist_file() {
                printf 'METADATA:%s|' "$1" >&2
                [ "$mock_metadata_status" -eq 0 ] || die "mock unsafe userlist metadata"
            }
            systemd_manager_version() { printf '%s' 255; }
            systemd-run() {
                printf 'SANDBOX:%s|' "$*" >&2
                if [ -n "$expected_command" ] && [[ "$*" != *"$expected_command"* ]]; then
                    return 99
                fi
                return "$mock_status"
            }
            validate_service_userlist \
                /usr/local/bin/alighieri "$summary" "$will_start" 2>&1
        )"; then
            got=ok
        else
            got=fail
        fi
        if [ "$got" = "$want" ] && [[ "$out" == *"$expected"* ]]; then
            printf 'ok   service userlist preflight %s\n' "$desc"
        else
            printf 'FAIL service userlist preflight %s: got %s [%s], want %s containing [%s]\n' \
                "$desc" "$got" "$out" "$want" "$expected"
            failures=$((failures + 1))
        fi
    }

    _check_userlist_preflight "rejects an older summary" \
        '{"ok":true}' 1 0 fail "does not report the effective userlist"
    _check_userlist_preflight "skips an unset userlist" \
        '{"ok":true,"userlist":""}' 1 1 ok ""
    _check_userlist_preflight "accepts a readable managed userlist" \
        '{"ok":true,"userlist":"/etc/alighieri/users"}' 1 0 ok \
        'PARENT:/etc/alighieri|METADATA:/etc/alighieri/users|SANDBOX:' \
        '/usr/local/bin/alighieri user list --userlist /etc/alighieri/users'
    _check_userlist_preflight "rejects a sandbox-hidden userlist" \
        '{"ok":true,"userlist":"/home/alice/users"}' 0 0 fail "hidden by the service"
    _check_userlist_preflight "rejects a service load failure" \
        '{"ok":true,"userlist":"/opt/private/users"}' 1 1 fail "cannot be loaded"
    _check_userlist_preflight "allows a missing bootstrap userlist while stopped" \
        "{\"ok\":true,\"userlist\":\"/opt/alighieri-selftest-missing-$$\"}" \
        0 1 ok "does not exist yet" "" missing
    _check_userlist_preflight "rejects a missing userlist before start" \
        '{"ok":true,"userlist":"/opt/missing-users"}' \
        1 0 fail "does not exist" "" missing
    _check_userlist_preflight "does not exempt a dangling symlink while stopped" \
        '{"ok":true,"userlist":"/opt/dangling-users"}' \
        0 0 fail "is a symlink" "" symlink
    _check_userlist_preflight "rejects a non-regular userlist" \
        '{"ok":true,"userlist":"/opt/users-dir"}' \
        1 0 fail "not a regular file" "" other
    _check_userlist_preflight "rejects an unsafe userlist parent before sandboxing" \
        '{"ok":true,"userlist":"/opt/users"}' \
        1 0 fail "mock unsafe userlist parent" "" regular 1 0
    _check_userlist_preflight "rejects unsafe userlist metadata before sandboxing" \
        '{"ok":true,"userlist":"/opt/users"}' \
        1 0 fail "mock unsafe userlist metadata" "" regular 0 1
    _check_userlist_preflight "checks a relative path at the service runtime location" \
        '{"ok":true,"userlist":"users"}' 1 0 ok \
        'PARENT:/|METADATA:/users|SANDBOX:' \
        '/usr/local/bin/alighieri user list --userlist users'

    _check_config_sources_preflight() { # description summary want expected [unsafe-parent symlink-path]
        local desc="$1" summary="$2" want="$3" expected="$4" \
              unsafe_parent="${5:-}" symlink_path="${6:-}" out got
        if out="$(
            service_config_source_path_kind() {
                if [ -n "$symlink_path" ] && [ "$1" = "$symlink_path" ]; then
                    printf '%s' symlink
                else
                    printf '%s' regular
                fi
            }
            reject_hidden_service_path() { :; }
            require_safe_service_config_directory() {
                printf 'PARENT:%s|' "$1" >&2
                if [ -n "$unsafe_parent" ] && [ "$1" = "$unsafe_parent" ]; then
                    die "mock unsafe configuration source parent $1"
                fi
            }
            require_secure_service_config_file() {
                printf 'METADATA:%s|' "$1" >&2
            }
            validate_service_config_sources "$summary" 2>&1
        )"; then
            got=ok
        else
            got=fail
        fi
        if [ "$got" = "$want" ] && [[ "$out" == *"$expected"* ]]; then
            printf 'ok   service configuration source preflight %s\n' "$desc"
        else
            printf 'FAIL service configuration source preflight %s: got %s [%s], want %s containing [%s]\n' \
                "$desc" "$got" "$out" "$want" "$expected"
            failures=$((failures + 1))
        fi
    }

    _check_config_sources_preflight "preserves include spaces and escaping" \
        '{"declared_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/conf d/part \"one\".conf"],"canonical_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/conf d/part \"one\".conf"],"declared_config_include_patterns":[],"canonical_config_include_patterns":[]}' \
        ok 'PARENT:/etc/alighieri/conf d|METADATA:/etc/alighieri/conf d/part "one".conf|'
    _check_config_sources_preflight "rejects an older summary" \
        '{"ok":true}' fail "does not report declared configuration sources"
    _check_config_sources_preflight "rejects inconsistent source arrays" \
        '{"declared_config_sources":["/etc/alighieri/main.conf"],"canonical_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/extra.conf"],"declared_config_include_patterns":[],"canonical_config_include_patterns":[]}' \
        fail "inconsistent declared and canonical"
    _check_config_sources_preflight "rejects a declared include symlink" \
        '{"declared_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/policy-link"],"canonical_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/policy.conf"],"declared_config_include_patterns":[],"canonical_config_include_patterns":[]}' \
        fail "declared configuration source /etc/alighieri/policy-link is a symlink" \
        '' /etc/alighieri/policy-link
    _check_config_sources_preflight "rejects a service-owned include" \
        '{"declared_config_sources":["/etc/alighieri/main.conf","/var/lib/alighieri/policy.conf"],"canonical_config_sources":["/etc/alighieri/main.conf","/var/lib/alighieri/policy.conf"],"declared_config_include_patterns":[],"canonical_config_include_patterns":[]}' \
        fail "mock unsafe configuration source parent /var/lib/alighieri" \
        /var/lib/alighieri
    _check_config_sources_preflight "rejects a canonical target under service-owned ancestry" \
        '{"declared_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/policy.conf"],"canonical_config_sources":["/etc/alighieri/main.conf","/var/lib/alighieri/policy.conf"],"declared_config_include_patterns":[],"canonical_config_include_patterns":[]}' \
        fail "mock unsafe configuration source parent /var/lib/alighieri" \
        /var/lib/alighieri
    _check_config_sources_preflight "rejects a summary without wildcard provenance" \
        '{"declared_config_sources":["/etc/alighieri/main.conf"],"canonical_config_sources":["/etc/alighieri/main.conf"]}' \
        fail "does not report declared configuration include patterns"
    _check_config_sources_preflight "rejects inconsistent wildcard pattern arrays" \
        '{"declared_config_sources":["/etc/alighieri/main.conf"],"canonical_config_sources":["/etc/alighieri/main.conf"],"declared_config_include_patterns":["/etc/alighieri/conf.d/*.conf"],"canonical_config_include_patterns":[]}' \
        fail "inconsistent declared and canonical configuration include pattern sets"
    # Model a currently unmatched wildcard separately from loaded sources. A
    # service-writable parent would let the daemon create a future match and
    # make it executable configuration on SIGHUP.
    _check_config_sources_preflight "rejects a zero-source wildcard under service-owned ancestry" \
        '{"declared_config_sources":["/etc/alighieri/main.conf"],"canonical_config_sources":["/etc/alighieri/main.conf"],"declared_config_include_patterns":["/var/lib/alighieri/*.conf"],"canonical_config_include_patterns":["/var/lib/alighieri/*.conf"]}' \
        fail "mock unsafe configuration source parent /var/lib/alighieri" \
        /var/lib/alighieri
    _check_config_sources_preflight "accepts a root-controlled wildcard with spaces" \
        '{"declared_config_sources":["/etc/alighieri/main.conf"],"canonical_config_sources":["/etc/alighieri/main.conf"],"declared_config_include_patterns":["/etc/alighieri/policy fragments/*.conf"],"canonical_config_include_patterns":["/etc/alighieri/policy fragments/*.conf"]}' \
        ok "PARENT:/etc/alighieri/policy fragments|"

    _check_warn() { # description want(warn|quiet) func summary
        local desc="$1" want="$2" func="$3" summary="$4" out got
        out="$("$func" "$summary" 2>&1)" || true
        if [ -n "$out" ]; then got=warn; else got=quiet; fi
        if [ "$got" = "$want" ]; then
            printf 'ok   %s\n' "$desc"
        else
            printf 'FAIL %s: expected %s, got %s\n' "$desc" "$want" "$got"
            failures=$((failures + 1))
        fi
    }

    # The warnings must stay silent for a path genuinely inside the writable dir
    # and fire for a traversal that escapes it (normalize_path via the real helpers).
    _check_warn "acme cache inside StateDirectory stays quiet" quiet \
        warn_acme_cache_outside_state_dir "{\"acme\":true,\"acme_cache\":\"$STATE_DIR/acme\"}"
    _check_warn "acme cache traversal escape warns" warn \
        warn_acme_cache_outside_state_dir "{\"acme\":true,\"acme_cache\":\"$STATE_DIR/../evil\"}"
    _check_warn "logfile inside log dir stays quiet" quiet \
        warn_logfile_outside_log_dir "{\"log_file\":\"$LOG_DIR/app.log\"}"
    _check_warn "logfile traversal escape warns" warn \
        warn_logfile_outside_log_dir "{\"log_file\":\"$LOG_DIR/../evil.log\"}"

    _check_json() { # description json key expected
        local got
        got="$(printf '%s' "$2" | json_string_field "$3")"
        if [ "$got" = "$4" ]; then
            printf 'ok   json_string_field %s\n' "$1"
        else
            printf 'FAIL json_string_field %s: got [%s] want [%s]\n' "$1" "$got" "$4"
            failures=$((failures + 1))
        fi
    }

    # JSON string extraction must read an escaped path in full and unescape it,
    # where the old `sed` capture truncated at the first `\"` and left `\\` literal.
    _check_json "plain value" '{"acme_cache":"/var/lib/alighieri/acme"}' \
        acme_cache "/var/lib/alighieri/acme"
    _check_json "value among other fields" \
        '{"listen":"0.0.0.0:1080","acme":true,"acme_cache":"/x","log_file":"/y"}' \
        log_file "/y"
    _check_json "escaped backslash" '{"acme_cache":"/var/lib/a\\b"}' \
        acme_cache '/var/lib/a\b'
    _check_json "escaped quote not truncated" '{"log_file":"/var/log/a\"b.log"}' \
        log_file '/var/log/a"b.log'
    _check_json "absent field is empty" '{"acme":true}' acme_cache ""
    _check_json "empty string value" '{"log_file":""}' log_file ""
    # An earlier field whose value is the key name (or contains it quoted) must
    # not be mistaken for the field: only a real `"key":` is accepted.
    _check_json "skips a value equal to the key name" \
        '{"message":"acme_cache","acme_cache":"/real/path"}' acme_cache "/real/path"
    _check_json "skips a quoted key-like substring in a value" \
        '{"path":"x\"acme_cache\"y","acme_cache":"/real"}' acme_cache "/real"

    _check_json_array() { # description json key want(ok|fail) expected
        local got='' status=fail
        if got="$(printf '%s' "$2" | json_string_array_field "$3")"; then
            status=ok
        fi
        if [ "$status" = "$4" ] &&
            { [ "$status" = fail ] || [ "$got" = "$5" ]; }; then
            printf 'ok   json_string_array_field %s\n' "$1"
        else
            printf 'FAIL json_string_array_field %s: got %s [%s] want %s [%s]\n' \
                "$1" "$status" "$got" "$4" "$5"
            failures=$((failures + 1))
        fi
    }

    # Source arrays must retain shell-significant path text exactly. Reject
    # controls because the line-oriented consumer cannot represent them without
    # confusing a single path for multiple sources.
    _check_json_array "preserves spaces, quotes, and backslashes" \
        '{"declared_config_sources":["/etc/alighieri/main.conf","/etc/alighieri/conf d/part \"one\"\\leaf.conf"]}' \
        declared_config_sources ok \
        $'/etc/alighieri/main.conf\n/etc/alighieri/conf d/part "one"\\leaf.conf'
    _check_json_array "skips a key-like value" \
        '{"message":"declared_config_sources","declared_config_sources":["/etc/alighieri/main.conf"]}' \
        declared_config_sources ok '/etc/alighieri/main.conf'
    _check_json_array "accepts an empty array" \
        '{"declared_config_sources":[]}' declared_config_sources ok ''
    _check_json_array "rejects an absent array" \
        '{"ok":true}' declared_config_sources fail ''
    _check_json_array "rejects a non-string member" \
        '{"declared_config_sources":["/etc/main",42]}' \
        declared_config_sources fail ''
    _check_json_array "rejects escaped controls" \
        '{"declared_config_sources":["/etc/a\ninclude"]}' \
        declared_config_sources fail ''

    _check_has() { # description json key want(yes|no)
        local got
        if printf '%s' "$2" | json_has_field "$3"; then got=yes; else got=no; fi
        if [ "$got" = "$4" ]; then
            printf 'ok   json_has_field %s\n' "$1"
        else
            printf 'FAIL json_has_field %s: got %s want %s\n' "$1" "$got" "$4"
            failures=$((failures + 1))
        fi
    }

    # Field presence must be a real `"key":`, not the key name appearing as
    # another field's value — otherwise the "older binary cannot verify this"
    # warnings get suppressed and the bind capability mis-derived.
    _check_has "present field" '{"listen":"127.0.0.1:80"}' listen yes
    _check_has "absent field" '{"acme":true}' log_file no
    _check_has "value equal to key name is not the field" \
        '{"message":"log_file"}' log_file no
    _check_has "quoted key-like substring in a value is not the field" \
        '{"path":"a\"listen\"b"}' listen no

    _check_bool() { # description json key want(yes|no)
        local got
        if printf '%s' "$2" | json_bool_is_true "$3"; then got=yes; else got=no; fi
        if [ "$got" = "$4" ]; then
            printf 'ok   json_bool_is_true %s\n' "$1"
        else
            printf 'FAIL json_bool_is_true %s: got %s want %s\n' "$1" "$got" "$4"
            failures=$((failures + 1))
        fi
    }

    # The boolean must be a real `"key":true`, tolerant of whitespace, and not
    # fooled by the literal appearing in a string value or by a false/absent field.
    _check_bool "true (compact)" '{"acme":true,"acme_cache":"/x"}' acme yes
    _check_bool "true with space after colon" '{"acme": true}' acme yes
    _check_bool "false" '{"acme":false}' acme no
    _check_bool "absent" '{"acme_cache":"/x"}' acme no
    _check_bool "string value true is not the boolean" '{"acme":"true"}' acme no
    _check_bool "escaped key:true in a value with real false" \
        '{"path":"\"acme\":true","acme":false}' acme no

    _check_install_activation() { # start-mode expected-systemctl-calls
        local start_mode="$1" expected="$2" calls="" saved_start="$START_ON_INSTALL"
        systemctl() {
            calls="${calls}${calls:+|}$*"
        }
        START_ON_INSTALL="$start_mode"
        activate_installed_service >/dev/null 2>&1
        START_ON_INSTALL="$saved_start"
        unset -f systemctl
        if [ "$calls" = "$expected" ]; then
            printf 'ok   install activation mode %s -> %s\n' "$start_mode" "$calls"
        else
            printf 'FAIL install activation mode %s: got [%s] want [%s]\n' \
                "$start_mode" "$calls" "$expected"
            failures=$((failures + 1))
        fi
    }

    # A prepared authenticated deployment must reload the unit but neither
    # enable nor start it. The ordinary second install performs all three.
    _check_install_activation 0 "daemon-reload"
    _check_install_activation 1 \
        "daemon-reload|enable ${SERVICE_NAME}.service|restart ${SERVICE_NAME}.service"

    _check_exec_start_dropin_guard() {
        local saved_unit="$UNIT_FILE" mock_effective_payload="" \
              mock_working_directory="/" mock_root_directory="" \
              mock_namespace_property="" mock_systemd_version="255.4-test" \
              mock_string_array_property="" mock_string_array_value="" \
              mock_exec_start_flags=0 mock_source_exec_prefix="" \
              mock_state_directory='as 1 "alighieri"' \
              mock_state_directory_mode='u 488' \
              mock_state_directory_symlink='a(sst) 0' \
              mock_read_write_paths='as 1 "/var/log/alighieri"' \
              mock_bounding_set='t 0' mock_ambient_capabilities='t 0'
        UNIT_FILE="$(mktemp)"
        printf '%s\n' \
            '[Service]' \
            'ExecStart=/usr/local/bin/alighieri /etc/alighieri/alighieri.conf' \
            >"$UNIT_FILE"
        systemctl() {
            case "${1:-}" in
                daemon-reload) printf 'CALL daemon-reload\n' >&2 ;;
                cat)
                    printf '%s\n' \
                        '[Service]' \
                        'ExecStart=/usr/local/bin/alighieri /etc/alighieri/alighieri.conf' \
                        '# /etc/systemd/system/alighieri.service.d/override.conf' \
                        'ExecStart='
                    [ -z "$mock_effective_payload" ] ||
                        printf 'ExecStart=%s%s\n' \
                            "$mock_source_exec_prefix" "$mock_effective_payload"
                    ;;
                show)
                    if [[ "$*" == *"--property=Version"* ]]; then
                        printf '%s\n' "$mock_systemd_version"
                    else
                        printf '%s\n' \
                            "User=$SERVICE_USER" \
                            "Group=$SERVICE_USER" \
                            "WorkingDirectory=$mock_working_directory" \
                            'ProtectSystem=strict' \
                            'ProtectHome=yes' \
                            'PrivateTmp=yes' \
                            'PrivateDevices=yes' \
                            'ProtectKernelTunables=yes' \
                            'ProtectKernelModules=yes' \
                            'ProtectControlGroups=yes' \
                            'DynamicUser=no' \
                            'PrivateUsers=no' \
                            'SupplementaryGroups=' \
                            "RootDirectory=$mock_root_directory" \
                            'RootImage='
                    fi
                    ;;
                enable | restart) printf 'CALL %s\n' "$*" >&2 ;;
            esac
        }
        busctl() {
            case "${1:-}" in
                call)
                    [ "${5:-}" = "LoadUnit" ] && [ "${6:-}" = "s" ] &&
                        [ "${7:-}" = "${SERVICE_NAME}.service" ] || return 1
                    printf '%s\n' \
                        'o "/org/freedesktop/systemd1/unit/alighieri_2eservice"'
                    ;;
                get-property)
                    local property="${*: -1}"
                    if [ "$property" = "ExecStart" ] ||
                        [ "$property" = "ExecStartEx" ]; then
                        local arg
                        local -a mock_argv=()
                        read -ra mock_argv <<<"$mock_effective_payload"
                        if [ "${#mock_argv[@]}" -eq 0 ]; then
                            if [ "$property" = "ExecStartEx" ]; then
                                printf '%s\n' 'a(sasasttttuii) 0'
                            else
                                printf '%s\n' 'a(sasbttttuii) 0'
                            fi
                        else
                            if [ "$property" = "ExecStartEx" ]; then
                                printf 'a(sasasttttuii) 1 "%s" %d' \
                                    "${mock_argv[0]}" "${#mock_argv[@]}"
                            else
                                printf 'a(sasbttttuii) 1 "%s" %d' \
                                    "${mock_argv[0]}" "${#mock_argv[@]}"
                            fi
                            for arg in "${mock_argv[@]}"; do
                                printf ' "%s"' "$arg"
                            done
                            if [ "$property" = "ExecStartEx" ]; then
                                printf ' %d' "$mock_exec_start_flags"
                                [ "$mock_exec_start_flags" -eq 0 ] ||
                                    printf '%s' ' "fully-privileged"'
                                printf '%s\n' ' 0 0 0 0 0 0 0'
                            else
                                printf '%s\n' ' false 0 0 0 0 0 0 0'
                            fi
                        fi
                    elif [ "$property" = "RootMStack" ]; then
                        if [ "$property" = "$mock_namespace_property" ]; then
                            printf '%s\n' 's "/srv/alighieri.mstack"'
                        else
                            printf '%s\n' 's ""'
                        fi
                    elif [ "$property" = StateDirectory ]; then
                        printf '%s\n' "$mock_state_directory"
                    elif [ "$property" = StateDirectoryMode ]; then
                        printf '%s\n' "$mock_state_directory_mode"
                    elif [ "$property" = StateDirectorySymlink ]; then
                        printf '%s\n' "$mock_state_directory_symlink"
                    elif [ "$property" = ReadWritePaths ]; then
                        printf '%s\n' "$mock_read_write_paths"
                    elif [ "$property" = CapabilityBoundingSet ]; then
                        printf '%s\n' "$mock_bounding_set"
                    elif [ "$property" = AmbientCapabilities ]; then
                        printf '%s\n' "$mock_ambient_capabilities"
                    elif [ -n "$mock_string_array_property" ] &&
                        [ "$property" = "$mock_string_array_property" ]; then
                        printf 'as 1 "%s"\n' "$mock_string_array_value"
                    elif [ "$property" = "$mock_namespace_property" ]; then
                        printf '%s\n' 'a(ssbt) 1 "/srv/users" "/etc/alighieri" false true'
                    else
                        printf '%s\n' 'as 0'
                    fi
                    ;;
            esac
        }

        local loaded_object
        if loaded_object="$(service_unit_object_path)" &&
            [ "$loaded_object" = "/org/freedesktop/systemd1/unit/alighieri_2eservice" ]; then
            printf 'ok   systemd unit lookup loads a fresh unit through Manager.LoadUnit\n'
        else
            printf 'FAIL systemd unit lookup did not use Manager.LoadUnit: [%s]\n' \
                "$loaded_object"
            failures=$((failures + 1))
        fi

        _check_rejected_effective_payload() { # description effective-payload
            local desc="$1" out activation_succeeded=0 \
                  saved_start="$START_ON_INSTALL"
            mock_effective_payload="$2"
            if ! effective_exec_start_overrides_base; then
                printf 'FAIL systemd drop-in override was not detected (%s)\n' "$desc"
                failures=$((failures + 1))
            elif effective_install_matches \
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf"; then
                printf 'FAIL systemd drop-in incorrectly matched the rewritten base unit (%s)\n' "$desc"
                failures=$((failures + 1))
            else
                START_ON_INSTALL=1
                if out="$(
                    activate_installed_service \
                        "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 0 2>&1
                )"; then
                    activation_succeeded=1
                fi
                START_ON_INSTALL="$saved_start"

                if [ "$activation_succeeded" -eq 1 ]; then
                    printf 'FAIL install activation accepted an overriding ExecStart drop-in (%s)\n' "$desc"
                    failures=$((failures + 1))
                elif [[ "$out" == *"overriding drop-in"* && "$out" != *"CALL restart"* && "$out" != *"CALL enable"* ]]; then
                    printf 'ok   install activation refuses %s before start\n' "$desc"
                else
                    printf 'FAIL install activation drop-in guard %s output: [%s]\n' "$desc" "$out"
                    failures=$((failures + 1))
                fi
            fi
        }

        _check_rejected_effective_payload "a different ExecStart" \
            "/opt/alighieri/alighieri /opt/alighieri/custom.conf"
        _check_rejected_effective_payload "an empty ExecStart reset" ""
        _check_rejected_effective_payload "a wrapper without a config" "/opt/wrapper"
        _check_rejected_effective_payload "a variable-expanded ExecStart" \
            "/usr/local/bin/alighieri /etc/\${SITE}/alighieri.conf"
        _check_rejected_effective_payload "a specifier-expanded ExecStart" \
            '/usr/local/bin/alighieri /etc/%n/alighieri.conf'

        # ExecStart's `+`/`!` prefixes can leave its legacy argv unchanged while
        # bypassing service credentials or sandboxing. ExecStartEx reports those
        # flags explicitly; reject them before activation.
        mock_effective_payload="/usr/local/bin/alighieri /etc/alighieri/alighieri.conf"
        mock_exec_start_flags=1
        local flags_out flags_accepted=0 flags_saved_start="$START_ON_INSTALL"
        START_ON_INSTALL=1
        if flags_out="$(
            activate_installed_service \
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 0 2>&1
        )"; then
            flags_accepted=1
        fi
        START_ON_INSTALL="$flags_saved_start"
        if [ "$flags_accepted" -eq 0 ] &&
            [[ "$flags_out" == *"execution flags"* &&
                "$flags_out" != *"CALL restart"* &&
                "$flags_out" != *"CALL enable"* ]]; then
            printf 'ok   install activation refuses privileged ExecStart flags before start\n'
        else
            printf 'FAIL install activation ExecStart flag guard output: [%s]\n' "$flags_out"
            failures=$((failures + 1))
        fi
        mock_exec_start_flags=0

        # Before ExecStartEx, D-Bus omitted `+`/`!`/`:`. The legacy fallback
        # must reject a privileged source prefix even though ExecStart reports
        # the same executable and argv.
        mock_systemd_version="242.9-test"
        mock_source_exec_prefix="+"
        if effective_install_matches \
            "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf"; then
            printf 'FAIL legacy ExecStart guard accepted a privileged prefix\n'
            failures=$((failures + 1))
        else
            printf 'ok   legacy ExecStart guard rejects a privileged prefix\n'
        fi
        mock_source_exec_prefix=""
        mock_systemd_version="255.4-test"

        # Even with the expected command, a surviving WorkingDirectory drop-in
        # would make `userlist: users` resolve as /srv/alighieri/users instead of
        # the /users path checked by the transient WorkingDirectory=/ preflight.
        # Refuse it after daemon-reload and before enable/restart.
        mock_effective_payload="/usr/local/bin/alighieri /etc/alighieri/alighieri.conf"
        mock_working_directory=""
        if effective_service_sandbox_matches; then
            printf 'ok   effective default WorkingDirectory matches explicit root\n'
        else
            printf 'FAIL effective default WorkingDirectory was not treated as root\n'
            failures=$((failures + 1))
        fi
        mock_working_directory="/srv/alighieri"
        local sandbox_out sandbox_accepted=0 saved_start="$START_ON_INSTALL"
        START_ON_INSTALL=1
        if sandbox_out="$(
            activate_installed_service \
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 0 2>&1
        )"; then
            sandbox_accepted=1
        fi
        START_ON_INSTALL="$saved_start"
        if [ "$sandbox_accepted" -eq 0 ] &&
            [[ "$sandbox_out" == *"WorkingDirectory"* &&
                "$sandbox_out" != *"CALL restart"* &&
                "$sandbox_out" != *"CALL enable"* ]]; then
            printf 'ok   install activation refuses a WorkingDirectory override before start\n'
        else
            printf 'FAIL install activation WorkingDirectory guard output: [%s]\n' "$sandbox_out"
            failures=$((failures + 1))
        fi

        # Manager-loaded writable directories and capability masks must match
        # the candidate unit exactly; they are list/bitmask properties that do
        # not appear in the scalar sandbox output above.
        mock_working_directory="/"
        if effective_service_sandbox_matches 0; then
            printf 'ok   effective managed storage and empty capabilities match\n'
        else
            printf 'FAIL effective managed storage or empty capabilities did not match\n'
            failures=$((failures + 1))
        fi

        mock_bounding_set='t 1024'
        mock_ambient_capabilities='t 1024'
        if effective_service_sandbox_matches 1024 &&
            ! effective_service_sandbox_matches 0; then
            printf 'ok   effective bind capability matches only the privileged profile\n'
        else
            printf 'FAIL effective bind capability mask comparison\n'
            failures=$((failures + 1))
        fi

        mock_bounding_set='t 1025'
        if effective_service_sandbox_matches 1024; then
            printf 'FAIL effective capability guard accepted an extra capability bit\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective capability guard rejects extra capability bits\n'
        fi
        mock_bounding_set='t 0'
        mock_ambient_capabilities='t 0'

        mock_read_write_paths='as 2 "/var/log/alighieri" "/"'
        if effective_service_sandbox_matches 0; then
            printf 'FAIL effective storage guard accepted an extra writable path\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective storage guard rejects extra writable paths\n'
        fi
        mock_read_write_paths='as 1 "/var/log/alighieri"'

        mock_state_directory='as 0'
        if effective_service_sandbox_matches 0; then
            printf 'FAIL effective storage guard accepted a cleared StateDirectory\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective storage guard rejects a cleared StateDirectory\n'
        fi
        mock_state_directory='as 1 "alighieri"'

        mock_state_directory_mode='u 511'
        if effective_service_sandbox_matches 0; then
            printf 'FAIL effective storage guard accepted a broadened StateDirectoryMode\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective storage guard rejects a broadened StateDirectoryMode\n'
        fi
        mock_state_directory_mode='u 488'

        # Runtime/Cache/Logs/ConfigurationDirectory are writable exceptions to
        # ProtectSystem=strict. Every one must remain empty even on the oldest
        # manager that supports the generated StateDirectory directive.
        mock_systemd_version="235.9-test"
        local storage_property
        for storage_property in RuntimeDirectory CacheDirectory LogsDirectory ConfigurationDirectory; do
            mock_string_array_property="$storage_property"
            mock_string_array_value="shared"
            if effective_service_sandbox_matches 0; then
                printf 'FAIL effective storage guard accepted non-empty %s\n' \
                    "$storage_property"
                failures=$((failures + 1))
            else
                printf 'ok   effective storage guard rejects non-empty %s\n' \
                    "$storage_property"
            fi
        done
        mock_string_array_property=""
        mock_string_array_value=""
        mock_systemd_version="255.4-test"

        mock_state_directory_symlink='a(sst) 1 "alighieri" "elsewhere" 0'
        if effective_service_sandbox_matches 0; then
            printf 'FAIL effective storage guard accepted a StateDirectory destination override\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective storage guard rejects a StateDirectory destination override\n'
        fi
        mock_state_directory_symlink='a(sst) 1 "alighieri" "" 0'
        if effective_service_sandbox_matches 0; then
            printf 'ok   effective storage guard accepts an empty StateDirectory mapping\n'
        else
            printf 'FAIL effective storage guard rejected an empty StateDirectory mapping\n'
            failures=$((failures + 1))
        fi
        mock_state_directory_symlink='a(sst) 0'

        # A capability mismatch must abort the activation wrapper before either
        # enable or restart is attempted.
        mock_ambient_capabilities='t 1025'
        sandbox_accepted=0
        START_ON_INSTALL=1
        if sandbox_out="$(
            activate_installed_service \
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 0 2>&1
        )"; then
            sandbox_accepted=1
        fi
        START_ON_INSTALL="$saved_start"
        if [ "$sandbox_accepted" -eq 0 ] &&
            [[ "$sandbox_out" == *"capabilities differ"* &&
                "$sandbox_out" != *"CALL restart"* &&
                "$sandbox_out" != *"CALL enable"* ]]; then
            printf 'ok   install activation refuses capability overrides before start\n'
        else
            printf 'FAIL install activation capability guard output: [%s]\n' "$sandbox_out"
            failures=$((failures + 1))
        fi
        mock_ambient_capabilities='t 0'

        # Namespace settings are additive, so comparing only scalar hardening
        # properties does not detect a surviving chroot/mount drop-in. It must
        # be rejected before activation even when ExecStart and every scalar
        # property still match the managed unit.
        mock_working_directory="/"
        mock_root_directory="/srv/alighieri-chroot"
        sandbox_accepted=0
        START_ON_INSTALL=1
        if sandbox_out="$(
            activate_installed_service \
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 0 2>&1
        )"; then
            sandbox_accepted=1
        fi
        START_ON_INSTALL="$saved_start"
        if [ "$sandbox_accepted" -eq 0 ] &&
            [[ "$sandbox_out" == *"filesystem namespace"* &&
                "$sandbox_out" != *"CALL restart"* &&
                "$sandbox_out" != *"CALL enable"* ]]; then
            printf 'ok   install activation refuses a RootDirectory override before start\n'
        else
            printf 'FAIL install activation RootDirectory guard output: [%s]\n' "$sandbox_out"
            failures=$((failures + 1))
        fi

        # List-valued namespace directives do not replace scalar properties and
        # old systemctl releases cannot print their effective values. The raw
        # D-Bus array count must still catch an additive bind mount.
        mock_root_directory=""
        mock_systemd_version="235.9-test"
        mock_string_array_property="ReadOnlyPaths"
        mock_string_array_value="/var/lib/alighieri/acme"
        if effective_service_sandbox_matches; then
            printf 'FAIL effective namespace guard accepted ReadOnlyPaths on systemd 235\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective namespace guard checks ReadOnlyPaths on systemd 235\n'
        fi
        mock_string_array_property=""
        mock_string_array_value=""
        mock_systemd_version="247.9-test"
        mock_namespace_property="MountImages"
        if effective_service_sandbox_matches; then
            printf 'FAIL effective namespace guard accepted MountImages on systemd 247\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective namespace guard checks MountImages on systemd 247\n'
        fi
        mock_systemd_version="260.1-test"
        mock_namespace_property="RootMStack"
        if effective_service_sandbox_matches; then
            printf 'FAIL effective namespace guard accepted RootMStack on systemd 260\n'
            failures=$((failures + 1))
        else
            printf 'ok   effective namespace guard checks RootMStack on systemd 260\n'
        fi
        mock_systemd_version="255.4-test"
        mock_namespace_property="BindPaths"
        sandbox_accepted=0
        START_ON_INSTALL=1
        if sandbox_out="$(
            activate_installed_service \
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 0 2>&1
        )"; then
            sandbox_accepted=1
        fi
        START_ON_INSTALL="$saved_start"
        if [ "$sandbox_accepted" -eq 0 ] &&
            [[ "$sandbox_out" == *"filesystem namespace"* &&
                "$sandbox_out" != *"CALL restart"* &&
                "$sandbox_out" != *"CALL enable"* ]]; then
            printf 'ok   install activation refuses an additive BindPaths override before start\n'
        else
            printf 'FAIL install activation BindPaths guard output: [%s]\n' "$sandbox_out"
            failures=$((failures + 1))
        fi

        unset -f _check_rejected_effective_payload
        unset -f busctl
        unset -f systemctl
        rm -f -- "$UNIT_FILE"
        UNIT_FILE="$saved_unit"
    }

    _check_exec_start_dropin_guard

    _check_install_config() { # description explicit requested installed expected
        local desc="$1" explicit="$2" requested="$3" installed="$4" expected="$5" \
              got saved_explicit="$CONFIG_EXPLICIT" saved_requested="$INSTALL_CONFIG"
        CONFIG_EXPLICIT="$explicit"
        INSTALL_CONFIG="$requested"
        got="$(select_install_config_path "$installed")"
        CONFIG_EXPLICIT="$saved_explicit"
        INSTALL_CONFIG="$saved_requested"
        if [ "$got" = "$expected" ]; then
            printf 'ok   install config selection %s -> %s\n' "$desc" "$got"
        else
            printf 'FAIL install config selection %s: got [%s] want [%s]\n' \
                "$desc" "$got" "$expected"
            failures=$((failures + 1))
        fi
    }

    # Plain reconfiguration preserves a custom unit path; --config deliberately
    # overrides it; and a fresh install retains the canonical default.
    _check_install_config "preserves existing custom path" 0 "" \
        "/opt/alighieri/custom.conf" "/opt/alighieri/custom.conf"
    _check_install_config "explicit path overrides existing unit" 1 \
        "/etc/alighieri/alighieri.conf" "/opt/alighieri/custom.conf" \
        "/etc/alighieri/alighieri.conf"
    _check_install_config "fresh install uses default" 0 "" "" "$CONFIG_FILE"

    _check_followup_install() { # description sudo-user bin-exp binary cfg-exp config script expected
        local desc="$1" sudo_user="$2" binary_explicit="$3" binary="$4" \
              config_explicit="$5" config="$6" script="$7" expected="$8" got \
              saved_sudo_user="${SUDO_USER:-}" \
              saved_binary_explicit="$BINARY_EXPLICIT" saved_binary="$BINARY" \
              saved_config_explicit="$CONFIG_EXPLICIT" saved_config="$INSTALL_CONFIG"
        SUDO_USER="$sudo_user"
        BINARY_EXPLICIT="$binary_explicit"
        BINARY="$binary"
        CONFIG_EXPLICIT="$config_explicit"
        INSTALL_CONFIG="$config"
        got="$(followup_install_command "$script")"
        SUDO_USER="$saved_sudo_user"
        BINARY_EXPLICIT="$saved_binary_explicit"
        BINARY="$saved_binary"
        CONFIG_EXPLICIT="$saved_config_explicit"
        INSTALL_CONFIG="$saved_config"
        if [ "$got" = "$expected" ]; then
            printf 'ok   follow-up install command %s\n' "$desc"
        else
            printf 'FAIL follow-up install command %s: got [%s] want [%s]\n' \
                "$desc" "$got" "$expected"
            failures=$((failures + 1))
        fi
    }

    # The post-install command returns to the unprivileged invoking shell after
    # sudo and must keep a prebuilt path exactly (with shell-safe quoting). A
    # direct-root source install needs neither sudo nor a synthetic --binary.
    _check_followup_install "sudo + prebuilt + explicit config" alice 1 \
        "/tmp/release builds/alighieri" 1 "/etc/alighieri/alighieri.conf" \
        "/opt/alighieri tools/alighieri.sh" \
        "sudo /opt/alighieri\\ tools/alighieri.sh install --binary /tmp/release\\ builds/alighieri --config /etc/alighieri/alighieri.conf"
    _check_followup_install "direct root + source build" root 0 \
        "/unused/generated/binary" 0 "" "/opt/alighieri tools/alighieri.sh" \
        "/opt/alighieri\\ tools/alighieri.sh install"

    _check_cli_rejected() { # description expected-error arguments...
        local desc="$1" expected="$2" out
        shift 2
        if out="$(bash "${BASH_SOURCE[0]}" "$@" 2>&1)"; then
            printf 'FAIL installer CLI accepted invalid %s\n' "$desc"
            failures=$((failures + 1))
        elif [[ "$out" == *"$expected"* && "$out" != *"must run as root"* ]]; then
            printf 'ok   installer CLI rejects %s\n' "$desc"
        else
            printf 'FAIL installer CLI %s: got [%s], want error containing [%s]\n' \
                "$desc" "$out" "$expected"
            failures=$((failures + 1))
        fi
    }

    # Reject invalid install-only config overrides before root/systemd checks or
    # any filesystem mutation.
    _check_cli_rejected "missing --config value" "--config requires a path" install --config
    _check_cli_rejected "empty --config value" "--config requires a path" install --config=
    _check_cli_rejected "relative --config path" "--config must be an absolute path" \
        install --config relative.conf
    _check_cli_rejected "whitespace in --config path" "--config must not contain whitespace" \
        install --config "/etc/alighieri/bad config"
    _check_cli_rejected "systemd specifier in --config path" \
        "--config must not contain systemd ExecStart metacharacters" \
        install --config "/etc/alighieri/%n.conf"
    _check_cli_rejected "systemd variable in --config path" \
        "--config must not contain systemd ExecStart metacharacters" \
        install --config "/etc/alighieri/\$CONFIG.conf"
    _check_cli_rejected "systemd quoting in --config path" \
        "--config must not contain systemd ExecStart metacharacters" \
        install --config '/etc/alighieri/"quoted".conf'
    _check_cli_rejected "systemd specifier in --prefix" \
        "--prefix must not contain systemd ExecStart metacharacters" \
        install --prefix "/opt/%n"
    _check_cli_rejected "trailing slash in --prefix" \
        "--prefix must use a canonical path" install --prefix "/opt/alighieri/"
    _check_cli_rejected "repeated slash in --prefix" \
        "--prefix must use a canonical path" install --prefix "//opt/alighieri"
    _check_cli_rejected "dot component in --prefix" \
        "--prefix must use a canonical path" install --prefix "/opt/./alighieri"
    _check_cli_rejected "dot-dot component in --prefix" \
        "--prefix must use a canonical path" install --prefix "/opt/link/../alighieri"
    _check_cli_rejected "--config on upgrade" "--config is valid only with the install command" \
        upgrade --config /etc/alighieri/alighieri.conf

    _check_install_preflight_transaction() {
        local tx_tmp unit config source bin_dir installed calls output userlist \
              expected_staged expected_staged_unit expected_backup expected_calls \
              expected_error failure_mode \
              succeeded got_binary got_unit got_calls before_inode after_inode \
              fresh_unit fresh_staged fresh_calls \
              signal_unit signal_staged_unit signal_staged_bin signal_installed \
              signal_calls \
              result test_failures=0 UNIT_FILE CONFIG_DIR CONFIG_FILE LOG_DIR \
              BIN_DIR BINARY PREFIX_EXPLICIT CONFIG_EXPLICIT START_ON_INSTALL \
              STAGED_BIN STAGED_UNIT UNIT_BACKUP UNIT_TRANSACTION_ACTIVE \
              UNIT_HAD_ORIGINAL BINARY_COMMIT_IN_PROGRESS
        tx_tmp="$(mktemp -d)"
        unit="$tx_tmp/alighieri.service"
        config="$tx_tmp/alighieri.conf"
        source="$tx_tmp/source-alighieri"
        bin_dir="$tx_tmp/bin"
        installed="$bin_dir/alighieri"
        calls="$tx_tmp/calls"
        output="$tx_tmp/output"
        userlist="$tx_tmp/users"
        expected_staged="${installed}.new.$$"
        expected_staged_unit="${unit}.new.$$"
        expected_backup="${unit}.previous.$$"
        command mkdir -p -- "$bin_dir"
        printf '%s\n' 'old-unit' >"$unit"
        printf '%s\n' 'internal: 127.0.0.1:1080' >"$config"
        printf '%s\n' 'new-binary' >"$source"

        UNIT_FILE="$unit"
        CONFIG_DIR="$tx_tmp/managed-config"
        CONFIG_FILE="$CONFIG_DIR/alighieri.conf"
        LOG_DIR="$tx_tmp/log"
        BIN_DIR="$bin_dir"
        BINARY="$source"
        PREFIX_EXPLICIT=1
        CONFIG_EXPLICIT=0
        START_ON_INSTALL=1
        STAGED_BIN=""
        STAGED_UNIT=""
        UNIT_BACKUP=""
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        BINARY_COMMIT_IN_PROGRESS=0

        _check_install_failure_case() { # failure-mode description
            local description="$2" guard_prefix='config-dir|config-file|'
            failure_mode="$1"
            succeeded=0
            printf '%s\n' 'old-binary' >"$installed"
            printf '%s\n' 'old-unit' >"$unit"
            : >"$calls"
            : >"$output"
            command rm -f -- "$expected_staged" "$expected_staged_unit" \
                "$expected_backup"
            before_inode="$(stat -c %i -- "$installed")"
            if (
                # All command/helper mocks live only in this case process. The
                # deployment globals above are function-local and dynamically
                # visible here, so neither kind of test state leaks afterward.
                require_service_sandbox() { :; }
                prepare_binary_directory() { command mkdir -p -- "$1"; }
                resolve_source_binary() { :; }
                ensure_user() { :; }
                installed_config_path() { printf '%s' "$config"; }
                reject_hidden_service_path() { :; }
                require_safe_service_config_directory() {
                    printf 'config-dir|' >>"$calls"
                    [ "$failure_mode" != config-dir ] ||
                        die "unsafe service config directory"
                }
                require_secure_service_config_file() {
                    printf 'config-file|' >>"$calls"
                    [ "$failure_mode" != config-metadata ] ||
                        die "unsafe service config metadata"
                }
                validate_service_config_sources() {
                    printf 'config-sources|' >>"$calls"
                    [ "$failure_mode" != config-source ] ||
                        die "unsafe included configuration source"
                }
                service_userlist_path_kind() { printf '%s' regular; }
                require_safe_service_userlist_directory() { :; }
                require_secure_service_userlist_file() { :; }
                service_capability_mask() { printf '%s' 0; }
                chown() { [ "${!#}" != "$config" ]; }
                chmod() { [ "${!#}" != "$config" ]; }
                install() {
                    local destination
                    if [ "${1:-}" = "-d" ]; then
                        destination="${!#}"
                        command mkdir -p -- "$destination"
                        return
                    fi
                    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
                    [ "$#" -eq 3 ] || return 1
                    shift
                    command cp -- "$1" "$2"
                    command chmod 755 -- "$2"
                }
                run_in_service_sandbox() {
                    if [ "${1:-}" != "$expected_staged" ] || [ ! -f "${1:-}" ] ||
                        [ "$(<"$1")" != "new-binary" ]; then
                        printf 'invalid-stage:%s|' "$*" >>"$calls"
                        return 1
                    fi
                    printf 'sandbox:%s|' "$*" >>"$calls"
                    if [ "${2:-}" = "--check" ] && [ "${3:-}" = "--json" ]; then
                        [ "$failure_mode" != "config" ] || return 1
                        printf '{"ok":true,"userlist":"%s"}\n' "$userlist"
                        return 0
                    fi
                    # The human-readable retry always fails. The userlist loader
                    # fails only in its focused case so post-unit checks can run.
                    [ "${2:-}" = "user" ] || return 1
                    [ "$failure_mode" != "userlist" ]
                }
                write_unit() {
                    local target="${4:-$UNIT_FILE}"
                    printf 'write|' >>"$calls"
                    printf '%s\n' 'new-unit' >"$target"
                }
                effective_install_matches() {
                    printf 'effective:%s|' "$*" >>"$calls"
                    [ "$failure_mode" != "exec" ]
                }
                require_effective_service_sandbox() {
                    printf 'sandbox-guard|' >>"$calls"
                    [ "$failure_mode" != "sandbox" ] ||
                        die "effective systemd service identity, WorkingDirectory, or filesystem namespace differs from the managed unit"
                }
                activate_prevalidated_service() { printf 'activate|' >>"$calls"; }
                move_file_command() {
                    if [ "$failure_mode" = "binary-move" ] &&
                        [ "${1:-}" = "-f" ] && [ "${3:-}" = "$expected_staged" ]; then
                        printf 'binary-move|' >>"$calls"
                        return 1
                    fi
                    command mv "$@"
                }
                local reload_count=0
                systemctl() {
                    printf 'systemctl:%s|' "$*" >>"$calls"
                    if [ "${1:-}" = "daemon-reload" ]; then
                        reload_count=$((reload_count + 1))
                        if [ "$failure_mode" = "reload" ] &&
                            [ "$reload_count" -eq 1 ]; then
                            return 1
                        fi
                    fi
                }
                trap cleanup EXIT
                do_install
            ) >"$output" 2>&1; then
                succeeded=1
            fi
            got_binary="$(<"$installed")"
            got_unit="$(<"$unit")"
            got_calls="$(<"$calls")"
            after_inode="$(stat -c %i -- "$installed")"
            case "$failure_mode" in
                config-dir)
                    expected_calls='config-dir|'
                    expected_error="unsafe service config directory"
                    ;;
                config-metadata)
                    expected_calls='config-dir|config-file|'
                    expected_error="unsafe service config metadata"
                    ;;
                config)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|sandbox:$expected_staged --check $config|"
                    expected_error="invalid or unreachable"
                    ;;
                config-source)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|config-sources|"
                    expected_error="unsafe included configuration source"
                    ;;
                userlist)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|config-sources|sandbox:$expected_staged user list --userlist $userlist|"
                    expected_error="cannot be loaded"
                    ;;
                reload)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|config-sources|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|systemctl:daemon-reload|"
                    expected_error="daemon-reload failed"
                    ;;
                exec)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|config-sources|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|effective:$installed $config|systemctl:daemon-reload|"
                    expected_error="overriding drop-in"
                    ;;
                sandbox)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|config-sources|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|effective:$installed $config|sandbox-guard|systemctl:daemon-reload|"
                    expected_error="filesystem namespace"
                    ;;
                binary-move)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|config-sources|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|effective:$installed $config|sandbox-guard|binary-move|systemctl:daemon-reload|"
                    expected_error="could not install the validated binary"
                    ;;
            esac
            if [ "$succeeded" -eq 0 ] &&
                [ "$got_binary" = "old-binary" ] &&
                [ "$before_inode" = "$after_inode" ] &&
                [ "$got_unit" = "old-unit" ] &&
                [ "$got_calls" = "$expected_calls" ] &&
                grep -Fq -- "$expected_error" "$output" &&
                [ ! -e "$expected_staged" ] &&
                [ ! -e "$expected_staged_unit" ] &&
                [ ! -e "$expected_backup" ]; then
                printf 'ok   install %s preserves binary, unit, and service\n' \
                    "$description"
            else
                printf 'FAIL install %s transaction: status %s, binary [%s], inode %s/%s, unit [%s], calls [%s], staged %s\n' \
                    "$description" "$succeeded" "$got_binary" "$before_inode" \
                    "$after_inode" "$got_unit" "$got_calls" \
                    "$([ -e "$expected_staged" ] && printf present || printf absent)"
                test_failures=$((test_failures + 1))
            fi
        }

        _check_install_failure_case config-dir "unsafe config directory"
        _check_install_failure_case config-metadata "unsafe config metadata"
        _check_install_failure_case config "config preflight failure"
        _check_install_failure_case config-source "included config integrity failure"
        _check_install_failure_case userlist "userlist preflight failure"
        _check_install_failure_case reload "daemon-reload validation failure"
        _check_install_failure_case exec "surviving ExecStart drop-in rejection"
        _check_install_failure_case sandbox "surviving sandbox drop-in rejection"
        _check_install_failure_case binary-move "binary replacement failure"

        # A first install has no base unit to restore. Its transaction must remove
        # the candidate and reload the manager when validation rejects it.
        fresh_unit="$tx_tmp/fresh.service"
        fresh_staged="${fresh_unit}.new.$$"
        fresh_calls="$tx_tmp/fresh-calls"
        printf '%s\n' 'candidate-unit' >"$fresh_staged"
        : >"$fresh_calls"
        if (
            UNIT_FILE="$fresh_unit"
            STAGED_UNIT="$fresh_staged"
            UNIT_BACKUP=""
            UNIT_TRANSACTION_ACTIVE=0
            UNIT_HAD_ORIGINAL=0
            systemctl() { printf 'daemon-reload|' >>"$fresh_calls"; }
            trap cleanup EXIT
            begin_unit_transaction
            [ "$(<"$UNIT_FILE")" = "candidate-unit" ]
            rollback_unit_transaction
            [ ! -e "$UNIT_FILE" ] && [ "$UNIT_TRANSACTION_ACTIVE" -eq 0 ]
        ) && [ "$(<"$fresh_calls")" = "daemon-reload|" ] &&
            [ ! -e "$fresh_unit" ] && [ ! -e "$fresh_staged" ]; then
            printf 'ok   fresh install rollback removes the uncommitted base unit\n'
        else
            printf 'FAIL fresh install rollback left a unit or skipped daemon-reload\n'
            test_failures=$((test_failures + 1))
        fi

        # Simulate EXIT landing in the instruction window immediately after the
        # same-filesystem binary rename. The vanished staged source is proof the
        # atomic commit completed, so cleanup must retain the validated unit.
        signal_unit="$tx_tmp/signal.service"
        signal_staged_unit="${signal_unit}.new.$$"
        signal_staged_bin="$tx_tmp/signal-bin.new.$$"
        signal_installed="$tx_tmp/signal-bin"
        signal_calls="$tx_tmp/signal-calls"
        printf '%s\n' 'old-unit' >"$signal_unit"
        printf '%s\n' 'new-unit' >"$signal_staged_unit"
        printf '%s\n' 'new-binary' >"$signal_staged_bin"
        : >"$signal_calls"
        if (
            UNIT_FILE="$signal_unit"
            STAGED_UNIT="$signal_staged_unit"
            STAGED_BIN="$signal_staged_bin"
            UNIT_BACKUP=""
            UNIT_TRANSACTION_ACTIVE=0
            UNIT_HAD_ORIGINAL=0
            BINARY_COMMIT_IN_PROGRESS=0
            systemctl() { printf 'daemon-reload|' >>"$signal_calls"; }
            begin_unit_transaction
            BINARY_COMMIT_IN_PROGRESS=1
            replace_file_atomically "$STAGED_BIN" "$signal_installed"
            cleanup
            [ "$(<"$UNIT_FILE")" = "new-unit" ] &&
                [ "$(<"$signal_installed")" = "new-binary" ] &&
                [ "$UNIT_TRANSACTION_ACTIVE" -eq 0 ]
        ) && [ ! -s "$signal_calls" ] &&
            [ ! -e "${signal_unit}.previous.$$" ]; then
            printf 'ok   cleanup commits the validated unit after an interrupted binary rename\n'
        else
            printf 'FAIL cleanup rolled back after the binary rename had completed\n'
            test_failures=$((test_failures + 1))
        fi

        command rm -f -- "$unit" "$config" "$source" "$installed" "$calls" \
            "$output" "$userlist" "$expected_staged" "$expected_staged_unit" \
            "$expected_backup" "$fresh_unit" "$fresh_staged" "$fresh_calls" \
            "$signal_unit" "$signal_staged_unit" "$signal_staged_bin" \
            "$signal_installed" "$signal_calls" "${signal_unit}.previous.$$"
        command rmdir -- "$LOG_DIR" "$bin_dir" "$tx_tmp"
        result="$test_failures"
        unset -f _check_install_failure_case
        [ "$result" -eq 0 ]
    }

    if ! _check_install_preflight_transaction; then
        failures=$((failures + 1))
    fi
    unset -f _check_install_preflight_transaction

    _check_fresh_install_transaction() {
        local fresh_tmp unit config source bin_dir installed calls output mode \
              succeeded got_calls expected_calls test_failures=0 \
              UNIT_FILE CONFIG_DIR CONFIG_FILE LOG_DIR BIN_DIR BINARY \
              BINARY_EXPLICIT PREFIX_EXPLICIT CONFIG_EXPLICIT INSTALL_CONFIG \
              START_ON_INSTALL STAGED_BIN STAGED_UNIT UNIT_BACKUP \
              UNIT_TRANSACTION_ACTIVE UNIT_HAD_ORIGINAL \
              BINARY_COMMIT_IN_PROGRESS

        for mode in success reject; do
            fresh_tmp="$(mktemp -d)"
            unit="$fresh_tmp/alighieri.service"
            config="$fresh_tmp/alighieri.conf"
            source="$fresh_tmp/source-alighieri"
            bin_dir="$fresh_tmp/bin"
            installed="$bin_dir/alighieri"
            calls="$fresh_tmp/calls"
            output="$fresh_tmp/output"
            printf '%s\n' 'internal: 127.0.0.1:1080' >"$config"
            printf '%s\n' 'new-binary' >"$source"
            : >"$calls"

            UNIT_FILE="$unit"
            CONFIG_DIR="$fresh_tmp/managed-config"
            CONFIG_FILE="$CONFIG_DIR/alighieri.conf"
            LOG_DIR="$fresh_tmp/log"
            BIN_DIR="$bin_dir"
            BINARY="$source"
            BINARY_EXPLICIT=1
            PREFIX_EXPLICIT=1
            CONFIG_EXPLICIT=1
            INSTALL_CONFIG="$config"
            START_ON_INSTALL=0
            STAGED_BIN=""
            STAGED_UNIT=""
            UNIT_BACKUP=""
            UNIT_TRANSACTION_ACTIVE=0
            UNIT_HAD_ORIGINAL=0
            BINARY_COMMIT_IN_PROGRESS=0
            succeeded=0

            if (
                require_service_sandbox() { :; }
                prepare_binary_directory() { command mkdir -p -- "$1"; }
                resolve_source_binary() { :; }
                ensure_user() { :; }
                reject_hidden_service_path() { :; }
                require_safe_service_config_directory() { :; }
                require_secure_service_config_file() { :; }
                validate_service_config_sources() { :; }
                service_capability_mask() { printf '%s' 0; }
                chown() { [ "${!#}" != "$config" ]; }
                install() {
                    local destination
                    if [ "${1:-}" = "-d" ]; then
                        destination="${!#}"
                        command mkdir -p -- "$destination"
                        return
                    fi
                    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
                    [ "$#" -eq 3 ] || return 1
                    shift
                    command cp -- "$1" "$2"
                    command chmod 755 -- "$2"
                }
                run_in_service_sandbox() {
                    [ "${1:-}" = "${installed}.new.$$" ] || return 1
                    printf 'preflight|' >>"$calls"
                    printf '%s\n' '{"ok":true,"userlist":""}'
                }
                busctl() {
                    [ "${1:-}" = "call" ] && [ "${5:-}" = "LoadUnit" ] &&
                        [ "${6:-}" = "s" ] &&
                        [ "${7:-}" = "${SERVICE_NAME}.service" ] || return 1
                    printf 'load:LoadUnit|' >>"$calls"
                    printf '%s\n' \
                        'o "/org/freedesktop/systemd1/unit/alighieri_2eservice"'
                }
                effective_install_matches() {
                    service_unit_object_path >/dev/null || return 1
                    [ "$mode" = "success" ]
                }
                require_effective_service_sandbox() {
                    printf 'sandbox-guard|' >>"$calls"
                }
                systemctl() { printf 'systemctl:%s|' "$*" >>"$calls"; }
                trap cleanup EXIT
                do_install
            ) >"$output" 2>&1; then
                succeeded=1
            fi

            got_calls="$(<"$calls")"
            if [ "$mode" = "success" ]; then
                expected_calls='preflight|systemctl:daemon-reload|load:LoadUnit|sandbox-guard|'
                if [ "$succeeded" -eq 1 ] && [ "$(<"$installed")" = "new-binary" ] &&
                    grep -Fq -- "ExecStart=$installed $config" "$unit" &&
                    [ "$(stat -c %a -- "$unit")" = "644" ] &&
                    [ "$got_calls" = "$expected_calls" ] &&
                    [ ! -e "${installed}.new.$$" ] && [ ! -e "${unit}.new.$$" ] &&
                    [ ! -e "${unit}.previous.$$" ]; then
                    printf 'ok   fresh --no-start install loads and commits an unloaded unit\n'
                else
                    printf 'FAIL fresh --no-start install transaction: status %s, calls [%s]\n' \
                        "$succeeded" "$got_calls"
                    test_failures=$((test_failures + 1))
                fi
            else
                expected_calls='preflight|systemctl:daemon-reload|load:LoadUnit|systemctl:daemon-reload|'
                if [ "$succeeded" -eq 0 ] && [ ! -e "$installed" ] &&
                    [ ! -e "$unit" ] && [ "$got_calls" = "$expected_calls" ] &&
                    grep -Fq -- 'overriding drop-in' "$output" &&
                    [ ! -e "${installed}.new.$$" ] && [ ! -e "${unit}.new.$$" ] &&
                    [ ! -e "${unit}.previous.$$" ]; then
                    printf 'ok   rejected fresh install leaves binary and base unit absent\n'
                else
                    printf 'FAIL rejected fresh install transaction: status %s, calls [%s]\n' \
                        "$succeeded" "$got_calls"
                    test_failures=$((test_failures + 1))
                fi
            fi

            command rm -f -- "$unit" "$config" "$source" "$installed" "$calls" \
                "$output" "${installed}.new.$$" "${unit}.new.$$" \
                "${unit}.previous.$$"
            command rmdir -- "$LOG_DIR" "$bin_dir" "$fresh_tmp"
        done
        [ "$test_failures" -eq 0 ]
    }

    if ! _check_fresh_install_transaction; then
        failures=$((failures + 1))
    fi
    unset -f _check_fresh_install_transaction

    _check_release_archive_binary_selection() {
        local archive_tmp explicit
        archive_tmp="$(mktemp -d)"
        explicit="$archive_tmp/operator-selected"
        command mkdir -p -- "$archive_tmp/doc"
        printf '%s\n' bundled >"$archive_tmp/alighieri"
        printf '%s\n' explicit >"$explicit"
        printf '%s\n' config >"$archive_tmp/doc/alighieri.conf"
        printf '%s\n' readme >"$archive_tmp/README.md"
        printf '%s\n' changelog >"$archive_tmp/CHANGELOG.md"

        _check_release_archive_binary_case() {
            local REPO_ROOT="$1" BINARY="$2" expected="$3"
            resolve_source_binary 2>/dev/null
            [ "$BINARY" = "$expected" ]
        }
        if _check_release_archive_binary_case \
            "$archive_tmp" '' "$archive_tmp/alighieri" &&
            _check_release_archive_binary_case \
                "$archive_tmp" "$explicit" "$explicit"; then
            printf 'ok   release archive auto-selects its binary and honours explicit --binary\n'
        else
            printf 'FAIL release archive binary selection\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$archive_tmp/alighieri" "$explicit" \
            "$archive_tmp/doc/alighieri.conf" "$archive_tmp/README.md" \
            "$archive_tmp/CHANGELOG.md"
        command rmdir -- "$archive_tmp/doc" "$archive_tmp"
        unset -f _check_release_archive_binary_case
    }
    _check_release_archive_binary_selection
    unset -f _check_release_archive_binary_selection

    _check_userlist_bootstrap_guidance() {
        local guidance_tmp existing missing output
        guidance_tmp="$(mktemp -d)"
        existing="$guidance_tmp/existing-users"
        missing="$guidance_tmp/missing-users"
        output="$guidance_tmp/output"
        printf '%s\n' alice >"$existing"

        if (
            followup_elevation() { printf '%s' sudo; }
            followup_install_command() { printf '%s' 'sudo ./scripts/alighieri.sh install'; }
            service_runtime_path() { printf '%s' "$1"; }
            print_userlist_bootstrap_guidance "$existing" \
                /usr/local/bin/alighieri
        ) >"$output" 2>&1 && [ ! -s "$output" ]; then
            printf 'ok   existing userlist suppresses redundant credential bootstrap guidance\n'
        else
            printf 'FAIL existing userlist bootstrap guidance suppression\n'
            failures=$((failures + 1))
        fi

        if (
            followup_elevation() { printf '%s' sudo; }
            followup_install_command() { printf '%s' 'sudo ./scripts/alighieri.sh install'; }
            service_runtime_path() { printf '%s' "$1"; }
            print_userlist_bootstrap_guidance "$missing" \
                /usr/local/bin/alighieri
        ) >"$output" 2>&1 &&
            grep -Fq -- 'Create the first proxy user' "$output" &&
            grep -Fq -- "--userlist $missing" "$output"; then
            printf 'ok   missing userlist receives first-user bootstrap guidance\n'
        else
            printf 'FAIL missing userlist bootstrap guidance\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$existing" "$output"
        command rmdir -- "$guidance_tmp"
    }
    _check_userlist_bootstrap_guidance
    unset -f _check_userlist_bootstrap_guidance

    _check_status_version() {
        local status_tmp binary output marker
        status_tmp="$(mktemp -d)"
        binary="$status_tmp/alighieri"
        output="$status_tmp/output"
        marker="$status_tmp/executed"
        ALIGHIERI_STATUS_TEST_MARKER="$marker"
        export ALIGHIERI_STATUS_TEST_MARKER
        # These are literal lines of the temporary test executable.
        # shellcheck disable=SC2016
        printf '%s\n' \
            '#!/usr/bin/env sh' \
            'if [ -n "${ALIGHIERI_STATUS_TEST_MARKER:-}" ]; then' \
            '    printf "%s\n" executed >"$ALIGHIERI_STATUS_TEST_MARKER"' \
            'fi' \
            'printf "%s\n" "alighieri 9.8.7"' >"$binary"
        command chmod 755 -- "$binary"

        if (
            require_safe_binary_directory() { :; }
            stat() { printf '%s\n' '0 755'; }
            installed_binary_is_safe_for_status "$binary" || exit 1
            stat() { printf '%s\n' '1000 755'; }
            ! installed_binary_is_safe_for_status "$binary" || exit 1
            stat() { printf '%s\n' '0 777'; }
            ! installed_binary_is_safe_for_status "$binary" || exit 1
            stat() { printf '%s\n' '0 4755'; }
            ! installed_binary_is_safe_for_status "$binary"
        ); then
            printf 'ok   status version query requires root-owned, non-writable, non-set-ID binary metadata\n'
        else
            printf 'FAIL status binary metadata guard\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$marker"
        if (
            status_effective_uid() { printf '%s\n' 0; }
            run_in_service_sandbox() {
                [ "$#" -eq 2 ] && [ "$1" = "$binary" ] && [ "$2" = --version ] ||
                    return 1
                printf '%s\n' 'alighieri sandboxed'
            }
            query_installed_binary_version "$binary"
        ) >"$output" 2>&1 && [ ! -e "$marker" ] &&
            grep -Fxq -- 'alighieri sandboxed' "$output"; then
            printf 'ok   privileged status queries version inside the service sandbox\n'
        else
            printf 'FAIL privileged status version sandbox routing\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$marker"
        if (
            status_effective_uid() { printf '%s\n' 1000; }
            run_in_service_sandbox() { return 1; }
            query_installed_binary_version "$binary"
        ) >"$output" 2>&1 && [ -e "$marker" ] &&
            grep -Fxq -- 'alighieri 9.8.7' "$output"; then
            printf 'ok   unprivileged status queries the trusted binary as its caller\n'
        else
            printf 'FAIL unprivileged status version query\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$marker"
        if (
            status_effective_uid() { return 1; }
            ! query_installed_binary_version "$binary"
        ) >"$output" 2>&1 && [ ! -e "$marker" ]; then
            printf 'ok   status version query fails closed when caller identity is unknown\n'
        else
            printf 'FAIL status version query with unknown caller identity\n'
            failures=$((failures + 1))
        fi

        if (
            UNIT_FILE="$status_tmp/missing.service"
            installed_binary_path() { printf '%s' "$binary"; }
            installed_config_path() { printf '%s' "$status_tmp/missing.conf"; }
            installed_binary_is_safe_for_status() { :; }
            query_installed_binary_version() { printf '%s\n' 'alighieri 9.8.7'; }
            do_status
        ) >"$output" 2>&1 &&
            grep -Fq -- 'Version:  alighieri 9.8.7' "$output"; then
            printf 'ok   deployment status reports the installed binary version\n'
        else
            printf 'FAIL deployment status version output\n'
            failures=$((failures + 1))
        fi

        if (
            UNIT_FILE="$status_tmp/missing.service"
            installed_binary_path() { printf '%s' "$binary"; }
            installed_config_path() { printf '%s' "$status_tmp/missing.conf"; }
            installed_binary_is_safe_for_status() { :; }
            query_installed_binary_version() {
                printf '%s\n' 'alighieri bogus-success-output'
                return 42
            }
            do_status
        ) >"$output" 2>&1 &&
            grep -Fq -- 'Version:  unknown (--version failed)' "$output" &&
            ! grep -Fq -- 'Version:  alighieri bogus-success-output' "$output"; then
            printf 'ok   deployment status rejects version output from a failed command\n'
        else
            printf 'FAIL deployment status accepted failed version output\n'
            failures=$((failures + 1))
        fi

        if (
            UNIT_FILE="$status_tmp/missing.service"
            installed_binary_path() { printf '%s' "$binary"; }
            installed_config_path() { printf '%s' "$status_tmp/missing.conf"; }
            installed_binary_is_safe_for_status() { return 1; }
            do_status
        ) >"$output" 2>&1 && [ ! -e "$marker" ] &&
            grep -Fq -- 'Version:  not queried' "$output"; then
            printf 'ok   deployment status never executes an untrusted unit binary\n'
        else
            printf 'FAIL deployment status executed an untrusted unit binary\n'
            failures=$((failures + 1))
        fi

        unset ALIGHIERI_STATUS_TEST_MARKER
        command rm -f -- "$binary" "$output" "$marker"
        command rmdir -- "$status_tmp"
    }
    _check_status_version
    unset -f _check_status_version

    _check_legacy_unit_recognition() {
        local legacy_tmp unit install_bin config_file
        legacy_tmp="$(mktemp -d)"
        unit="$legacy_tmp/alighieri.service"
        install_bin="/usr/local/bin/alighieri"
        config_file="/etc/alighieri/alighieri.conf"

        if (
            UNIT_FILE="$unit"
            unit_file_is_safe_for_legacy_migration() { :; }
            loaded_unit_source_is_unoverridden() { :; }
            loaded_exec_start_payload() {
                printf '%s' "$install_bin $config_file"
            }

            render_legacy_unit_v0_1 "$install_bin" "$config_file" >"$unit"
            [ "$(legacy_generated_unit_kind)" = v0.1.x ] || exit 1

            render_legacy_unit_v0_2_to_v0_4 \
                "$install_bin" "$config_file" '' >"$unit"
            [ "$(legacy_generated_unit_kind)" = v0.2.0-v0.4.0 ] || exit 1

            render_legacy_unit_v0_2_to_v0_4 "$install_bin" "$config_file" \
                CAP_NET_BIND_SERVICE >"$unit"
            [ "$(legacy_generated_unit_kind)" = v0.2.0-v0.4.0 ] || exit 1

            write_unit "$install_bin" "$config_file" 0 "$unit"
            ! legacy_generated_unit_kind >/dev/null 2>&1 || exit 1

            render_legacy_unit_v0_1 "$install_bin" "$config_file" >"$unit"
            printf '%s\n' '# operator customization' >>"$unit"
            ! legacy_generated_unit_kind >/dev/null 2>&1 || exit 1

            render_legacy_unit_v0_1 "$install_bin" "$config_file" >"$unit"
            loaded_exec_start_payload() {
                printf '%s' "$install_bin $config_file --extra"
            }
            ! legacy_generated_unit_kind >/dev/null 2>&1 || exit 1

            loaded_exec_start_payload() {
                printf '%s' "$install_bin $config_file"
            }
            loaded_unit_source_is_unoverridden() { return 1; }
            ! legacy_generated_unit_kind >/dev/null 2>&1
        ); then
            printf 'ok   exact v0.1-v0.4 units are recognized; current, edited, and overridden units are not\n'
        else
            printf 'FAIL legacy generated-unit recognition\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$unit"
        command rmdir -- "$legacy_tmp"
    }
    _check_legacy_unit_recognition
    unset -f _check_legacy_unit_recognition

    _check_legacy_unit_metadata() {
        local metadata_tmp unit
        metadata_tmp="$(mktemp -d)"
        unit="$metadata_tmp/alighieri.service"
        printf '%s\n' unit >"$unit"

        if (
            UNIT_FILE="$unit"
            stat() { printf '%s\n' '0 644'; }
            unit_file_is_safe_for_legacy_migration || exit 1
            stat() { printf '%s\n' '0 664'; }
            ! unit_file_is_safe_for_legacy_migration || exit 1
            stat() { printf '%s\n' '1000 644'; }
            ! unit_file_is_safe_for_legacy_migration || exit 1
            command rm -f -- "$unit"
            if command ln -s -- "$metadata_tmp/target" "$unit" 2>/dev/null; then
                stat() { printf '%s\n' '0 644'; }
                ! unit_file_is_safe_for_legacy_migration
            fi
        ); then
            printf 'ok   legacy migration requires a root-owned, non-writable physical unit\n'
        else
            printf 'FAIL legacy unit metadata guard\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$unit"
        command rmdir -- "$metadata_tmp"
    }
    _check_legacy_unit_metadata
    unset -f _check_legacy_unit_metadata

    _check_upgrade_unit_selection() {
        local selection_tmp output
        selection_tmp="$(mktemp -d)"
        output="$selection_tmp/output"

        if (
            UPGRADE_LEGACY_UNIT_KIND=""
            legacy_generated_unit_kind() { printf '%s' v0.1.x; }
            effective_service_sandbox_matches() { return 1; }
            info() { :; }
            prepare_upgrade_unit_migration /usr/local/bin/alighieri \
                /etc/alighieri/alighieri.conf \
                '/usr/local/bin/alighieri /etc/alighieri/alighieri.conf'
            [ "$UPGRADE_LEGACY_UNIT_KIND" = v0.1.x ]
        ) && (
            UPGRADE_LEGACY_UNIT_KIND="stale"
            legacy_generated_unit_kind() { return 1; }
            effective_service_sandbox_matches() { :; }
            prepare_upgrade_unit_migration /usr/local/bin/alighieri \
                /etc/alighieri/custom.conf \
                '/usr/local/bin/alighieri /etc/alighieri/custom.conf'
            [ -z "$UPGRADE_LEGACY_UNIT_KIND" ]
        ); then
            printf 'ok   upgrade selects exact legacy migration and preserves compatible custom units\n'
        else
            printf 'FAIL upgrade unit selection\n'
            failures=$((failures + 1))
        fi

        if (
            legacy_generated_unit_kind() { return 1; }
            effective_service_sandbox_matches() { return 1; }
            prepare_upgrade_unit_migration /usr/local/bin/alighieri \
                /etc/alighieri/alighieri.conf \
                '/usr/local/bin/alighieri /etc/alighieri/alighieri.conf'
        ) >"$output" 2>&1; then
            printf 'FAIL customized unsafe unit was accepted for upgrade\n'
            failures=$((failures + 1))
        elif grep -Fq -- 'not an exact unmodified Alighieri legacy template' "$output" &&
            grep -Fq -- 'systemctl cat alighieri.service' "$output"; then
            printf 'ok   customized unsafe unit receives precise inspection guidance\n'
        else
            printf 'FAIL customized unsafe unit diagnostic\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$output"
        command rmdir -- "$selection_tmp"
    }
    _check_upgrade_unit_selection
    unset -f _check_upgrade_unit_selection

    _check_legacy_upgrade_transaction() {
        local upgrade_tmp unit config source bin_dir installed calls output \
              transaction_dir retained_backup \
              failure_mode UNIT_FILE CONFIG_DIR CONFIG_FILE LOG_DIR BIN_DIR \
              BINARY STAGED_BIN STAGED_UNIT UNIT_CANDIDATE_SNAPSHOT UNIT_BACKUP \
              UNIT_TRANSACTION_DIR UNIT_RETAINED_BACKUP UNIT_TRANSACTION_ACTIVE \
              UNIT_HAD_ORIGINAL UNIT_TRANSACTION_USES_STAGED_LINK \
              UNIT_ROLLBACK_CONFLICT_COPY BINARY_COMMIT_IN_PROGRESS \
              UPGRADE_LEGACY_UNIT_KIND RESTART_ON_UPGRADE
        upgrade_tmp="$(mktemp -d)"
        unit="$upgrade_tmp/alighieri.service"
        config="$upgrade_tmp/alighieri.conf"
        source="$upgrade_tmp/candidate-alighieri"
        bin_dir="$upgrade_tmp/bin"
        installed="$bin_dir/alighieri"
        calls="$upgrade_tmp/calls"
        output="$upgrade_tmp/output"
        transaction_dir="${unit}.migration"
        retained_backup="${unit}.pre-migration"
        command mkdir -p -- "$bin_dir"
        printf '%s\n' 'internal: 127.0.0.1:1080' >"$config"
        printf '%s\n' candidate >"$source"

        UNIT_FILE="$unit"
        CONFIG_DIR="$upgrade_tmp/etc"
        CONFIG_FILE="$config"
        LOG_DIR="$upgrade_tmp/log"
        BIN_DIR="$bin_dir"
        BINARY="$source"
        STAGED_BIN=""
        STAGED_UNIT=""
        UNIT_CANDIDATE_SNAPSHOT=""
        UNIT_BACKUP=""
        UNIT_TRANSACTION_DIR=""
        UNIT_RETAINED_BACKUP=""
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        UNIT_TRANSACTION_USES_STAGED_LINK=0
        UNIT_ROLLBACK_CONFLICT_COPY=""
        BINARY_COMMIT_IN_PROGRESS=0
        UPGRADE_LEGACY_UNIT_KIND=""
        RESTART_ON_UPGRADE=1

        if (
            require_service_sandbox() { :; }
            installed_binary_path() { printf '%s' "$installed"; }
            installed_config_path() { printf '%s' "$config"; }
            existing_install_directory_for_binary() { dirname -- "$1"; }
            require_safe_binary_directory() { :; }
            require_safe_service_config_directory() { :; }
            require_secure_service_config_file() { :; }
            reject_hidden_service_path() { :; }
            resolve_source_binary() { :; }
            stage_executable_copy() {
                command cp -- "$1" "$2" && command chmod 755 -- "$2"
            }
            loaded_exec_start_payload() {
                printf '%s' "$installed $config"
            }
            unit_file_is_safe_for_legacy_migration() {
                if [ "$failure_mode" = backup-metadata ] && [ "$#" -gt 0 ]; then
                    return 1
                fi
            }
            hardlink_utility_available() {
                [ "$failure_mode" != hardlink-missing ]
            }
            loaded_unit_source_is_unoverridden() {
                if [ "$failure_mode" = override-after-begin ] &&
                    [ "$UNIT_TRANSACTION_ACTIVE" -eq 1 ]; then
                    return 1
                fi
            }
            effective_install_matches() { :; }
            effective_service_sandbox_matches() { :; }
            require_effective_service_sandbox() {
                printf 'sandbox-guard|' >>"$calls"
                case "$failure_mode" in
                    validation | unit-rollback-race | unit-rollback-in-place)
                        die "simulated migrated-unit validation failure"
                        ;;
                esac
            }
            run_in_service_sandbox() {
                printf 'preflight|' >>"$calls"
                if [ "$failure_mode" = unit-race ]; then
                    printf '%s\n' '# concurrent operator edit' >>"$unit"
                fi
                printf '%s\n' '{"ok":true,"userlist":""}'
            }
            validate_service_config_sources() { :; }
            validate_service_userlist() { :; }
            service_capability_mask() { printf '%s' 0; }
            move_file_command() {
                if [ "$failure_mode" = unit-detach-race ] &&
                    [ "${3:-}" = "$UNIT_FILE" ] && [ "${4:-}" = "$UNIT_BACKUP" ]; then
                    printf '%s\n' '# concurrent operator edit at detach' >>"$UNIT_FILE"
                fi
                if [ "${4:-}" = "${UNIT_TRANSACTION_DIR}/rollback.displaced" ]; then
                    if [ "$failure_mode" = unit-rollback-race ]; then
                        printf '%s\n' \
                            '[Unit]' \
                            'Description=Concurrent rollback replacement' \
                            >"${UNIT_FILE}.operator"
                        command mv -f -- "${UNIT_FILE}.operator" "$UNIT_FILE"
                    elif [ "$failure_mode" = unit-rollback-in-place ]; then
                        printf '%s\n' '# concurrent in-place rollback edit' >>"$UNIT_FILE"
                    fi
                fi
                if [ "$failure_mode" = binary-move ] &&
                    [ "${3:-}" = "$STAGED_BIN" ]; then
                    return 1
                fi
                if [ "$failure_mode" = backup-open-write ] &&
                    [ "${3:-}" = "$STAGED_BIN" ]; then
                    printf '%s\n' '# late write through displaced unit inode' >>"$UNIT_BACKUP"
                fi
                command mv "$@"
            }
            link_file_command() {
                if [ "$failure_mode" = unit-publish-race ] &&
                    [ "${1:-}" = "$STAGED_UNIT" ] && [ "${2:-}" = "$UNIT_FILE" ]; then
                    printf '%s\n' \
                        '[Unit]' \
                        'Description=Concurrent operator replacement' >"$UNIT_FILE"
                fi
                command link "$@"
            }
            systemctl() {
                printf '%s|' "$*" >>"$calls"
            }

            failure_mode=success
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if ! (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = candidate ] || exit 1
            grep -Fq -- 'WorkingDirectory=/' "$unit" || exit 1
            grep -Fq -- 'StateDirectory=alighieri' "$unit" || exit 1
            grep -Fq -- 'restart alighieri.service|' "$calls" || exit 1
            [ ! -e "$transaction_dir" ] || exit 1
            legacy_unit_file_matches_kind "$retained_backup" v0.1.x \
                "$installed" "$config" || exit 1
            command rm -f -- "$retained_backup"

            failure_mode='backup-open-write'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if ! (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = candidate ] || exit 1
            grep -Fq -- '# late write through displaced unit inode' \
                "$retained_backup" || exit 1
            [ ! -e "$transaction_dir" ] || exit 1
            command rm -f -- "$retained_backup"

            failure_mode=validation
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained_backup" ] || exit 1
            grep -Fq -- 'simulated migrated-unit validation failure' "$output" || exit 1

            failure_mode='hardlink-missing'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained_backup" ] || exit 1
            grep -Fq -- "'link' utility" "$output" || exit 1

            failure_mode='backup-metadata'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            grep -Fq -- 'content or metadata changed' "$output" || exit 1

            failure_mode=override-after-begin
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            grep -Fq -- 'override appeared during migration' "$output" || exit 1

            failure_mode='binary-move'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            grep -Fq -- 'could not replace the installed binary' "$output" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained_backup" ] &&
                [ ! -e "${installed}.new.$$" ] || exit 1

            failure_mode=no-restart
            RESTART_ON_UPGRADE=0
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if ! (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = candidate ] || exit 1
            grep -Fq -- 'WorkingDirectory=/' "$unit" || exit 1
            ! grep -Fq -- 'restart alighieri.service|' "$calls" || exit 1
            grep -Fq -- 'not restarted (--no-restart)' "$output" || exit 1
            legacy_unit_file_matches_kind "$retained_backup" v0.1.x \
                "$installed" "$config" || exit 1
            command rm -f -- "$retained_backup"
            RESTART_ON_UPGRADE=1

            failure_mode='unit-rollback-race'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            grep -Fq -- 'Description=Concurrent rollback replacement' "$unit" || exit 1
            legacy_unit_file_matches_kind "${transaction_dir}/previous" v0.1.x \
                "$installed" "$config" || exit 1
            grep -Fq -- 'did not overwrite the concurrently changed systemd unit' \
                "$output" || exit 1
            command rm -f -- "$retained_backup" "${transaction_dir}/previous" \
                "${transaction_dir}/candidate" "${transaction_dir}/candidate.snapshot" \
                "${transaction_dir}/rollback.displaced" \
                "${transaction_dir}/binary-commit-intent" \
                "${transaction_dir}/binary-commit-intent.staged" \
                "${transaction_dir}/binary-rollback"
            command rmdir -- "$transaction_dir"

            failure_mode='unit-rollback-in-place'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            grep -Fq -- '# concurrent in-place rollback edit' "$unit" || exit 1
            legacy_unit_file_matches_kind "${transaction_dir}/previous" v0.1.x \
                "$installed" "$config" || exit 1
            grep -Fq -- 'did not overwrite the concurrently changed systemd unit' \
                "$output" || exit 1
            command rm -f -- "$retained_backup" "${transaction_dir}/previous" \
                "${transaction_dir}/candidate" "${transaction_dir}/candidate.snapshot" \
                "${transaction_dir}/rollback.displaced" \
                "${transaction_dir}/binary-commit-intent" \
                "${transaction_dir}/binary-commit-intent.staged" \
                "${transaction_dir}/binary-rollback"
            command rmdir -- "$transaction_dir"

            failure_mode='unit-detach-race'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            grep -Fq -- '# concurrent operator edit at detach' "$unit" || exit 1
            grep -Fq -- 'content or metadata changed' "$output" || exit 1
            [ ! -e "$transaction_dir" ] || exit 1

            failure_mode='unit-race'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            grep -Fq -- '# concurrent operator edit' "$unit" || exit 1
            grep -Fq -- 'legacy systemd unit changed during upgrade' "$output" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained_backup" ] || exit 1

            failure_mode='unit-publish-race'
            : >"$calls"
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            printf '%s\n' installed >"$installed"
            if (trap cleanup EXIT; do_upgrade) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$installed")" = installed ] || exit 1
            grep -Fq -- 'Description=Concurrent operator replacement' "$unit" || exit 1
            ! grep -Fq -- 'WorkingDirectory=/' "$unit" || exit 1
            legacy_unit_file_matches_kind "${transaction_dir}/previous" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "${unit}.new.$$" ] || exit 1
            grep -Fq -- 'changed during migration publication' "$output" || exit 1
            grep -Fq -- "recovery copy at ${transaction_dir}/previous" "$output" || exit 1
            [ -f "$retained_backup" ]
        ); then
            printf 'ok   legacy upgrade commits atomically and rolls back every staged failure\n'
        else
            printf 'FAIL legacy upgrade transaction\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$unit" "${unit}.operator" "$config" "$source" "$installed" "$calls" \
            "$output" "${installed}.new.$$" "${unit}.new.$$" \
            "$retained_backup" "${transaction_dir}/candidate" \
            "${transaction_dir}/candidate.snapshot" "${transaction_dir}/previous" \
            "${transaction_dir}/rollback.displaced" \
            "${transaction_dir}/binary-commit-intent" \
            "${transaction_dir}/binary-commit-intent.staged" \
            "${transaction_dir}/binary-rollback" \
            "${transaction_dir}/binary-rollback-untrusted" \
            "${transaction_dir}/committed" \
            "${transaction_dir}/link.probe"
        command rmdir -- "$transaction_dir" 2>/dev/null || true
        command rmdir -- "$bin_dir" "$upgrade_tmp"
    }
    _check_legacy_upgrade_transaction
    unset -f _check_legacy_upgrade_transaction

    _check_legacy_transaction_recovery() {
        local recovery_tmp unit transaction_dir candidate snapshot backup retained \
              displaced intent rollback_marker committed staged_binary output \
              installed config calls reload_fail UNIT_FILE STAGED_UNIT UNIT_CANDIDATE_SNAPSHOT \
              UNIT_BACKUP UNIT_TRANSACTION_DIR UNIT_RETAINED_BACKUP \
              UNIT_TRANSACTION_ACTIVE UNIT_HAD_ORIGINAL \
              UNIT_TRANSACTION_USES_STAGED_LINK UNIT_ROLLBACK_CONFLICT_COPY \
              UNIT_ROLLBACK_RELOAD_FAILED
        recovery_tmp="$(mktemp -d)"
        unit="$recovery_tmp/alighieri.service"
        transaction_dir="${unit}.migration"
        candidate="${transaction_dir}/candidate"
        snapshot="${transaction_dir}/candidate.snapshot"
        backup="${transaction_dir}/previous"
        retained="${unit}.pre-migration"
        displaced="${transaction_dir}/rollback.displaced"
        intent="${transaction_dir}/binary-commit-intent"
        rollback_marker="${transaction_dir}/binary-rollback"
        committed="${transaction_dir}/committed"
        staged_binary="$recovery_tmp/alighieri.new.123"
        output="$recovery_tmp/output"
        installed="$recovery_tmp/alighieri"
        config="$recovery_tmp/alighieri.conf"
        calls="$recovery_tmp/calls"
        printf '%s\n' installed >"$installed"
        printf '%s\n' 'internal: 127.0.0.1:1080' >"$config"

        if (
            UNIT_FILE="$unit"
            STAGED_UNIT=""
            UNIT_CANDIDATE_SNAPSHOT=""
            UNIT_BACKUP=""
            UNIT_TRANSACTION_DIR=""
            UNIT_RETAINED_BACKUP=""
            UNIT_TRANSACTION_ACTIVE=0
            UNIT_HAD_ORIGINAL=0
            UNIT_TRANSACTION_USES_STAGED_LINK=0
            UNIT_ROLLBACK_CONFLICT_COPY=""
            UNIT_ROLLBACK_RELOAD_FAILED=0
            reload_fail=0
            legacy_transaction_directory_is_safe() { :; }
            systemctl() {
                printf '%s|' "$*" >>"$calls"
                if [ "$reload_fail" -eq 1 ] && [ "${1:-}" = daemon-reload ]; then
                    return 1
                fi
            }

            # Crash before detach: the original live unit is authoritative and
            # the deterministic journal can be discarded safely.
            render_legacy_unit_v0_1 "$installed" "$config" >"$unit"
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] || exit 1

            # Crash after detach but before publication: restore the journaled
            # exact unit with create-if-absent semantics.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] || exit 1

            # Crash after publication: classify the live candidate against its
            # independent snapshot, then roll the exact previous unit back.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] || exit 1
            grep -Fq -- 'daemon-reload|' "$calls" || exit 1

            # Crash after publishing the old recovery link but before removing
            # `previous`: recognize the shared inode and finish idempotently.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$backup" "$unit"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] || exit 1

            # Crash after moving the live candidate into the deterministic
            # journal: resume classification and restore the previous inode.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$displaced"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] || exit 1

            # Published intent + existing source means the binary rename never
            # committed. Persist rollback, restore the unit, then remove source.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            printf '%s\n' staged >"$staged_binary"
            printf '%s\n%s\n' "$staged_binary" complete >"$intent"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] &&
                [ ! -e "$staged_binary" ] || exit 1

            # Published intent + absent source means the atomic binary rename
            # committed. Finalize the candidate and retain the exact old unit.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit" "$staged_binary"
            command link "$candidate" "$unit"
            printf '%s\n%s\n' "$staged_binary" complete >"$intent"
            recover_interrupted_legacy_unit_transaction
            [ "$(<"$unit")" = candidate ] || exit 1
            legacy_unit_file_matches_kind "$retained" v0.1.x \
                "$installed" "$config" || exit 1
            [ ! -e "$transaction_dir" ] || exit 1
            command rm -f -- "$unit" "$retained"

            # A failed reload keeps the journal after disk rollback. The next
            # invocation retries reload before removing the recovery evidence.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command link "$candidate" "$unit"
            reload_fail=1
            if (recover_interrupted_legacy_unit_transaction) >"$output" 2>&1; then
                exit 1
            fi
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ -d "$transaction_dir" ] || exit 1
            reload_fail=0
            recover_interrupted_legacy_unit_transaction
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] || exit 1

            # A displaced operator unit is republished without replacement and
            # PID 1 is reloaded before recovery reports the conflict.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            printf '%s\n' operator-unit >"$displaced"
            command rm -f -- "$unit"
            : >"$calls"
            if (recover_interrupted_legacy_unit_transaction) >"$output" 2>&1; then
                exit 1
            fi
            [ "$(<"$unit")" = operator-unit ] && [ -f "$backup" ] || exit 1
            grep -Fq -- 'daemon-reload|' "$calls" || exit 1
            command rm -f -- "$unit" "$candidate" "$snapshot" "$backup" \
                "$retained" "$displaced" "$intent" "${intent}.staged" \
                "$rollback_marker" "${transaction_dir}/binary-rollback-untrusted"
            command rmdir -- "$transaction_dir"

            # Dependency failure is detected before an existing journal or live
            # unit is mutated, leaving a later supported recovery possible.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            if (mock_hardlink_result=1; \
                hardlink_utility_available() { return "$mock_hardlink_result"; }; \
                recover_interrupted_legacy_unit_transaction) >"$output" 2>&1; then
                exit 1
            fi
            [ "$unit" -ef "$candidate" ] && [ -f "$backup" ] || exit 1
            grep -Fq -- "'link' utility" "$output" || exit 1
            recover_interrupted_legacy_unit_transaction
            [ ! -e "$transaction_dir" ] && [ ! -e "$retained" ] || exit 1

            # Torn unpublished/rollback records unambiguously mean rollback but
            # must never authorize deletion of a partially recorded path.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            : >"${intent}.staged"
            recover_interrupted_legacy_unit_transaction
            [ "$(<"$installed")" = installed ] && [ ! -e "$transaction_dir" ] || exit 1

            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            printf '%s\n' "$installed" >"${intent}.staged"
            recover_interrupted_legacy_unit_transaction
            [ "$(<"$installed")" = installed ] && [ ! -e "$transaction_dir" ] || exit 1

            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            command link "$backup" "$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            printf '%s\n' "$installed" >"$rollback_marker"
            recover_interrupted_legacy_unit_transaction
            [ "$(<"$installed")" = installed ] && [ ! -e "$transaction_dir" ] || exit 1

            # A root operator may win the documented retained-backup pathname
            # race. Roll back the unit without unlinking that different inode.
            command mkdir -m 700 -- "$transaction_dir"
            printf '%s\n' candidate >"$candidate"
            command cp -p -- "$candidate" "$snapshot"
            render_legacy_unit_v0_1 "$installed" "$config" >"$backup"
            printf '%s\n' operator-retained >"$retained"
            command rm -f -- "$unit"
            command link "$candidate" "$unit"
            recover_interrupted_legacy_unit_transaction
            legacy_unit_file_matches_kind "$unit" v0.1.x \
                "$installed" "$config" || exit 1
            [ "$(<"$retained")" = operator-retained ] &&
                [ ! -e "$transaction_dir" ] || exit 1
            command rm -f -- "$retained"
        ); then
            printf 'ok   persistent legacy migration journal recovers every recorded crash boundary\n'
        else
            printf 'FAIL persistent legacy migration recovery\n'
            failures=$((failures + 1))
        fi

        command rm -f -- "$unit" "$candidate" "$snapshot" "$backup" "$retained" \
            "$displaced" "$intent" "${intent}.staged" "$rollback_marker" \
            "${transaction_dir}/binary-rollback-untrusted" "$committed" \
            "${transaction_dir}/link.probe" "$staged_binary" "$output" \
            "$installed" "$config" "$calls"
        command rmdir -- "$transaction_dir" 2>/dev/null || true
        command rmdir -- "$recovery_tmp"
    }
    _check_legacy_transaction_recovery
    unset -f _check_legacy_transaction_recovery

    _check_upgrade_reload_order() {
        local upgrade_tmp unit config source installed order got installed_contents \
              expected='reload|guard:storage|config-dir|config-file|preflight|config-sources|reload|guard:0|restart|' \
              reload_count=0 change_exec_start=0 invalid_exec_start=0 \
              config_guard_failure='' succeeded=0
        upgrade_tmp="$(mktemp -d)"
        unit="$upgrade_tmp/alighieri.service"
        config="$upgrade_tmp/alighieri.conf"
        source="$upgrade_tmp/source-alighieri"
        installed="$upgrade_tmp/installed-alighieri"
        order="$upgrade_tmp/order"
        printf '%s\n' '[Service]' >"$unit"
        printf '%s\n' 'internal: 127.0.0.1:1080' >"$config"
        printf '%s\n' source >"$source"
        printf '%s\n' installed >"$installed"
        : >"$order"

        UNIT_FILE="$unit"
        BINARY="$source"
        RESTART_ON_UPGRADE=1
        STAGED_BIN=""
        require_service_sandbox() { :; }
        require_safe_binary_directory() { :; }
        prepare_upgrade_unit_migration() {
            printf 'guard:storage|' >>"$order"
            UPGRADE_LEGACY_UNIT_KIND=""
        }
        require_effective_service_sandbox() {
            printf 'guard:%s|' "$1" >>"$order"
        }
        loaded_exec_start_payload() {
            [ "$invalid_exec_start" -eq 0 ] || return 1
            if [ "$change_exec_start" -eq 1 ] && [ "$reload_count" -ge 2 ]; then
                printf '%s' "/opt/replaced/alighieri /opt/replaced/alighieri.conf"
            else
                printf '%s' "$installed $config"
            fi
        }
        installed_binary_path() { printf '%s' "$installed"; }
        installed_config_path() { printf '%s' "$config"; }
        require_safe_service_config_directory() {
            printf 'config-dir|' >>"$order"
            [ "$config_guard_failure" != directory ] ||
                die "unsafe service config directory"
        }
        require_secure_service_config_file() {
            printf 'config-file|' >>"$order"
            [ "$config_guard_failure" != metadata ] ||
                die "unsafe service config metadata"
        }
        reject_hidden_service_path() { :; }
        resolve_source_binary() { :; }
        run_in_service_sandbox() {
            printf 'preflight|' >>"$order"
            printf '%s\n' '{"ok":true,"userlist":""}'
        }
        validate_service_config_sources() {
            printf 'config-sources|' >>"$order"
        }
        service_capability_mask() { printf '%s' 0; }
        systemctl() {
            case "${1:-}" in
                daemon-reload)
                    reload_count=$((reload_count + 1))
                    printf 'reload|' >>"$order"
                    ;;
                restart) printf 'restart|' >>"$order" ;;
            esac
        }

        if do_upgrade >/dev/null 2>&1; then succeeded=1; fi
        got="$(<"$order")"
        if [ "$succeeded" -eq 1 ] && [ "$got" = "$expected" ]; then
            printf 'ok   upgrade reloads and rechecks the namespace before preflight and restart\n'
        else
            printf 'FAIL upgrade sandbox guard order: got [%s], want [%s]\n' \
                "$got" "$expected"
            failures=$((failures + 1))
        fi

        # Both integrity guards must reject before the candidate is preflighted,
        # the installed binary is replaced, or the service is restarted.
        for config_guard_failure in directory metadata; do
            printf '%s\n' installed >"$installed"
            : >"$order"
            reload_count=0
            succeeded=0
            if (do_upgrade >/dev/null 2>&1); then succeeded=1; fi
            got="$(<"$order")"
            installed_contents="$(<"$installed")"
            if [ "$config_guard_failure" = directory ]; then
                expected='reload|guard:storage|config-dir|'
            else
                expected='reload|guard:storage|config-dir|config-file|'
            fi
            if [ "$succeeded" -eq 0 ] && [ "$got" = "$expected" ] &&
                [ "$installed_contents" = installed ]; then
                printf 'ok   upgrade refuses unsafe config %s before replacement\n' \
                    "$config_guard_failure"
            else
                printf 'FAIL upgrade config %s guard: status %s, calls [%s], binary [%s]\n' \
                    "$config_guard_failure" "$succeeded" "$got" "$installed_contents"
                failures=$((failures + 1))
            fi
        done
        config_guard_failure=''

        # If the second reload changes ExecStart, abort before replacing the
        # captured binary or restarting a command that was never preflighted.
        printf '%s\n' installed >"$installed"
        command rm -f -- "${installed}.new.$$"
        : >"$order"
        reload_count=0
        change_exec_start=1
        succeeded=0
        if (do_upgrade >/dev/null 2>&1); then succeeded=1; fi
        got="$(<"$order")"
        installed_contents="$(<"$installed")"
        expected='reload|guard:storage|config-dir|config-file|preflight|config-sources|reload|'
        if [ "$succeeded" -eq 0 ] && [ "$got" = "$expected" ] &&
            [ "$installed_contents" = "installed" ]; then
            printf 'ok   upgrade refuses an ExecStart change before binary replacement\n'
        else
            printf 'FAIL upgrade ExecStart race guard: status %s, calls [%s], binary [%s]\n' \
                "$succeeded" "$got" "$installed_contents"
            failures=$((failures + 1))
        fi

        # Expansion markers are rejected by the real D-Bus decoder because the
        # literal manager-loaded argv is not necessarily the path systemd opens
        # on restart. An unsupported payload must abort before staging/moving the
        # binary or touching the service.
        printf '%s\n' installed >"$installed"
        : >"$order"
        reload_count=0
        change_exec_start=0
        invalid_exec_start=1
        succeeded=0
        if (do_upgrade >/dev/null 2>&1); then succeeded=1; fi
        got="$(<"$order")"
        installed_contents="$(<"$installed")"
        expected='reload|'
        if [ "$succeeded" -eq 0 ] && [ "$got" = "$expected" ] &&
            [ "$installed_contents" = "installed" ]; then
            printf 'ok   upgrade refuses an expandable ExecStart before binary replacement\n'
        else
            printf 'FAIL upgrade expandable ExecStart guard: status %s, calls [%s], binary [%s]\n' \
                "$succeeded" "$got" "$installed_contents"
            failures=$((failures + 1))
        fi

        # The same final reload/ExecStart race check applies when the operator
        # deliberately leaves the current process running.
        printf '%s\n' installed >"$installed"
        command rm -f -- "${installed}.new.$$"
        : >"$order"
        reload_count=0
        invalid_exec_start=0
        change_exec_start=1
        RESTART_ON_UPGRADE=0
        succeeded=0
        if (do_upgrade >/dev/null 2>&1); then succeeded=1; fi
        got="$(<"$order")"
        installed_contents="$(<"$installed")"
        expected='reload|guard:storage|config-dir|config-file|preflight|config-sources|reload|'
        if [ "$succeeded" -eq 0 ] && [ "$got" = "$expected" ] &&
            [ "$installed_contents" = installed ]; then
            printf 'ok   --no-restart upgrade refuses an ExecStart race before replacement\n'
        else
            printf 'FAIL --no-restart ExecStart race guard: status %s, calls [%s], binary [%s]\n' \
                "$succeeded" "$got" "$installed_contents"
            failures=$((failures + 1))
        fi

        # --no-restart still replaces the on-disk binary, so reload and require
        # the manager-loaded command/capability profile to match the candidate
        # config even though the service process is deliberately left untouched.
        printf '%s\n' installed >"$installed"
        command rm -f -- "${installed}.new.$$"
        : >"$order"
        reload_count=0
        invalid_exec_start=0
        change_exec_start=0
        RESTART_ON_UPGRADE=0
        succeeded=0
        if do_upgrade >/dev/null 2>&1; then succeeded=1; fi
        got="$(<"$order")"
        installed_contents="$(<"$installed")"
        expected='reload|guard:storage|config-dir|config-file|preflight|config-sources|reload|guard:0|'
        if [ "$succeeded" -eq 1 ] && [ "$got" = "$expected" ] &&
            [ "$installed_contents" = source ]; then
            printf 'ok   --no-restart upgrade reloads and validates before replacement\n'
        else
            printf 'FAIL --no-restart capability guard: status %s, calls [%s], binary [%s]\n' \
                "$succeeded" "$got" "$installed_contents"
            failures=$((failures + 1))
        fi
        RESTART_ON_UPGRADE=1
        rm -f -- "$unit" "$config" "$source" "$installed" "$order" \
            "${installed}.new.$$"
        rmdir -- "$upgrade_tmp"
    }

    # Upgrade must not compare loaded scalar state with newer on-disk list
    # directives, and it must close the potentially long build/preflight window
    # before restart.
    _check_upgrade_reload_order

    if [ "$failures" -ne 0 ]; then
        printf '\n%d self-test(s) failed\n' "$failures" >&2
        return 1
    fi
    printf '\nall self-tests passed\n'
}

write_unit() {
    local install_bin="$1" config_file="$2" capability_mask="$3" \
          output_file="${4:-$UNIT_FILE}"
    # Grant the minimal capability to bind a privileged port only when the
    # config actually needs one; otherwise keep all capabilities dropped.
    local caps=""
    case "$capability_mask" in
        0) ;;
        1024) caps="CAP_NET_BIND_SERVICE" ;;
        *) return 1 ;;
    esac
    cat >"$output_file" <<UNIT
[Unit]
Description=Alighieri SOCKS5 proxy server
Documentation=https://github.com/wiresock/alighieri
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=/
ExecStart=$install_bin $config_file
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

# Hardening. CAP_NET_BIND_SERVICE is granted (below) only when the config needs
# a privileged port — an internal: port under 1024, or ACME, whose TLS-ALPN-01
# challenge is answered on :443; otherwise all capabilities are dropped.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=$caps
AmbientCapabilities=$caps
ReadWritePaths=$LOG_DIR
# StateDirectory keeps /var/lib/${SERVICE_NAME} writable under
# ProtectSystem=strict (created on start, owned by the service user); it holds
# the ACME certificate cache (tls.acme.cache).
StateDirectory=${SERVICE_NAME}
StateDirectoryMode=0750

[Install]
WantedBy=multi-user.target
UNIT
}

# ── Actions ───────────────────────────────────────────────────────────────────
reload_and_validate_installed_service() {
    local expected_binary="${1:-}" expected_config="${2:-}" \
          expected_capability_mask="${3:-}"
    systemctl daemon-reload ||
        die "systemd daemon-reload failed while validating the new unit; the previous unit will be restored"
    if [ -n "$expected_binary" ] &&
        ! effective_install_matches "$expected_binary" "$expected_config"; then
        die "effective systemd ExecStart command or execution flags do not match $expected_binary $expected_config; remove or update the overriding drop-in, then re-run install"
    fi
    if [ -n "$expected_binary" ]; then
        case "$expected_capability_mask" in
            0 | 1024) ;;
            *) die "internal error: expected systemd capability mask was not provided" ;;
        esac
        require_effective_service_sandbox "$expected_capability_mask"
    fi
}

activate_prevalidated_service() {
    if [ "$START_ON_INSTALL" -eq 1 ]; then
        systemctl enable "${SERVICE_NAME}.service"
        # restart, not just start, so re-running install applies an updated binary
        # or unit (start is a no-op when the service is already running).
        systemctl restart "${SERVICE_NAME}.service"
        ok "Alighieri is installed and running."
    else
        ok "Alighieri is installed but was not enabled or started (--no-start)."
    fi
}

activate_installed_service() {
    reload_and_validate_installed_service "$@"
    activate_prevalidated_service
}

print_userlist_bootstrap_guidance() {
    local effective_userlist="$1" install_bin="$2" elevation followup_install \
          quoted_install_bin quoted_userlist runtime_userlist
    [ -n "$effective_userlist" ] || return 0

    runtime_userlist="$(service_runtime_path "$effective_userlist")"
    # A normal started install already rejects a missing userlist. With
    # --no-start, show bootstrap steps only when the configured file really is
    # absent; never tell an existing authenticated deployment to recreate
    # credentials it has just validated successfully.
    if [ -e "$runtime_userlist" ] || [ -L "$runtime_userlist" ]; then
        return 0
    fi

    elevation="$(followup_elevation)"
    followup_install="$(followup_install_command)"
    printf -v quoted_install_bin '%q' "$install_bin"
    printf -v quoted_userlist '%q' "$runtime_userlist"
    cat <<DONE >&2
Create the first proxy user, then complete installation:
  ${elevation:+$elevation }$quoted_install_bin user add alice --userlist $quoted_userlist
  ${elevation:+$elevation }chown root:$SERVICE_USER -- $quoted_userlist && ${elevation:+$elevation }chmod 640 -- $quoted_userlist
  $followup_install
DONE
}

do_install() {
    require_service_sandbox
    # Rewriting the base unit cannot supersede an existing systemd ExecStart
    # drop-in. Refuse an explicit config switch before mutating the binary, and
    # verify again after daemon-reload below to close the race with new drop-ins.
    if [ "$CONFIG_EXPLICIT" -eq 1 ] && [ -f "$UNIT_FILE" ] &&
        effective_exec_start_overrides_base &&
        [ "$(installed_config_path)" != "$INSTALL_CONFIG" ]; then
        die "cannot apply --config $INSTALL_CONFIG while a systemd drop-in overrides ExecStart; remove or update the override, then re-run install"
    fi

    # Reconfiguring an existing install without an explicit --prefix (e.g. the
    # menu's "reconfigure") should reuse the prefix the unit already points at,
    # so we don't relocate the binary to the default and orphan the old one.
    if [ "$PREFIX_EXPLICIT" -eq 0 ] && [ -f "$UNIT_FILE" ]; then
        local existing_dir
        # Apply the same canonical spelling invariant as --prefix before the
        # directory is reused to render and verify a new ExecStart.
        existing_dir="$(existing_install_directory_for_binary "$(installed_binary_path)")"
        if [ "$existing_dir" != "$BIN_DIR" ]; then
            info "reusing existing install location $existing_dir (pass --prefix to override)"
            BIN_DIR="$existing_dir"
        fi
    fi

    resolve_source_binary
    ensure_user

    local install_bin
    install_bin="$(join_path_child "$BIN_DIR" "$SERVICE_NAME")"
    prepare_binary_directory "$BIN_DIR"
    # Keep the active executable untouched until every failure-prone config and
    # userlist preflight has succeeded. Staging beside the destination also
    # keeps the final move atomic and lets the EXIT trap clean up any rejection.
    STAGED_BIN="${install_bin}.new.$$"
    info "staging binary for service preflight at $STAGED_BIN"
    # The helper keeps exact-path semantics without a GNU-only option, so this
    # also works with BusyBox and refuses a pre-existing symlink or directory.
    stage_executable_copy "$BINARY" "$STAGED_BIN" ||
        die "could not stage the candidate binary at $STAGED_BIN"

    # Preserve the config path the existing unit launches with unless the
    # operator explicitly selects a replacement via install --config. This lets
    # automated workflows intentionally switch an old custom unit to a newly
    # generated canonical config without changing plain reconfigure behavior.
    local existing_cfg=""
    if [ -f "$UNIT_FILE" ]; then
        existing_cfg="$(installed_config_path)"
    fi
    local config_file
    config_file="$(select_install_config_path "$existing_cfg")"
    if [ "$CONFIG_EXPLICIT" -eq 1 ]; then
        if [ -n "$existing_cfg" ] && [ "$existing_cfg" != "$config_file" ]; then
            info "replacing the existing unit's config path $existing_cfg with explicit path $config_file"
        fi
    elif [ -n "$existing_cfg" ] && [ "$existing_cfg" != "$CONFIG_FILE" ]; then
        info "reusing the config path from the existing unit: $existing_cfg"
    fi
    local config_dir
    config_dir="$(dirname -- "$config_file")"
    # The unit's ExecStart is space-delimited and installed_config_path tokenizes
    # on spaces, so a whitespace path can't round-trip; reject it like --prefix.
    case "$config_file" in
        *[[:space:]]*)
            die "config path $config_file contains whitespace, which the space-delimited ExecStart cannot represent; use a whitespace-free path" ;;
    esac
    validate_exec_start_path "config path" "$config_file"
    reject_hidden_service_path "config path" "$config_file"

    # Create and harden the config directory only when the config lives in the
    # dedicated default dir — even under a custom filename like custom.conf, so
    # /etc/alighieri is still restored to root:alighieri 750. Never create or
    # chmod a custom, possibly shared parent dir (e.g. /etc, /opt/...).
    local manage_config_dir=0
    [ "$config_dir" = "$CONFIG_DIR" ] && manage_config_dir=1

    if [ "$manage_config_dir" -eq 1 ]; then
        # Restrict the config dir to root and the service group so other local
        # users cannot even list userlist / TLS-key names under it. install -d
        # does not re-apply mode/ownership to a pre-existing directory, so set
        # them explicitly to re-harden a reconfigure over an older, looser dir.
        [ -L "$CONFIG_DIR" ] &&
            die "config directory $CONFIG_DIR is a symlink; refusing to change its target's ownership/mode"
        install -d -m 750 -o root -g "$SERVICE_USER" -- "$CONFIG_DIR"
        chown "root:$SERVICE_USER" "$CONFIG_DIR"
        chmod 750 "$CONFIG_DIR"
    fi
    # A service config is an integrity boundary: another local user must not be
    # able to replace it after this root process validates it. Check every
    # lexical and resolved parent before inspecting or trusting the leaf.
    require_safe_service_config_directory "$config_dir"

    # Refuse a symlinked config path (-f/-e follow symlinks) and any existing
    # non-regular file. The managed path may be created below; a custom path must
    # already be a physical, pre-hardened file so a typo such as /etc/shadow is
    # never chowned/chmodded before the parser rejects it.
    [ -L "$config_file" ] &&
        die "config path $config_file is a symlink; refusing to write or change permissions through it"
    if [ -e "$config_file" ] && [ ! -f "$config_file" ]; then
        die "config path $config_file exists but is not a regular file; refusing to manage it"
    fi

    if [ "$manage_config_dir" -eq 1 ]; then
        if [ -f "$config_file" ]; then
            info "keeping existing config $config_file"
        else
            # Both source checkouts and Linux release archives carry the
            # version-matched default config. Never fetch a mutable replacement
            # while this installer is running as root.
            [ -f "${REPO_ROOT}/doc/alighieri.conf" ] ||
                die "default config ${REPO_ROOT}/doc/alighieri.conf not found; run from a checkout or Linux release archive, or create $config_file first"
            info "installing default config to $config_file"
            cp -- "${REPO_ROOT}/doc/alighieri.conf" "$config_file"
        fi
        # Files in the dedicated managed directory are installer-owned, so
        # re-apply their service-readable secret permissions on reconfigure.
        chown "root:$SERVICE_USER" "$config_file"
        chmod 640 "$config_file"
    else
        # Never mutate an arbitrary custom file before it has passed validation.
        # Requiring the final metadata up front also makes the later sandbox
        # preflight authoritative without briefly exposing a sensitive typo.
        [ -f "$config_file" ] ||
            die "the unit references $config_file, which does not exist; create it, or reinstall to reset to the default config"
    fi
    require_secure_service_config_file "$config_file"

    # Validate inside the actual service sandbox and capture the resolved facts
    # in one `--check --json`, reused below for path checks and write_unit's
    # CAP_NET_BIND_SERVICE decision. This catches config/include/TLS paths root can
    # read but the service user or the unit's path-hiding controls cannot reach.
    # A config failure must abort before rewriting/restarting the active unit; on
    # failure, re-run in text mode to surface the human-readable error first.
    local check_summary capability_mask
    if ! check_summary="$(run_in_service_sandbox \
        "$STAGED_BIN" --check --json "$config_file" 2>/dev/null)"; then
        run_in_service_sandbox "$STAGED_BIN" --check "$config_file" || true
        die "config $config_file is invalid or unreachable by $SERVICE_USER inside the hardened systemd sandbox; fix the errors above, then re-run install"
    fi
    validate_service_config_sources "$check_summary"
    validate_service_userlist "$STAGED_BIN" "$check_summary" "$START_ON_INSTALL"
    warn_acme_cache_outside_state_dir "$check_summary"
    warn_logfile_outside_log_dir "$check_summary"
    capability_mask="$(service_capability_mask "$check_summary")"

    # Log directory for optional file logging. The default config logs to
    # stdout, which systemd captures into the journal. As with the config dir,
    # enforce mode/ownership explicitly so a reconfigure re-hardens an existing
    # directory that install -d would leave untouched.
    [ -L "$LOG_DIR" ] &&
        die "log directory $LOG_DIR is a symlink; refusing to change its target's ownership/mode"
    install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_USER" -- "$LOG_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chmod 750 "$LOG_DIR"

    # Render the new base unit beside its destination, then expose it only as an
    # uncommitted transaction while systemd loads and merges surviving drop-ins.
    # The EXIT trap restores the prior unit (and reloads it) on every rejection;
    # the active binary remains untouched until ExecStart flags and the effective
    # service sandbox have both matched the generated unit.
    STAGED_UNIT="${UNIT_FILE}.new.$$"
    info "staging systemd unit validation at $STAGED_UNIT"
    write_unit "$install_bin" "$config_file" "$capability_mask" "$STAGED_UNIT" ||
        die "could not render the staged systemd unit at $STAGED_UNIT"
    chmod 644 "$STAGED_UNIT" ||
        die "could not set safe permissions on the staged systemd unit at $STAGED_UNIT"
    begin_unit_transaction
    reload_and_validate_installed_service \
        "$install_bin" "$config_file" "$capability_mask"

    info "installing validated binary to $install_bin"
    # The checked replacement refuses an unexpected directory destination
    # instead of moving the staged executable inside it under another basename.
    # Arm cleanup to distinguish a signal before the atomic rename (source still
    # present: roll back) from one after it (source gone: commit the validated
    # unit so it remains consistent with the newly installed binary).
    journal_binary_commit_intent "$STAGED_BIN" ||
        die "could not journal the pending binary install; the previous unit will be restored"
    BINARY_COMMIT_IN_PROGRESS=1
    if ! replace_file_atomically "$STAGED_BIN" "$install_bin"; then
        if [ -e "$STAGED_BIN" ] || [ -L "$STAGED_BIN" ]; then
            BINARY_COMMIT_IN_PROGRESS=0
        fi
        die "could not install the validated binary at $install_bin; the previous unit will be restored"
    fi
    commit_unit_transaction ||
        die "the binary was installed, but the unit transaction could not be finalized"
    STAGED_BIN=""
    BINARY_COMMIT_IN_PROGRESS=0

    activate_prevalidated_service
    local effective_userlist
    effective_userlist="$(printf '%s\n' "$check_summary" | json_string_field userlist)"
    cat <<DONE >&2
  Config:   $config_file   (edit, then: systemctl reload $SERVICE_NAME)
  Logs:     journalctl -u $SERVICE_NAME -f
  Status:   systemctl status $SERVICE_NAME   (or: $0 status)
  Upgrade:  $0 upgrade
  Stop:     systemctl stop $SERVICE_NAME
DONE

    # Use the parser's effective include-aware/last-wins value. Relative paths
    # are resolved exactly as the unit's WorkingDirectory=/ does, so a command
    # copied from another shell directory cannot create the wrong file.
    print_userlist_bootstrap_guidance "$effective_userlist" "$install_bin"
}

do_upgrade() {
    require_service_sandbox
    [ -f "$UNIT_FILE" ] ||
        die "Alighieri is not installed (no $UNIT_FILE); run: sudo $0 install"
    # Synchronise the manager with the backing unit/drop-ins before querying its
    # scalar and raw D-Bus namespace properties. Without this reload, an edited
    # or removed BindPaths (for example) could look different on disk while
    # restart still uses stale loaded state.
    systemctl daemon-reload
    local install_bin install_dir config_file config_dir capability_mask \
          expected_exec_start current_exec_start current_legacy_kind
    expected_exec_start="$(loaded_exec_start_payload)" ||
        die "effective systemd ExecStart is empty or unsupported; fix the unit before upgrading"
    install_bin="$(installed_binary_path)"
    install_dir="$(existing_install_directory_for_binary "$install_bin")"
    require_safe_binary_directory "$install_dir"
    config_file="$(installed_config_path)"
    config_dir="$(dirname -- "$config_file")"
    prepare_upgrade_unit_migration \
        "$install_bin" "$config_file" "$expected_exec_start"
    # Upgrade replaces an existing binary. Require a regular file at that path so
    # a malformed unit (ExecStart pointing at a directory, or under a missing
    # directory) fails clearly here instead of install/mv misbehaving — e.g. mv
    # moving the staged binary *into* a directory.
    [ -f "$install_bin" ] ||
        die "no binary to upgrade at $install_bin; (re)install with: sudo $0 install"
    # The service launches with this config; if it is missing, upgrading and
    # restarting would crash-loop. Fail loudly now instead of skipping the
    # pre-flight below.
    require_safe_service_config_directory "$config_dir"
    [ ! -L "$config_file" ] ||
        die "the service's config $config_file is a symlink; replace it with a physical, pre-hardened file before upgrading"
    [ -f "$config_file" ] ||
        die "the service's config $config_file does not exist; create it or fix the unit before upgrading"
    require_secure_service_config_file "$config_file"
    reject_hidden_service_path "config path" "$config_file"
    resolve_source_binary

    # Stage the new binary beside the destination first. install -m 755 gives it
    # the exec bit even when the --binary source is a non-executable artifact,
    # and the destination directory is on the right filesystem and known to be
    # executable (unlike a possibly noexec /tmp). Pre-flight that staged copy
    # against the live config so a config-incompatible upgrade fails loudly
    # instead of crash-looping, then move it into place atomically — which also
    # avoids ETXTBSY from rewriting the binary the running service is executing.
    STAGED_BIN="${install_bin}.new.$$"
    stage_executable_copy "$BINARY" "$STAGED_BIN" ||
        die "could not stage the candidate binary at $STAGED_BIN"
    local check_summary
    if ! check_summary="$(run_in_service_sandbox \
        "$STAGED_BIN" --check --json "$config_file" 2>/dev/null)"; then
        run_in_service_sandbox "$STAGED_BIN" --check "$config_file" || true
        die "new binary rejects $config_file or cannot read it inside the hardened service sandbox; fix the errors above before upgrading"
    fi
    validate_service_config_sources "$check_summary"
    validate_service_userlist "$STAGED_BIN" "$check_summary" 1
    capability_mask="$(service_capability_mask "$check_summary")"

    # Source builds and service-user preflights can take time. Reload and verify
    # once more immediately before replacing the binary, even with --no-restart,
    # so a drop-in changed during that window cannot evade validation and alter
    # the command or sandbox used by the next activation.
    systemctl daemon-reload
    current_exec_start="$(loaded_exec_start_payload 2>/dev/null || true)"
    if [ "$current_exec_start" != "$expected_exec_start" ]; then
        [ -n "$current_exec_start" ] || current_exec_start="<empty>"
        die "effective systemd ExecStart changed during upgrade (now $current_exec_start); no binary was replaced and the service was not restarted; review the unit/drop-ins, then retry"
    fi

    if [ -n "$UPGRADE_LEGACY_UNIT_KIND" ]; then
        # Re-recognize the exact template after the potentially long build and
        # preflight window. Then detach and validate that exact live inode before
        # publishing the staged unit with create-if-absent semantics, so a
        # concurrent customized unit is preserved rather than overwritten.
        current_legacy_kind="$(legacy_generated_unit_kind 2>/dev/null || true)"
        [ "$current_legacy_kind" = "$UPGRADE_LEGACY_UNIT_KIND" ] ||
            die "the legacy systemd unit changed during upgrade; no binary was replaced and the service was not restarted; review the unit/drop-ins, then retry"
        STAGED_UNIT="${UNIT_FILE}.new.$$"
        info "staging legacy systemd unit migration at $STAGED_UNIT"
        write_unit "$install_bin" "$config_file" "$capability_mask" "$STAGED_UNIT" ||
            die "could not render the staged systemd unit at $STAGED_UNIT"
        chmod 644 "$STAGED_UNIT" ||
            die "could not set safe permissions on the staged systemd unit at $STAGED_UNIT"
        begin_legacy_unit_transaction \
            "$UPGRADE_LEGACY_UNIT_KIND" "$install_bin" "$config_file"
        reload_and_validate_installed_service \
            "$install_bin" "$config_file" "$capability_mask"
        loaded_unit_source_is_unoverridden ||
            die "a systemd unit override appeared during migration; the previous unit will be restored"
    else
        require_effective_service_sandbox "$capability_mask"
    fi

    info "upgrading binary at $install_bin"
    journal_binary_commit_intent "$STAGED_BIN" ||
        die "could not journal the pending binary replacement; the previous unit will be restored"
    BINARY_COMMIT_IN_PROGRESS=1
    if ! replace_file_atomically "$STAGED_BIN" "$install_bin"; then
        if [ -e "$STAGED_BIN" ] || [ -L "$STAGED_BIN" ]; then
            BINARY_COMMIT_IN_PROGRESS=0
        fi
        die "could not replace the installed binary at $install_bin; the previous unit will be restored"
    fi
    commit_unit_transaction ||
        die "the binary was replaced, but the unit transaction could not be finalized"
    STAGED_BIN=""
    BINARY_COMMIT_IN_PROGRESS=0

    if [ "$RESTART_ON_UPGRADE" -eq 1 ]; then
        systemctl restart "${SERVICE_NAME}.service"
        if [ -n "$UPGRADE_LEGACY_UNIT_KIND" ]; then
            ok "Upgraded $SERVICE_NAME, migrated its legacy systemd unit, and restarted it."
        else
            ok "Upgraded and restarted $SERVICE_NAME."
        fi
    else
        if [ -n "$UPGRADE_LEGACY_UNIT_KIND" ]; then
            ok "Upgraded $SERVICE_NAME binary and migrated its legacy systemd unit."
            warn "not restarted (--no-restart); apply the new binary and unit together with: systemctl restart $SERVICE_NAME"
        else
            ok "Upgraded $SERVICE_NAME binary."
            warn "not restarted (--no-restart); apply with: systemctl restart $SERVICE_NAME"
        fi
    fi
}

do_uninstall() {
    # Only act on the service and binary when the unit is present. Without a unit
    # installed_binary_path falls back to the default location, and removing that
    # could delete an unrelated binary (e.g. from `cargo install`) we never
    # managed — so a missing unit means there is nothing of ours to remove.
    local removed=0
    if [ -f "$UNIT_FILE" ]; then
        local install_bin
        install_bin="$(installed_binary_path)"
        systemctl disable --now "${SERVICE_NAME}.service"
        rm -f -- "$UNIT_FILE"
        systemctl daemon-reload
        if [ -f "$install_bin" ]; then
            rm -f -- "$install_bin"
        fi
        removed=1
    else
        info "no systemd unit at $UNIT_FILE; service and binary already absent"
    fi

    # Refuse to remove through a symlink (we would delete an unexpected link),
    # matching the symlink guards on the install path.
    if [ "$PURGE_CONFIG" -eq 1 ]; then
        if [ -L "$CONFIG_DIR" ]; then
            warn "config directory $CONFIG_DIR is a symlink; not removing it"
        else
            warn "removing config directory $CONFIG_DIR (userlist and any TLS keys)"
            rm -rf -- "$CONFIG_DIR"
        fi
    fi
    if [ "$PURGE_LOGS" -eq 1 ]; then
        if [ -L "$LOG_DIR" ]; then
            warn "log directory $LOG_DIR is a symlink; not removing it"
        else
            info "removing log directory $LOG_DIR"
            rm -rf -- "$LOG_DIR"
        fi
    fi
    if [ "$PURGE_STATE" -eq 1 ]; then
        if [ -L "$STATE_DIR" ]; then
            warn "state directory $STATE_DIR is a symlink; not removing it"
        else
            warn "removing state directory $STATE_DIR (ACME account and certificates)"
            rm -rf -- "$STATE_DIR"
        fi
    fi
    if [ "$PURGE_USER" -eq 1 ]; then
        if id "$SERVICE_USER" >/dev/null 2>&1; then
            info "removing system user $SERVICE_USER"
            userdel "$SERVICE_USER" || warn "could not remove user $SERVICE_USER"
        fi
        if getent group "$SERVICE_USER" >/dev/null 2>&1; then
            groupdel "$SERVICE_USER" 2>/dev/null || true
        fi
    fi

    [ "$removed" -eq 1 ] && ok "Alighieri service and binary removed."
    if [ "$PURGE_CONFIG" -eq 0 ] || [ "$PURGE_LOGS" -eq 0 ] || [ "$PURGE_STATE" -eq 0 ] || [ "$PURGE_USER" -eq 0 ]; then
        info "Left in place (remove manually if you want them gone):"
        [ "$PURGE_CONFIG" -eq 1 ] || info "  Config: $CONFIG_DIR"
        [ "$PURGE_LOGS" -eq 1 ] || info "  Logs:   $LOG_DIR"
        { [ "$PURGE_STATE" -eq 1 ] || [ ! -d "$STATE_DIR" ]; } || info "  State:  $STATE_DIR"
        [ "$PURGE_USER" -eq 1 ] || info "  User:   userdel $SERVICE_USER"
    fi
}

do_status() {
    local install_bin config_file version
    install_bin="$(installed_binary_path)"
    config_file="$(installed_config_path)"

    printf 'Alighieri deployment status\n'
    if [ -x "$install_bin" ]; then
        printf '  Binary:   %s (installed)\n' "$install_bin"
        if installed_binary_is_safe_for_status "$install_bin"; then
            if version="$(query_installed_binary_version "$install_bin" 2>/dev/null)" &&
                [ -n "$version" ]; then
                printf '  Version:  %s\n' "$version"
            else
                printf '  Version:  unknown (--version failed)\n'
            fi
        else
            printf '  Version:  not queried (binary is not safely root-controlled)\n'
        fi
    else
        printf '  Binary:   %s (missing)\n' "$install_bin"
    fi

    if [ -f "$UNIT_FILE" ]; then
        printf '  Unit:     %s (present)\n' "$UNIT_FILE"
        if command -v systemctl >/dev/null 2>&1; then
            printf '  Enabled:  %s\n' "$(systemctl is-enabled "${SERVICE_NAME}.service" 2>/dev/null || echo unknown)"
            printf '  Active:   %s\n' "$(systemctl is-active "${SERVICE_NAME}.service" 2>/dev/null || echo unknown)"
        fi
    else
        printf '  Unit:     %s (absent)\n' "$UNIT_FILE"
    fi
    if [ -d "${UNIT_FILE}.migration" ] && [ ! -L "${UNIT_FILE}.migration" ]; then
        printf '  Migration: transaction active or pending recovery at %s\n' \
            "${UNIT_FILE}.migration"
    fi

    if [ -f "$config_file" ]; then
        printf '  Config:   %s (present)\n' "$config_file"
        # These reads need root (config is mode 640); degrade quietly otherwise.
        local internal userlist
        internal="$(grep -E '^[[:space:]]*internal:' "$config_file" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' || true)"
        userlist="$(grep -E '^[[:space:]]*userlist:' "$config_file" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' || true)"
        [ -n "$internal" ] && printf '  Listen:   %s\n' "$internal"
        [ -n "$userlist" ] && printf '  Userlist: %s\n' "$userlist"
    else
        printf '  Config:   %s (absent)\n' "$config_file"
    fi
    printf '  Logs:     journalctl -u %s -f\n' "$SERVICE_NAME"
}

# ── Interactive management menu (run bare on an installed system) ──────────────
uninstall_menu() {
    printf '\nUninstall options:\n'
    printf '   1) Remove service and binary (keep config, logs, user)\n'
    printf '   2) Also purge config (%s)\n' "$CONFIG_DIR"
    printf '   3) Also purge config and logs\n'
    printf '   4) Purge everything (config, logs, state, user)\n'
    printf '   5) Cancel\n'
    local opt=""
    until [[ "$opt" =~ ^[1-5]$ ]]; do
        read -rp "Select an uninstall option [1-5]: " opt || die "no input available"
    done
    case "$opt" in
        1) ;;
        2) PURGE_CONFIG=1 ;;
        3) PURGE_CONFIG=1; PURGE_LOGS=1 ;;
        4) PURGE_CONFIG=1; PURGE_LOGS=1; PURGE_STATE=1; PURGE_USER=1 ;;
        5) info "cancelled"; return ;;
    esac
    prepare_mutating_lifecycle_command
    do_uninstall
}

manage_menu() {
    printf 'Alighieri is already installed.\n\n'
    printf 'What do you want to do?\n'
    printf '   1) Show status\n'
    printf '   2) Tail logs (journalctl -f)\n'
    printf '   3) Upgrade binary\n'
    printf '   4) Reconfigure (re-run install)\n'
    printf '   5) Uninstall\n'
    printf '   6) Exit\n'
    local opt=""
    until [[ "$opt" =~ ^[1-6]$ ]]; do
        read -rp "Select an option [1-6]: " opt || die "no input available"
    done
    case "$opt" in
        1) do_status ;;
        2)
            if command -v journalctl >/dev/null 2>&1; then
                journalctl -u "$SERVICE_NAME" -f --no-pager || true
            else
                warn "journalctl is not available on this system"
            fi
            ;;
        3) prepare_mutating_lifecycle_command; do_upgrade ;;
        4) prepare_mutating_lifecycle_command; do_install ;;
        5) uninstall_menu ;;
        6) exit 0 ;;
    esac
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
# help is handled during argument parsing (exits immediately).
case "$ACTION" in
    status) do_status; exit 0 ;;
esac

# Hidden self-test hook: run the bundled normalize_path / warning checks with no
# root or systemd (used by CI). Must come before the require_* gates below.
if [ "$ACTION" = "__selftest" ]; then
    if run_selftest; then exit 0; else exit 1; fi
fi

# auto on an installed host with no TTY just prints status, which needs neither
# root nor systemctl — handle it before enforcing those requirements.
if [ "$ACTION" = "auto" ] && [ ! -t 0 ] && is_installed; then
    info "Alighieri is already installed; pass install|upgrade|uninstall|status (no terminal for the menu)."
    do_status
    exit 0
fi

require_root
require_systemd

case "$ACTION" in
    install) prepare_mutating_lifecycle_command; do_install ;;
    upgrade) prepare_mutating_lifecycle_command; do_upgrade ;;
    uninstall) prepare_mutating_lifecycle_command; do_uninstall ;;
    auto)
        if [ -e "${UNIT_FILE}.migration" ] || [ -L "${UNIT_FILE}.migration" ]; then
            prepare_mutating_lifecycle_command
            release_lifecycle_lock
        fi
        if is_installed; then
            manage_menu
        else
            prepare_mutating_lifecycle_command
            do_install
        fi
        ;;
    *) usage >&2; die "unknown action: $ACTION" ;;
esac
