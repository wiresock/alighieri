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
# Release installs should pass --binary ./alighieri; that path uses only the
# extracted release payload. A checkout without a prebuilt binary builds with
# Cargo and may fetch its locked dependencies, but the helper never clones a
# mutable repository branch or downloads a replacement lifecycle script.
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
UNIT_BACKUP=""
UNIT_TRANSACTION_ACTIVE=0
UNIT_HAD_ORIGINAL=0
BINARY_COMMIT_IN_PROGRESS=0

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
                     the service. Leaves the unit and config untouched.
  uninstall          Stop and disable the service and remove the unit and binary.
  status             Show the binary, service, and config state.
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
  sudo $0 install --binary ./alighieri      # install a prebuilt binary
  sudo $0 install --config /etc/alighieri/alighieri.conf
                                             # explicitly select the unit config
  sudo $0 upgrade                            # rebuild from source and restart
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
    local -a properties=(InaccessiblePaths BindPaths BindReadOnlyPaths)

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
}

require_effective_service_sandbox() {
    effective_service_sandbox_matches ||
        die "effective systemd service identity, WorkingDirectory, or filesystem namespace differs from the managed unit; remove or update the overriding drop-in, then retry"
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

require_safe_service_config_directory() {
    local directory="$1" physical \
          remediation="fix its ownership/mode or choose a config under $CONFIG_DIR"
    case "$directory" in
        /*) ;;
        *) die "service config directory is not absolute: $directory" ;;
    esac
    [ "$(normalize_path "$directory")" = "$directory" ] ||
        die "service config directory is not canonical: $directory"
    binary_directory_exists "$directory" ||
        die "service config directory $directory is missing or is not a directory"

    physical="$(physical_directory_path "$directory")" ||
        die "could not resolve service config directory $directory"
    require_safe_directory_chain "$directory" "service config path" "$remediation"
    if [ "$physical" != "$directory" ]; then
        require_safe_directory_chain "$physical" \
            "resolved service config path for $directory" "$remediation"
    fi
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

# Restore the previous base unit while an install validation transaction is
# active. This is intentionally best-effort and safe under the EXIT trap: leave
# the backup in place if restoration itself fails so an operator can recover it.
rollback_unit_transaction() {
    [ "$UNIT_TRANSACTION_ACTIVE" -eq 1 ] || return 0

    local restored=0
    if [ "$UNIT_HAD_ORIGINAL" -eq 1 ]; then
        if [ -n "$UNIT_BACKUP" ] && [ -f "$UNIT_BACKUP" ] &&
            replace_file_atomically "$UNIT_BACKUP" "$UNIT_FILE" 2>/dev/null; then
            restored=1
        fi
    elif command rm -f -- "$UNIT_FILE" 2>/dev/null; then
        restored=1
    fi

    if [ "$restored" -eq 1 ]; then
        UNIT_TRANSACTION_ACTIVE=0
        UNIT_HAD_ORIGINAL=0
        UNIT_BACKUP=""
        # Synchronise the manager with the restored/removed unit. A failure here
        # must not hide the original install error or make the EXIT trap recurse,
        # but it is safety-relevant because PID 1 may retain the rejected unit.
        if ! systemctl daemon-reload >/dev/null 2>&1; then
            warn "the previous systemd unit was restored on disk, but daemon-reload failed; PID 1 may still retain the rejected candidate (run: systemctl daemon-reload)"
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

commit_unit_transaction() {
    UNIT_TRANSACTION_ACTIVE=0
    UNIT_HAD_ORIGINAL=0
    if [ -n "$UNIT_BACKUP" ]; then
        command rm -f -- "$UNIT_BACKUP" 2>/dev/null ||
            warn "could not remove obsolete unit backup $UNIT_BACKUP"
    fi
    UNIT_BACKUP=""
}

# Remove any staged install/upgrade artifacts and roll back an uncommitted unit.
cleanup() {
    # Best-effort: a failing rm must not abort the EXIT trap (under errexit) or
    # change the script's original exit status, so swallow any error.
    # The staged binary lives beside its destination, so mv uses one atomic
    # rename. If a signal lands after that rename but before the following shell
    # instruction, its source is gone: retain the already-validated unit rather
    # than rolling it back around the newly installed binary.
    if [ "$UNIT_TRANSACTION_ACTIVE" -eq 1 ] &&
        [ "$BINARY_COMMIT_IN_PROGRESS" -eq 1 ] && [ -n "$STAGED_BIN" ] &&
        [ ! -e "$STAGED_BIN" ] && [ ! -L "$STAGED_BIN" ]; then
        commit_unit_transaction
    else
        rollback_unit_transaction
    fi
    if [ -n "$STAGED_BIN" ]; then rm -f -- "$STAGED_BIN" 2>/dev/null || true; fi
    if [ -n "$STAGED_UNIT" ]; then rm -f -- "$STAGED_UNIT" 2>/dev/null || true; fi
    return 0
}
trap cleanup EXIT

# True when REPO_ROOT is an Alighieri checkout we can build and configure from.
in_checkout() {
    [ -f "${REPO_ROOT}/Cargo.toml" ] && [ -f "${REPO_ROOT}/doc/alighieri.conf" ]
}

# Refuse to obtain executable source dynamically in a root process. Source
# builds must come from the checkout containing this script; Linux release
# archives instead carry a matching binary and default config.
require_checkout() {
    in_checkout ||
        die "source checkout not found; run this helper from an Alighieri checkout, or use a Linux release archive and pass --binary ./alighieri"
}

# Locate the binary to install/upgrade from: an explicit --binary, a prebuilt
# target/release build, or a fresh cargo build from the checkout.
resolve_source_binary() {
    if [ -n "$BINARY" ]; then
        # A regular file is enough; install sets mode 755 on the destination, so
        # the source need not already carry the exec bit (e.g. unzipped artifact).
        [ -f "$BINARY" ] || die "binary not found: $BINARY"
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
    local arg
    local -a escaped_args=()
    # systemd-run expands $VAR and ${VAR} in command arguments by default.
    # Doubling every dollar is the portable escape (including on releases
    # older than --expand-environment=no) and makes the transient process see
    # the exact parser-reported path that the long-running service will use.
    for arg in "$@"; do
        escaped_args+=("${arg//\$/\$\$}")
    done
    systemd-run --quiet --wait --pipe --collect \
        --property="User=$SERVICE_USER" \
        --property="Group=$SERVICE_USER" \
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

# Load the parser-selected userlist as the service account when this install will
# start the service. Merely testing `-r` would miss malformed credential data;
# `user list` uses the same UserDb loader as startup. `--no-start` intentionally
# permits a missing file for first-user bootstrap, but validates one that already
# exists. An absent JSON field means an older binary cannot safely report an
# include-aware/last-wins path, so fail closed rather than silently skip it.
validate_service_userlist() {
    local install_bin="$1" summary="$2" will_start="${3:-1}" userlist runtime_path
    if ! printf '%s\n' "$summary" | json_has_field userlist; then
        die "installed alighieri does not report the effective userlist in --check --json; use the helper with its matching current binary before installing the hardened service"
    fi
    userlist="$(printf '%s\n' "$summary" | json_string_field userlist)"
    [ -n "$userlist" ] || return 0
    reject_hidden_service_path "configured userlist path" "$userlist"

    runtime_path="$(service_runtime_path "$userlist")"
    if [ "$will_start" -eq 0 ] && [ ! -e "$runtime_path" ]; then
        warn "configured userlist $userlist does not exist yet; --no-start leaves the service stopped so credentials can be created before the final install"
        return 0
    fi
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
        local helper_tmp source staged installed backup blocked destination_dir \
              symlink_path mode_probe symlink_suffix='' symlink_checked=0 \
              mode_checked=0 result=0
        helper_tmp="$(mktemp -d)"
        source="$helper_tmp/source"
        staged="$helper_tmp/staged"
        installed="$helper_tmp/installed"
        backup="$helper_tmp/backup"
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
        replace_file_atomically "$staged" "$installed" || result=1
        [ "$(<"$installed")" = candidate ] &&
            [ "$(<"$backup")" = candidate ] && [ ! -e "$staged" ] || result=1

        # None of the helpers may reinterpret a directory as a destination
        # container, and a rejected atomic replacement must retain its source.
        if stage_executable_copy "$source" "$destination_dir" ||
            copy_regular_file_to_absent_path "$source" "$destination_dir" ||
            replace_file_atomically "$blocked" "$destination_dir"; then
            result=1
        fi
        [ -f "$blocked" ] &&
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
        command rm -f -- "$source" "$staged" "$installed" "$backup" "$blocked" "$mode_probe" \
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
    systemd-run() { printf '%s' "$*"; }
    sandbox_call="$(run_in_service_sandbox \
        /usr/local/bin/alighieri --check --json /etc/alighieri/alighieri.conf)"
    unset -f systemd-run
    for expected_arg in \
        '--property=User=alighieri' '--property=Group=alighieri' \
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

    # systemd-run performs environment expansion in its ExecStart argv even
    # without invoking a shell. The helper must escape every literal dollar so
    # a config value such as `${SUDO_USER}/users-$$` is checked verbatim rather
    # than against the transient service manager's environment/PID spelling.
    systemd-run() { printf '%s' "$*"; }
    sandbox_call="$(run_in_service_sandbox \
        /usr/local/bin/alighieri user list --userlist \
        "\${SUDO_USER}/users-\$\$")"
    unset -f systemd-run
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

    _check_userlist_preflight() { # description summary will-start mock-status want expected [command]
        local desc="$1" summary="$2" will_start="$3" mock_status="$4" \
              want="$5" expected="$6" expected_command="${7:-}" out got
        systemd-run() {
            if [ -n "$expected_command" ] && [[ "$*" != *"$expected_command"* ]]; then
                return 99
            fi
            return "$mock_status"
        }
        if out="$(validate_service_userlist \
            /usr/local/bin/alighieri "$summary" "$will_start" 2>&1)"; then
            got=ok
        else
            got=fail
        fi
        unset -f systemd-run
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
        '{"ok":true,"userlist":"/etc/alighieri/users"}' 1 0 ok "" \
        '/usr/local/bin/alighieri user list --userlist /etc/alighieri/users'
    _check_userlist_preflight "rejects a sandbox-hidden userlist" \
        '{"ok":true,"userlist":"/home/alice/users"}' 0 0 fail "hidden by the service"
    _check_userlist_preflight "rejects a service load failure" \
        '{"ok":true,"userlist":"/opt/private/users"}' 1 1 fail "cannot be loaded"
    _check_userlist_preflight "allows a missing bootstrap userlist while stopped" \
        "{\"ok\":true,\"userlist\":\"/opt/alighieri-selftest-missing-$$\"}" \
        0 1 ok "does not exist yet"

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
              mock_exec_start_flags=0 mock_source_exec_prefix=""
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
                        "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 2>&1
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
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 2>&1
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
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 2>&1
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
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 2>&1
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
                "/usr/local/bin/alighieri" "/etc/alighieri/alighieri.conf" 2>&1
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
                userlist)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|sandbox:$expected_staged user list --userlist $userlist|"
                    expected_error="cannot be loaded"
                    ;;
                reload)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|systemctl:daemon-reload|"
                    expected_error="daemon-reload failed"
                    ;;
                exec)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|effective:$installed $config|systemctl:daemon-reload|"
                    expected_error="overriding drop-in"
                    ;;
                sandbox)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|effective:$installed $config|sandbox-guard|systemctl:daemon-reload|"
                    expected_error="filesystem namespace"
                    ;;
                binary-move)
                    expected_calls="${guard_prefix}sandbox:$expected_staged --check --json $config|sandbox:$expected_staged user list --userlist $userlist|write|systemctl:daemon-reload|effective:$installed $config|sandbox-guard|binary-move|systemctl:daemon-reload|"
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

    _check_upgrade_reload_order() {
        local upgrade_tmp unit config source installed order got installed_contents \
              expected='reload|guard|config-dir|config-file|preflight|reload|guard|restart|' \
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
        require_effective_service_sandbox() { printf 'guard|' >>"$order"; }
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
                expected='reload|guard|config-dir|'
            else
                expected='reload|guard|config-dir|config-file|'
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
        : >"$order"
        reload_count=0
        change_exec_start=1
        succeeded=0
        if (do_upgrade >/dev/null 2>&1); then succeeded=1; fi
        got="$(<"$order")"
        installed_contents="$(<"$installed")"
        expected='reload|guard|config-dir|config-file|preflight|reload|guard|'
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
        expected='reload|guard|'
        if [ "$succeeded" -eq 0 ] && [ "$got" = "$expected" ] &&
            [ "$installed_contents" = "installed" ]; then
            printf 'ok   upgrade refuses an expandable ExecStart before binary replacement\n'
        else
            printf 'FAIL upgrade expandable ExecStart guard: status %s, calls [%s], binary [%s]\n' \
                "$succeeded" "$got" "$installed_contents"
            failures=$((failures + 1))
        fi
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
    local install_bin="$1" config_file="$2" summary="$3" \
          output_file="${4:-$UNIT_FILE}"
    # Grant the minimal capability to bind a privileged port only when the
    # config actually needs one; otherwise keep all capabilities dropped.
    local caps=""
    if needs_net_bind_capability "$summary"; then
        caps="CAP_NET_BIND_SERVICE"
    fi
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
    local expected_binary="${1:-}" expected_config="${2:-}"
    systemctl daemon-reload ||
        die "systemd daemon-reload failed while validating the new unit; the previous unit will be restored"
    if [ -n "$expected_binary" ] &&
        ! effective_install_matches "$expected_binary" "$expected_config"; then
        die "effective systemd ExecStart command or execution flags do not match $expected_binary $expected_config; remove or update the overriding drop-in, then re-run install"
    fi
    if [ -n "$expected_binary" ]; then
        require_effective_service_sandbox
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
    local expected_binary="${1:-}" expected_config="${2:-}"
    reload_and_validate_installed_service "$expected_binary" "$expected_config"
    activate_prevalidated_service
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
    local check_summary
    if ! check_summary="$(run_in_service_sandbox \
        "$STAGED_BIN" --check --json "$config_file" 2>/dev/null)"; then
        run_in_service_sandbox "$STAGED_BIN" --check "$config_file" || true
        die "config $config_file is invalid or unreachable by $SERVICE_USER inside the hardened systemd sandbox; fix the errors above, then re-run install"
    fi
    validate_service_userlist "$STAGED_BIN" "$check_summary" "$START_ON_INSTALL"
    warn_acme_cache_outside_state_dir "$check_summary"
    warn_logfile_outside_log_dir "$check_summary"

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
    write_unit "$install_bin" "$config_file" "$check_summary" "$STAGED_UNIT" ||
        die "could not render the staged systemd unit at $STAGED_UNIT"
    chmod 644 "$STAGED_UNIT" ||
        die "could not set safe permissions on the staged systemd unit at $STAGED_UNIT"
    begin_unit_transaction
    reload_and_validate_installed_service "$install_bin" "$config_file"

    info "installing validated binary to $install_bin"
    # The checked replacement refuses an unexpected directory destination
    # instead of moving the staged executable inside it under another basename.
    # Arm cleanup to distinguish a signal before the atomic rename (source still
    # present: roll back) from one after it (source gone: commit the validated
    # unit so it remains consistent with the newly installed binary).
    BINARY_COMMIT_IN_PROGRESS=1
    if ! replace_file_atomically "$STAGED_BIN" "$install_bin"; then
        BINARY_COMMIT_IN_PROGRESS=0
        die "could not install the validated binary at $install_bin; the previous unit will be restored"
    fi
    commit_unit_transaction
    STAGED_BIN=""
    BINARY_COMMIT_IN_PROGRESS=0

    activate_prevalidated_service
    local elevation followup_install quoted_install_bin quoted_userlist \
          effective_userlist runtime_userlist
    elevation="$(followup_elevation)"
    followup_install="$(followup_install_command)"
    printf -v quoted_install_bin '%q' "$install_bin"
    effective_userlist="$(printf '%s\n' "$check_summary" | json_string_field userlist)"
    cat <<DONE >&2
  Config:   $config_file   (edit, then: systemctl reload $SERVICE_NAME)
  Logs:     journalctl -u $SERVICE_NAME -f
  Status:   systemctl status $SERVICE_NAME   (or: $0 status)
  Upgrade:  $0 upgrade
  Stop:     systemctl stop $SERVICE_NAME
DONE

    # Only print credential bootstrap guidance when the parsed config actually
    # has a userlist. Use its effective include-aware/last-wins value, and make a
    # relative setting absolute exactly as the unit's WorkingDirectory=/ does,
    # so a command copied from another shell directory cannot create the wrong
    # file.
    if [ -n "$effective_userlist" ]; then
        runtime_userlist="$(service_runtime_path "$effective_userlist")"
        printf -v quoted_userlist '%q' "$runtime_userlist"
        cat <<DONE >&2
If the config uses username authentication, create the userlist now, e.g.:
  ${elevation:+$elevation }$quoted_install_bin user add alice --userlist $quoted_userlist
  ${elevation:+$elevation }chown root:$SERVICE_USER $quoted_userlist && ${elevation:+$elevation }chmod 640 $quoted_userlist
  $followup_install
DONE
    fi
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
    require_effective_service_sandbox
    local install_bin install_dir config_file config_dir \
          expected_exec_start current_exec_start
    expected_exec_start="$(loaded_exec_start_payload)" ||
        die "effective systemd ExecStart is empty or unsupported; fix the unit before upgrading"
    install_bin="$(installed_binary_path)"
    install_dir="$(existing_install_directory_for_binary "$install_bin")"
    require_safe_binary_directory "$install_dir"
    config_file="$(installed_config_path)"
    config_dir="$(dirname -- "$config_file")"
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
    validate_service_userlist "$STAGED_BIN" "$check_summary" 1

    # Source builds and service-user preflights can take time. Reload and verify
    # once more immediately before replacing/restarting so a drop-in changed
    # during that window cannot silently invalidate the sandbox comparison.
    if [ "$RESTART_ON_UPGRADE" -eq 1 ]; then
        systemctl daemon-reload
        require_effective_service_sandbox
        current_exec_start="$(loaded_exec_start_payload 2>/dev/null || true)"
        if [ "$current_exec_start" != "$expected_exec_start" ]; then
            [ -n "$current_exec_start" ] || current_exec_start="<empty>"
            die "effective systemd ExecStart changed during upgrade (now $current_exec_start); no binary was replaced and the service was not restarted; review the unit/drop-ins, then retry"
        fi
    fi

    info "upgrading binary at $install_bin"
    replace_file_atomically "$STAGED_BIN" "$install_bin" ||
        die "could not replace the installed binary at $install_bin"
    STAGED_BIN=""

    if [ "$RESTART_ON_UPGRADE" -eq 1 ]; then
        systemctl restart "${SERVICE_NAME}.service"
        ok "Upgraded and restarted $SERVICE_NAME."
    else
        ok "Upgraded $SERVICE_NAME binary."
        warn "not restarted (--no-restart); apply with: systemctl restart $SERVICE_NAME"
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
    local install_bin config_file
    install_bin="$(installed_binary_path)"
    config_file="$(installed_config_path)"

    printf 'Alighieri deployment status\n'
    if [ -x "$install_bin" ]; then
        printf '  Binary:   %s (installed)\n' "$install_bin"
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
        3)
            in_checkout ||
                die "upgrade from a release layout requires an explicit artifact; re-run: sudo $0 upgrade --binary /path/to/alighieri"
            do_upgrade
            ;;
        4)
            in_checkout ||
                die "reconfigure from a release layout requires an explicit artifact; re-run: sudo $0 install --binary /path/to/alighieri"
            do_install
            ;;
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
    install) do_install ;;
    upgrade) do_upgrade ;;
    uninstall) do_uninstall ;;
    auto)
        if is_installed; then
            manage_menu
        else
            do_install
        fi
        ;;
    *) usage >&2; die "unknown action: $ACTION" ;;
esac
