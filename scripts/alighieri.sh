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
# It also runs standalone — download just this file and run it:
#
#   curl -O https://raw.githubusercontent.com/wiresock/alighieri/main/scripts/alighieri.sh
#   chmod +x alighieri.sh
#   sudo ./alighieri.sh
#
# Run from a repository checkout, or standalone: when it can't find the source
# locally it shallow-clones the repository into a temporary directory to build
# the binary and read the default config (needs git and a Rust toolchain; or
# pass --binary to install a prebuilt binary and skip the build).
#
# Configuration constants are intentionally NOT read from the environment:
# this script runs as root, and honouring env overrides would widen the
# attack surface for privilege escalation via environment injection (including
# the clone source below). Use the documented flags instead.
#
# https://github.com/wiresock/alighieri
set -euo pipefail

# Source fetched when running standalone. Hardcoded, never from the environment:
# this runs as root, so an attacker-controlled clone URL would be code execution.
readonly REPO_URL="https://github.com/wiresock/alighieri.git"
readonly REPO_REF="main"

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
RESTART_ON_UPGRADE=1
PURGE_CONFIG=0
PURGE_LOGS=0
PURGE_STATE=0
PURGE_USER=0
ACTION="auto"
COMMAND_SEEN=0
BOOTSTRAP_DIR=""
STAGED_BIN=""

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
  --no-restart       (upgrade) Replace the binary but do not restart the service.
  --purge-config     (uninstall) Also remove ${CONFIG_DIR} (userlist, TLS keys!).
  --purge-logs       (uninstall) Also remove ${LOG_DIR}.
  --purge-state      (uninstall) Also remove ${STATE_DIR} (ACME certs/account!).
  --purge-user       (uninstall) Also remove the ${SERVICE_USER} system user.
  --purge-all        (uninstall) --purge-config --purge-logs --purge-state --purge-user.
  -h, --help         Show this help.

Examples:
  sudo $0                                   # install, or manage if installed
  sudo $0 install --binary ./alighieri      # install a prebuilt binary
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
        --binary) shift; [ $# -gt 0 ] || die "--binary requires a path"; BINARY="$1" ;;
        --prefix) shift; [ $# -gt 0 ] || die "--prefix requires a path"; PREFIX="$1"; PREFIX_EXPLICIT=1 ;;
        --no-restart) RESTART_ON_UPGRADE=0 ;;
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

BIN_DIR="${PREFIX}/bin"

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

nologin_shell() {
    for candidate in /usr/sbin/nologin /sbin/nologin /bin/false; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return
        fi
    done
    printf '%s' /bin/false
}

# Effective ExecStart payload (everything after its first '=') for the service.
# Prefer the merged unit (base + drop-ins) via `systemctl cat`, so a
# `systemctl edit` override of ExecStart is honoured; fall back to the on-disk
# unit file when systemctl is unavailable or knows nothing about it. The last
# ExecStart= wins, matching systemd's override semantics. Empty when none found.
exec_start_payload() {
    local line=""
    if command -v systemctl >/dev/null 2>&1; then
        line="$(systemctl cat -- "${SERVICE_NAME}.service" 2>/dev/null |
            grep '^[[:space:]]*ExecStart=' | tail -n1 || true)"
    fi
    if [ -z "$line" ] && [ -f "$UNIT_FILE" ]; then
        line="$(grep '^[[:space:]]*ExecStart=' "$UNIT_FILE" 2>/dev/null | tail -n1 || true)"
    fi
    [ -n "$line" ] && printf '%s' "${line#*=}"
    return 0
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
    printf '%s' "${BIN_DIR}/${SERVICE_NAME}"
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

# "Installed" means this script's systemd unit is present. A bare binary at the
# default path (e.g. from `cargo install`) is not treated as an install, so the
# menu and uninstall never act on something we did not deploy.
is_installed() {
    [ -f "$UNIT_FILE" ]
}

# Remove transient artifacts on exit: any temporary clone created by
# bootstrap_repo, and any staged upgrade binary that was not moved into place.
# The installed binary and config have already been copied out by then.
cleanup() {
    # Best-effort: a failing rm must not abort the EXIT trap (under errexit) or
    # change the script's original exit status, so swallow any error.
    if [ -n "$BOOTSTRAP_DIR" ]; then rm -rf -- "$BOOTSTRAP_DIR" 2>/dev/null || true; fi
    if [ -n "$STAGED_BIN" ]; then rm -f -- "$STAGED_BIN" 2>/dev/null || true; fi
    return 0
}
trap cleanup EXIT

# True when REPO_ROOT is an Alighieri checkout we can build and configure from.
in_checkout() {
    [ -f "${REPO_ROOT}/Cargo.toml" ] && [ -f "${REPO_ROOT}/doc/alighieri.conf" ]
}

# When running standalone (the script was downloaded on its own rather than from
# a checkout), shallow-clone the repository so we have the source to build and
# the default config to install. Points REPO_ROOT at the clone; a no-op when
# already inside a checkout or after a previous clone this run.
bootstrap_repo() {
    in_checkout && return 0
    command -v git >/dev/null 2>&1 ||
        die "running standalone but git is not installed; install git and re-run, run from a checkout, or pass --binary"
    # `--` everywhere the temp-dir path is used so a TMPDIR beginning with `-`
    # (e.g. preserved via sudo -E) can't make mktemp/git/chown/cd/cp parse it as
    # an option in this root script.
    BOOTSTRAP_DIR="$(mktemp -d -- "${TMPDIR:-/tmp}/alighieri-bootstrap.XXXXXX")"
    info "fetching source: git clone --depth 1 --branch ${REPO_REF} ${REPO_URL}"
    GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "$REPO_REF" -- "$REPO_URL" "$BOOTSTRAP_DIR" >&2 ||
        die "failed to clone ${REPO_URL} (private repo or no network?); clone it manually and run from the checkout, or pass --binary"
    REPO_ROOT="$BOOTSTRAP_DIR"
    in_checkout ||
        die "cloned repository at ${REPO_ROOT} is missing Cargo.toml or doc/alighieri.conf"
}

# Locate the binary to install/upgrade from: an explicit --binary, a prebuilt
# target/release build, or a fresh cargo build from the checkout (cloning the
# source first when running standalone).
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
    bootstrap_repo
    build_from_source
    BINARY="${REPO_ROOT}/target/release/${SERVICE_NAME}"
}

# Build the release binary in REPO_ROOT. cargo runs dependency build scripts and
# proc-macros, so when invoked via sudo we build as the original unprivileged
# user (via runuser) instead of executing that third-party code as root — giving
# them ownership of a temporary clone, but never re-owning an existing checkout.
# Building as the invoking user also picks up their per-user Rust toolchain,
# which root's PATH often lacks. Otherwise build as the current user, warning
# when that user is root.
build_from_source() {
    local build_user="" invoker="${SUDO_USER:-}"
    if [ "$(id -u)" -eq 0 ] && [ -n "$invoker" ] && [ "$invoker" != "root" ] &&
        command -v runuser >/dev/null 2>&1; then
        build_user="$invoker"
    fi

    if [ -n "$build_user" ]; then
        # The build user needs to write target/; hand over a temporary clone, but
        # never change ownership of a checkout the user already has. -h re-owns
        # any symlink itself rather than dereferencing it, so a link in the clone
        # can't redirect this root chown onto a target outside the clone.
        if [ -n "$BOOTSTRAP_DIR" ] && [ "$REPO_ROOT" = "$BOOTSTRAP_DIR" ]; then
            chown -hR -- "$build_user" "$REPO_ROOT"
        fi
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

# Lexically normalise a path — collapse `.`, `..`, and redundant `/` — using only
# shell parameter expansion, with no external command. Symlinks are deliberately
# NOT resolved: the prefix checks below compare the *declared* config path against
# the unit's StateDirectory/log dir, so the lexical form is both sufficient and
# correct, and it behaves identically everywhere (including busybox, which lacks
# GNU `realpath -m`). Without this a traversal like `$STATE_DIR/../elsewhere`
# would textually match the `$STATE_DIR/*` prefix and silently suppress the
# warning. A leading `/` is preserved; the result has no trailing slash, except
# an absolute path that collapses to the root (e.g. `/`, `/a/..`, `/../`), which
# normalises to `/`.
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

# Hidden, test-only entry point: exercise normalize_path and the two hardened-path
# warnings against a fixed table of cases. Run by CI (`bash scripts/alighieri.sh
# __selftest`) and intentionally kept off the operator-facing command surface.
# Needs neither root nor systemd. Exits nonzero if any case is wrong.
run_selftest() {
    local failures=0

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

    if [ "$failures" -ne 0 ]; then
        printf '\n%d self-test(s) failed\n' "$failures" >&2
        return 1
    fi
    printf '\nall self-tests passed\n'
}

write_unit() {
    local install_bin="$1" config_file="$2" summary="$3"
    # Grant the minimal capability to bind a privileged port only when the
    # config actually needs one; otherwise keep all capabilities dropped.
    local caps=""
    if needs_net_bind_capability "$summary"; then
        caps="CAP_NET_BIND_SERVICE"
    fi
    cat >"$UNIT_FILE" <<UNIT
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

# ── Actions ───────────────────────────────────────────────────────────────────
do_install() {
    # Reconfiguring an existing install without an explicit --prefix (e.g. the
    # menu's "reconfigure") should reuse the prefix the unit already points at,
    # so we don't relocate the binary to the default and orphan the old one.
    if [ "$PREFIX_EXPLICIT" -eq 0 ] && [ -f "$UNIT_FILE" ]; then
        local existing_dir
        existing_dir="$(dirname -- "$(installed_binary_path)")"
        # Whitespace would break the space-delimited ExecStart we rewrite below,
        # like the --prefix validation; reject it rather than emit a broken unit.
        case "$existing_dir" in
            *[[:space:]]*) die "the existing unit's install directory contains whitespace ($existing_dir); pass --prefix with a whitespace-free path" ;;
        esac
        if [ "$existing_dir" != "$BIN_DIR" ]; then
            info "reusing existing install location $existing_dir (pass --prefix to override)"
            BIN_DIR="$existing_dir"
        fi
    fi

    resolve_source_binary
    ensure_user

    local install_bin="${BIN_DIR}/${SERVICE_NAME}"
    info "installing binary to $install_bin"
    install -d -m 755 -- "$BIN_DIR"
    # `--` so a --binary source (or any path) beginning with `-` is never parsed
    # as an install option in this root script.
    install -m 755 -- "$BINARY" "$install_bin"

    # Preserve the config path the existing unit launches with, so a reconfigure
    # doesn't silently switch the service to the default config. A custom path
    # (operator-set via --config or a positional arg in a hand-edited unit) is
    # kept verbatim.
    local config_file="$CONFIG_FILE"
    if [ -f "$UNIT_FILE" ]; then
        local existing_cfg
        existing_cfg="$(installed_config_path)"
        if [ "$existing_cfg" != "$CONFIG_FILE" ]; then
            info "reusing the config path from the existing unit: $existing_cfg"
            config_file="$existing_cfg"
        fi
    fi
    local config_dir
    config_dir="$(dirname -- "$config_file")"
    # Refuse a symlinked config path (-f/-e follow symlinks, so cp/chown/chmod
    # below would act on the link target) and any existing non-regular file (e.g.
    # a directory, where cp would copy *into* it and chmod would change the dir),
    # so these root operations only ever target a real file.
    [ -L "$config_file" ] &&
        die "config path $config_file is a symlink; refusing to write or change permissions through it"
    if [ -e "$config_file" ] && [ ! -f "$config_file" ]; then
        die "config path $config_file exists but is not a regular file; refusing to manage it"
    fi
    # The unit's ExecStart is space-delimited and installed_config_path tokenizes
    # on spaces, so a whitespace path can't round-trip; reject it like --prefix.
    case "$config_file" in
        *[[:space:]]*)
            die "config path $config_file contains whitespace, which the space-delimited ExecStart cannot represent; use a whitespace-free path" ;;
    esac

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
        if [ -f "$config_file" ]; then
            info "keeping existing config $config_file"
        else
            # A prebuilt --binary install skips the build, so the source (and its
            # default config) may not be present yet; fetch it when standalone.
            bootstrap_repo
            [ -f "${REPO_ROOT}/doc/alighieri.conf" ] ||
                die "default config ${REPO_ROOT}/doc/alighieri.conf not found; run from a checkout or create $config_file first"
            info "installing default config to $config_file"
            cp -- "${REPO_ROOT}/doc/alighieri.conf" "$config_file"
        fi
    else
        # Custom config location from the unit: require it to exist; we manage
        # only the file's permissions below, never its (possibly shared) dir.
        [ -f "$config_file" ] ||
            die "the unit references $config_file, which does not exist; create it, or reinstall to reset to the default config"
    fi
    # Enforce the config file's ownership and mode so the service user can read
    # it and no one else can — whether default or a preserved custom path.
    # Symlinks (and directories) were rejected above, so this only ever touches a
    # real file, never a link target.
    chown "root:$SERVICE_USER" "$config_file"
    chmod 640 "$config_file"

    # Validate the config and capture the resolved facts in one `--check --json`,
    # reused below for the warnings and write_unit's CAP_NET_BIND_SERVICE decision
    # rather than each re-running the binary (`--check` only parses; it does no
    # DNS). A config that fails to parse must abort the install — otherwise
    # write_unit, deriving the capability from a failed check, would emit a unit
    # that may lack the capability the config needs once fixed. On failure, re-run
    # in text mode to surface the human-readable error before aborting.
    local check_summary
    if ! check_summary="$("$install_bin" --check --json "$config_file" 2>/dev/null)"; then
        "$install_bin" --check "$config_file" || true
        die "config $config_file failed validation; fix the errors above, then re-run install"
    fi
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

    info "writing systemd unit $UNIT_FILE"
    write_unit "$install_bin" "$config_file" "$check_summary"

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    # restart, not just start, so re-running install applies an updated binary
    # or unit (start is a no-op when the service is already running).
    systemctl restart "${SERVICE_NAME}.service"

    ok "Alighieri is installed and running."
    cat <<DONE >&2
  Config:   $config_file   (edit, then: systemctl reload $SERVICE_NAME)
  Logs:     journalctl -u $SERVICE_NAME -f
  Status:   systemctl status $SERVICE_NAME   (or: $0 status)
  Upgrade:  $0 upgrade
  Stop:     systemctl stop $SERVICE_NAME

If the config uses username authentication, create the userlist now, e.g.:
  $install_bin user add alice --userlist $config_dir/users
  chown root:$SERVICE_USER $config_dir/users && chmod 640 $config_dir/users
  systemctl restart $SERVICE_NAME
DONE
}

do_upgrade() {
    [ -f "$UNIT_FILE" ] ||
        die "Alighieri is not installed (no $UNIT_FILE); run: sudo $0 install"
    local install_bin config_file
    install_bin="$(installed_binary_path)"
    config_file="$(installed_config_path)"
    # Upgrade replaces an existing binary. Require a regular file at that path so
    # a malformed unit (ExecStart pointing at a directory, or under a missing
    # directory) fails clearly here instead of install/mv misbehaving — e.g. mv
    # moving the staged binary *into* a directory.
    [ -f "$install_bin" ] ||
        die "no binary to upgrade at $install_bin; (re)install with: sudo $0 install"
    # The service launches with this config; if it is missing, upgrading and
    # restarting would crash-loop. Fail loudly now instead of skipping the
    # pre-flight below.
    [ -f "$config_file" ] ||
        die "the service's config $config_file does not exist; create it or fix the unit before upgrading"
    resolve_source_binary

    # Stage the new binary beside the destination first. install -m 755 gives it
    # the exec bit even when the --binary source is a non-executable artifact,
    # and the destination directory is on the right filesystem and known to be
    # executable (unlike a possibly noexec /tmp). Pre-flight that staged copy
    # against the live config so a config-incompatible upgrade fails loudly
    # instead of crash-looping, then move it into place atomically — which also
    # avoids ETXTBSY from rewriting the binary the running service is executing.
    STAGED_BIN="${install_bin}.new.$$"
    install -m 755 -- "$BINARY" "$STAGED_BIN"
    if ! "$STAGED_BIN" --check "$config_file" >/dev/null 2>&1; then
        rm -f -- "$STAGED_BIN"
        STAGED_BIN=""
        die "new binary rejects $config_file; validate the config against the new release and fix it before upgrading"
    fi

    info "upgrading binary at $install_bin"
    mv -f "$STAGED_BIN" "$install_bin"
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
        3) do_upgrade ;;
        4) do_install ;;
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
