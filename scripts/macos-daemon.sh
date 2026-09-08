#!/usr/bin/env bash
# Provision and install the Alighieri macOS public-TLS LaunchDaemon.
#
#   sudo ./scripts/macos-daemon.sh provision
#   sudo ./scripts/macos-daemon.sh install --binary ./alighieri --config PATH [--no-start]
#   sudo ./scripts/macos-daemon.sh start
#   ./scripts/macos-daemon.sh __selftest
#
# The daemon tree is /opt/alighieri, outside Homebrew prefixes. Constants are
# not read from the environment except ALIGHIERI_* test doubles used by
# __selftest.
set -euo pipefail

ACCOUNT="_alighieri"
DEFAULT_ROOT="/opt/alighieri"
PLIST_LABEL="com.wiresock.alighieri"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
UID_MIN=261
UID_MAX=400

DSCL_BIN="${ALIGHIERI_DSCL:-dscl}"
ID_BIN="${ALIGHIERI_ID:-id}"
INSTALL_BIN="${ALIGHIERI_INSTALL:-install}"
LAUNCHCTL_BIN="${ALIGHIERI_LAUNCHCTL:-launchctl}"
STAT_BIN="${ALIGHIERI_STAT:-stat}"

usage() {
  echo "usage: $0 provision|install|start|__selftest [--root DIR] [--binary PATH] [--config PATH] [--no-start]" >&2
  exit 2
}

fail() {
  echo "macos-daemon: $*" >&2
  exit 1
}

dscl_cmd() { "$DSCL_BIN" "$@"; }
id_cmd() { "$ID_BIN" "$@"; }

is_root() { [[ "$(id_cmd -u)" == "0" ]]; }

# Intel Homebrew's default prefix is /usr/local (often 0755, owned by the
# installing user). Apple Silicon Homebrew uses /opt/homebrew. Refuse those
# trees even when their mode bits look safe.
refuse_homebrew_root() {
  local path="$1"
  case "$path" in
    /usr/local|/usr/local/*|/opt/homebrew|/opt/homebrew/*)
      fail "refusing Homebrew-controlled daemon root: $path"
      ;;
  esac
}

refuse_symlink() {
  local path="$1"
  if [[ -L "$path" ]]; then
    fail "refusing symlink: $path"
  fi
}

validate_daemon_root() {
  local path="$1"
  [[ -n "$path" ]] || fail "daemon root is required"
  [[ "$path" == /* ]] || fail "daemon root must be an absolute path: $path"
  [[ "$path" != "/" ]] || fail "refusing filesystem root as the daemon tree"
  if [[ "$path" == *'/./'* || "$path" == */. || "$path" == *'/..'* || "$path" == */.. ]]; then
    fail "daemon root must not contain . or .. components: $path"
  fi
  if [[ "$(dirname "$path")" == "/" ]]; then
    fail "daemon root must not be a top-level directory: $path"
  fi
  refuse_homebrew_root "$path"
}

read_mode() {
  local path="$1" mode=""
  mode="$("$STAT_BIN" -f '%Lp' "$path" 2>/dev/null || true)"
  if [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  mode="$("$STAT_BIN" -c '%a' "$path" 2>/dev/null || true)"
  if [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  fail "cannot read permissions of $path"
}

read_owner() {
  local path="$1" owner=""
  owner="$("$STAT_BIN" -f '%u' "$path" 2>/dev/null || true)"
  if [[ "$owner" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$owner"
    return 0
  fi
  owner="$("$STAT_BIN" -c '%u' "$path" 2>/dev/null || true)"
  if [[ "$owner" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$owner"
    return 0
  fi
  fail "cannot read owner of $path"
}

# lstat-walk ancestors of $1. Refuse symlinks and group/other-writable
# components. When running as root, also require root ownership. Shared
# prefixes such as /opt are inspected but never taken over.
assert_safe_ancestors() {
  local path="$1"
  local current="$path"
  while [[ -n "$current" && "$current" != "/" ]]; do
    if [[ -e "$current" || -L "$current" ]]; then
      if [[ -L "$current" ]]; then
        fail "refusing symlink in daemon path ancestry: $current"
      fi
      if [[ ! -d "$current" ]]; then
        fail "refusing non-directory in daemon path ancestry: $current"
      fi
      local mode
      mode="$(read_mode "$current")"
      local other="$((8#${mode} % 8))"
      local group="$(((8#${mode} / 8) % 8))"
      if (( other & 2 )); then
        fail "refusing other-writable ancestor: $current"
      fi
      if (( group & 2 )); then
        fail "refusing group-writable ancestor: $current"
      fi
      if is_root; then
        local owner
        owner="$(read_owner "$current")"
        if [[ "$owner" != "0" ]]; then
          fail "refusing non-root-owned ancestor: $current"
        fi
      fi
    fi
    current="$(dirname "$current")"
  done
}

record_exists() {
  dscl_cmd . -read "$1" >/dev/null 2>&1
}

read_prop() {
  # dscl may print "Key: value" on one line or "Key:" then an indented value.
  dscl_cmd . -read "$1" "$2" 2>/dev/null | tr -d '\r' | awk '
    {
      if (NR == 1) {
        sub(/^[^:]+:[[:space:]]*/, "")
        if ($0 != "") { print; exit }
        next
      }
      sub(/^[[:space:]]+/, "")
      if ($0 != "") { print; exit }
    }
  '
}

ids_in_use() {
  {
    dscl_cmd . -list /Users UniqueID 2>/dev/null | awk '{print $2}'
    dscl_cmd . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}'
  } | tr -d '\r' | awk 'NF && $1 ~ /^[0-9]+$/'
}

allocate_id() {
  local used
  used="$(ids_in_use | sort -n | uniq)"
  local candidate="$UID_MIN"
  while [[ "$candidate" -le "$UID_MAX" ]]; do
    if ! printf '%s\n' "$used" | grep -Fxq "$candidate"; then
      echo "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  return 1
}

user_matches() {
  local uid="$1" gid="$2"
  [[ "$uid" == "$gid" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" UniqueID)" == "$uid" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" PrimaryGroupID)" == "$gid" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" UserShell)" == "/usr/bin/false" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" NFSHomeDirectory)" == "/var/empty" ]] || return 1
  local auth
  auth="$(read_prop "/Users/${ACCOUNT}" AuthenticationAuthority || true)"
  [[ -z "$auth" ]] || return 1
}

group_matches() {
  local gid="$1"
  [[ "$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)" == "$gid" ]] || return 1
}

provision() {
  # Run the mutating work in a subshell so the rollback EXIT trap cannot
  # replace a caller's trap (the selftest uses EXIT to remove its temp dir).
  (
    created_group=0
    created_user=0
    # Invoked by the EXIT trap; shellcheck cannot see trap dispatch.
    # shellcheck disable=SC2317
    rollback() {
      if (( created_user )); then
        if [[ -n "${id:-}" && "$(read_prop "/Users/${ACCOUNT}" UniqueID || true)" == "$id" ]]; then
          dscl_cmd . -delete "/Users/${ACCOUNT}" >/dev/null 2>&1 || true
        fi
      fi
      if (( created_group )); then
        if [[ -n "${id:-}" && "$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID || true)" == "$id" ]]; then
          dscl_cmd . -delete "/Groups/${ACCOUNT}" >/dev/null 2>&1 || true
        fi
      fi
    }
    trap rollback EXIT

    if record_exists "/Users/${ACCOUNT}" && record_exists "/Groups/${ACCOUNT}"; then
      uid="$(read_prop "/Users/${ACCOUNT}" UniqueID)"
      gid="$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)"
      user_matches "$uid" "$gid" || fail "existing ${ACCOUNT} user does not match the expected daemon identity"
      group_matches "$gid" || fail "existing ${ACCOUNT} group does not match the expected daemon identity"
      trap - EXIT
      exit 0
    fi
    if record_exists "/Users/${ACCOUNT}" || record_exists "/Groups/${ACCOUNT}"; then
      fail "partial ${ACCOUNT} identity exists; resolve it before provisioning"
    fi

    id="$(allocate_id)" || fail "no unused system UID/GID in ${UID_MIN}-${UID_MAX}"
    dscl_cmd . -create "/Groups/${ACCOUNT}"
    created_group=1
    dscl_cmd . -create "/Groups/${ACCOUNT}" PrimaryGroupID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}"
    created_user=1
    dscl_cmd . -create "/Users/${ACCOUNT}" UniqueID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}" PrimaryGroupID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}" UserShell /usr/bin/false
    dscl_cmd . -create "/Users/${ACCOUNT}" NFSHomeDirectory /var/empty
    dscl_cmd . -create "/Users/${ACCOUNT}" Password '*'
    user_matches "$id" "$id" || fail "provisioned ${ACCOUNT} user failed verification"
    group_matches "$id" || fail "provisioned ${ACCOUNT} group failed verification"
    trap - EXIT
  )
}

xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

write_plist() {
  local root="$1" plist="$2"
  local binary_xml config_xml
  binary_xml="$(xml_escape "${root}/bin/alighieri")"
  config_xml="$(xml_escape "${root}/alighieri.conf")"
  cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${PLIST_LABEL}</string>
	<key>UserName</key>
	<string>${ACCOUNT}</string>
	<key>GroupName</key>
	<string>${ACCOUNT}</string>
	<key>Umask</key>
	<integer>63</integer>
	<key>ProgramArguments</key>
	<array>
		<string>${binary_xml}</string>
		<string>${config_xml}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
EOF
}

install_tree() {
  local root="$1" binary="$2" config="$3" start="$4"
  [[ -f "$binary" ]] || fail "binary is not a file: $binary"
  [[ -f "$config" ]] || fail "config is not a file: $config"
  validate_daemon_root "$root"
  refuse_symlink "$root"
  refuse_symlink "$root/bin"
  refuse_symlink "$root/acme"
  refuse_symlink "$root/logs"
  refuse_symlink "$root/bin/alighieri"
  refuse_symlink "$root/alighieri.conf"
  assert_safe_ancestors "$root"

  "$INSTALL_BIN" -d -m 0755 "$root" "$root/bin"
  refuse_symlink "$root"
  refuse_symlink "$root/bin"
  "$INSTALL_BIN" -m 0755 "$binary" "$root/bin/alighieri"
  if command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$root/bin/alighieri" 2>/dev/null || true
    if xattr -p com.apple.quarantine "$root/bin/alighieri" >/dev/null 2>&1; then
      fail "installed binary still has com.apple.quarantine"
    fi
  fi
  "$INSTALL_BIN" -d "$root/acme" "$root/logs"
  refuse_symlink "$root/acme"
  refuse_symlink "$root/logs"
  chmod 0700 "$root/acme" "$root/logs" || fail "failed to set mode 0700 on $root/acme and $root/logs"
  if is_root; then
    chown root:wheel "$root" "$root/bin" "$root/bin/alighieri"
    chown "${ACCOUNT}:${ACCOUNT}" "$root/acme" "$root/logs"
  fi
  local staged
  staged="$(mktemp "${root}/alighieri.conf.tmp.XXXXXX")"
  if ! "$INSTALL_BIN" -m 0640 "$config" "$staged"; then
    rm -f -- "$staged"
    fail "failed to stage configuration"
  fi
  if ! "$root/bin/alighieri" --check --config "$staged"; then
    rm -f -- "$staged"
    fail "configuration check failed"
  fi
  mv -f -- "$staged" "$root/alighieri.conf"
  if is_root; then
    chown "root:${ACCOUNT}" "$root/alighieri.conf"
    chmod 0640 "$root/alighieri.conf"
  fi
  local plist_dest="$PLIST_PATH"
  if ! is_root; then
    plist_dest="$root/${PLIST_LABEL}.plist"
  fi
  local staged_plist
  staged_plist="$(mktemp "${root}/plist.XXXXXX")"
  write_plist "$root" "$staged_plist"
  mv -f -- "$staged_plist" "$plist_dest"
  if is_root; then
    chown root:wheel "$plist_dest"
    chmod 0644 "$plist_dest"
  fi
  if [[ "$start" == "1" ]]; then
    start_daemon
  fi
}

start_daemon() {
  { "$LAUNCHCTL_BIN" bootout "system/${PLIST_LABEL}" || true; }
  "$LAUNCHCTL_BIN" bootstrap system "$PLIST_PATH"
}

selftest() {
  local tmp
  # Keep the fixture tree off /tmp and /var: on Darwin those are symlinks
  # (/tmp -> /private/tmp, /var -> /private/var) and the ancestor walk
  # must still be able to prove a successful install.
  mkdir -p target
  tmp="$(mktemp -d "${PWD}/target/alighieri-macos-daemon.XXXXXX")"
  ALIGHIERI_SELFTEST_TMP="$tmp"
  trap 'rm -rf "${ALIGHIERI_SELFTEST_TMP:-}"' EXIT
  local db="$tmp/dscl"
  mkdir -p "$db/Users" "$db/Groups"

  cat >"$tmp/dscl.sh" <<'EOF'
#!/bin/sh
set -eu
db="${ALIGHIERI_DSCL_DB:?}"
op="$2"
shift 2
list_records() {
  kind="$1"; key="$2"
  [ -d "$db$kind" ] || return 0
  find "$db$kind" -mindepth 1 -maxdepth 1 -type d -print | {
    while IFS= read -r rec; do
      [ -f "$rec/$key" ] || continue
      printf '%s %s\n' "$(basename "$rec")" "$(tr -d '\r' < "$rec/$key")"
    done
    true
  }
}
case "$op" in
  -create)
    rec="$1"; shift
    mkdir -p "$db$rec"
    if [ $# -ge 2 ]; then
      printf '%s\n' "$2" >"$db$rec/$1"
    fi
    ;;
  -read)
    rec="$1"; key="${2:-}"
    [ -d "$db$rec" ] || exit 1
    if [ -n "$key" ]; then
      [ -f "$db$rec/$key" ] || exit 1
      printf '%s: %s\n' "$key" "$(tr -d '\r' < "$db$rec/$key")"
    fi
    ;;
  -list)
    list_records "$1" "$2"
    ;;
  -delete)
    rm -rf "$db$1"
    ;;
  *)
    exit 2
    ;;
esac
EOF
  chmod +x "$tmp/dscl.sh"

  cat >"$tmp/stat.sh" <<'EOF'
#!/bin/sh
set -eu
fmt=""
path=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f|-c)
      fmt="$2"
      shift 2
      ;;
    *)
      path="$1"
      shift
      ;;
  esac
done
case "$fmt" in
  %Lp|%a)
    echo 755
    ;;
  %u)
    echo 0
    ;;
  *)
    exit 2
    ;;
esac
EOF
  chmod +x "$tmp/stat.sh"

  cat >"$tmp/launchctl.sh" <<'EOF'
#!/bin/sh
set -eu
echo "$@" >> "${ALIGHIERI_LAUNCHCTL_LOG:?}"
if [ "$1" = bootout ]; then
  exit 1
fi
if [ "$1" = bootstrap ]; then
  exit 0
fi
exit 0
EOF
  chmod +x "$tmp/launchctl.sh"

  export ALIGHIERI_DSCL="$tmp/dscl.sh"
  export ALIGHIERI_DSCL_DB="$db"
  export ALIGHIERI_ID="$ID_BIN"
  export ALIGHIERI_LAUNCHCTL_LOG="$tmp/launchctl.log"
  DSCL_BIN="$tmp/dscl.sh"
  LAUNCHCTL_BIN="$tmp/launchctl.sh"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"

  # Clean provision then exact rerun.
  provision
  provision

  expect_provision_failure() {
    local msg="$1" status=0
    set +e
    ( set -euo pipefail; provision )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$msg"
  }

  # Existing-name mismatch.
  printf '%s\n' 1 >"$db/Users/_alighieri/UniqueID"
  expect_provision_failure "mismatching existing user must be rejected"
  printf '%s\n' 261 >"$db/Users/_alighieri/UniqueID"

  # Partial identity: group without user.
  rm -rf "$db/Users/_alighieri"
  expect_provision_failure "partial identity must be rejected"
  dscl_cmd . -create "/Users/_alighieri"
  dscl_cmd . -create "/Users/_alighieri" UniqueID 261
  dscl_cmd . -create "/Users/_alighieri" PrimaryGroupID 261
  dscl_cmd . -create "/Users/_alighieri" UserShell /usr/bin/false
  dscl_cmd . -create "/Users/_alighieri" NFSHomeDirectory /var/empty

  # UID collision: the only candidate in a one-id window is already taken.
  UID_MAX=261
  ACCOUNT="_other"
  expect_provision_failure "exhausted UID range must fail"
  ACCOUNT="_alighieri"
  UID_MAX=400

  # Rollback only records created by this invocation: fail after the group is
  # created and confirm a pre-existing user is left untouched.
  mkdir -p "$db/Users/_keep"
  printf '%s\n' keep >"$db/Users/_keep/UniqueID"
  ACCOUNT="_rollback"
  DSCL_BIN="$tmp/dscl-fail-user.sh"
  cat >"$tmp/dscl-fail-user.sh" <<'EOF'
#!/bin/sh
set -eu
db="${ALIGHIERI_DSCL_DB:?}"
op="$2"
shift 2
list_records() {
  kind="$1"; key="$2"
  [ -d "$db$kind" ] || return 0
  find "$db$kind" -mindepth 1 -maxdepth 1 -type d -print | {
    while IFS= read -r rec; do
      [ -f "$rec/$key" ] || continue
      printf '%s %s\n' "$(basename "$rec")" "$(tr -d '\r' < "$rec/$key")"
    done
    true
  }
}
case "$op" in
  -create)
    rec="$1"; shift
    case "$rec" in
      /Users/_rollback)
        exit 1
        ;;
    esac
    mkdir -p "$db$rec"
    if [ $# -ge 2 ]; then
      printf '%s\n' "$2" >"$db$rec/$1"
    fi
    ;;
  -read)
    rec="$1"; key="${2:-}"
    [ -d "$db$rec" ] || exit 1
    if [ -n "$key" ]; then
      [ -f "$db$rec/$key" ] || exit 1
      printf '%s: %s\n' "$key" "$(tr -d '\r' < "$db$rec/$key")"
    fi
    ;;
  -list)
    list_records "$1" "$2"
    ;;
  -delete)
    rm -rf "$db$1"
    ;;
  *)
    exit 2
    ;;
esac
EOF
  chmod +x "$tmp/dscl-fail-user.sh"
  expect_provision_failure "user-create failure must fail"
  [[ ! -d "$db/Groups/_rollback" ]] || fail "failed provision must roll back the created group"
  [[ -d "$db/Users/_keep" ]] || fail "rollback must not delete unrelated users"
  ACCOUNT="_alighieri"
  DSCL_BIN="$tmp/dscl.sh"

  # Install fail-fast: missing binary.
  local root="$tmp/opt/alighieri"
  mkdir -p "$tmp/opt"
  chmod 755 "$tmp/opt"
  if ( install_tree "$root" "$tmp/missing-bin" "$tmp/missing.conf" 1 ); then
    fail "missing binary must fail"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "missing binary must not bootstrap"
  fi

  # Homebrew-style writable ancestor must be refused.
  local brew="$tmp/usr/local"
  mkdir -p "$brew"
  printf '%s\n' '#!/bin/sh' 'exit 0' >"$tmp/dummy-bin"
  chmod +x "$tmp/dummy-bin"
  printf '%s\n' 'internal: 127.0.0.1 port = 1080' >"$tmp/dummy.conf"
  cat >"$tmp/stat-775.sh" <<'EOF'
#!/bin/sh
set -eu
fmt=""
path=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f|-c)
      fmt="$2"
      shift 2
      ;;
    *)
      path="$1"
      shift
      ;;
  esac
done
case "$fmt" in
  %Lp|%a)
    echo 775
    ;;
  %u)
    echo 0
    ;;
  *)
    exit 2
    ;;
esac
EOF
  chmod +x "$tmp/stat-775.sh"
  STAT_BIN="$tmp/stat-775.sh"
  if ( install_tree "$brew/alighieri" "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "group-writable Homebrew-style prefix must be refused"
  fi
  STAT_BIN="${ALIGHIERI_STAT:-stat}"
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "Homebrew-prefix refusal must not bootstrap"
  fi
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree /usr/local/alighieri "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "must refuse /usr/local daemon root"
  fi
  if ( install_tree /opt/homebrew/alighieri "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "must refuse /opt/homebrew daemon root"
  fi
  if ( install_tree /opt/./homebrew/alighieri "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "must refuse non-canonical Homebrew daemon root"
  fi
  if ( install_tree / "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "must refuse filesystem root"
  fi
  if ( install_tree /alighieri "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "must refuse a top-level daemon root"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "Homebrew-root refusal must not bootstrap"
  fi

  # Successful install with mocked ancestor modes; --no-start must not bootstrap.
  STAT_BIN="$tmp/stat.sh"
  printf '%s\n' '#!/bin/sh' 'exit 0' >"$tmp/fake-bin"
  chmod +x "$tmp/fake-bin"
  printf '%s\n' 'internal: 127.0.0.1 port = 1080' >"$tmp/fake.conf"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  install_tree "$root" "$tmp/fake-bin" "$tmp/fake.conf" 0
  [[ -x "$root/bin/alighieri" ]] || fail "installed binary missing"
  [[ -f "$root/alighieri.conf" ]] || fail "installed config missing"
  grep -Fq "<integer>63</integer>" "$root/${PLIST_LABEL}.plist" \
    || fail "generated plist missing Umask 63 (077 octal)"
  grep -Fq "${root}/bin/alighieri" "$root/${PLIST_LABEL}.plist" \
    || fail "generated plist missing staged binary path"
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "install --no-start must not bootstrap"
  fi

  # Config --check failure must not bootstrap even when start is requested.
  printf '%s\n' '#!/bin/sh' 'exit 1' >"$tmp/bad-bin"
  chmod +x "$tmp/bad-bin"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$root" "$tmp/bad-bin" "$tmp/fake.conf" 1 ); then
    fail "failed --check must fail the install"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed --check must not bootstrap"
  fi

  # start_daemon ignores a failed bootout and then bootstraps.
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  start_daemon
  grep -Fq "bootout system/${PLIST_LABEL}" "$ALIGHIERI_LAUNCHCTL_LOG" \
    || fail "start must attempt bootout"
  grep -Fq "bootstrap system ${PLIST_PATH}" "$ALIGHIERI_LAUNCHCTL_LOG" \
    || fail "start must bootstrap after ignored bootout"

  # AND/OR grouping: ignored xattr must not hide a later failure.
  if bash -c 'false && { true || true; } && true'; then
    fail "false && grouped-or must fail"
  fi
  bash -c 'true && { false || true; } && true'
  if bash -c 'true && false && { false || true; } && true'; then
    fail "critical failure before grouped-or must fail"
  fi

  echo "macos-daemon selftest: ok"
}

cmd="${1:-}"
[[ -n "$cmd" ]] || usage
shift || true
root="$DEFAULT_ROOT"
binary=""
config=""
start=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      root="${2:-}"
      shift 2
      ;;
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --config)
      config="${2:-}"
      shift 2
      ;;
    --no-start)
      start=0
      shift
      ;;
    *)
      usage
      ;;
  esac
done

case "$cmd" in
  provision) provision ;;
  install)
    [[ -n "$binary" && -n "$config" ]] || usage
    install_tree "$root" "$binary" "$config" "$start"
    ;;
  start) start_daemon ;;
  __selftest) selftest ;;
  *) usage ;;
esac
