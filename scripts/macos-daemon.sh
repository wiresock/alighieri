#!/usr/bin/env bash
# Provision and install the Alighieri macOS public-TLS LaunchDaemon.
#
#   sudo ./scripts/macos-daemon.sh provision
#   sudo ./scripts/macos-daemon.sh install --binary ./alighieri --config PATH [--no-start]
#   sudo ./scripts/macos-daemon.sh start
#   ./scripts/macos-daemon.sh __selftest
#
# The daemon tree is /opt/alighieri, outside Homebrew prefixes. Tool paths are
# the system binaries under /usr/bin. ALIGHIERI_* names are not read from the
# environment; __selftest assigns in-process doubles directly.
set -euo pipefail

ACCOUNT="_alighieri"
DEFAULT_ROOT="/opt/alighieri"
PLIST_LABEL="com.wiresock.alighieri"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
UID_MIN=261
UID_MAX=400
SCRIPT_PATH="${BASH_SOURCE[0]}"

# Privileged verbs always start from these paths. __selftest may reassign the
# variables in-process; production commands call use_system_tools first.
use_system_tools() {
  DSCL_BIN=/usr/bin/dscl
  ID_BIN=/usr/bin/id
  INSTALL_BIN=/usr/bin/install
  LAUNCHCTL_BIN=/usr/bin/launchctl
  STAT_BIN=/usr/bin/stat
  XATTR_BIN=/usr/bin/xattr
  MV_BIN=/bin/mv
}

use_system_tools

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
mv_cmd() { "$MV_BIN" "$@"; }

is_root() { [[ "$(id_cmd -u)" == "0" ]]; }

on_darwin() { [[ "$(uname -s)" == "Darwin" ]]; }

# Ownership mutations that require Directory Service names (wheel, _alighieri)
# only run on a real macOS root install. Identity *policy* still uses is_root
# so leftover-tree checks work under the selftest's fake uid 0.
apply_install_ownership() {
  is_root || return 0
  on_darwin || return 0
  chown_nofollow "$@"
}

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

assert_not_group_or_other_writable() {
  local path="$1"
  local mode other group
  mode="$(read_mode "$path")"
  other="$((8#${mode} % 8))"
  group="$(((8#${mode} / 8) % 8))"
  if (( other & 2 )); then
    fail "refusing other-writable path: $path"
  fi
  if (( group & 2 )); then
    fail "refusing group-writable path: $path"
  fi
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
      assert_not_group_or_other_writable "$current"
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

# Existing executable-tree directory ($root or $root/bin): directory, not a
# symlink, not group/other-writable, root-owned when running as root. Missing
# paths are created later.
assert_existing_exec_dir() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return 0
  fi
  refuse_symlink "$path"
  if [[ ! -d "$path" ]]; then
    fail "refusing non-directory: $path"
  fi
  assert_not_group_or_other_writable "$path"
  if is_root; then
    local owner
    owner="$(read_owner "$path")"
    if [[ "$owner" != "0" ]]; then
      fail "refusing non-root-owned directory: $path"
    fi
  fi
}

# Existing ACME/log state directory: directory, not a symlink, not
# group/other-writable. When running as root, owner must be root or _alighieri
# (the installer then normalizes to _alighieri:_alighieri 0700).
assert_existing_state_dir() {
  local path="$1"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return 0
  fi
  refuse_symlink "$path"
  if [[ ! -d "$path" ]]; then
    fail "refusing non-directory: $path"
  fi
  assert_not_group_or_other_writable "$path"
  if is_root; then
    local owner expected
    owner="$(read_owner "$path")"
    expected="$(read_prop "/Users/${ACCOUNT}" UniqueID)"
    if [[ "$owner" != "0" && "$owner" != "$expected" ]]; then
      fail "refusing unexpected owner ${owner} on state directory: $path"
    fi
  fi
}

chown_nofollow() {
  local spec="$1"
  shift
  local path
  for path in "$@"; do
    refuse_symlink "$path"
  done
  if [[ "$(uname -s)" == "Darwin" ]]; then
    chown -h "$spec" "$@" || fail "failed to chown $spec $*"
  else
    chown "$spec" "$@" || fail "failed to chown $spec $*"
  fi
}

chmod_nofollow() {
  local mode="$1"
  shift
  local path
  for path in "$@"; do
    refuse_symlink "$path"
  done
  if [[ "$(uname -s)" == "Darwin" ]]; then
    chmod -h "$mode" "$@" || fail "failed to chmod $mode $*"
  else
    chmod "$mode" "$@" || fail "failed to chmod $mode $*"
  fi
}

strip_quarantine() {
  local path="$1"
  local xattr_cmd="${XATTR_BIN:-/usr/bin/xattr}"
  if [[ "$xattr_cmd" == /usr/bin/xattr ]] && ! on_darwin; then
    return 0
  fi
  [[ -x "$xattr_cmd" ]] || return 0
  refuse_symlink "$path"
  "$xattr_cmd" -s -d com.apple.quarantine "$path" 2>/dev/null || \
    "$xattr_cmd" -d com.apple.quarantine "$path" 2>/dev/null || true
  if "$xattr_cmd" -s -p com.apple.quarantine "$path" >/dev/null 2>&1; then
    return 1
  fi
  if "$xattr_cmd" -p com.apple.quarantine "$path" >/dev/null 2>&1; then
    return 1
  fi
  return 0
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

# Directory Service inventory. A failed user-list or group-list is an error,
# not an empty snapshot: swallowing either side would let allocate_id reuse a
# live UniqueID. Two concurrent root provisioners can still race after this
# snapshot; serialize that at the operator level.
list_numeric_ids() {
  local kind="$1" key="$2" out=""
  out="$(dscl_cmd . -list "$kind" "$key")" || return 1
  printf '%s\n' "$out" | tr -d '\r' | awk 'NF >= 2 && $NF ~ /^[0-9]+$/ { print $NF }'
}

count_id_holders() {
  local kind="$1" key="$2" id="$3" out=""
  out="$(dscl_cmd . -list "$kind" "$key")" || return 1
  printf '%s\n' "$out" | tr -d '\r' | awk -v id="$id" 'NF >= 2 && $NF == id { c++ } END { print c+0 }'
}

allocate_id() {
  local users groups used candidate
  users="$(list_numeric_ids /Users UniqueID)" || return 1
  groups="$(list_numeric_ids /Groups PrimaryGroupID)" || return 1
  used="$(printf '%s\n' "$users" "$groups" | awk 'NF' | sort -n | uniq)"
  candidate="$UID_MIN"
  while [[ "$candidate" -le "$UID_MAX" ]]; do
    if ! printf '%s\n' "$used" | grep -Fxq "$candidate"; then
      echo "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  return 1
}

assert_numeric_identity_unique() {
  local uid="$1" gid="$2" nusers ngroups
  nusers="$(count_id_holders /Users UniqueID "$uid")" \
    || fail "failed to enumerate user UniqueIDs"
  ngroups="$(count_id_holders /Groups PrimaryGroupID "$gid")" \
    || fail "failed to enumerate group PrimaryGroupIDs"
  [[ "$nusers" == "1" ]] || fail "UniqueID ${uid} is shared by ${nusers} users; refuse to reuse ${ACCOUNT}"
  [[ "$ngroups" == "1" ]] || fail "PrimaryGroupID ${gid} is shared by ${ngroups} groups; refuse to reuse ${ACCOUNT}"
}

# Dedicated daemon group: empty GroupMembership, or only this account.
assert_group_membership_locked() {
  local members tok
  members="$(read_prop "/Groups/${ACCOUNT}" GroupMembership || true)"
  while IFS= read -r tok; do
    [[ -n "$tok" ]] || continue
    if [[ "$tok" != "$ACCOUNT" && "$tok" != "${ACCOUNT#_}" ]]; then
      fail "unexpected GroupMembership '${tok}' on ${ACCOUNT}"
    fi
  done <<<"$members"
}

id_in_service_range() {
  local n="$1"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  (( n != 0 && n >= UID_MIN && n <= UID_MAX ))
}

password_is_locked() {
  local pw
  pw="$(read_prop "/Users/${ACCOUNT}" Password || true)"
  [[ "$pw" == "*" ]]
}

user_matches() {
  local uid="$1" gid="$2"
  [[ "$uid" == "$gid" ]] || return 1
  id_in_service_range "$uid" || return 1
  id_in_service_range "$gid" || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" UniqueID)" == "$uid" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" PrimaryGroupID)" == "$gid" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" UserShell)" == "/usr/bin/false" ]] || return 1
  [[ "$(read_prop "/Users/${ACCOUNT}" NFSHomeDirectory)" == "/var/empty" ]] || return 1
  password_is_locked || return 1
  local auth
  auth="$(read_prop "/Users/${ACCOUNT}" AuthenticationAuthority || true)"
  [[ -z "$auth" ]] || return 1
}

group_matches() {
  local gid="$1"
  id_in_service_range "$gid" || return 1
  [[ "$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)" == "$gid" ]] || return 1
}

require_daemon_identity() {
  if ! record_exists "/Users/${ACCOUNT}"; then
    fail "missing ${ACCOUNT} user; run provision first"
  fi
  if ! record_exists "/Groups/${ACCOUNT}"; then
    fail "missing ${ACCOUNT} group; run provision first"
  fi
  local uid gid
  uid="$(read_prop "/Users/${ACCOUNT}" UniqueID)"
  gid="$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)"
  user_matches "$uid" "$gid" || fail "existing ${ACCOUNT} user does not match the expected daemon identity"
  group_matches "$gid" || fail "existing ${ACCOUNT} group does not match the expected daemon identity"
  assert_numeric_identity_unique "$uid" "$gid"
  assert_group_membership_locked
}

lock_service_account() {
  dscl_cmd . -create "/Users/${ACCOUNT}" Password '*'
  dscl_cmd . -delete "/Users/${ACCOUNT}" AuthenticationAuthority >/dev/null 2>&1 || true
  dscl_cmd . -delete "/Users/${ACCOUNT}" PasswordPolicyOptions >/dev/null 2>&1 || true
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
      # Delete records this invocation created, even if UniqueID/GID assignment
      # never succeeded. created_* is set only after -create of that record.
      if (( created_user )); then
        dscl_cmd . -delete "/Users/${ACCOUNT}" >/dev/null 2>&1 || true
      fi
      if (( created_group )); then
        dscl_cmd . -delete "/Groups/${ACCOUNT}" >/dev/null 2>&1 || true
      fi
    }
    trap rollback EXIT

    if record_exists "/Users/${ACCOUNT}" && record_exists "/Groups/${ACCOUNT}"; then
      uid="$(read_prop "/Users/${ACCOUNT}" UniqueID)"
      gid="$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)"
      user_matches "$uid" "$gid" || fail "existing ${ACCOUNT} user does not match the expected daemon identity"
      group_matches "$gid" || fail "existing ${ACCOUNT} group does not match the expected daemon identity"
      assert_numeric_identity_unique "$uid" "$gid"
      assert_group_membership_locked
      trap - EXIT
      exit 0
    fi
    if record_exists "/Users/${ACCOUNT}" || record_exists "/Groups/${ACCOUNT}"; then
      fail "partial ${ACCOUNT} identity exists; resolve it before provisioning"
    fi

    id=""
    if ! id="$(allocate_id)"; then
      fail "no unused system UID/GID in ${UID_MIN}-${UID_MAX}, or Directory Service enumeration failed"
    fi
    [[ -n "$id" ]] || fail "allocator returned an empty id"
    dscl_cmd . -create "/Groups/${ACCOUNT}"
    created_group=1
    dscl_cmd . -create "/Groups/${ACCOUNT}" PrimaryGroupID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}"
    created_user=1
    dscl_cmd . -create "/Users/${ACCOUNT}" UniqueID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}" PrimaryGroupID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}" UserShell /usr/bin/false
    dscl_cmd . -create "/Users/${ACCOUNT}" NFSHomeDirectory /var/empty
    lock_service_account
    user_matches "$id" "$id" || fail "provisioned ${ACCOUNT} user failed verification"
    group_matches "$id" || fail "provisioned ${ACCOUNT} group failed verification"
    assert_numeric_identity_unique "$id" "$id"
    assert_group_membership_locked
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

# Stage the new binary and config under private names, --check the staged
# pair, then replace the live binary and then the live config. A failed
# --check or quarantine check deletes the temps and leaves the previous
# live files untouched. If the config mv fails after the binary mv, the
# new binary remains with the previous config; both staged files already
# passed --check together.
install_tree() {
  local root="$1" binary="$2" config="$3" start="$4"
  [[ -f "$binary" && ! -L "$binary" ]] || fail "binary is not a regular file: $binary"
  [[ -f "$config" && ! -L "$config" ]] || fail "config is not a regular file: $config"
  validate_daemon_root "$root"
  # Root installs always provision/validate. A non-root staging install (CI
  # smoke) cannot talk to Directory Service; if an identity already exists it
  # is still validated so a leftover mismatched account cannot be used.
  if is_root; then
    provision
    require_daemon_identity
  elif record_exists "/Users/${ACCOUNT}" || record_exists "/Groups/${ACCOUNT}"; then
    require_daemon_identity
  fi
  refuse_symlink "$root"
  refuse_symlink "$root/bin"
  refuse_symlink "$root/acme"
  refuse_symlink "$root/logs"
  refuse_symlink "$root/bin/alighieri"
  refuse_symlink "$root/alighieri.conf"
  assert_safe_ancestors "$root"
  assert_existing_exec_dir "$root"
  assert_existing_exec_dir "$root/bin"
  assert_existing_state_dir "$root/acme"
  assert_existing_state_dir "$root/logs"

  "$INSTALL_BIN" -d -m 0755 "$root" "$root/bin" || fail "failed to create daemon directories"
  refuse_symlink "$root"
  refuse_symlink "$root/bin"
  assert_existing_exec_dir "$root"
  assert_existing_exec_dir "$root/bin"
  apply_install_ownership root:wheel "$root" "$root/bin"

  # Run the commit in a subshell that is *not* the left-hand side of `||`.
  # `cmd || return` disables `set -e` inside cmd, so an unguarded `mv`
  # could fail and still reach start_daemon.
  local commit_status=0
  set +e
  (
    set -euo pipefail
    staged_bin=""
    staged_conf=""
    staged_plist=""
    backup_bin=""
    # Invoked by the EXIT trap; shellcheck cannot see trap dispatch.
    # shellcheck disable=SC2317
    cleanup_staged() {
      rm -f -- ${staged_bin:+"$staged_bin"} ${staged_conf:+"$staged_conf"} ${staged_plist:+"$staged_plist"}
      if [[ -n "${backup_bin:-}" && -f "$backup_bin" ]]; then
        if [[ ! -e "$root/bin/alighieri" ]]; then
          # Use /bin/mv, not mv_cmd: a test double that injects live-path
          # failures must not block restoring the backup.
          /bin/mv -f -- "$backup_bin" "$root/bin/alighieri" || true
        else
          rm -f -- "$backup_bin"
        fi
      fi
    }
    trap cleanup_staged EXIT

    staged_bin="$(mktemp "${root}/bin/alighieri.tmp.XXXXXX")"
    rm -f -- "$staged_bin"
    if ! "$INSTALL_BIN" -m 0755 "$binary" "$staged_bin"; then
      fail "failed to stage binary"
    fi
    refuse_symlink "$staged_bin"
    chmod_nofollow 0755 "$staged_bin"
    if ! strip_quarantine "$staged_bin"; then
      fail "staged binary still has com.apple.quarantine"
    fi
    apply_install_ownership root:wheel "$staged_bin"

    "$INSTALL_BIN" -d "$root/acme" "$root/logs" || fail "failed to create state directories"
    refuse_symlink "$root/acme"
    refuse_symlink "$root/logs"
    assert_existing_state_dir "$root/acme"
    assert_existing_state_dir "$root/logs"
    chmod_nofollow 0700 "$root/acme" "$root/logs"
    apply_install_ownership "${ACCOUNT}:${ACCOUNT}" "$root/acme" "$root/logs"

    staged_conf="$(mktemp "${root}/alighieri.conf.tmp.XXXXXX")"
    if ! "$INSTALL_BIN" -m 0640 "$config" "$staged_conf"; then
      fail "failed to stage configuration"
    fi
    if ! "$staged_bin" --check --config "$staged_conf"; then
      fail "configuration check failed for $staged_bin"
    fi

    if [[ -f "$root/bin/alighieri" ]]; then
      backup_bin="$(mktemp "${root}/bin/alighieri.bak.XXXXXX")"
      mv_cmd -f -- "$root/bin/alighieri" "$backup_bin" \
        || fail "failed to backup the live binary"
    fi
    if ! mv_cmd -f -- "$staged_bin" "$root/bin/alighieri"; then
      fail "failed to replace the live binary"
    fi
    staged_bin=""
    if ! mv_cmd -f -- "$staged_conf" "$root/alighieri.conf"; then
      if [[ -n "$backup_bin" ]]; then
        /bin/mv -f -- "$backup_bin" "$root/bin/alighieri" || true
        backup_bin=""
      fi
      fail "failed to replace the live configuration"
    fi
    staged_conf=""
    rm -f -- ${backup_bin:+"$backup_bin"}
    backup_bin=""
    chmod_nofollow 0640 "$root/alighieri.conf"
    apply_install_ownership "root:${ACCOUNT}" "$root/alighieri.conf"

    plist_dest="$root/${PLIST_LABEL}.plist"
    if is_root && on_darwin; then
      plist_dest="$PLIST_PATH"
    fi
    staged_plist="$(mktemp "${root}/plist.XXXXXX")"
    write_plist "$root" "$staged_plist"
    if ! mv_cmd -f -- "$staged_plist" "$plist_dest"; then
      fail "failed to replace the launchd plist"
    fi
    staged_plist=""
    apply_install_ownership root:wheel "$plist_dest"
    chmod_nofollow 0644 "$plist_dest"
    trap - EXIT
  )
  commit_status=$?
  set -e
  [[ "$commit_status" -eq 0 ]] || return 1

  if [[ "$start" == "1" ]]; then
    start_daemon
  fi
}

start_daemon() {
  require_daemon_identity
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
    if [ -n "${ALIGHIERI_DSCL_FAIL_CREATE:-}" ]; then
      if [ $# -eq 0 ] && [ "$ALIGHIERI_DSCL_FAIL_CREATE" = "$rec" ]; then
        exit 1
      fi
      if [ $# -ge 1 ] && [ "$ALIGHIERI_DSCL_FAIL_CREATE" = "$rec $1" ]; then
        exit 1
      fi
    fi
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
    if [ -n "${ALIGHIERI_DSCL_FAIL_LIST:-}" ] && [ "$ALIGHIERI_DSCL_FAIL_LIST" = "$1" ]; then
      exit 1
    fi
    list_records "$1" "$2"
    ;;
  -delete)
    rec="$1"
    key="${2:-}"
    if [ -n "$key" ]; then
      rm -f "$db$rec/$key"
    else
      rm -rf "$db$rec"
    fi
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
mode="755"
owner="0"
if [ -n "${ALIGHIERI_STAT_MAP:-}" ] && [ -f "${ALIGHIERI_STAT_MAP}" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    map_path="${line%% *}"
    rest="${line#* }"
    map_mode="${rest%% *}"
    map_uid="${rest#* }"
    if [ "$map_path" = "$path" ]; then
      mode="$map_mode"
      owner="$map_uid"
      break
    fi
  done < "${ALIGHIERI_STAT_MAP}"
fi
case "$fmt" in
  %Lp|%a)
    echo "$mode"
    ;;
  %u)
    echo "$owner"
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

  cat >"$tmp/id-root.sh" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = "-u" ]; then
  echo 0
  exit 0
fi
exit 0
EOF
  chmod +x "$tmp/id-root.sh"

  cat >"$tmp/xattr-none.sh" <<'EOF'
#!/bin/sh
exit 1
EOF
  chmod +x "$tmp/xattr-none.sh"
  XATTR_BIN="$tmp/xattr-none.sh"

  export ALIGHIERI_DSCL_DB="$db"
  export ALIGHIERI_LAUNCHCTL_LOG="$tmp/launchctl.log"
  DSCL_BIN="$tmp/dscl.sh"
  LAUNCHCTL_BIN="$tmp/launchctl.sh"
  STAT_BIN="$tmp/stat.sh"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"

  # Clean provision then exact rerun.
  provision
  provision
  [[ "$(read_prop "/Users/${ACCOUNT}" Password)" == "*" ]] \
    || fail "provisioned password must be *"

  expect_provision_failure() {
    local msg="$1" status=0
    set +e
    ( set -euo pipefail; provision )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$msg"
  }

  expect_install_failure() {
    local msg="$1" status=0
    : >"$ALIGHIERI_LAUNCHCTL_LOG"
    set +e
    ( set -euo pipefail; install_tree "$root" "$tmp/dummy-bin" "$tmp/dummy.conf" 1 )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$msg"
    if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
      fail "$msg: must not bootstrap"
    fi
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
  dscl_cmd . -create "/Users/_alighieri" Password '*'

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
    rec="$1"
    key="${2:-}"
    if [ -n "$key" ]; then
      rm -f "$db$rec/$key"
    else
      rm -rf "$db$rec"
    fi
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

  printf '%s\n' '#!/bin/sh' 'exit 0' >"$tmp/dummy-bin"
  chmod +x "$tmp/dummy-bin"
  printf '%s\n' 'internal: 127.0.0.1 port = 1080' >"$tmp/dummy.conf"

  local root="$tmp/opt/alighieri"
  mkdir -p "$tmp/opt"
  chmod 755 "$tmp/opt"

  reset_valid_identity() {
    rm -rf "$db/Users/_alighieri" "$db/Groups/_alighieri"
    provision
  }
  reset_valid_identity

  # Install fail-fast: missing binary.
  if ( install_tree "$root" "$tmp/missing-bin" "$tmp/dummy.conf" 1 ); then
    fail "missing binary must fail"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "missing binary must not bootstrap"
  fi
  [[ ! -e "$root/bin/alighieri" ]] || fail "missing binary must not install a dest binary"

  plant_identity() {
    local uid="$1" gid="$2" shell="$3" home="$4" password="$5" auth="$6"
    mkdir -p "$db/Users/_alighieri" "$db/Groups/_alighieri"
    printf '%s\n' "$uid" >"$db/Users/_alighieri/UniqueID"
    printf '%s\n' "$gid" >"$db/Users/_alighieri/PrimaryGroupID"
    printf '%s\n' "$shell" >"$db/Users/_alighieri/UserShell"
    printf '%s\n' "$home" >"$db/Users/_alighieri/NFSHomeDirectory"
    printf '%s\n' "$password" >"$db/Users/_alighieri/Password"
    if [[ -n "$auth" ]]; then
      printf '%s\n' "$auth" >"$db/Users/_alighieri/AuthenticationAuthority"
    else
      rm -f "$db/Users/_alighieri/AuthenticationAuthority"
    fi
    printf '%s\n' "$gid" >"$db/Groups/_alighieri/PrimaryGroupID"
  }

  plant_identity 0 0 /usr/bin/false /var/empty '*' ""
  expect_install_failure "UID 0 identity must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "UID 0 identity must not write the binary"

  plant_identity 501 501 /usr/bin/false /var/empty '*' ""
  expect_install_failure "UID 501 identity must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "UID 501 identity must not write the binary"

  plant_identity 261 20 /usr/bin/false /var/empty '*' ""
  expect_install_failure "mismatched GID must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "mismatched GID must not write the binary"

  plant_identity 261 261 /bin/zsh /var/empty '*' ""
  expect_install_failure "login-capable shell must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "login shell must not write the binary"

  plant_identity 261 261 /usr/bin/false /var/empty '*' ";ShadowHash;"
  expect_install_failure "AuthenticationAuthority must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "AuthenticationAuthority must not write the binary"

  plant_identity 261 261 /usr/bin/false /var/empty 'secret' ""
  expect_install_failure "non-locked password must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "non-locked password must not write the binary"

  plant_identity 261 261 /usr/bin/false /var/empty '*' ""
  rm -rf "$db/Users/_alighieri"
  expect_install_failure "missing user (group remains) must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "missing user must not write the binary"

  reset_valid_identity
  rm -rf "$db/Groups/_alighieri"
  expect_install_failure "missing group (user remains) must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "missing group must not write the binary"

  reset_valid_identity
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( start_daemon ); then
    :
  else
    fail "start with a valid identity must attempt bootstrap"
  fi
  grep -Fq "bootstrap system ${PLIST_PATH}" "$ALIGHIERI_LAUNCHCTL_LOG" \
    || fail "start with a valid identity must bootstrap"

  rm -rf "$db/Users/_alighieri"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( start_daemon ); then
    fail "start with a missing user must fail"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "start with a missing user must not bootstrap"
  fi

  reset_valid_identity
  rm -rf "$db/Groups/_alighieri"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( start_daemon ); then
    fail "start with a missing group must fail"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "start with a missing group must not bootstrap"
  fi
  reset_valid_identity

  # Directory Service inventory failure must not allocate a default UID.
  ALIGHIERI_DSCL_FAIL_LIST=/Users
  export ALIGHIERI_DSCL_FAIL_LIST
  expect_provision_failure "user UniqueID inventory failure must fail closed"
  unset ALIGHIERI_DSCL_FAIL_LIST
  ALIGHIERI_DSCL_FAIL_LIST=/Groups
  export ALIGHIERI_DSCL_FAIL_LIST
  expect_provision_failure "group PrimaryGroupID inventory failure must fail closed"
  unset ALIGHIERI_DSCL_FAIL_LIST

  rm -rf "$db/Users/_alighieri" "$db/Groups/_alighieri"
  ALIGHIERI_DSCL_FAIL_LIST=/Users
  export ALIGHIERI_DSCL_FAIL_LIST
  expect_provision_failure "allocator must not create an account after a failed user list"
  [[ ! -d "$db/Users/_alighieri" ]] || fail "failed user inventory must not create a user"
  [[ ! -d "$db/Groups/_alighieri" ]] || fail "failed user inventory must not create a group"
  unset ALIGHIERI_DSCL_FAIL_LIST
  reset_valid_identity

  # Existing identity with a colliding UniqueID/GID must be refused.
  mkdir -p "$db/Users/_collider"
  printf '%s\n' 261 >"$db/Users/_collider/UniqueID"
  expect_provision_failure "duplicate UniqueID on an existing identity must be rejected"
  expect_install_failure "duplicate UniqueID must not install"
  [[ ! -e "$root/bin/alighieri" ]] || fail "duplicate UniqueID must not write the binary"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( start_daemon ); then
    fail "duplicate UniqueID must not start"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "duplicate UniqueID must not bootstrap"
  fi
  rm -rf "$db/Users/_collider"

  mkdir -p "$db/Groups/_collider"
  printf '%s\n' 261 >"$db/Groups/_collider/PrimaryGroupID"
  expect_provision_failure "duplicate PrimaryGroupID on an existing identity must be rejected"
  expect_install_failure "duplicate PrimaryGroupID must not install"
  rm -rf "$db/Groups/_collider"

  printf '%s\n' "_www" >"$db/Groups/_alighieri/GroupMembership"
  expect_provision_failure "unexpected GroupMembership must be rejected"
  expect_install_failure "unexpected GroupMembership must not install"
  rm -f "$db/Groups/_alighieri/GroupMembership"
  reset_valid_identity

  # Rollback must delete records created by this invocation even when the
  # numeric ID was never assigned.
  rm -rf "$db/Users/_alighieri" "$db/Groups/_alighieri"
  ALIGHIERI_DSCL_FAIL_CREATE="/Groups/_alighieri PrimaryGroupID"
  export ALIGHIERI_DSCL_FAIL_CREATE
  expect_provision_failure "GID assignment failure must fail"
  [[ ! -d "$db/Groups/_alighieri" ]] || fail "GID assignment failure must roll back the group"
  [[ ! -d "$db/Users/_alighieri" ]] || fail "GID assignment failure must not leave a user"
  unset ALIGHIERI_DSCL_FAIL_CREATE

  ALIGHIERI_DSCL_FAIL_CREATE="/Users/_alighieri UniqueID"
  export ALIGHIERI_DSCL_FAIL_CREATE
  expect_provision_failure "UniqueID assignment failure must fail"
  [[ ! -d "$db/Users/_alighieri" ]] || fail "UniqueID assignment failure must roll back the user"
  [[ ! -d "$db/Groups/_alighieri" ]] || fail "UniqueID assignment failure must roll back the group"
  unset ALIGHIERI_DSCL_FAIL_CREATE
  reset_valid_identity

  # Homebrew-style writable ancestor must be refused.
  local brew="$tmp/usr/local"
  mkdir -p "$brew"
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
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$brew/alighieri" "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ); then
    fail "group-writable Homebrew-style prefix must be refused"
  fi
  STAT_BIN="$tmp/stat.sh"
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

  # Child-tree leftover ownership/symlink must fail before writing the binary.
  mkdir -p "$root/bin" "$root/acme" "$root/logs"
  chmod 755 "$root" "$root/bin"
  ID_BIN="$tmp/id-root.sh"
  export ALIGHIERI_STAT_MAP="$tmp/stat.map"

  printf '%s\n' "$root/bin 755 501" >"$ALIGHIERI_STAT_MAP"
  expect_install_failure "attacker-owned bin must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "attacker-owned bin must not receive the binary"

  printf '%s\n' "$root/bin 775 0" >"$ALIGHIERI_STAT_MAP"
  expect_install_failure "group-writable bin must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "writable bin must not receive the binary"

  printf '%s\n' "$root/acme 700 501" >"$ALIGHIERI_STAT_MAP"
  expect_install_failure "attacker-owned acme must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "attacker-owned acme must not write the binary"

  printf '%s\n' "$root/logs 700 501" >"$ALIGHIERI_STAT_MAP"
  expect_install_failure "attacker-owned logs must be rejected"
  [[ ! -e "$root/bin/alighieri" ]] || fail "attacker-owned logs must not write the binary"

  unset ALIGHIERI_STAT_MAP
  ID_BIN=/usr/bin/id
  mkdir -p "$root"
  rm -rf "${root:?}/bin" "${root:?}/acme" "${root:?}/logs" "${root:?}/alighieri.conf"
  if ln -s "$tmp/elsewhere" "$root/bin" 2>/dev/null; then
    expect_install_failure "symlinked bin must be rejected"
    [[ ! -e "$tmp/elsewhere/alighieri" ]] || fail "symlinked bin must not write through the link"
    rm -f "$root/bin"
  else
    echo "macos-daemon selftest: skipping dest-symlink fixtures (ln not available)" >&2
  fi
  mkdir -p "$root/bin"
  if ln -s "$tmp/evil.conf" "$root/alighieri.conf" 2>/dev/null; then
    expect_install_failure "symlinked config dest must be rejected"
    rm -f "$root/alighieri.conf"
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

  local live_bin_hash live_conf_hash live_plist_hash
  live_bin_hash="$(cksum <"$root/bin/alighieri")"
  live_conf_hash="$(cksum <"$root/alighieri.conf")"
  live_plist_hash="$(cksum <"$root/${PLIST_LABEL}.plist")"

  # Config --check failure must not replace the live binary/config/plist.
  printf '%s\n' '#!/bin/sh' 'exit 1' >"$tmp/bad-bin"
  chmod +x "$tmp/bad-bin"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$root" "$tmp/bad-bin" "$tmp/fake.conf" 1 ); then
    fail "failed --check must fail the install"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed --check must not bootstrap"
  fi
  [[ "$(cksum <"$root/bin/alighieri")" == "$live_bin_hash" ]] \
    || fail "failed --check must leave the live binary unchanged"
  [[ "$(cksum <"$root/alighieri.conf")" == "$live_conf_hash" ]] \
    || fail "failed --check must leave the live config unchanged"
  [[ "$(cksum <"$root/${PLIST_LABEL}.plist")" == "$live_plist_hash" ]] \
    || fail "failed --check must leave the live plist unchanged"
  grep -Fq 'exit 0' "$root/bin/alighieri" \
    || fail "failed --check replaced the live binary"

  # Quarantine remaining on the staged binary must not replace live files.
  cat >"$tmp/xattr-quarantine.sh" <<'EOF'
#!/bin/sh
set -eu
case " $* " in
  *" -p "*) exit 0 ;;
  *) exit 0 ;;
esac
EOF
  chmod +x "$tmp/xattr-quarantine.sh"
  XATTR_BIN="$tmp/xattr-quarantine.sh"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$root" "$tmp/dummy-bin" "$tmp/fake.conf" 1 ); then
    fail "quarantined staged binary must fail the install"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "quarantined staged binary must not bootstrap"
  fi
  [[ "$(cksum <"$root/bin/alighieri")" == "$live_bin_hash" ]] \
    || fail "quarantine failure must leave the live binary unchanged"
  [[ "$(cksum <"$root/alighieri.conf")" == "$live_conf_hash" ]] \
    || fail "quarantine failure must leave the live config unchanged"
  [[ "$(cksum <"$root/${PLIST_LABEL}.plist")" == "$live_plist_hash" ]] \
    || fail "quarantine failure must leave the live plist unchanged"
  XATTR_BIN=/usr/bin/xattr

  cat >"$tmp/mv.sh" <<'EOF'
#!/bin/sh
set -eu
fail_dest="${ALIGHIERI_MV_FAIL:-}"
last=""
for last do
  :
done
if [ -n "$fail_dest" ] && [ "$last" = "$fail_dest" ]; then
  echo "INJECTED mv failure: $last" >&2
  exit 1
fi
exec /bin/mv "$@"
EOF
  chmod +x "$tmp/mv.sh"

  expect_retained_live_tree() {
    local msg="$1"
    [[ "$(cksum <"$root/bin/alighieri")" == "$live_bin_hash" ]] \
      || fail "$msg: live binary changed"
    [[ "$(cksum <"$root/alighieri.conf")" == "$live_conf_hash" ]] \
      || fail "$msg: live config changed"
    [[ "$(cksum <"$root/${PLIST_LABEL}.plist")" == "$live_plist_hash" ]] \
      || fail "$msg: live plist changed"
    grep -Fq 'exit 0' "$root/bin/alighieri" \
      || fail "$msg: live binary is not the previously installed script"
  }

  MV_BIN="$tmp/mv.sh"
  ALIGHIERI_MV_FAIL="$root/bin/alighieri"
  export ALIGHIERI_MV_FAIL
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$root" "$tmp/dummy-bin" "$tmp/fake.conf" 1 ); then
    fail "failed live-binary rename must fail the install"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed live-binary rename must not bootstrap"
  fi
  expect_retained_live_tree "failed live-binary rename"

  ALIGHIERI_MV_FAIL="$root/alighieri.conf"
  export ALIGHIERI_MV_FAIL
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$root" "$tmp/dummy-bin" "$tmp/fake.conf" 1 ); then
    fail "failed live-config rename must fail the install"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed live-config rename must not bootstrap"
  fi
  expect_retained_live_tree "failed live-config rename"

  ALIGHIERI_MV_FAIL="$root/${PLIST_LABEL}.plist"
  export ALIGHIERI_MV_FAIL
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( install_tree "$root" "$tmp/dummy-bin" "$tmp/fake.conf" 1 ); then
    fail "failed plist rename must fail the install"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed plist rename must not bootstrap"
  fi
  # Binary+config already passed --check and were committed; plist remains the
  # previous live file and launchd must not start.
  [[ "$(cksum <"$root/${PLIST_LABEL}.plist")" == "$live_plist_hash" ]] \
    || fail "failed plist rename must leave the live plist unchanged"
  unset ALIGHIERI_MV_FAIL
  MV_BIN=/bin/mv

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

  # Production verbs must ignore inherited ALIGHIERI_* toolchain overrides.
  local evil_log="$tmp/evil-invoked"
  cat >"$tmp/evil.sh" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >> "$evil_log"
exit 0
EOF
  chmod +x "$tmp/evil.sh"
  assert_env_ignored() {
    local verb="$1"
    : >"$evil_log"
    set +e
    env \
      ALIGHIERI_DSCL="$tmp/evil.sh" \
      ALIGHIERI_ID="$tmp/evil.sh" \
      ALIGHIERI_INSTALL="$tmp/evil.sh" \
      ALIGHIERI_LAUNCHCTL="$tmp/evil.sh" \
      ALIGHIERI_STAT="$tmp/evil.sh" \
      ALIGHIERI_XATTR="$tmp/evil.sh" \
      bash "$SCRIPT_PATH" "$verb" \
        --root "$tmp/env-ignored" \
        --binary "$tmp/dummy-bin" \
        --config "$tmp/dummy.conf" \
        --no-start \
        >/dev/null 2>&1
    set -e
    [[ ! -s "$evil_log" ]] || fail "$verb honored ALIGHIERI_* toolchain overrides"
  }
  assert_env_ignored provision
  assert_env_ignored install
  assert_env_ignored start

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
  provision)
    use_system_tools
    provision
    ;;
  install)
    use_system_tools
    [[ -n "$binary" && -n "$config" ]] || usage
    install_tree "$root" "$binary" "$config" "$start"
    ;;
  start)
    use_system_tools
    start_daemon
    ;;
  __selftest) selftest ;;
  *) usage ;;
esac
