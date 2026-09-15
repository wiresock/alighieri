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
INSTALL_LOCK_DIR="/var/run/alighieri-macos-install.lock"
# Older name kept as a fallback for in-process selftest assignments.
PROVISION_LOCK_DIR="/var/run/alighieri-macos-provision.lock"
INSTALL_LOCK_RETRIES=100
PROVISION_LOCK_RETRIES=100
INSTALL_LOCK_SLEEP=0.05
PROVISION_LOCK_SLEEP=0.05
INSTALL_LOCK_DEPTH=0
# In-process selftest hooks; production verbs clear these.
INSTALL_FAIL_AFTER=""
INSTALL_PAUSE_DIR=""
INSTALL_PAUSE_POINT=""
INCOMPLETE_RECOVERY_MARKER=""

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
  RESTORE_BIN=/bin/mv
  INSTALL_FAIL_AFTER=""
  INSTALL_PAUSE_DIR=""
  INSTALL_PAUSE_POINT=""
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
restore_cmd() { "$RESTORE_BIN" "$@"; }

# Move a live file aside. Prints the backup path only after the original has
# been transferred. A failed move removes the mktemp placeholder so cleanup
# cannot restore an empty file over the untouched original.
backup_live_file() {
  local live="$1" prefix="$2" tmp
  [[ -f "$live" ]] || return 0
  tmp="$(mktemp "$prefix")"
  if mv_cmd -f -- "$live" "$tmp"; then
    printf '%s\n' "$tmp"
    return 0
  fi
  rm -f -- "$tmp"
  return 1
}

# Confirm the LaunchDaemon is not loaded before replacing files. A loaded job
# whose bootout fails, or an unreadable job state, aborts without publication.
unload_job_before_replace() {
  local out="" rc=0
  out="$("$LAUNCHCTL_BIN" print "system/${PLIST_LABEL}" 2>&1)" || rc=$?
  if (( rc == 0 )); then
    "$LAUNCHCTL_BIN" bootout "system/${PLIST_LABEL}" \
      || fail "failed to unload ${PLIST_LABEL}; refusing to replace files"
    rc=0
    out="$("$LAUNCHCTL_BIN" print "system/${PLIST_LABEL}" 2>&1)" || rc=$?
    if (( rc == 0 )); then
      fail "${PLIST_LABEL} is still loaded after bootout; refusing to replace files"
    fi
    if ! printf '%s\n' "$out" | grep -Eq 'Could not find service|No such process'; then
      fail "failed to confirm ${PLIST_LABEL} is unloaded"
    fi
    return 0
  fi
  if printf '%s\n' "$out" | grep -Eq 'Could not find service|No such process'; then
    return 0
  fi
  fail "failed to query ${PLIST_LABEL} state; refusing to replace files"
}

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

# Returns 0 if the record exists, 1 if it is positively absent. Lookup
# errors (as opposed to eDSRecordNotFound) abort rather than looking absent.
record_exists() {
  local rec="$1" out="" rc=0
  out="$(dscl_cmd . -read "$rec" 2>&1)" || rc=$?
  if (( rc == 0 )); then
    return 0
  fi
  if printf '%s\n' "$out" | grep -Eq 'eDSRecordNotFound|No such record'; then
    return 1
  fi
  fail "failed to look up ${rec}"
}

# Print every value of Open Directory attribute $2 on record $1.
# Returns 0 when the attribute is present, 2 when it is absent, 1 when the
# lookup failed. "No such key" / eDSAttributeNotFound is absence, not success
# with an empty membership and not a hard failure.
read_attr_values() {
  local rec="$1" key="$2" out="" rc=0
  out="$(dscl_cmd . -read "$rec" "$key" 2>&1)" || rc=$?
  if printf '%s\n' "$out" | grep -Eq 'No such key:|eDSAttributeNotFound'; then
    return 2
  fi
  if (( rc != 0 )); then
    return 1
  fi
  if [[ -z "$out" ]]; then
    return 2
  fi
  printf '%s\n' "$out" | tr -d '\r' | awk -v key="$key" '
    NR == 1 {
      prefix = key ":"
      if (index($0, prefix) == 1) {
        rest = substr($0, length(prefix) + 1)
      } else {
        rest = $0
        sub(/^[^:]+:/, "", rest)
      }
      n = split(rest, a, /[[:space:]]+/)
      for (i = 1; i <= n; i++) if (a[i] != "") print a[i]
      next
    }
    {
      sub(/^[[:space:]]+/, "")
      n = split($0, a, /[[:space:]]+/)
      for (i = 1; i <= n; i++) if (a[i] != "") print a[i]
    }
  '
  return 0
}

read_prop() {
  # First nonempty value of an attribute. Missing attributes fail (callers
  # that treat absence as empty use `|| true`).
  local values rc=0
  values="$(read_attr_values "$1" "$2")" || rc=$?
  (( rc == 0 )) || return 1
  printf '%s\n' "$values" | awk 'NF { print; exit }'
}

# Directory Service inventory. A failed user-list or group-list is an error,
# not an empty snapshot: swallowing either side would let allocate_id reuse a
# live UniqueID. Concurrent provisioners are serialized by PROVISION_LOCK_DIR.
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

# RecordName values that identify ACCOUNT. An unverified short name such as
# "alighieri" is not accepted unless it is actually an alias of this record.
account_record_names() {
  local rc=0 names=""
  names="$(read_attr_values "/Users/${ACCOUNT}" RecordName)" || rc=$?
  if (( rc == 1 )); then
    return 1
  fi
  if (( rc == 2 )) || [[ -z "$names" ]]; then
    printf '%s\n' "$ACCOUNT"
    return 0
  fi
  printf '%s\n' "$names"
}

name_is_account_alias() {
  local tok="$1" names="$2"
  printf '%s\n' "$names" | grep -Fxq "$tok"
}

# Dedicated daemon group: no unexpected name, GUID, nested, or primary-group
# members. Absence of a membership attribute is allowed; a failed read is not.
# Callers must not wrap this in `$(...)`: fail() inside a substitution only
# exits that substitution.
assert_group_membership_locked() {
  local gid names rc=0 values="" tok user_guid guid_rc=0 list uname ugid
  gid="$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)" \
    || fail "failed to read ${ACCOUNT} PrimaryGroupID"
  names="$(account_record_names)" \
    || fail "failed to read ${ACCOUNT} RecordName"

  rc=0
  values="$(read_attr_values "/Groups/${ACCOUNT}" GroupMembership)" || rc=$?
  if (( rc == 1 )); then
    fail "failed to read GroupMembership for ${ACCOUNT}"
  fi
  if (( rc == 0 )); then
    while IFS= read -r tok; do
      [[ -n "$tok" ]] || continue
      if ! name_is_account_alias "$tok" "$names"; then
        fail "unexpected GroupMembership '${tok}' on ${ACCOUNT}"
      fi
    done <<<"$values"
  fi

  user_guid=""
  guid_rc=0
  user_guid="$(read_attr_values "/Users/${ACCOUNT}" GeneratedUID)" || guid_rc=$?
  if (( guid_rc == 1 )); then
    fail "failed to read GeneratedUID for ${ACCOUNT}"
  fi
  rc=0
  values="$(read_attr_values "/Groups/${ACCOUNT}" GroupMembers)" || rc=$?
  if (( rc == 1 )); then
    fail "failed to read GroupMembers for ${ACCOUNT}"
  fi
  if (( rc == 0 )); then
    while IFS= read -r tok; do
      [[ -n "$tok" ]] || continue
      if (( guid_rc == 2 )) || [[ -z "$user_guid" || "$tok" != "$user_guid" ]]; then
        fail "unexpected GroupMembers '${tok}' on ${ACCOUNT}"
      fi
    done <<<"$values"
  fi

  rc=0
  values="$(read_attr_values "/Groups/${ACCOUNT}" NestedGroups)" || rc=$?
  if (( rc == 1 )); then
    fail "failed to read NestedGroups for ${ACCOUNT}"
  fi
  if (( rc == 0 )); then
    while IFS= read -r tok; do
      [[ -n "$tok" ]] || continue
      fail "unexpected NestedGroups '${tok}' on ${ACCOUNT}"
    done <<<"$values"
  fi

  list="$(dscl_cmd . -list /Users PrimaryGroupID)" \
    || fail "failed to enumerate user PrimaryGroupIDs"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    uname="${line%% *}"
    ugid="${line##* }"
    [[ "$ugid" == "$gid" ]] || continue
    if ! name_is_account_alias "$uname" "$names"; then
      fail "user ${uname} has PrimaryGroupID ${gid}; refuse to reuse ${ACCOUNT}"
    fi
  done <<<"$list"
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

install_lock_dir() {
  printf '%s\n' "${INSTALL_LOCK_DIR:-$PROVISION_LOCK_DIR}"
}

# Shared lock for provision, install, and start. Nested callers in the same
# process (install -> provision) increment depth instead of mkdir again.
acquire_install_lock() {
  local dir n=0 max
  dir="$(install_lock_dir)"
  max="${INSTALL_LOCK_RETRIES:-${PROVISION_LOCK_RETRIES:-100}}"
  [[ -n "$dir" ]] || fail "install lock directory is unset"
  if (( INSTALL_LOCK_DEPTH > 0 )); then
    INSTALL_LOCK_DEPTH=$((INSTALL_LOCK_DEPTH + 1))
    return 0
  fi
  while ! mkdir "$dir" 2>/dev/null; do
    n=$((n + 1))
    if (( n >= max )); then
      fail "another Alighieri install is in progress (${dir})"
    fi
    sleep "${INSTALL_LOCK_SLEEP:-${PROVISION_LOCK_SLEEP:-0.05}}"
  done
  INSTALL_LOCK_DEPTH=1
}

release_install_lock() {
  (( INSTALL_LOCK_DEPTH > 0 )) || return 0
  INSTALL_LOCK_DEPTH=$((INSTALL_LOCK_DEPTH - 1))
  if (( INSTALL_LOCK_DEPTH == 0 )); then
    rmdir "$(install_lock_dir)" 2>/dev/null || true
  fi
}

acquire_provision_lock() { acquire_install_lock; }
release_provision_lock() { release_install_lock; }

maybe_pause_install() {
  local point="$1"
  if [[ -n "${INSTALL_PAUSE_DIR:-}" && "${INSTALL_PAUSE_POINT:-}" == "$point" ]]; then
    printf 'paused\n' >"${INSTALL_PAUSE_DIR}/ready"
    while [[ ! -f "${INSTALL_PAUSE_DIR}/go" ]]; do
      sleep 0.05
    done
  fi
}

assert_no_incomplete_recovery() {
  local m
  for m in \
    ${INCOMPLETE_RECOVERY_MARKER:+"$INCOMPLETE_RECOVERY_MARKER"} \
    "${root:-$DEFAULT_ROOT}/.alighieri-incomplete-recovery"
  do
    [[ -n "$m" ]] || continue
    if [[ -f "$m" ]]; then
      fail "incomplete install recovery at ${m}; refusing to start"
    fi
  done
}

# dscl -create is not exclusive. Only claim deletion ownership when the
# record has no identifying numeric id yet (we just created an empty record).
# A failed ownership read is not "absent": abort without claiming, changing
# IDs, or deleting records.
claim_created_record() {
  local rec="$1" key="$2" rc=0 existing=""
  existing="$(read_attr_values "$rec" "$key")" || rc=$?
  if (( rc == 1 )); then
    fail "failed to read ${key} for ${rec}; will not take deletion ownership"
  fi
  if (( rc == 0 )) && [[ -n "$existing" ]]; then
    return 1
  fi
  return 0
}

provision() {
  # Run the mutating work in a subshell so the rollback EXIT trap cannot
  # replace a caller's trap (the selftest uses EXIT to remove its temp dir).
  (
    created_group=0
    created_user=0
    lock_held=0
    # Invoked by the EXIT trap; shellcheck cannot see trap dispatch.
    # shellcheck disable=SC2317
    rollback() {
      # Delete records this invocation uniquely created, even if UniqueID/GID
      # assignment never succeeded. created_* is not set merely because
      # dscl -create returned success against an existing record.
      if (( created_user )); then
        dscl_cmd . -delete "/Users/${ACCOUNT}" >/dev/null 2>&1 || true
      fi
      if (( created_group )); then
        dscl_cmd . -delete "/Groups/${ACCOUNT}" >/dev/null 2>&1 || true
      fi
      if (( lock_held )); then
        release_provision_lock
      fi
    }
    trap rollback EXIT

    acquire_provision_lock
    lock_held=1

    if record_exists "/Users/${ACCOUNT}" && record_exists "/Groups/${ACCOUNT}"; then
      uid="$(read_prop "/Users/${ACCOUNT}" UniqueID)"
      gid="$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)"
      user_matches "$uid" "$gid" || fail "existing ${ACCOUNT} user does not match the expected daemon identity"
      group_matches "$gid" || fail "existing ${ACCOUNT} group does not match the expected daemon identity"
      assert_numeric_identity_unique "$uid" "$gid"
      assert_group_membership_locked
      lock_held=0
      release_provision_lock
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

    # Re-check under the lock before create. If a populated record is already
    # present, dscl -create succeeding must not take deletion ownership.
    if record_exists "/Users/${ACCOUNT}" && record_exists "/Groups/${ACCOUNT}"; then
      uid="$(read_prop "/Users/${ACCOUNT}" UniqueID)"
      gid="$(read_prop "/Groups/${ACCOUNT}" PrimaryGroupID)"
      user_matches "$uid" "$gid" || fail "existing ${ACCOUNT} user does not match the expected daemon identity"
      group_matches "$gid" || fail "existing ${ACCOUNT} group does not match the expected daemon identity"
      assert_numeric_identity_unique "$uid" "$gid"
      assert_group_membership_locked
      lock_held=0
      release_provision_lock
      trap - EXIT
      exit 0
    fi
    if record_exists "/Users/${ACCOUNT}" || record_exists "/Groups/${ACCOUNT}"; then
      fail "partial ${ACCOUNT} identity exists; resolve it before provisioning"
    fi

    dscl_cmd . -create "/Groups/${ACCOUNT}"
    if ! claim_created_record "/Groups/${ACCOUNT}" PrimaryGroupID; then
      fail "${ACCOUNT} group already exists; another installer owns it"
    fi
    created_group=1
    dscl_cmd . -create "/Groups/${ACCOUNT}" PrimaryGroupID "$id"
    dscl_cmd . -create "/Users/${ACCOUNT}"
    if ! claim_created_record "/Users/${ACCOUNT}" UniqueID; then
      fail "${ACCOUNT} user already exists; another installer owns it"
    fi
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
    lock_held=0
    release_provision_lock
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

# Stage binary, config, and plist under private names, apply ownership/modes
# to the staged files, --check the staged pair, unload a loaded KeepAlive
# job, then publish. Previous live files stay backed up until publish (and
# bootstrap, when requested) succeeds. Restoration uses RESTORE_BIN, not
# MV_BIN, so a live-path test double cannot block recovery.
install_tree() {
  local root="$1" binary="$2" config="$3" start="$4"
  [[ -f "$binary" && ! -L "$binary" ]] || fail "binary is not a regular file: $binary"
  [[ -f "$config" && ! -L "$config" ]] || fail "config is not a regular file: $config"
  validate_daemon_root "$root"
  INCOMPLETE_RECOVERY_MARKER="${root}/.alighieri-incomplete-recovery"
  local tx_status=0
  set +e
  (
    set -euo pipefail
    acquire_install_lock
    trap release_install_lock EXIT
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
  commit_status=0
  set +e
  (
    set -euo pipefail
    staged_bin=""
    staged_conf=""
    staged_plist=""
    backup_bin=""
    backup_conf=""
    backup_plist=""
    committed=0
    plist_dest="$root/${PLIST_LABEL}.plist"
    if is_root && on_darwin; then
      plist_dest="$PLIST_PATH"
    fi

    # Invoked by the EXIT trap; shellcheck cannot see trap dispatch.
    # shellcheck disable=SC2317
    restore_previous_generation() {
      local failed=0 bin_ok=1 conf_ok=1
      if [[ -n "${backup_bin:-}" && -f "$backup_bin" ]]; then
        if restore_cmd -f -- "$backup_bin" "$root/bin/alighieri"; then
          backup_bin=""
        else
          failed=1
          bin_ok=0
        fi
      fi
      if [[ -n "${backup_conf:-}" && -f "$backup_conf" ]]; then
        if restore_cmd -f -- "$backup_conf" "$root/alighieri.conf"; then
          backup_conf=""
        else
          failed=1
          conf_ok=0
        fi
      fi
      # Restore an auto-start plist only when the executable/config pair is
      # coherent. Otherwise keep the previous plist outside launchd's
      # discovery path and remove any published dest plist.
      if [[ -n "${backup_plist:-}" && -f "$backup_plist" ]]; then
        if (( bin_ok && conf_ok )); then
          if restore_cmd -f -- "$backup_plist" "$plist_dest"; then
            backup_plist=""
          else
            failed=1
          fi
        else
          if [[ -f "$plist_dest" && "$plist_dest" != "$backup_plist" ]]; then
            rm -f -- "$plist_dest"
          fi
          {
            echo "incomplete"
            echo "binary_backup=${backup_bin:-}"
            echo "config_backup=${backup_conf:-}"
            echo "plist_backup=${backup_plist}"
          } >"${INCOMPLETE_RECOVERY_MARKER}"
          failed=1
        fi
      fi
      return "$failed"
    }

    # Invoked by the EXIT trap; shellcheck cannot see trap dispatch.
    # shellcheck disable=SC2317
    report_mixed_tree() {
      echo "macos-daemon: restore failed; live files may mix generations and must not be started" >&2
      echo "macos-daemon: live binary=$root/bin/alighieri backup=${backup_bin:-<none>}" >&2
      echo "macos-daemon: live config=$root/alighieri.conf backup=${backup_conf:-<none>}" >&2
      echo "macos-daemon: live plist=$plist_dest backup=${backup_plist:-<none>}" >&2
      echo "macos-daemon: auto-start plist withheld; marker=${INCOMPLETE_RECOVERY_MARKER:-<none>}" >&2
    }

    # Invoked by the EXIT trap; shellcheck cannot see trap dispatch.
    # shellcheck disable=SC2317
    cleanup_staged() {
      set +e
      rm -f -- ${staged_bin:+"$staged_bin"} ${staged_conf:+"$staged_conf"} ${staged_plist:+"$staged_plist"}
      if [[ "${committed:-0}" -eq 1 ]]; then
        rm -f -- ${backup_bin:+"$backup_bin"} ${backup_conf:+"$backup_conf"} ${backup_plist:+"$backup_plist"}
        return 0
      fi
      if ! restore_previous_generation; then
        report_mixed_tree
      fi
    }
    trap cleanup_staged EXIT

    inject_install_fault() {
      local point="$1"
      if [[ "${INSTALL_FAIL_AFTER:-}" == "$point" ]]; then
        fail "injected install failure at ${point}"
      fi
    }

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
    chmod_nofollow 0640 "$staged_conf"
    apply_install_ownership "root:${ACCOUNT}" "$staged_conf"
    if ! "$staged_bin" --check --config "$staged_conf"; then
      fail "configuration check failed for $staged_bin"
    fi

    staged_plist="$(mktemp "${root}/plist.XXXXXX")"
    write_plist "$root" "$staged_plist"
    chmod_nofollow 0644 "$staged_plist"
    apply_install_ownership root:wheel "$staged_plist"

    # Unload a system KeepAlive job before replacing files. Non-root staging
    # installs cannot query the system domain (CI smoke); a launchctl test
    # double still exercises the unload path.
    if is_root || [[ "$LAUNCHCTL_BIN" != /usr/bin/launchctl ]]; then
      unload_job_before_replace
    fi
    inject_install_fault after-unload

    if [[ -f "$root/bin/alighieri" ]]; then
      backup_bin="$(backup_live_file "$root/bin/alighieri" "${root}/bin/alighieri.bak.XXXXXX")" \
        || fail "failed to backup the live binary"
    fi
    if [[ -f "$root/alighieri.conf" ]]; then
      backup_conf="$(backup_live_file "$root/alighieri.conf" "${root}/alighieri.conf.bak.XXXXXX")" \
        || fail "failed to backup the live configuration"
    fi
    if [[ -f "$plist_dest" ]]; then
      backup_plist="$(backup_live_file "$plist_dest" "${root}/plist.bak.XXXXXX")" \
        || fail "failed to backup the live plist"
    fi

    if ! mv_cmd -f -- "$staged_bin" "$root/bin/alighieri"; then
      fail "failed to replace the live binary"
    fi
    staged_bin=""
    inject_install_fault after-binary
    maybe_pause_install after-binary

    if ! mv_cmd -f -- "$staged_conf" "$root/alighieri.conf"; then
      fail "failed to replace the live configuration"
    fi
    staged_conf=""
    inject_install_fault after-config

    chmod_nofollow 0640 "$root/alighieri.conf"
    inject_install_fault chmod-conf
    apply_install_ownership "root:${ACCOUNT}" "$root/alighieri.conf"
    inject_install_fault chown-conf

    if ! mv_cmd -f -- "$staged_plist" "$plist_dest"; then
      fail "failed to replace the launchd plist"
    fi
    staged_plist=""
    inject_install_fault after-plist

    apply_install_ownership root:wheel "$plist_dest"
    inject_install_fault chown-plist
    chmod_nofollow 0644 "$plist_dest"
    inject_install_fault chmod-plist

    if [[ "$start" == "1" ]]; then
      inject_install_fault bootstrap
      "$LAUNCHCTL_BIN" bootstrap system "$PLIST_PATH" \
        || fail "failed to bootstrap ${PLIST_LABEL}"
    fi

    committed=1
    rm -f -- ${INCOMPLETE_RECOVERY_MARKER:+"$INCOMPLETE_RECOVERY_MARKER"}
    trap - EXIT
    rm -f -- ${backup_bin:+"$backup_bin"} ${backup_conf:+"$backup_conf"} ${backup_plist:+"$backup_plist"}
  )
  commit_status=$?
  set -e
  [[ "$commit_status" -eq 0 ]] || exit 1
    trap - EXIT
    release_install_lock
  )
  tx_status=$?
  set -e
  [[ "$tx_status" -eq 0 ]] || return 1
}

start_daemon() {
  local start_status=0
  set +e
  (
    set -euo pipefail
    acquire_install_lock
    trap release_install_lock EXIT
    assert_no_incomplete_recovery
    require_daemon_identity
    { "$LAUNCHCTL_BIN" bootout "system/${PLIST_LABEL}" || true; }
    "$LAUNCHCTL_BIN" bootstrap system "$PLIST_PATH"
    trap - EXIT
    release_install_lock
  )
  start_status=$?
  set -e
  [[ "$start_status" -eq 0 ]] || return 1
}

selftest() {
  local tmp
  # Keep the fixture tree off /tmp and /var: on Darwin those are symlinks
  # (/tmp -> /private/tmp, /var -> /private/var) and the ancestor walk
  # must still be able to prove a successful install.
  mkdir -p target
  tmp="$(mktemp -d "${PWD}/target/alighieri-macos-daemon.XXXXXX")"
  ALIGHIERI_SELFTEST_TMP="$tmp"
  INSTALL_LOCK_DIR="$tmp/provision.lock"
  PROVISION_LOCK_DIR="$tmp/provision.lock"
  RESTORE_BIN=/bin/mv
  INSTALL_FAIL_AFTER=""
  INSTALL_PAUSE_DIR=""
  INSTALL_PAUSE_POINT=""
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
    if [ -n "${ALIGHIERI_DSCL_FAIL_CREATE_ONCE:-}" ] && [ -f "${ALIGHIERI_DSCL_FAIL_CREATE_ONCE}" ]; then
      if [ $# -ge 1 ] && [ "$rec $1" = "/Users/_alighieri UniqueID" ]; then
        rm -f "${ALIGHIERI_DSCL_FAIL_CREATE_ONCE}"
        exit 1
      fi
    fi
    if [ -n "${ALIGHIERI_DSCL_SLOW_CREATE:-}" ]; then
      sleep 0.05
    fi
    mkdir -p "$db$rec"
    if [ $# -ge 2 ]; then
      printf '%s\n' "$2" >"$db$rec/$1"
    fi
    ;;
  -read)
    rec="$1"; key="${2:-}"
    if [ -z "$key" ] && [ -n "${ALIGHIERI_DSCL_HIDE_EXISTENCE:-}" ]; then
      case "$rec" in
        /Users/_alighieri|/Groups/_alighieri)
          echo "DS Error: injected existence lookup failure" >&2
          exit 1
          ;;
      esac
    fi
    if [ -z "$key" ] && [ -n "${ALIGHIERI_DSCL_LIE_ABSENT:-}" ]; then
      case "$rec" in
        /Users/_alighieri|/Groups/_alighieri)
          echo "eDSRecordNotFound" >&2
          exit 1
          ;;
      esac
    fi
    if [ -n "${ALIGHIERI_DSCL_FAIL_READ:-}" ] && [ "$ALIGHIERI_DSCL_FAIL_READ" = "$rec ${key:-}" ]; then
      echo "DS Error: injected read failure" >&2
      exit 1
    fi
    if [ ! -d "$db$rec" ]; then
      echo "eDSRecordNotFound" >&2
      exit 1
    fi
    if [ -n "$key" ]; then
      if [ ! -f "$db$rec/$key" ]; then
        echo "No such key: $key"
        exit 0
      fi
      printf '%s: %s\n' "$key" "$(tr -d '\r' < "$db$rec/$key" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
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
state_file="${ALIGHIERI_LAUNCHCTL_STATE_FILE:?}"
if [ ! -f "$state_file" ]; then
  echo absent >"$state_file"
fi
state="$(tr -d '\r' < "$state_file")"
cmd="$1"
case "$cmd" in
  print)
    if [ "$state" = loaded ]; then
      echo "state = running"
      exit 0
    fi
    echo "Could not find service" >&2
    exit 113
    ;;
  bootout)
    if [ -n "${ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT:-}" ]; then
      echo "INJECTED bootout failure" >&2
      exit 1
    fi
    if [ "$state" = loaded ]; then
      echo absent >"$state_file"
      exit 0
    fi
    echo "Could not find service" >&2
    exit 113
    ;;
  bootstrap)
    if [ -n "${ALIGHIERI_LAUNCHCTL_FAIL_BOOTSTRAP:-}" ]; then
      echo "INJECTED bootstrap failure" >&2
      exit 1
    fi
    echo loaded >"$state_file"
    exit 0
    ;;
  *)
    echo "unexpected launchctl command: $*" >&2
    exit 2
    ;;
esac
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
  export ALIGHIERI_LAUNCHCTL_STATE_FILE="$tmp/launchctl.state"
  DSCL_BIN="$tmp/dscl.sh"
  LAUNCHCTL_BIN="$tmp/launchctl.sh"
  STAT_BIN="$tmp/stat.sh"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  echo absent >"$ALIGHIERI_LAUNCHCTL_STATE_FILE"

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
    if [ ! -d "$db$rec" ]; then
      echo "eDSRecordNotFound" >&2
      exit 1
    fi
    if [ -n "$key" ]; then
      if [ ! -f "$db$rec/$key" ]; then
        echo "No such key: $key"
        exit 0
      fi
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

  printf '%s\n' "alighieri" >"$db/Groups/_alighieri/GroupMembership"
  expect_provision_failure "unverified alighieri alias must be rejected"
  expect_install_failure "unverified alighieri alias must not install"
  [[ -d "$db/Users/_alighieri" && -d "$db/Groups/_alighieri" ]] \
    || fail "rejected alias must not modify the existing identity"
  rm -f "$db/Groups/_alighieri/GroupMembership"

  printf '%s\n' "_alighieri" "_www" >"$db/Groups/_alighieri/GroupMembership"
  expect_provision_failure "wrapped extra GroupMembership must be rejected"
  expect_install_failure "wrapped extra GroupMembership must not install"
  rm -f "$db/Groups/_alighieri/GroupMembership"

  printf '%s\n' "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" >"$db/Groups/_alighieri/GroupMembers"
  expect_provision_failure "unrelated GroupMembers GUID must be rejected"
  expect_install_failure "unrelated GroupMembers GUID must not install"
  rm -f "$db/Groups/_alighieri/GroupMembers"

  printf '%s\n' "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" >"$db/Groups/_alighieri/NestedGroups"
  expect_provision_failure "NestedGroups membership must be rejected"
  expect_install_failure "NestedGroups membership must not install"
  rm -f "$db/Groups/_alighieri/NestedGroups"

  mkdir -p "$db/Users/_www"
  printf '%s\n' 261 >"$db/Users/_www/PrimaryGroupID"
  expect_provision_failure "foreign primary-group member must be rejected"
  expect_install_failure "foreign primary-group member must not install"
  rm -rf "$db/Users/_www"

  ALIGHIERI_DSCL_FAIL_READ="/Groups/_alighieri GroupMembership"
  export ALIGHIERI_DSCL_FAIL_READ
  expect_provision_failure "failed GroupMembership lookup must fail closed"
  expect_install_failure "failed GroupMembership lookup must not install"
  unset ALIGHIERI_DSCL_FAIL_READ
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

  assert_identity_unchanged() {
    local msg="$1"
    [[ -d "$db/Users/_alighieri" ]] || fail "$msg: user record deleted"
    [[ -d "$db/Groups/_alighieri" ]] || fail "$msg: group record deleted"
    [[ "$(read_prop "/Users/_alighieri" UniqueID)" == "261" ]] \
      || fail "$msg: user UniqueID changed"
    [[ "$(read_prop "/Groups/_alighieri" PrimaryGroupID)" == "261" ]] \
      || fail "$msg: group PrimaryGroupID changed"
    [[ "$(read_prop "/Users/_alighieri" PrimaryGroupID)" == "261" ]] \
      || fail "$msg: user PrimaryGroupID changed"
  }

  # Lookup errors on existence must fail closed, not look like absence.
  ALIGHIERI_DSCL_HIDE_EXISTENCE=1
  export ALIGHIERI_DSCL_HIDE_EXISTENCE
  expect_provision_failure "existence lookup failure must fail closed"
  unset ALIGHIERI_DSCL_HIDE_EXISTENCE
  assert_identity_unchanged "existence lookup failure"

  # Existence lied as absent and the group's GID read failed: do not claim
  # ownership, overwrite the GID, or delete the pre-existing group.
  ALIGHIERI_DSCL_LIE_ABSENT=1
  export ALIGHIERI_DSCL_LIE_ABSENT
  ALIGHIERI_DSCL_FAIL_READ="/Groups/_alighieri PrimaryGroupID"
  export ALIGHIERI_DSCL_FAIL_READ
  expect_provision_failure "failed group GID read must not take deletion ownership"
  unset ALIGHIERI_DSCL_FAIL_READ
  assert_identity_unchanged "failed group GID read"

  unset ALIGHIERI_DSCL_LIE_ABSENT
  rm -rf "$db/Groups/_alighieri"
  ALIGHIERI_DSCL_LIE_ABSENT=1
  export ALIGHIERI_DSCL_LIE_ABSENT
  ALIGHIERI_DSCL_FAIL_READ="/Users/_alighieri UniqueID"
  export ALIGHIERI_DSCL_FAIL_READ
  expect_provision_failure "failed user UniqueID read must not take deletion ownership"
  unset ALIGHIERI_DSCL_FAIL_READ
  unset ALIGHIERI_DSCL_LIE_ABSENT
  [[ -d "$db/Users/_alighieri" ]] || fail "failed user UniqueID read: user record deleted"
  [[ "$(read_prop "/Users/_alighieri" UniqueID)" == "261" ]] \
    || fail "failed user UniqueID read: UniqueID changed"
  [[ "$(read_prop "/Users/_alighieri" PrimaryGroupID)" == "261" ]] \
    || fail "failed user UniqueID read: user PrimaryGroupID changed"
  [[ ! -d "$db/Groups/_alighieri" ]] \
    || fail "failed user UniqueID read: must not leave a group after rollback"
  reset_valid_identity

  mkdir "$INSTALL_LOCK_DIR"
  INSTALL_LOCK_RETRIES=3
  PROVISION_LOCK_RETRIES=3
  expect_provision_failure "held provision lock must fail"
  INSTALL_LOCK_RETRIES=100
  PROVISION_LOCK_RETRIES=100
  [[ -d "$db/Users/_alighieri" ]] || fail "lock failure must not delete identity"
  rmdir "$INSTALL_LOCK_DIR"

  # Two provisioners at the create boundary: one fails UniqueID assignment,
  # the other must still leave a complete identity.
  rm -rf "$db/Users/_alighieri" "$db/Groups/_alighieri"
  rmdir "$PROVISION_LOCK_DIR" 2>/dev/null || true
  : >"$tmp/fail-uid-once"
  ALIGHIERI_DSCL_FAIL_CREATE_ONCE="$tmp/fail-uid-once"
  export ALIGHIERI_DSCL_FAIL_CREATE_ONCE
  ALIGHIERI_DSCL_SLOW_CREATE=1
  export ALIGHIERI_DSCL_SLOW_CREATE
  rm -f "$tmp/p1.ok" "$tmp/p2.ok"
  local p1_pid="" p2_pid=""
  ( set -euo pipefail; provision; echo ok >"$tmp/p1.ok" ) &
  p1_pid=$!
  ( set -euo pipefail; provision; echo ok >"$tmp/p2.ok" ) &
  p2_pid=$!
  wait "$p1_pid" || true
  wait "$p2_pid" || true
  unset ALIGHIERI_DSCL_FAIL_CREATE_ONCE ALIGHIERI_DSCL_SLOW_CREATE
  [[ -d "$db/Users/_alighieri" && -d "$db/Groups/_alighieri" ]] \
    || fail "concurrent provision must leave a complete identity"
  [[ -f "$tmp/p1.ok" || -f "$tmp/p2.ok" ]] \
    || fail "concurrent provision: both attempts failed"
  user_matches "$(read_prop "/Users/_alighieri" UniqueID)" "$(read_prop "/Groups/_alighieri" PrimaryGroupID)" \
    || fail "concurrent provision left a mismatched identity"
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
  printf '%s\n' '#!/bin/sh' '# gen-old' 'exit 0' >"$tmp/fake-bin"
  chmod +x "$tmp/fake-bin"
  printf '%s\n' '# gen-old-conf' 'internal: 127.0.0.1 port = 1080' >"$tmp/fake.conf"
  printf '%s\n' '#!/bin/sh' '# gen-new' 'exit 0' >"$tmp/dummy-bin"
  chmod +x "$tmp/dummy-bin"
  printf '%s\n' '# gen-new-conf' 'internal: 127.0.0.1 port = 1080' >"$tmp/dummy.conf"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  install_tree "$root" "$tmp/fake-bin" "$tmp/fake.conf" 0
  [[ -x "$root/bin/alighieri" ]] || fail "installed binary missing"
  [[ -f "$root/alighieri.conf" ]] || fail "installed config missing"
  grep -Fq "<integer>63</integer>" "$root/${PLIST_LABEL}.plist" \
    || fail "generated plist missing Umask 63 (077 octal)"
  grep -Fq "${root}/bin/alighieri" "$root/${PLIST_LABEL}.plist" \
    || fail "generated plist missing staged binary path"
  grep -Fq '# gen-old' "$root/bin/alighieri" \
    || fail "installed binary is not the old generation"
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
fail_src="${ALIGHIERI_MV_FAIL_SRC:-}"
last=""
src=""
for arg do
  case "$arg" in
    -*)
      ;;
    *)
      if [ -z "$src" ]; then
        src="$arg"
      fi
      last="$arg"
      ;;
  esac
done
if [ -n "$fail_dest" ] && [ "$last" = "$fail_dest" ]; then
  echo "INJECTED mv failure: $last" >&2
  exit 1
fi
if [ -n "$fail_src" ] && [ "$src" = "$fail_src" ]; then
  echo "INJECTED mv source failure: $src" >&2
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
    grep -Fq '# gen-old' "$root/bin/alighieri" \
      || fail "$msg: live binary is not the old generation"
    grep -Fq '# gen-old-conf' "$root/alighieri.conf" \
      || fail "$msg: live config is not the old generation"
    if grep -Fq '# gen-new' "$root/bin/alighieri"; then
      fail "$msg: live binary is the new generation"
    fi
  }

  mark_job_loaded() {
    echo loaded >"$ALIGHIERI_LAUNCHCTL_STATE_FILE"
  }

  expect_unloaded_retained() {
    local msg="$1"
    expect_retained_live_tree "$msg"
    grep -Fq bootout "$ALIGHIERI_LAUNCHCTL_LOG" \
      || fail "$msg: must bootout before replacing files"
    if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
      fail "$msg: must not bootstrap"
    fi
    [[ "$(tr -d '\r' <"$ALIGHIERI_LAUNCHCTL_STATE_FILE")" == "absent" ]] \
      || fail "$msg: job must remain unloaded"
  }

  fail_install_capturing() {
    local status=0
    set +e
    ( set -euo pipefail; install_tree "$root" "$tmp/dummy-bin" "$tmp/dummy.conf" 1 )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$1"
  }

  assert_no_empty_backups() {
    local f
    for f in "$root/bin/alighieri.bak."* "$root/alighieri.conf.bak."* "$root/plist.bak."*; do
      [[ -e "$f" ]] || continue
      [[ -s "$f" ]] || fail "empty backup placeholder remains: $f"
    done
  }

  # Loaded job whose unload fails: do not replace any live file.
  mark_job_loaded
  ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT=1
  export ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed bootout of a loaded job must fail the install"
  expect_retained_live_tree "failed bootout of a loaded job"
  [[ "$(tr -d '\r' <"$ALIGHIERI_LAUNCHCTL_STATE_FILE")" == "loaded" ]] \
    || fail "failed bootout must leave the job loaded"
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed bootout must not bootstrap"
  fi
  unset ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT

  # Unexpected launchctl verbs must be rejected by the double.
  if ( "$LAUNCHCTL_BIN" blame "system/${PLIST_LABEL}" ); then
    fail "unexpected launchctl command must fail"
  fi

  # Absent job remains a valid fresh-install / --no-start case (already
  # installed above). Confirm print-not-found does not require bootout.
  echo absent >"$ALIGHIERI_LAUNCHCTL_STATE_FILE"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  install_tree "$root" "$tmp/fake-bin" "$tmp/fake.conf" 0
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "absent-job --no-start must not bootstrap"
  fi
  grep -Fq '# gen-old' "$root/bin/alighieri" \
    || fail "absent-job reinstall must keep a coherent generation"
  live_bin_hash="$(cksum <"$root/bin/alighieri")"
  live_conf_hash="$(cksum <"$root/alighieri.conf")"
  live_plist_hash="$(cksum <"$root/${PLIST_LABEL}.plist")"

  MV_BIN="$tmp/mv.sh"

  # Fail each live-to-backup move independently. The original must survive
  # and an empty mktemp placeholder must not be restored over it.
  mark_job_loaded
  ALIGHIERI_MV_FAIL_SRC="$root/bin/alighieri"
  export ALIGHIERI_MV_FAIL_SRC
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed binary backup must fail the install"
  expect_unloaded_retained "failed binary backup"
  [[ -s "$root/bin/alighieri" ]] || fail "failed binary backup left a zero-byte original"
  assert_no_empty_backups
  unset ALIGHIERI_MV_FAIL_SRC

  mark_job_loaded
  ALIGHIERI_MV_FAIL_SRC="$root/alighieri.conf"
  export ALIGHIERI_MV_FAIL_SRC
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed config backup must fail the install"
  expect_unloaded_retained "failed config backup"
  [[ -s "$root/alighieri.conf" ]] || fail "failed config backup left a zero-byte original"
  assert_no_empty_backups
  unset ALIGHIERI_MV_FAIL_SRC

  mark_job_loaded
  ALIGHIERI_MV_FAIL_SRC="$root/${PLIST_LABEL}.plist"
  export ALIGHIERI_MV_FAIL_SRC
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed plist backup must fail the install"
  expect_unloaded_retained "failed plist backup"
  [[ -s "$root/${PLIST_LABEL}.plist" ]] || fail "failed plist backup left a zero-byte original"
  assert_no_empty_backups
  unset ALIGHIERI_MV_FAIL_SRC

  mark_job_loaded
  ALIGHIERI_MV_FAIL="$root/bin/alighieri"
  export ALIGHIERI_MV_FAIL
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed live-binary rename must fail the install"
  expect_unloaded_retained "failed live-binary rename"

  mark_job_loaded
  ALIGHIERI_MV_FAIL="$root/alighieri.conf"
  export ALIGHIERI_MV_FAIL
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed live-config rename must fail the install"
  expect_unloaded_retained "failed live-config rename"

  mark_job_loaded
  ALIGHIERI_MV_FAIL="$root/${PLIST_LABEL}.plist"
  export ALIGHIERI_MV_FAIL
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  fail_install_capturing "failed plist rename must fail the install"
  expect_unloaded_retained "failed plist rename"
  unset ALIGHIERI_MV_FAIL
  MV_BIN=/bin/mv

  # Every operation after binary replacement, including ownership and
  # bootstrap, must leave a coherent recoverable generation.
  local point
  for point in after-binary after-config chmod-conf chown-conf after-plist chown-plist chmod-plist bootstrap; do
    INSTALL_FAIL_AFTER="$point"
    mark_job_loaded
    : >"$ALIGHIERI_LAUNCHCTL_LOG"
    fail_install_capturing "injected failure at ${point} must fail the install"
    expect_unloaded_retained "injected failure at ${point}"
  done
  INSTALL_FAIL_AFTER=""

  # Config replacement fails and restoring the previous binary also fails:
  # keep the backup, report it, and do not bootstrap the mixed pair.
  cat >"$tmp/restore-fail.sh" <<EOF
#!/bin/sh
set -eu
last=""
for last do
  :
done
if [ "\$last" = "$root/bin/alighieri" ]; then
  echo "INJECTED restore failure: \$last" >&2
  exit 1
fi
exec /bin/mv "\$@"
EOF
  chmod +x "$tmp/restore-fail.sh"
  RESTORE_BIN="$tmp/restore-fail.sh"
  MV_BIN="$tmp/mv.sh"
  ALIGHIERI_MV_FAIL="$root/alighieri.conf"
  export ALIGHIERI_MV_FAIL
  mark_job_loaded
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  local restore_err="" restore_status=0
  set +e
  restore_err="$( ( set -euo pipefail; install_tree "$root" "$tmp/dummy-bin" "$tmp/dummy.conf" 1 ) 2>&1 )"
  restore_status=$?
  set -e
  [[ "$restore_status" -ne 0 ]] || fail "failed restore must fail the install"
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "failed restore must not bootstrap the mixed pair"
  fi
  grep -Fq bootout "$ALIGHIERI_LAUNCHCTL_LOG" \
    || fail "failed restore must bootout so KeepAlive cannot activate the mixed pair"
  grep -Fq '# gen-new' "$root/bin/alighieri" \
    || fail "failed restore must leave the new binary in place"
  grep -Fq '# gen-old-conf' "$root/alighieri.conf" \
    || fail "failed restore must leave the previous config in place"
  local bak=""
  bak="$(printf '%s\n' "$root/bin/alighieri.bak."*)"
  [[ -n "$bak" && -f "$bak" ]] \
    || fail "failed restore must retain the binary backup"
  grep -Fq "$bak" <<<"$restore_err" \
    || fail "failed restore must report the backup path"
  grep -Fq "restore failed" <<<"$restore_err" \
    || fail "failed restore must report the mixed live state"
  grep -Fq '# gen-old' "$bak" \
    || fail "retained backup is not the old generation"
  [[ ! -f "$root/${PLIST_LABEL}.plist" ]] \
    || fail "failed binary restore must not restore an auto-start plist"
  [[ -f "$root/.alighieri-incomplete-recovery" ]] \
    || fail "failed binary restore must record incomplete recovery"
  local plist_bak=""
  plist_bak="$(printf '%s\n' "$root/plist.bak."*)"
  [[ -n "$plist_bak" && -f "$plist_bak" ]] \
    || fail "failed binary restore must retain the previous plist outside launchd"
  grep -Fq "<key>RunAtLoad</key>" "$plist_bak" \
    || fail "retained plist is not a launchd job"
  grep -Fq "<key>KeepAlive</key>" "$plist_bak" \
    || fail "retained plist is missing KeepAlive"
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( start_daemon ); then
    fail "start must reject incomplete recovery"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "start must not bootstrap a mixed generation"
  fi
  unset ALIGHIERI_MV_FAIL
  MV_BIN=/bin/mv
  RESTORE_BIN=/bin/mv
  restore_cmd -f -- "$bak" "$root/bin/alighieri" \
    || fail "could not put the old generation back after the restore-failure fixture"
  restore_cmd -f -- "$plist_bak" "$root/${PLIST_LABEL}.plist" \
    || fail "could not restore the withheld plist after the restore-failure fixture"
  rm -f -- "$root/.alighieri-incomplete-recovery"
  expect_retained_live_tree "after recovering from the restore-failure fixture"

  # Two installers at a publication boundary: A pauses after publishing the
  # binary, B must wait, A then fails and rolls back, B installs a complete
  # generation. start must not run while A holds the transaction lock.
  printf '%s\n' '#!/bin/sh' '# gen-b' 'exit 0' >"$tmp/b-bin"
  chmod +x "$tmp/b-bin"
  printf '%s\n' '# gen-b-conf' 'internal: 127.0.0.1 port = 1080' >"$tmp/b.conf"
  rm -rf "$tmp/pause" "$tmp/a.status" "$tmp/b.status"
  mkdir -p "$tmp/pause"
  INSTALL_PAUSE_DIR="$tmp/pause"
  INSTALL_PAUSE_POINT=after-binary
  INSTALL_FAIL_AFTER=after-config
  mark_job_loaded
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  ( set -euo pipefail; install_tree "$root" "$tmp/dummy-bin" "$tmp/dummy.conf" 0; echo 0 >"$tmp/a.status" ) &
  local a_pid=$!
  local waited=0
  while [[ ! -f "${INSTALL_PAUSE_DIR}/ready" ]]; do
    waited=$((waited + 1))
    if (( waited > 100 )); then
      fail "installer A did not pause after binary publication"
    fi
    sleep 0.05
  done
  INSTALL_LOCK_RETRIES=3
  PROVISION_LOCK_RETRIES=3
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  if ( start_daemon ); then
    fail "start must not run during another install transaction"
  fi
  if grep -Fq bootstrap "$ALIGHIERI_LAUNCHCTL_LOG"; then
    fail "start during an install transaction must not bootstrap"
  fi
  INSTALL_LOCK_RETRIES=100
  PROVISION_LOCK_RETRIES=100
  INSTALL_PAUSE_POINT=""
  INSTALL_FAIL_AFTER=""
  ( set -euo pipefail; install_tree "$root" "$tmp/b-bin" "$tmp/b.conf" 0; echo 0 >"$tmp/b.status" ) &
  local b_pid=$!
  printf 'go\n' >"${INSTALL_PAUSE_DIR}/go"
  wait "$a_pid" || true
  wait "$b_pid" || true
  INSTALL_PAUSE_DIR=""
  [[ ! -f "$tmp/a.status" ]] || fail "installer A must fail and roll back"
  [[ -f "$tmp/b.status" ]] || fail "installer B must complete"
  grep -Fq '# gen-b' "$root/bin/alighieri" \
    || fail "overlapping installs must leave B's complete binary"
  grep -Fq '# gen-b-conf' "$root/alighieri.conf" \
    || fail "overlapping installs must leave B's complete config"
  grep -Fq "${root}/bin/alighieri" "$root/${PLIST_LABEL}.plist" \
    || fail "overlapping installs must leave a coherent plist"

  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  install_tree "$root" "$tmp/dummy-bin" "$tmp/dummy.conf" 1
  grep -Fq "bootstrap system ${PLIST_PATH}" "$ALIGHIERI_LAUNCHCTL_LOG" \
    || fail "successful install with start must bootstrap"
  grep -Fq '# gen-new' "$root/bin/alighieri" \
    || fail "successful upgrade must install the new generation"

  # start_daemon ignores a failed bootout and then bootstraps.
  mark_job_loaded
  ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT=1
  export ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT
  : >"$ALIGHIERI_LAUNCHCTL_LOG"
  start_daemon
  unset ALIGHIERI_LAUNCHCTL_FAIL_BOOTOUT
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
