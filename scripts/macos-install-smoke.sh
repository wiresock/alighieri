#!/usr/bin/env bash
# Static and staged checks for the macOS LaunchAgent/LaunchDaemon examples.
# Does not load launchd jobs or create system accounts.
set -euo pipefail

fail() {
  echo "macos-install-smoke: $*" >&2
  exit 1
}

expect_plist_string() {
  local plist="$1" key="$2" expected="$3"
  local actual=""
  if command -v plutil >/dev/null 2>&1; then
    actual="$(plutil -extract "$key" raw -o - "$plist")"
  elif [[ "$key" != *.* ]]; then
    actual="$(awk -v key="$key" '
      $0 ~ "<key>" key "</key>" { getline; gsub(/.*<string>|<\/string>.*/, ""); print; exit }
    ' "$plist")"
  else
    local prefix="${key%%.*}"
    local index="${key##*.}"
    [[ "$index" =~ ^[0-9]+$ ]] || fail "unsupported plist key $key"
    actual="$(awk -v prefix="$prefix" -v idx="$index" '
      $0 ~ "<key>" prefix "</key>" { in_arr=1; n=0; next }
      in_arr && /<string>/ {
        gsub(/.*<string>|<\/string>.*/, "")
        if (n == idx) { print; exit }
        n++
      }
      in_arr && /<\/array>/ { in_arr=0 }
    ' "$plist")"
  fi
  [[ "$actual" == "$expected" ]] || fail "$plist $key: expected $expected, got ${actual:-<missing>}"
}

expect_plist_integer() {
  local plist="$1" key="$2" expected="$3"
  local actual=""
  if command -v plutil >/dev/null 2>&1; then
    actual="$(plutil -extract "$key" raw -o - "$plist")"
  else
    actual="$(awk -v key="$key" '
      $0 ~ "<key>" key "</key>" { getline; gsub(/.*<integer>|<\/integer>.*/, ""); print; exit }
    ' "$plist")"
  fi
  [[ "$actual" == "$expected" ]] || fail "$plist $key: expected integer $expected, got ${actual:-<missing>}"
}

expect_plist_missing() {
  local plist="$1" key="$2"
  if grep -Fq "<key>$key</key>" "$plist"; then
    fail "$plist must not contain $key"
  fi
}

bash scripts/macos-daemon.sh __selftest

for plist in doc/macos-launchagent.plist doc/macos-launchdaemon.plist; do
  [[ -f "$plist" ]] || fail "missing $plist"
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$plist" >/dev/null
  fi
  grep -Eq "/opt/homebrew|/usr/local/" "$plist" \
    && fail "$plist must not point at Homebrew-controlled paths"
done

expect_plist_string doc/macos-launchagent.plist Label com.wiresock.alighieri
expect_plist_string doc/macos-launchagent.plist ProgramArguments.0 /opt/alighieri/bin/alighieri
expect_plist_string doc/macos-launchagent.plist ProgramArguments.1 __ALIGHIERI_CONFIG__
expect_plist_string doc/macos-launchagent.plist LimitLoadToSessionType Aqua
expect_plist_missing doc/macos-launchagent.plist UserName
expect_plist_missing doc/macos-launchagent.plist StandardOutPath
grep -Fq "/opt/alighieri/alighieri.conf" doc/macos-launchagent.plist \
  && fail "LaunchAgent template must not point at the daemon config"

expect_plist_string doc/macos-launchdaemon.plist Label com.wiresock.alighieri
expect_plist_string doc/macos-launchdaemon.plist UserName _alighieri
expect_plist_string doc/macos-launchdaemon.plist GroupName _alighieri
expect_plist_integer doc/macos-launchdaemon.plist Umask 63
expect_plist_string doc/macos-launchdaemon.plist ProgramArguments.0 /opt/alighieri/bin/alighieri
expect_plist_string doc/macos-launchdaemon.plist ProgramArguments.1 /opt/alighieri/alighieri.conf
expect_plist_missing doc/macos-launchdaemon.plist StandardOutPath

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  [[ "$(git ls-files -s scripts/macos-daemon.sh | awk '{print $1}')" == "100755" ]] \
    || fail "scripts/macos-daemon.sh must be committed as mode 100755"
fi
[[ -x scripts/macos-daemon.sh ]] \
  || fail "scripts/macos-daemon.sh is not executable; do not chmod in tests, fix the git file mode"

# SHA256SUMS lists every platform. Operators download one archive; check that
# entry only. A full `sha256sum -c SHA256SUMS` fails when the other archives
# are absent.
checksum_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}
sums_dir="$(mktemp -d "${PWD}/target/alighieri-checksum.XXXXXX")"
printf 'keep\n' >"$sums_dir/keep-me.tar.gz"
printf 'other\n' >"$sums_dir/other.tar.gz"
(
  cd "$sums_dir"
  checksum_tool keep-me.tar.gz other.tar.gz >SHA256SUMS
)
rm -f "$sums_dir/other.tar.gz"
(
  cd "$sums_dir"
  grep -F keep-me.tar.gz SHA256SUMS | checksum_tool -c -
) >/dev/null || fail "single-archive SHA256SUMS check failed"
if (
  cd "$sums_dir"
  checksum_tool -c SHA256SUMS
) >/dev/null 2>&1; then
  fail "full SHA256SUMS check must fail when other archives are missing"
fi
rm -rf "$sums_dir"

if [[ "$(uname -s)" == "Darwin" ]]; then
  root="${PWD}/target/alighieri-macos-smoke"
  rm -rf "$root"
  mkdir -p "$root"
  chmod 755 "$root"
  trap 'rm -rf "$root"' EXIT

  binary=""
  shopt -s nullglob
  candidates=()
  if [[ -n "${ALIGHIERI_SMOKE_BIN:-}" ]]; then
    candidates+=("${ALIGHIERI_SMOKE_BIN}")
  fi
  candidates+=(
    target/debug/alighieri
    target/release/alighieri
    target/*/release/alighieri
    target/*/debug/alighieri
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      binary="$candidate"
      break
    fi
  done
  shopt -u nullglob
  [[ -n "$binary" ]] || fail "no built Alighieri binary to stage"

  if command -v vtool >/dev/null 2>&1; then
    minos="$(vtool -show-build "$binary" | awk '/minos/ { print $2; exit }')"
    [[ -n "$minos" ]] || fail "vtool did not report a minos for $binary"
    awk -v minos="$minos" 'BEGIN {
      n = split(minos, p, ".")
      major = p[1] + 0
      minor = (n >= 2 ? p[2] : 0) + 0
      if (major < 10 || (major == 10 && minor < 14)) {
        exit 1
      }
    }' || fail "Darwin binary minos $minos is older than 10.14"
    if command -v lipo >/dev/null 2>&1 && lipo -archs "$binary" 2>/dev/null | grep -Fq x86_64; then
      awk -v minos="$minos" 'BEGIN {
        n = split(minos, p, ".")
        major = p[1] + 0
        minor = (n >= 2 ? p[2] : 0) + 0
        if (major > 10 || (major == 10 && minor > 14)) {
          exit 1
        }
      }' || fail "x86_64 Darwin minos $minos is newer than the documented 10.14 floor"
    fi
  fi

  conf="$root/generated.conf"
  cat >"$conf" <<'EOF'
internal: 127.0.0.1 port = 1080
socksmethod: none
client pass { from: 127.0.0.0/8 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }
logoutput: file
logfile: PLACEHOLDER/logs/alighieri.log
EOF
  staged_root="$root/opt/alighieri"
  mkdir -p "$(dirname "$staged_root")"
  chmod 755 "$(dirname "$staged_root")"
  sed "s|PLACEHOLDER|$staged_root|g" "$conf" >"$root/check.conf"

  scripts/macos-daemon.sh install \
    --root "$staged_root" \
    --binary "$binary" \
    --config "$root/check.conf" \
    --no-start

  [[ -x "$staged_root/bin/alighieri" ]] || fail "staged binary missing"
  "$staged_root/bin/alighieri" --check --config "$staged_root/alighieri.conf"

  staged_plist="$staged_root/com.wiresock.alighieri.plist"
  [[ -f "$staged_plist" ]] || fail "helper did not generate a plist"
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$staged_plist" >/dev/null
  fi
  expect_plist_string "$staged_plist" UserName _alighieri
  expect_plist_integer "$staged_plist" Umask 63
  expect_plist_string "$staged_plist" ProgramArguments.0 "$staged_root/bin/alighieri"
  expect_plist_string "$staged_plist" ProgramArguments.1 "$staged_root/alighieri.conf"
  mode_of() {
    local mode=""
    mode="$(stat -f '%Lp' "$1" 2>/dev/null || true)"
    if [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
      printf '%s\n' "$mode"
      return
    fi
    stat -c '%a' "$1"
  }
  [[ "$(mode_of "$staged_root/alighieri.conf")" == "640" ]] \
    || fail "staged config mode is $(mode_of "$staged_root/alighieri.conf"), expected 640"
  [[ "$(mode_of "$staged_root/acme")" == "700" ]] \
    || fail "staged acme mode is $(mode_of "$staged_root/acme"), expected 700"
  [[ "$(mode_of "$staged_root/logs")" == "700" ]] \
    || fail "staged logs mode is $(mode_of "$staged_root/logs"), expected 700"

  # Independent assertion failures: each required key/path is checked above.
  grep -Fq "/usr/local" "$staged_plist" && fail "staged plist still mentions /usr/local"
  grep -Fq "/opt/homebrew" "$staged_plist" && fail "staged plist mentions Homebrew"

  if command -v plutil >/dev/null 2>&1; then
    agent_plist="$root/agent.plist"
    cp doc/macos-launchagent.plist "$agent_plist"
    special="/Volumes/Work & Personal/alighieri.conf"
    plutil -replace ProgramArguments.1 -string "$special" "$agent_plist"
    plutil -lint "$agent_plist" >/dev/null
    expect_plist_string "$agent_plist" ProgramArguments.1 "$special"
    grep -Fq "__ALIGHIERI_CONFIG__" "$agent_plist" \
      && fail "plutil replacement left the config placeholder"
  fi
fi

echo "macos-install-smoke: ok"
