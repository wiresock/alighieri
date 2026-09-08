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
  elif grep -Fq "<string>${expected}</string>" "$plist"; then
    actual="$expected"
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
expect_plist_string doc/macos-launchagent.plist LimitLoadToSessionType Aqua
expect_plist_missing doc/macos-launchagent.plist UserName
expect_plist_missing doc/macos-launchagent.plist StandardOutPath

expect_plist_string doc/macos-launchdaemon.plist Label com.wiresock.alighieri
expect_plist_string doc/macos-launchdaemon.plist UserName _alighieri
expect_plist_string doc/macos-launchdaemon.plist GroupName _alighieri
expect_plist_integer doc/macos-launchdaemon.plist Umask 63
expect_plist_string doc/macos-launchdaemon.plist ProgramArguments.0 /opt/alighieri/bin/alighieri
expect_plist_string doc/macos-launchdaemon.plist ProgramArguments.1 /opt/alighieri/alighieri.conf
expect_plist_missing doc/macos-launchdaemon.plist StandardOutPath

[[ -x scripts/macos-daemon.sh ]] || chmod +x scripts/macos-daemon.sh

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

  # Independent assertion failures: each required key/path is checked above.
  grep -Fq "/usr/local" "$staged_plist" && fail "staged plist still mentions /usr/local"
  grep -Fq "/opt/homebrew" "$staged_plist" && fail "staged plist mentions Homebrew"
fi

echo "macos-install-smoke: ok"
