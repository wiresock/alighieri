#!/usr/bin/env bash
# Static checks for the macOS LaunchAgent/LaunchDaemon examples.
# Does not load launchd jobs.
set -euo pipefail

fail() {
  echo "macos-install-smoke: $*" >&2
  exit 1
}

for plist in doc/macos-launchagent.plist doc/macos-launchdaemon.plist; do
  [[ -f "$plist" ]] || fail "missing $plist"
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$plist" >/dev/null
  fi
done

agent="$(cat doc/macos-launchagent.plist)"
daemon="$(cat doc/macos-launchdaemon.plist)"

echo "$agent" | grep -Fq "/usr/local/libexec/alighieri" \
  || fail "LaunchAgent binary is not /usr/local/libexec/alighieri"
echo "$agent" | grep -Eq "/opt/homebrew|/usr/local/bin/" \
  && fail "LaunchAgent must not point at Homebrew-replaceable paths"
echo "$agent" | grep -Fq "<key>UserName</key>" \
  && fail "LaunchAgent must run as the session user, not a system account"
echo "$agent" | grep -Fq "LimitLoadToSessionType" \
  || fail "LaunchAgent must be limited to an Aqua login session"
echo "$agent" | grep -Fq "StandardOutPath" \
  && fail "LaunchAgent must not rely on unbounded launchd stdout files"

echo "$daemon" | grep -Fq "<string>_alighieri</string>" \
  || fail "LaunchDaemon must run as the dedicated _alighieri account"
echo "$daemon" | grep -Fq "/usr/local/libexec/alighieri" \
  || fail "LaunchDaemon binary is not /usr/local/libexec/alighieri"
echo "$daemon" | grep -Eq "/opt/homebrew|/usr/local/bin/" \
  && fail "LaunchDaemon must not point at Homebrew-replaceable paths"
echo "$daemon" | grep -Fq "StandardOutPath" \
  && fail "LaunchDaemon must not rely on unbounded launchd stdout files"

if [[ "$(uname -s)" == "Darwin" ]]; then
  prefix="$(mktemp -d "${TMPDIR:-/tmp}/alighieri-macos-prefix.XXXXXX")"
  trap 'rm -rf "$prefix"' EXIT
  mkdir -p "$prefix/libexec" "$prefix/etc/alighieri" "$prefix/LaunchAgents"
  # Stage the documented layout without requiring root.
  install -m 755 "$(command -v true)" "$prefix/libexec/alighieri"
  install -m 644 doc/alighieri.conf "$prefix/etc/alighieri/alighieri.conf"
  install -m 644 doc/macos-launchagent.plist "$prefix/LaunchAgents/com.wiresock.alighieri.plist"
  [[ -x "$prefix/libexec/alighieri" ]] || fail "staged binary is not executable"
  [[ -f "$prefix/etc/alighieri/alighieri.conf" ]] || fail "staged config missing"
  program="$(sed -n 's/.*<string>\(\/usr\/local\/libexec\/alighieri\)<\/string>.*/\1/p' \
    "$prefix/LaunchAgents/com.wiresock.alighieri.plist" | head -n 1)"
  [[ "$program" == "/usr/local/libexec/alighieri" ]] \
    || fail "staged LaunchAgent ProgramArguments drifted"
fi

echo "macos-install-smoke: ok"
