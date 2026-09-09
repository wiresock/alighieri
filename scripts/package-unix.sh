#!/usr/bin/env bash
# Build a Linux or macOS release directory/archive from already-built binaries.
# Used by the release workflow and by CI packaging smokes.
set -euo pipefail

usage() {
  echo "usage: $0 --os linux|macos --target TRIPLE --version VERSION --bindir DIR [--archive]" >&2
  exit 2
}

os=""
target=""
version=""
bindir=""
make_archive=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --os)
      os="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --bindir)
      bindir="${2:-}"
      shift 2
      ;;
    --archive)
      make_archive=1
      shift
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$os" && -n "$target" && -n "$version" && -n "$bindir" ]] || usage
[[ "$os" == "linux" || "$os" == "macos" ]] || usage

dir="alighieri-v${version}-${target}"
rm -rf "$dir"
mkdir -p "$dir/doc/templates"

install -m 755 "$bindir/alighieri" "$dir/alighieri"
install -m 644 doc/alighieri.conf "$dir/doc/alighieri.conf"
install -m 644 doc/acme-tls-test.md "$dir/doc/acme-tls-test.md"
install -m 644 doc/management-cli.md "$dir/doc/management-cli.md"
install -m 644 doc/templates/public-tls-proxifyre.conf \
  "$dir/doc/templates/public-tls-proxifyre.conf"
install -m 644 README.md LICENSE LICENSING.md CHANGELOG.md "$dir/"

required=(
  "$dir/alighieri"
  "$dir/README.md"
  "$dir/LICENSE"
  "$dir/LICENSING.md"
  "$dir/CHANGELOG.md"
  "$dir/doc/alighieri.conf"
  "$dir/doc/acme-tls-test.md"
  "$dir/doc/management-cli.md"
  "$dir/doc/templates/public-tls-proxifyre.conf"
)

if [[ "$os" == "linux" ]]; then
  mkdir -p "$dir/scripts"
  install -m 755 "$bindir/alighieri-installer-fs" "$dir/alighieri-installer-fs"
  install -m 755 scripts/alighieri.sh "$dir/scripts/alighieri.sh"
  required+=(
    "$dir/alighieri-installer-fs"
    "$dir/scripts/alighieri.sh"
  )
  test ! -e "$dir/doc/macos-launchagent.plist"
  test ! -e "$dir/scripts/macos-daemon.sh"
  test ! -e "$dir/alighieri-rdp-transport"
  test ! -e "$dir/alighieri-rdp-agent"
else
  mkdir -p "$dir/scripts"
  install -m 644 doc/macos-launchagent.plist "$dir/doc/macos-launchagent.plist"
  install -m 644 doc/macos-launchdaemon.plist "$dir/doc/macos-launchdaemon.plist"
  install -m 755 scripts/macos-daemon.sh "$dir/scripts/macos-daemon.sh"
  required+=(
    "$dir/doc/macos-launchagent.plist"
    "$dir/doc/macos-launchdaemon.plist"
    "$dir/scripts/macos-daemon.sh"
  )
  test ! -e "$dir/alighieri-installer-fs"
  test ! -e "$dir/alighieri-rdp-transport"
  test ! -e "$dir/alighieri-rdp-agent"
  test ! -e "$dir/scripts/alighieri.sh"
fi

test -x "$dir/alighieri"
for path in "${required[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "required package file is missing: $path" >&2
    exit 1
  fi
done

if [[ "$make_archive" -eq 1 ]]; then
  tar czf "$dir.tar.gz" "$dir"
  archive_contents="$(tar tzf "$dir.tar.gz")"
  while IFS= read -r path; do
    rel="${path#"$dir"/}"
    grep -Fqx "$dir/$rel" <<<"$archive_contents"
  done < <(find "$dir" -type f)
  printf '%s\n' "$dir.tar.gz"
else
  printf '%s\n' "$dir"
fi
