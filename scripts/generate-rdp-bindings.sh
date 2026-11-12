#!/usr/bin/env bash
# Regenerate src/rdp/windows/bindings.rs, the Win32/COM bindings used by the
# `rdp` feature, from Microsoft's Win32 metadata.
#
#   scripts/generate-rdp-bindings.sh          rewrite the committed file
#   scripts/generate-rdp-bindings.sh --check  fail if the committed file is stale
#
# The `windows` crate stopped at 0.62, so these bindings are generated with
# windows-bindgen (tools/rdp-bindings) instead. The bundled windows-bindgen
# metadata omits the Remote Desktop DVC interfaces (IWTSPlugin and friends), so
# the full metadata package is downloaded and pinned by version and SHA-256.
# To add an API, list it in tools/rdp-bindings/filter.txt and rerun this script.
# Requires curl, unzip, sha256sum or shasum, and a Rust toolchain >= 1.95 with
# rustfmt.
set -euo pipefail

METADATA_VERSION="71.0.45-preview"
METADATA_SHA256="c26f8ac7190dcd5599d074b534c5e2c1860cca84e107a63090ac22aceb7ad556"
METADATA_URL="https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.win32metadata/${METADATA_VERSION}/microsoft.windows.sdk.win32metadata.${METADATA_VERSION}.nupkg"

check=false
case "${1:-}" in
  "") ;;
  --check) check=true ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
committed="${root}/src/rdp/windows/bindings.rs"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --retry 3 -o "${tmp}/metadata.nupkg" "$METADATA_URL"
if command -v sha256sum >/dev/null 2>&1; then
  echo "${METADATA_SHA256}  ${tmp}/metadata.nupkg" | sha256sum --check --strict --quiet -
else
  echo "${METADATA_SHA256}  ${tmp}/metadata.nupkg" | shasum -a 256 --check --strict --quiet -
fi
unzip -q -o "${tmp}/metadata.nupkg" Windows.Win32.winmd -d "$tmp"

output="$committed"
if "$check"; then
  output="${tmp}/bindings.rs"
fi

cargo run --quiet --locked \
  --manifest-path "${root}/tools/rdp-bindings/Cargo.toml" \
  --target-dir "${root}/target/rdp-bindings" \
  -- "${tmp}/Windows.Win32.winmd" "$output" "$METADATA_VERSION"

if "$check"; then
  if ! diff -u "$committed" "$output"; then
    echo "src/rdp/windows/bindings.rs is stale: run scripts/generate-rdp-bindings.sh" >&2
    exit 1
  fi
  echo "src/rdp/windows/bindings.rs is up to date"
fi
