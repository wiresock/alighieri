#!/usr/bin/env bash
# Write a temporary tap formula that installs an immutable archive of HEAD.
# The committed formula stays head-only. Formula evaluation must not read
# the working tree: Homebrew reloads the formula inside the build sandbox,
# which cannot see the GitHub workspace.
set -euo pipefail

dest="${1:?tap formula path}"
root="$(cd "$(dirname "$0")/.." && pwd)"
rev="$(git -C "$root" rev-parse HEAD)"
work="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
work="${work%/}"
archive="${work}/alighieri-${rev}.tar.gz"
meta="${work}/alighieri-pr-source.env"

git -C "$root" archive --format=tar.gz --output="$archive" "$rev"

python3 - "$root/Formula/alighieri.rb" "$dest" "$archive" "$rev" "$meta" <<'PY'
import hashlib
import pathlib
import re
import sys
import tarfile

formula_path, dest, archive, revision, meta_path = sys.argv[1:]
archive_path = pathlib.Path(archive)
data = archive_path.read_bytes()
sha = hashlib.sha256(data).hexdigest()

with tarfile.open(archive_path, "r:gz") as tar:
    cargo_toml = tar.extractfile("Cargo.toml")
    cargo_lock = tar.extractfile("Cargo.lock")
    if cargo_toml is None or cargo_lock is None:
        sys.exit("PR archive is missing Cargo.toml or Cargo.lock")
    toml_text = cargo_toml.read().decode("utf-8").replace("\r\n", "\n")
    lock_text = cargo_lock.read().decode("utf-8").replace("\r\n", "\n")

version = None
for line in toml_text.splitlines():
    if line.startswith('version = "'):
        version = line.split('"', 2)[1]
        break
if not version:
    sys.exit("could not read the crate version from the PR archive")

versions = []
for block in lock_text.split("[[package]]"):
    if re.search(r'^name = "rustls"$', block, re.M):
        match = re.search(r'^version = "([^"]+)"', block, re.M)
        versions.append(match.group(1) if match else "")
if not versions:
    sys.exit("PR archive Cargo.lock has no rustls package")

def parse(value):
    core = value.split("-", 1)[0].split("+", 1)[0]
    parts = []
    for part in core.split("."):
        if not part.isdigit():
            sys.exit(f"unparseable rustls version {value}")
        parts.append(int(part))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

floor = (0, 23, 45)  # RUSTSEC-2026-0285 fixed rustls 0.23.40
for found in versions:
    if parse(found) < floor:
        sys.exit(
            f"PR archive rustls {found} is older than 0.23.45 (RUSTSEC-2026-0285)"
        )

text = pathlib.Path(formula_path).read_text(encoding="utf-8")
if "HOMEBREW_ALIGHIERI_SOURCE" in text or "v0.6.0.tar.gz" in text:
    sys.exit("committed formula is not head-only")
needle = 'homepage "https://github.com/wiresock/alighieri"\n'
url = archive_path.resolve().as_posix()
if not url.startswith("/"):
    sys.exit(f"archive path is not absolute: {url}")
insert = (
    needle
    + f'  url "file://{url}"\n'
    + f'  sha256 "{sha}"\n'
    + f'  version "{version}"\n'
)
if needle not in text:
    sys.exit("could not find the homepage line in the committed formula")
pathlib.Path(dest).write_text(text.replace(needle, insert, 1), encoding="utf-8")
pathlib.Path(meta_path).write_text(
    "\n".join(
        [
            f"ALIGHIERI_PR_REVISION={revision}",
            f"ALIGHIERI_PR_SHA256={sha}",
            f"ALIGHIERI_PR_ARCHIVE={archive_path.resolve().as_posix()}",
            f"ALIGHIERI_PR_VERSION={version}",
            f"ALIGHIERI_PR_RUSTLS={','.join(versions)}",
            "",
        ]
    ),
    encoding="utf-8",
)
print(f"PR archive {revision} rustls {', '.join(versions)}")
PY
