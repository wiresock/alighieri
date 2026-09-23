class Alighieri < Formula
  desc "Lightweight SOCKS5 proxy with Dante-inspired configuration"
  homepage "https://github.com/wiresock/alighieri"
  # Repository formula. There is no stable archive until a release contains
  # the patched dependency set, so this is head-only unless a local checkout
  # is selected. Do not point `url` at an untagged branch or an older tag.
  #
  #   HOMEBREW_ALIGHIERI_SOURCE=/path/to/checkout
  #     builds that git revision (development and PR testing)
  #   brew install --HEAD
  #     builds GitHub main
  #
  # A plain `brew install` with neither of those refuses before fetching.
  src = ENV.fetch("HOMEBREW_ALIGHIERI_SOURCE", "").strip
  unless src.empty?
    odie "HOMEBREW_ALIGHIERI_SOURCE is not a directory: #{src}" unless File.directory?(src)

    rev = IO.popen(["git", "-C", src, "rev-parse", "--verify", "HEAD"], err: File::NULL, &:read).to_s.strip
    odie "HOMEBREW_ALIGHIERI_SOURCE is not a git checkout: #{src}" unless /^[0-9a-f]{40}$/.match?(rev)

    url "file://#{src}", using: :git, revision: rev

    # A git checkout has no version embedded in the URL. Use the crate
    # version the selected tree declares. This is not a public tag and must
    # not be hardcoded to whatever release happens to be current.
    cargo_toml = File.join(src, "Cargo.toml")
    crate_version = File.read(cargo_toml)[/^version\s*=\s*"([^"]+)"/, 1]
    odie "could not read the crate version from #{cargo_toml}" if crate_version.to_s.empty?

    version crate_version
  end
  license "AGPL-3.0-or-later"
  head "https://github.com/wiresock/alighieri.git", branch: "main"

  # github_latest would report the previous tag as a stable update. There is
  # no patched archive to track until one is published.
  livecheck do
    skip "No stable archive until a release contains the patched dependency set"
  end

  depends_on "rust" => :build

  deny_network_access!

  def fetch
    system "cargo", "fetch", "--locked", "--target", "host-tuple"
  end

  def install
    system "cargo", "install", "--bin", "alighieri", *std_cargo_args
    etc.install "doc/alighieri.conf"
  end

  def caveats
    <<~EOS
      This formula lives in the Alighieri repository. It is not in
      Homebrew/core and there is no WireSock tap.

      There is no stable Homebrew source until a release contains the
      patched dependency set. Set HOMEBREW_ALIGHIERI_SOURCE to a checkout
      to build that revision, or install GitHub main with --HEAD.
      A plain install does not build a tagged archive.

      Default config:
        #{etc}/alighieri.conf

      `brew services` runs a per-user service on the example loopback
      listener (127.0.0.1:1080). After editing that config, apply it with
      `brew services restart alighieri`. Homebrew generates its own
      service job. This is not the manual per-user LaunchAgent and it is
      not the hardened public-TLS LaunchDaemon (dedicated _alighieri
      account under /opt/alighieri), which is still:

        sudo ./scripts/macos-daemon.sh

      and is not managed by Homebrew.
    EOS
  end

  service do
    run [opt_bin/"alighieri", "--config", etc/"alighieri.conf"]
    keep_alive true
    working_dir var
    log_path var/"log/alighieri.log"
    error_log_path var/"log/alighieri.log"
  end

  test do
    output = shell_output("#{bin}/alighieri --version")
    assert_match(/^alighieri /, output)
    system bin/"alighieri", "--check", "--config", etc/"alighieri.conf"
  end
end
