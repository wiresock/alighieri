class Alighieri < Formula
  desc "Lightweight SOCKS5 proxy with Dante-inspired configuration"
  homepage "https://github.com/wiresock/alighieri"
  # HOMEBREW_ALIGHIERI_SOURCE=/path/to/checkout builds that tree (PR testing).
  # Otherwise the tagged GitHub archive is used; --HEAD tracks GitHub main.
  if (src = ENV.fetch("HOMEBREW_ALIGHIERI_SOURCE", nil)) && File.directory?(src)
    url "file://#{src}", using: :git
    version "0.6.0"
  else
    url "https://github.com/wiresock/alighieri/archive/refs/tags/v0.6.0.tar.gz"
    sha256 "ed9a87483a7152992974a2a59266afd9d797f131b74b6b4d9d1da58ee19bc6f8"
  end
  license "AGPL-3.0-or-later"
  head "https://github.com/wiresock/alighieri.git", branch: "main"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "rust" => :build

  deny_network_access!

  def fetch
    system "cargo", "fetch", "--locked", "--target", "host-tuple"
  end

  def install
    system "cargo", "install", "--bin", "alighieri", *std_cargo_args
    etc.install "doc/alighieri.conf"
    (var/"log").mkpath
  end

  def post_install
    (var/"log").mkpath
  end

  def caveats
    <<~EOS
      This formula lives in the Alighieri repository for local and --HEAD
      installs. It is not in Homebrew/core and there is no WireSock tap.

      Default config:
        #{etc}/alighieri.conf

      `brew services` starts a per-user LaunchAgent on the example loopback
      listener (127.0.0.1:1080). That matches the project's LaunchAgent
      model. The hardened public-TLS LaunchDaemon (dedicated _alighieri
      account under /opt/alighieri) is still:
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
