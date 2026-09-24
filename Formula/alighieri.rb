class Alighieri < Formula
  desc "Lightweight SOCKS5 proxy with Dante-inspired configuration"
  homepage "https://github.com/wiresock/alighieri"
  license "AGPL-3.0-or-later"
  # Head-only until a release contains the patched dependency set.
  # Do not add a stable `url`: the previous tag predates that set, and a
  # formula must not read a local checkout while Homebrew reloads it inside
  # the build sandbox. `brew install --HEAD` tracks GitHub main.
  head "https://github.com/wiresock/alighieri.git", branch: "main"

  # github_latest would report the previous tag as a stable update.
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
      patched dependency set. Install GitHub main with:

        brew install --HEAD alighieri

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
