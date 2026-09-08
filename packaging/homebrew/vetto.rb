class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.19"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.19/vetto-macos-aarch64.tar.gz"
      sha256 "5e0abff03602319d64d1f43642bda41ce44722c71c24553adc0507dfea368eb1"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.17/vetto-macos-x86_64.tar.gz"
      sha256 "08e0c1841081a45f812159610d0a5c05e686d0358b2d2c483756bd4fc587d9f8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.17/vetto-linux-aarch64.tar.gz"
      sha256 "6d4515b12581fc5d7dd2620a37fcc651aa0a6c5ff6550905c7847c4b994caa94"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.17/vetto-linux-x86_64.tar.gz"
      sha256 "fc12c131ff2d2ba713c16b43f1ce7e77f49597cf864abc428a4a15842997588c"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end