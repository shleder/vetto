class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.4.7"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-macos-aarch64.tar.gz"
      sha256 "366eff431f410cd57e08e537e361f7c648fc0805e6cbf53a19879e429a6f2405"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-macos-x86_64.tar.gz"
      sha256 "0bd80f4434284df7a51443ba95cfb6b2a1819c0dd9d2351968f0c709045a3a88"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-linux-aarch64.tar.gz"
      sha256 "3891b4b4bf12904b3ce4ef444c78bee9913ba0dfb88c9541713aedf6c9236ac4"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-linux-x86_64.tar.gz"
      sha256 "50a1f94af61a9a4c30b51d284eb1ffce9bdfa6329feddbd78343c9ec6bf20252"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end