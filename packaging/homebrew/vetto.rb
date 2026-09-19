class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.3.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.0/vetto-macos-aarch64.tar.gz"
      sha256 "68a8adf34199fab509d76f2e089b9a67dc4652857748ed8648a082bbf9f8c806"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.0/vetto-macos-x86_64.tar.gz"
      sha256 "96d92c40d148aa73771a7146bd1db819c035a5540cd10860a9a82200a0ced071"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.0/vetto-linux-aarch64.tar.gz"
      sha256 "8a63b9a8097b9eb622e9458164006d868507de2b3f822a089e0e501ef6b2a367"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.0/vetto-linux-x86_64.tar.gz"
      sha256 "3e047e6f7664912df2de49dfdf7845b5f43de6d45b1ff504c3aa87e11c0f3de8"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end