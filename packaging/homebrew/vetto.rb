class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.5"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.5/vetto-macos-aarch64.tar.gz"
      sha256 "9710e5b94bc2c28e7a644a875189f58f3b01b157e0bc620025de62a4ef8a8b1f"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.5/vetto-macos-x86_64.tar.gz"
      sha256 "6345e1b81ff5cb1faa5e1c1839d39305e83740b2a2b27e10caf65cc134bf4b41"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.5/vetto-linux-aarch64.tar.gz"
      sha256 "f7c9fcde23c0fd6983ef2dde511b88053b0c03e817e66bf5c886f0f0e3f3bc63"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.5/vetto-linux-x86_64.tar.gz"
      sha256 "deaca44700919a84a93f306c1220f2f338bab515bd2da9473df5823b7bab0369"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end