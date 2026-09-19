class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.3.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.2/vetto-macos-aarch64.tar.gz"
      sha256 "44be7f5a852cb70a1fa6165b10ba9741ee992b90fe2bd7be924eb4e26885c937"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.2/vetto-macos-x86_64.tar.gz"
      sha256 "b19ef0834ec45694a771fb291452471ad308fe457ea308f7c6a719c93f44830a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.2/vetto-linux-aarch64.tar.gz"
      sha256 "fa545eecdd2b84d7bd6b8ef3665cfe699fe5a1b0450877aa450bec397d8300cf"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.2/vetto-linux-x86_64.tar.gz"
      sha256 "764d908bb99dd8dab76027dd69c5e502876d8233bcb23c6984451ae1e83c548e"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end