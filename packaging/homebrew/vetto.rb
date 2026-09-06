class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.15"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.15/vetto-macos-aarch64.tar.gz"
      sha256 "5992d31b879ceecedfa7440ac7e0811888174e0f25a4dccadbafb537812c729f"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.15/vetto-macos-x86_64.tar.gz"
      sha256 "bde9091d5cb8ddc4115971d3e0bf4ec60a2358f6b3e38072062d1e76993d99d4"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.15/vetto-linux-aarch64.tar.gz"
      sha256 "3a52accb9b702546b0924f5a64baef5e383aeb9c282cd8dda3e3e895e78ccb11"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.15/vetto-linux-x86_64.tar.gz"
      sha256 "2f2b33232adb1f60e15a474d6d04a46423a236d66866ba2bfd82f518c39894ce"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end