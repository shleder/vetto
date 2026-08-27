class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.2/vetto-macos-aarch64.tar.gz"
      sha256 "d8151491daf57059dd5baeee122743171019859ac0fd2f4d044703562d684788"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.2/vetto-macos-x86_64.tar.gz"
      sha256 "5a8299459087af4a7cfe2fe877674b410998f43bfd39f7a926d8e8fde43214d4"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.2/vetto-linux-aarch64.tar.gz"
      sha256 "f8c9ac02f6bfb7d72c05aa0552e0aa139d32addcf1a3a025bfee492052075f26"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.2/vetto-linux-x86_64.tar.gz"
      sha256 "39c4c89004036c16ac7ed7fa37fe828fcc97ed12ebe429ecefadc175d7c44b78"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end
