class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.16"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.16/vetto-macos-aarch64.tar.gz"
      sha256 "a84da1a82c8a672e040ce92193a272713d335aee8cc6d190b99f25dac6898548"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.16/vetto-macos-x86_64.tar.gz"
      sha256 "1d16fbbf7427e84d7776b1712601c14417920526fa28ede1e976fc8a84794346"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.16/vetto-linux-aarch64.tar.gz"
      sha256 "816aae420aa4bf352f9311e779d4e7d6ba538195f343ffb6db9e2a8eb3c13202"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.16/vetto-linux-x86_64.tar.gz"
      sha256 "c2f785e0517bf3d7ea89482892460758b77600ac22cd2c1c41eefd65afdbd645"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end