class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.4.7"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-macos-aarch64.tar.gz"
      sha256 "b0a7bcf5455de0149566e71bdfd9012567ee2f46f03ed1f97fc1fc8dc7ba2391"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-macos-x86_64.tar.gz"
      sha256 "ad8a56fa3933b5d6bba5edb799baba26a66c1d0f36f03c06796ab47c2e2feeab"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-linux-aarch64.tar.gz"
      sha256 "9d35b329f0766aa1a294eb58cc2da2c38a27062ade9d53ae3911770b0920d41d"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.4.7/vetto-linux-x86_64.tar.gz"
      sha256 "4e3cc1e4055d19a6aefadeb80ef896ff8bd265240681d7ea39e7371708bd1c52"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end