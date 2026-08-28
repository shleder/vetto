class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.3"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.3/vetto-macos-aarch64.tar.gz"
      sha256 "713a40fbc6a59ac91b89f59c3676845d7b845232010641f6b6aab75441b9f7e1"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.3/vetto-macos-x86_64.tar.gz"
      sha256 "6e70db39d71ac69422e7360fa5ea6b315fc676cf0a659c038d5c90231f1e348d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.3/vetto-linux-aarch64.tar.gz"
      sha256 "4d4b4a2f8b2c025d5ecd0184724cd116fdf4bb1d78e563360238cb4790dd59c0"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.3/vetto-linux-x86_64.tar.gz"
      sha256 "f6c8a68a380e61a4f2acffa945b9d1cdb34fb7674d5c5c3828932c40ce299f8b"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end
