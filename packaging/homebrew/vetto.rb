class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.1"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.1/vetto-macos-aarch64.tar.gz"
      sha256 "111aa30fb6e0efba132f99a0da070924b2e76e3d891735befcb4c15734ed2655"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.1/vetto-macos-x86_64.tar.gz"
      sha256 "cf69b306c4604e988672eaa34f7cbad16a7df77ab669ca85716f7683687fbd13"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.1/vetto-linux-aarch64.tar.gz"
      sha256 "33bd123ec55d3942981a67b17f4d292f094621f1fbe7023bb1ce01dc7a0c7218"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.1/vetto-linux-x86_64.tar.gz"
      sha256 "0e04f48828ecb98de1af79d42315fe07dae39bf34bffb97a8b69c5788240924d"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end
