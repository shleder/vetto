class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.2.23"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.23/vetto-macos-aarch64.tar.gz"
      sha256 "ebcc2b7375cd19caed2969f95ea6a1f22c4eba74408ed460c37e377db73d72d1"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.23/vetto-macos-x86_64.tar.gz"
      sha256 "a2bd271442d03a10315cb2a235cf1379a943b6c8482c66ec4bca9902ddebbf0e"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.2.23/vetto-linux-aarch64.tar.gz"
      sha256 "c2f0814cc22e030261a719ff248d5949a50a75ffbf727f8db748df028c1fa2b4"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.2.23/vetto-linux-x86_64.tar.gz"
      sha256 "68a952a752218fa155659a5e2563ea2969f71eb7504f5bfe01bb917df4ee4992"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end