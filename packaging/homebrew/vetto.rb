class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.3.9"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.9/vetto-macos-aarch64.tar.gz"
      sha256 "07e2e20ea821dda5bce9e53b1dcf45026eeaa6f1f51537dd43837b46522810a4"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.9/vetto-macos-x86_64.tar.gz"
      sha256 "bf31a986bdbebf14d6303852b784f6416640afd2fd0d07aa5ac0d32314aca509"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.9/vetto-linux-aarch64.tar.gz"
      sha256 "b24857304709dc61b3d7bb5e43e4aebdf30f166c9e2a1c8e313360ed12094fbf"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.9/vetto-linux-x86_64.tar.gz"
      sha256 "45e699d581ae72ded672405a8d5bc982db95f2d10acc3e871251e5062a9c9c77"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end