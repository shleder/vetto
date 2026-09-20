class Vetto < Formula
  desc "Daemon-less OS sandbox and subagent security layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  version "0.3.10"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.10/vetto-macos-aarch64.tar.gz"
      sha256 "301c733726a4c466f6a440f65077341b66bab8610d305fcea714e33377b7f61b"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.10/vetto-macos-x86_64.tar.gz"
      sha256 "2bdcf411dea142a23cc38b5a69ea5529ecee74449f92263ec87ab553d881f6e3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/shleder/vetto/releases/download/v0.3.10/vetto-linux-aarch64.tar.gz"
      sha256 "2762072d938cf4331e79ebf9d068c84b71297e38602822eb1fc5c05916811b1d"
    else
      url "https://github.com/shleder/vetto/releases/download/v0.3.10/vetto-linux-x86_64.tar.gz"
      sha256 "b7edf41fdfb25e05f376656171246c88514af1baf0cd07cf6e9b1232814ecb1d"
    end
  end

  def install
    bin.install "vetto"
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end