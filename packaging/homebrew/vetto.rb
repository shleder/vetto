class Vetto < Formula
  desc "Daemon-less sandbox and audit layer for AI coding agents"
  homepage "https://github.com/shleder/vetto"
  head "https://github.com/shleder/vetto.git", branch: "main"
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: ".")
  end

  test do
    assert_match "vetto", shell_output("#{bin}/vetto --version")
  end
end
