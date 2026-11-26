class Jex < Formula
  desc "CryptoPro container reader and GOST CAdES/XAdES signing tool for Rutoken"
  homepage "https://github.com/jex-crypto/jex"
  url "https://github.com/jex-crypto/jex/archive/refs/tags/v0.13.0.tar.gz"
  sha256 "2feebb59466db9eaeb3cdfcb2b174db197f03cd566f1fa276ddf74891ea55257"
  license "AGPL-3.0-or-later"
  head "https://github.com/jex-crypto/jex.git", branch: "main"

  depends_on "rust" => :build

  on_linux do
    depends_on "pkgconf" => :build
    depends_on "pcsc-lite"
  end

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    on_linux do
      <<~EOS
        Access to a Rutoken needs a running PC/SC daemon (pcscd) and a CCID
        driver. Installing them from your distribution is usually simplest,
        e.g. on Debian/Ubuntu: sudo apt install pcscd libccid
      EOS
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/jex --version")
  end
end
