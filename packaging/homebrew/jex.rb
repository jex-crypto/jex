class Jex < Formula
  desc "CryptoPro container reader and GOST CAdES/XAdES signing tool for Rutoken"
  homepage "https://github.com/jex-crypto/jex"
  url "https://github.com/jex-crypto/jex/archive/refs/tags/v0.13.1.tar.gz"
  sha256 "49f142ddc98117fc818fd9c4e3c0161a1e42655d94f3d3a4f6ba1b594e0ccebc"
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
