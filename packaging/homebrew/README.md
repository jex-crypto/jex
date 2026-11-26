# Homebrew tap

`jex.rb` is the formula for the tap repository
[`jex-crypto/homebrew-jex`](https://github.com/jex-crypto/homebrew-jex).
It builds from the GitHub release source tarball with the default cargo
features. macOS uses the system PC/SC framework; on Linux the formula
depends on Homebrew's `pcsc-lite`.

## One-time tap setup

```bash
# Create an empty public repo named "homebrew-jex" under jex-crypto, then:
git clone git@github.com:jex-crypto/homebrew-jex.git
cd homebrew-jex
mkdir -p Formula
cp /path/to/jex/packaging/homebrew/jex.rb Formula/jex.rb
# fill in sha256 (see below), then
git add Formula/jex.rb && git commit -m "jex 0.13.0" && git push
```

Users then install with:

```bash
brew install jex-crypto/jex/jex
```

## Bumping to a new release

1. Push the `vX.Y.Z` tag in the main repository (the release workflow runs).
2. Compute the checksum of the source tarball that GitHub generates for the tag:

   ```bash
   VERSION=X.Y.Z
   curl -fsSL "https://github.com/jex-crypto/jex/archive/refs/tags/v${VERSION}.tar.gz" | shasum -a 256
   ```

3. In `Formula/jex.rb` update the version in `url` and replace `sha256`.
   Keep `packaging/homebrew/jex.rb` in the main repository in sync.

   Alternatively, let Homebrew do both steps:

   ```bash
   brew bump-formula-pr --url "https://github.com/jex-crypto/jex/archive/refs/tags/v${VERSION}.tar.gz" jex-crypto/jex/jex
   ```

4. Check locally before pushing:

   ```bash
   brew install --build-from-source jex-crypto/jex/jex
   brew test jex-crypto/jex/jex
   brew audit --strict --online jex-crypto/jex/jex
   ```

The URL carries the literal version rather than `#{version}` so that
`brew audit` and `brew bump-formula-pr` can derive the version from it.

## Bottles (optional)

Without bottles every user compiles from source (a few minutes, mostly
`eframe`). Bottles can be added later with the `brew test-bot` workflow in
the tap repository (`brew tap-new` generates a template).
