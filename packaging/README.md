# Packaging and releases

| Channel | Location | Built from |
|---------|----------|------------|
| GitHub release tarballs | `.github/workflows/release.yml` | Tag `vX.Y.Z`; `x86_64`/`aarch64` Linux (glibc, Ubuntu 22.04) and macOS |
| Debian/Ubuntu `.deb` | `[package.metadata.deb]` in `Cargo.toml`, [`debian/`](debian/README.md) | cargo-deb in the release workflow (`amd64`, `arm64`) |
| Homebrew | [`homebrew/`](homebrew/README.md) -> tap `jex-crypto/homebrew-jex` | Release source tarball |
| AUR `jex`, `jex-bin` | [`arch/`](arch/README.md) | Source tarball / prebuilt release tarballs |
| FreeBSD `security/jex` | [`freebsd/`](freebsd/README.md) | Release source tarball, `USES=cargo` |
| crates.io (optional) | `Cargo.toml` (`exclude` keeps keys, signatures and personal fixtures out) | `cargo publish` |

All packages use the default cargo features (`nmcades-ui`, the `eframe`
PIN dialog), except where a FreeBSD user turns the `GUI` option off.
Every package needs pcsc-lite at run time (macOS: system PC/SC framework).

Release assets per tag:

```text
jex-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz
jex-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz
jex-X.Y.Z-x86_64-apple-darwin.tar.gz
jex-X.Y.Z-aarch64-apple-darwin.tar.gz
jex_X.Y.Z-1_amd64.deb
jex_X.Y.Z-1_arm64.deb
SHA256SUMS
```

Each tarball contains `jex-X.Y.Z-<target>/{jex,README.md,LICENSE}`.

## CI

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request: `cargo build --locked` / `cargo test --locked` on Ubuntu and macOS,
a `--no-default-features` build, a build with the minimum supported Rust
(`rust-version` from `Cargo.toml`), and a FreeBSD build/test in a VM
(allowed to fail). The unit test that contacts a public TSA is skipped.

## Release checklist

1. **Bump the version** in `Cargo.toml` and run `cargo build` so
   `Cargo.lock` is updated; add an entry to `CHANGELOG.md`.
   Also bump the version in:
   - `packaging/homebrew/jex.rb` (`url`)
   - `packaging/arch/PKGBUILD`, `packaging/arch/jex-bin/PKGBUILD` (`pkgver`, reset `pkgrel=1`)
   - `packaging/freebsd/security/jex/Makefile` (`DISTVERSION`)
2. Commit, wait for CI to pass on `main`.
3. **Tag and push**:

   ```bash
   git tag -a vX.Y.Z -m "Jex X.Y.Z"
   git push origin vX.Y.Z
   ```

   The release workflow checks that the tag matches `Cargo.toml`, builds all
   targets and the `.deb` files, and publishes the GitHub release with
   `SHA256SUMS`. A failed run can be repeated from the Actions tab
   (`workflow_dispatch` with the existing tag).
4. **Smoke test** a downloaded binary: `jex --version`, `jex rutoken list`
   with a token attached; `sha256sum -c SHA256SUMS`.
5. **Homebrew**: compute the source tarball checksum and update the tap
   (`homebrew/README.md`):

   ```bash
   curl -fsSL https://github.com/jex-crypto/jex/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
   ```

6. **AUR**: in `arch/` and `arch/jex-bin/` run `updpkgsums`,
   `makepkg --printsrcinfo > .SRCINFO`, test with `makepkg` and push both
   AUR repositories (`arch/README.md`).
7. **FreeBSD**: on a FreeBSD box regenerate `distinfo` and
   `Makefile.crates` (`make makesum`, `make cargo-crates`), test with
   poudriere and submit an update PR on Bugzilla (`freebsd/README.md`).
8. Commit the updated checksums/files under `packaging/` back to `main`.
9. Optional: `cargo publish` (check `cargo package --list` first).
