# Debian / Ubuntu packages

`.deb` packages are built with [cargo-deb](https://github.com/kornelski/cargo-deb)
from the `[package.metadata.deb]` section of `Cargo.toml`. The release
workflow builds them for `amd64` and `arm64` and attaches them to the GitHub
release.

The package installs:

| Path | Content |
|------|---------|
| `/usr/bin/jex` | Binary (default features, including the GUI PIN dialog) |
| `/usr/share/doc/jex/README.md` | User documentation |
| `/usr/share/doc/jex/LICENSE`, `/usr/share/doc/jex/copyright` | AGPL-3.0-or-later |

Dependencies: `libpcsclite1` plus whatever `dpkg-shlibdeps` detects
(`$auto`, normally `libc6` and `libgcc-s1`). `pcscd` is recommended;
`libccid`, `libgl1` and `libxkbcommon-x11-0` are suggested (CCID driver and
run-time libraries the GUI PIN dialog loads with `dlopen`).

## Building locally

On Debian or Ubuntu:

```bash
sudo apt install build-essential pkg-config libpcsclite-dev dpkg-dev
cargo install cargo-deb --locked
cargo build --release --locked
cargo deb --no-build                 # -> target/debian/jex_<version>-1_<arch>.deb
```

`cargo deb` without `--no-build` runs the release build itself. To check the
result:

```bash
dpkg-deb --info target/debian/jex_*.deb
dpkg-deb --contents target/debian/jex_*.deb
lintian target/debian/jex_*.deb      # optional
sudo apt install ./target/debian/jex_*.deb
sudo systemctl enable --now pcscd.socket
```

The release binaries are built on Ubuntu 22.04, so the packages install on
Debian 12+ and Ubuntu 22.04+. Building on a newer distribution raises the
minimum glibc accordingly.

## Ubuntu PPA (later)

A Launchpad PPA builds from a *source* package, offline, so it needs a full
`debian/` directory instead of cargo-deb:

1. Create `debian/` (`control`, `rules` using `dh $@` with `dh-cargo` or a
   plain `override_dh_auto_build: cargo build --release --frozen`,
   `changelog`, `copyright`, `source/format` = `3.0 (quilt)`).
2. Vendor dependencies so the Launchpad builder needs no network:
   `cargo vendor` into the orig tarball (or a second component tarball) and
   point `.cargo/config.toml` at `vendor/`.
3. Make sure the target series ships a new enough Rust: the crate needs
   Rust 1.88 (`rust-version` in `Cargo.toml`); on older series build-depend
   on a versioned toolchain package such as `rustc-1.88` / `cargo-1.88` if
   available.
4. Build and upload:

   ```bash
   debuild -S -sa
   dput ppa:<launchpad-owner>/jex ../jex_<version>-1~<series>1_source.changes
   ```

An official Debian package would instead go through the Debian Rust team,
which packages every crate dependency separately; that is a much larger
effort and not planned here.
