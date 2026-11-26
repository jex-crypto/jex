# Arch Linux / AUR

Two AUR packages are provided:

| Directory | AUR package | Source |
|-----------|-------------|--------|
| `.`       | `jex`       | Builds the GitHub release source tarball with cargo (default features). |
| `jex-bin` | `jex-bin`   | Repackages the prebuilt `x86_64`/`aarch64` release tarballs. |

Both depend on `pcsclite`. For a Rutoken you also need the `ccid` driver and
the PC/SC daemon:

```bash
sudo pacman -S ccid
sudo systemctl enable --now pcscd.socket
```

`jex` follows the Arch wiki Rust package guidelines: `cargo fetch --locked`
in `prepare()`, `--frozen` builds and tests so nothing is downloaded after
`prepare()`. `check()` skips the one unit test that contacts a public
timestamp authority.

## Updating for a new release

```bash
cd packaging/arch            # or packaging/arch/jex-bin
sed -i "s/^pkgver=.*/pkgver=X.Y.Z/; s/^pkgrel=.*/pkgrel=1/" PKGBUILD
updpkgsums                   # replaces the SKIP checksums (pacman-contrib)
makepkg -cf                  # or: extra-x86_64-build (devtools) for a clean chroot
namcap PKGBUILD *.pkg.tar.zst
makepkg --printsrcinfo > .SRCINFO
```

`.SRCINFO` is required by the AUR and must be regenerated whenever the
PKGBUILD changes; it is not kept in this repository.

## Publishing to the AUR

One-time: add an SSH key to your AUR account, then for each package:

```bash
git clone ssh://aur@aur.archlinux.org/jex.git aur-jex          # or jex-bin.git
cp packaging/arch/PKGBUILD aur-jex/                           # or jex-bin/PKGBUILD
cd aur-jex
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "Update to X.Y.Z"
git push
```

The AUR repository must contain only `PKGBUILD`, `.SRCINFO` and any files
they reference.
