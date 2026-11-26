# FreeBSD port: security/jex

`security/jex/` is a ready-to-submit port skeleton:

| File | Purpose |
|------|---------|
| `Makefile` | `USES=cargo`, `USE_GITHUB`, `LIB_DEPENDS` on `devel/pcsc-lite`, `GUI` option |
| `Makefile.crates` | `CARGO_CRATES` list, **placeholder** - generate it (see below) |
| `distinfo` | Checksums, **placeholder** - generate it (see below) |
| `pkg-descr` | Long description |

## Options

`GUI` (default on) maps to the default cargo feature `nmcades-ui`, which
builds an `eframe` PIN dialog for the browser host. `eframe`/`winit` are pure
Rust on FreeBSD and load X11, xkbcommon and OpenGL with `dlopen(3)`, so the
build itself only needs pcsc-lite. Turning `GUI` off builds with
`--no-default-features` and drops the X11/OpenGL dependencies, which is the
right choice for headless machines and is a fallback if the GUI stack ever
fails to build on a given release. `stage-qa` may warn that the binary does
not link to the X11/GL libraries; that is expected because they are
loaded at run time.

## Generating `distinfo` and `Makefile.crates`

On a FreeBSD machine with an up-to-date ports tree:

```sh
cp -R packaging/freebsd/security/jex /usr/ports/security/jex
cd /usr/ports/security/jex
make makesum                                   # fetch source tarball, write distinfo
make cargo-crates > Makefile.crates            # list crates from the extracted Cargo.lock
make makesum                                   # add checksums of all crates to distinfo
make stage && make stage-qa && make check-plist
make test                                      # optional
portlint -AC
```

Repeat this for every version bump: update `DISTVERSION`, reset
`PORTREVISION` (if present), regenerate both files, and copy them back into
`packaging/freebsd/security/jex/`.

Test in a clean jail before submitting:

```sh
poudriere testport -j 14amd64 -p default -o security/jex
poudriere testport -j 14amd64 -p default -o security/jex -c   # also try GUI=off
```

## Submitting to the ports tree

1. Make sure `distinfo` and `Makefile.crates` are real (no placeholders)
   and `portlint -AC` is clean.
2. Create a shar archive or a git diff against the ports tree:

   ```sh
   cd /usr/ports
   git add security/jex
   git diff --staged > /tmp/security-jex.diff
   ```

3. File a new bug at <https://bugs.freebsd.org/bugzilla/> with product
   *Ports & Packages*, component *Individual Port(s)*, summary
   `[NEW PORT] security/jex: CryptoPro container reader and GOST CAdES/XAdES signing tool`,
   and attach the diff together with the poudriere `testport` log.
4. Updates later are submitted the same way with summary
   `security/jex: Update to X.Y.Z`.

Users then run `pcscd` from `devel/pcsc-lite` and the `devel/libccid`
driver:

```sh
pkg install pcsc-lite libccid
sysrc pcscd_enable=YES && service pcscd start
```
