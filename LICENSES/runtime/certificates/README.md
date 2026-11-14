# TLS certificate bundle

The final `scratch` image copies `/etc/ssl/certs/ca-certificates.crt` from the pinned builder:

```text
golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf
```

The inspected builder identifies this file with Alpine's `ca-certificates-bundle` package, version `20261020-r0`. Its package metadata declares `MPL-2.0 AND MIT`. The final image copies the certificate bundle only; it does not contain Alpine's package manager, `c_rehash`, or certificate-update executables. The generated passwd/group files contain project-supplied account definitions.

The certificate data comes from Mozilla NSS `certdata.txt`, which carries the Mozilla Public License 2.0 notice reproduced in [NOTICE](NOTICE). The full [Mozilla Public License 2.0](../../MPL-2.0.txt) accompanies the distribution. The original certificate source and associated build source are available from Alpine's [exact source archive](https://gitlab.alpinelinux.org/alpine/ca-certificates/-/archive/20261020/ca-certificates-20261020.tar.bz2). This is the source form of the bundled certificate data; threat-bot does not modify its certificate contents. Alpine's build converts `certdata.txt` to PEM files and concatenates them in sorted order to form the bundle.

The source archive's SHA-512, checked against its APKBUILD, is:

```text
d28eb01751b1a914ffb5d8cb99e662f0a35a95148c21dcf98de1ab3108b54db9714a99472d07715023867f4f76a21f2a79a2bc1c7e9876ce5167fdd865ad2dd7
```

The source archive also contains Timo Teräs's MIT-licensed `c_rehash.c`; its original attribution is preserved in [NOTICE](NOTICE) to explain the package-level license declaration, although that executable is not copied into this image. A GPL-licensed helper in the source archive is likewise not distributed in the runtime image. These source-archive components do not describe additional runtime binaries.

[Machine-readable provenance](provenance.json) records the exact reviewed builder and source. `make licenses-check` checks the builder pin, certificate copy path, and notice hashes; it does not download or inspect the image. When the pin or copied runtime scope changes, inspect the new image/package contents and source before updating this evidence. Release maintainers must verify that the source archive remains available and preserve it alongside release records before distributing the image.
