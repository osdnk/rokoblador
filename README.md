# rokoblador

Composes the `rokoko` round chain with a LaBRADOR tail proof into a single
non-interactive argument. The prover runs `rokoko`'s chain up to a boundary
cut, translates the boundary statement into a LaBRADOR statement and witness,
and proves it through FFI into `liblabrador.a`. The verifier replays
`rokoko`'s verifier chain over the round proof, derives the LaBRADOR
statement independently from public data, checks it matches the prover's,
and verifies the LaBRADOR proof against it. LaBRADOR's commitment-key
expansion runs concurrently with `rokoko`'s setup.

Requirements: `cargo +nightly` and an x86_64 host with AVX-512. `rokoko` and
`labrador` are git submodules; clone with:

    git clone --recursive https://github.com/osdnk/rokoblador

(or `git submodule update --init` after a plain clone). `rokoko` carries its
own nested submodules (Intel HEXL, the lattice estimator) for optional,
non-default build paths; the default build here uses `rokoko`'s pure-Rust
`incomplete-rexl` path and never touches them, so a plain first-level
`--recursive`/`--init` is enough — no `--recursive` chained into `rokoko`
itself is needed. Override the labrador checkout with
`ROKOBLADOR_LABRADOR_DIR` if you want to point at a different one.

Run the protocol:

    cargo +nightly run --release

Run the tamper suite (each case mutates the statement or witness and must
be rejected):

    cargo +nightly test --release --test tamper

`--cut K` (default 4) picks the round of the `rokoko` chain to cut at.
