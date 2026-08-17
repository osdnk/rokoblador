![rokoblador](banner.png)

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

Measured on an i7-11850H (default parameters; prover overhead = export +
LaBRADOR proving, i.e. the cost beyond running `rokoko` alone to round k;
verifier = the full verify phase):

| cut k | proof (KB) | rokoko + pack | prover overhead | verifier |
|---|---|---|---|---|
| 3 | 90.7 | 19.2 + 71.5 | 0.73 s | 0.54 s |
| 4 | 97.1 | 27.2 + 70.0 | 0.34 s | 0.28 s |
| 5 (default) | 103.6 | 35.9 + 67.8 | 0.16 s | 0.11 s |
| 6 | 113.0 | 46.7 + 66.3 | 0.09 s | 0.07 s |

A full 9-round `rokoko` run proves the same statement at 157.3 KB with a
~7 ms verifier.

`--cut K` (default 5) picks the round of the `rokoko` chain to cut at.
`--self-check` re-enables the R64 reference re-evaluation of every
constraint (off by default; the tamper/integration tests always run with it).
`--fingerprint` prints a blake3 fingerprint of the whole statement and
witness, for cross-run determinism checks (off by default).
