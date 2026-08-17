# rokoblador

Composes the `rokoko` round chain with a LaBRADOR tail proof into a single
non-interactive argument. The prover runs `rokoko`'s chain up to a boundary
cut, translates the boundary statement into a LaBRADOR statement and witness,
and proves it through FFI into `liblabrador.a`. The verifier replays
`rokoko`'s verifier chain over the round proof, derives the LaBRADOR
statement independently from public data, checks it matches the prover's,
and verifies the LaBRADOR proof against it. LaBRADOR's commitment-key
expansion runs concurrently with `rokoko`'s setup.

Requirements: `cargo +nightly`, an x86_64 host with AVX-512, and `rokoko`
and `labrador` checked out as sibling directories of this crate (override
the labrador path with `ROKOBLADOR_LABRADOR_DIR`).

Run the protocol:

    cargo +nightly run --release -- --cut 3

Run the tamper suite (each case mutates the statement or witness and must
be rejected):

    cargo +nightly test --release --test tamper

`--cut K` (default 3) picks the round of the `rokoko` chain to cut at.
