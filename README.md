# rokoblador

Composes the `rokoko` sumcheck/PCS round chain with a LaBRADOR tail proof as
two properly separated non-interactive phases: PROVE (drive `rokoko`'s
prover chain to a boundary cut, build the LaBRADOR statement/witness
in-memory from the prover's boundary, prove it via direct FFI into
`liblabrador.a`) then VERIFY (drive `rokoko`'s verifier chain over the same
round proof, independently rebuild the statement from the verifier's
boundary, check it structurally matches the prover's model, then verify the
LaBRADOR proof via FFI against that independently-rebuilt statement); there
is no file handoff and no C-side protocol logic, only a thin C adapter for
LaBRADOR's struct-heavy sparse-constraint API, with `rokoko`'s own comkey
warm-up running on a background thread concurrently with `rokoko` setup.

Requirements: `cargo +nightly`, an x86_64 host with AVX-512, and `rokoko`
and `labrador` checked out as sibling directories of this crate (override
the labrador path with `ROKOBLADOR_LABRADOR_DIR`).

Run the full prove-then-verify protocol:

    cargo +nightly run --release -- --cut 3

Run the in-memory tamper suite (mutates clones of the built statement and
witness, checks LaBRADOR and the Rust-side validation reject each case):

    cargo +nightly test --release --test tamper

`--cut K` (default 3) picks which round of the `rokoko` chain to cut at.
