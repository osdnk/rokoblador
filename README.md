# rokoblador

Composes the `rokoko` sumcheck/PCS round chain with a LaBRADOR tail proof:
`rokoko` runs its round chain to a boundary cut, exports both the prover's
and the verifier's independently-derived statement/witness in LaBRADOR's v2
wire format, checks they match byte-for-byte, then hands the statement off
to LaBRADOR (linked in as a static C library) to fold into one proof.

Requirements: `cargo +nightly`, an x86_64 host with AVX-512, and `rokoko`
and `labrador` checked out as sibling directories of this crate (override
the labrador path with `ROKOBLADOR_LABRADOR_DIR`).

Run a full cut-and-fold:

    cargo +nightly run --release -- --cut 3 --out ./rokoblador-export

Verify a previously exported statement/witness pair through LaBRADOR alone:

    target/release/rokoblador check <statement.bin> <witness.bin>

`--cut K` (default 3) picks which round of the `rokoko` chain to cut at;
`--out DIR` (default `./rokoblador-export`) is where the statement, witness
and digests are written.
