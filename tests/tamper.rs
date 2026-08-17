use std::num::NonZeroUsize;

use rokoblador::{driver, export, labrador};

fn build_models() -> (export::Statement, export::Witness) {
    rokoko::common::init_common();
    let cut = NonZeroUsize::new(3).unwrap();
    let mut setup = driver::setup();
    let mut prove_output = driver::prove(&mut setup, cut);
    export::export_prover(3, &mut prove_output.prover_boundary, setup.crs())
}

fn find_last_w_block(stmt: &export::Statement) -> (usize, usize) {
    for c in stmt.constraints.iter().rev() {
        for j in 0..c.idx.len() {
            if c.idx[j] == 1 && c.len[j] > 0 {
                return (c.off[j], c.len[j]);
            }
        }
    }
    panic!("no idx==1 block found in any constraint");
}

fn find_negative_coeff(wit: &export::Witness, vector: usize, off: usize, len: usize) -> usize {
    let start = off * 64;
    let end = (off + len) * 64;
    for i in start..end {
        if wit.vectors[vector][i] < 0 {
            return i;
        }
    }
    panic!("no negative coefficient found in the sampled w-only block");
}

#[test]
fn tamper_suite() {
    let (stmt, wit) = build_models();

    let (handle, pack_kb) = labrador::prove(&stmt, &wit).expect("t6: untampered prove must succeed");
    labrador::verify(&stmt, &handle).expect("t6: untampered verify must succeed");
    assert!(pack_kb > 0.0, "t6: packed proof size must be positive");

    {
        let (off, len) = find_last_w_block(&stmt);
        let coeff_idx = find_negative_coeff(&wit, 1, off, len);
        let mut w = wit.clone();
        w.vectors[1][coeff_idx] += 1;
        let err = labrador::prove(&stmt, &w).expect_err("t1: tampered witness coeff must fail to prove");
        assert!(err.contains("simple_verify"), "t1: unexpected error: {err}");
    }

    {
        let mut s = stmt.clone();
        let last = s.constraints.last_mut().expect("statement has constraints");
        let b = last.b.as_mut().expect("t2: last constraint must carry b");
        b[0] = (b[0] + 1) % s.q;
        let err = labrador::prove(&s, &wit).expect_err("t2: tampered constraint b must fail to prove");
        assert!(err.contains("simple_verify"), "t2: unexpected error: {err}");
    }

    {
        let mut s = stmt.clone();
        let honest: i128 = wit.vectors[0].iter().map(|&c| (c as i128) * (c as i128)).sum();
        s.vectors[0].betasq = honest as u64 - 1;
        let err = labrador::prove(&s, &wit).expect_err("t3: betasq below honest normsq must fail");
        assert!(err.contains("recomputed normsq") && err.contains("exceeds statement betasq"), "t3: unexpected error: {err}");
    }

    {
        let mut s = stmt.clone();
        let b0 = s.vectors[0].betasq;
        s.betasq_inner_total = b0 - 1;
        let err = labrador::prove(&s, &wit).expect_err("t4: betasq_inner_total below B0 must fail");
        assert!(err.contains("betasq_inner_total"), "t4: unexpected error: {err}");
    }

    {
        let mut s = stmt.clone();
        s.digest[0] ^= 0xFF;
        assert_ne!(s, stmt, "t5: a digest-tampered statement must differ from the prover's model");
    }
}
