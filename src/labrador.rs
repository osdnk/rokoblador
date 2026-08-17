use std::ffi::c_void;
use std::os::raw::c_int;

use crate::export::{Statement, Witness, INNER_FLAG, ROLE_W};

const WITNESS_COEFF_MAX: i64 = 23170;

extern "C" {
    fn labrador50_init_comkey(n: usize);
    fn labrador50_free_comkey();
    fn labrador50_init_witness_raw(wt: *mut c_void, r: usize, n: *const usize);
    fn labrador50_set_witness_vector_raw(wt: *mut c_void, i: usize, n: usize, deg: usize, s: *const i64) -> c_int;
    fn labrador50_free_witness(wt: *mut c_void);
    fn labrador50_init_smplstmnt_raw(st: *mut c_void, r: usize, n: *const usize, betasq: *const u64, k: usize) -> c_int;
    fn labrador50_free_smplstmnt(st: *mut c_void);
    fn labrador50_free_commitment(com: *mut c_void);
    fn labrador50_simple_verify(st: *const c_void, wt: *const c_void) -> c_int;
    fn labrador50_composite_prove_simple(proof: *mut c_void, com: *mut c_void, st: *const c_void, wt: *const c_void) -> c_int;
    fn labrador50_composite_verify_simple(proof: *const c_void, com: *const c_void, st: *const c_void) -> c_int;
    fn labrador50_free_composite(proof: *mut c_void);

    fn rb_alloc_smplstmnt() -> *mut c_void;
    fn rb_alloc_witness() -> *mut c_void;
    fn rb_alloc_composite() -> *mut c_void;
    fn rb_alloc_commitment() -> *mut c_void;
    fn rb_free(p: *mut c_void);
    fn rb_smplstmnt_set_digest(st: *mut c_void, digest: *const u8);
    fn rb_smplstmnt_add_constraint(
        st: *mut c_void,
        ci: usize,
        nz: usize,
        idx: *const usize,
        off: *const usize,
        len: *const usize,
        b: *const i64,
        phi: *const i64,
    );
    fn rb_witness_normsq(wt: *mut c_void, i: usize) -> u64;
    fn rb_composite_size(cp: *mut c_void) -> f64;
    fn rb_compiled_q() -> u64;
}

pub fn compiled_q() -> u64 {
    unsafe { rb_compiled_q() }
}

pub fn precomputed_len_for_rank(total_rank: usize) -> usize {
    let scaled = total_rank * 3 / 2;
    scaled.div_ceil(32) * 32
}

pub fn warm_comkey(precomputed_len: usize) -> std::thread::JoinHandle<std::time::Duration> {
    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        unsafe { labrador50_init_comkey(precomputed_len) };
        start.elapsed()
    })
}

pub fn free_comkey() {
    unsafe { labrador50_free_comkey() }
}

struct RawStatement(*mut c_void);

impl Drop for RawStatement {
    fn drop(&mut self) {
        unsafe {
            labrador50_free_smplstmnt(self.0);
            rb_free(self.0);
        }
    }
}

struct RawWitness(*mut c_void);

impl Drop for RawWitness {
    fn drop(&mut self) {
        unsafe {
            labrador50_free_witness(self.0);
            rb_free(self.0);
        }
    }
}

struct RawComposite(*mut c_void);

impl Drop for RawComposite {
    fn drop(&mut self) {
        unsafe {
            labrador50_free_composite(self.0);
            rb_free(self.0);
        }
    }
}

struct RawCommitment(*mut c_void);

impl Drop for RawCommitment {
    fn drop(&mut self) {
        unsafe {
            labrador50_free_commitment(self.0);
            rb_free(self.0);
        }
    }
}

#[derive(Debug)]
pub struct ProofHandle {
    composite: *mut c_void,
    commitment: *mut c_void,
}

impl Drop for ProofHandle {
    fn drop(&mut self) {
        unsafe {
            labrador50_free_composite(self.composite);
            rb_free(self.composite);
            labrador50_free_commitment(self.commitment);
            rb_free(self.commitment);
        }
    }
}

fn check_statement(stmt: &Statement) -> Result<(), String> {
    let q = compiled_q();
    if stmt.q != q {
        return Err(format!("statement q {} does not match compiled modulus {q}", stmt.q));
    }
    let mut role0_sum: u128 = 0;
    let mut inner_sum: u128 = 0;
    for v in &stmt.vectors {
        if v.role == ROLE_W {
            role0_sum += v.betasq as u128;
            if v.flags & INNER_FLAG != 0 {
                inner_sum += v.betasq as u128;
            }
        }
    }
    if role0_sum > stmt.betasq_w_total as u128 {
        return Err("sum betasq (role 0) exceeds betasq_w_total".into());
    }
    if inner_sum > stmt.betasq_inner_total as u128 {
        return Err("sum betasq (INNER) exceeds betasq_inner_total".into());
    }
    for (ci, c) in stmt.constraints.iter().enumerate() {
        if c.idx.is_empty() || c.idx.len() > 64 {
            return Err(format!("constraint {ci}: nz {} out of range", c.idx.len()));
        }
        let mut prev: Option<(usize, usize)> = None;
        for j in 0..c.idx.len() {
            let vi = c.idx[j];
            if vi >= stmt.vectors.len() {
                return Err(format!("constraint {ci}: block {j} idx {vi} out of range"));
            }
            if let Some((pidx, poff)) = prev {
                if vi < pidx {
                    return Err(format!("constraint {ci}: block {j} idx not monotone"));
                }
                if vi == pidx && c.off[j] <= poff {
                    return Err(format!("constraint {ci}: block {j} offset not strictly increasing"));
                }
            }
            if c.off[j] + c.len[j] > stmt.vectors[vi].n {
                return Err(format!("constraint {ci}: block {j} off+len exceeds vector {vi} rank"));
            }
            prev = Some((vi, c.off[j]));
        }
    }
    Ok(())
}

fn check_witness(stmt: &Statement, wit: &Witness) -> Result<(), String> {
    if stmt.vectors.len() != wit.vectors.len() {
        return Err("statement/witness vector count mismatch".into());
    }
    for (i, (v, coeffs)) in stmt.vectors.iter().zip(wit.vectors.iter()).enumerate() {
        if coeffs.len() != v.n * 64 {
            return Err(format!("vector {i}: witness coefficient count mismatch"));
        }
        for &c in coeffs {
            if c.abs() > WITNESS_COEFF_MAX {
                return Err(format!("vector {i}: |coeff| = {} exceeds {WITNESS_COEFF_MAX}", c.abs()));
            }
        }
    }
    Ok(())
}

fn build_raw_statement(stmt: &Statement) -> Result<RawStatement, String> {
    let n: Vec<usize> = stmt.vectors.iter().map(|v| v.n).collect();
    let betasq: Vec<u64> = stmt.vectors.iter().map(|v| v.betasq).collect();
    let ptr = unsafe { rb_alloc_smplstmnt() };
    if ptr.is_null() {
        return Err("out of memory allocating smplstmnt".into());
    }
    let raw = RawStatement(ptr);
    let ret = unsafe { labrador50_init_smplstmnt_raw(raw.0, n.len(), n.as_ptr(), betasq.as_ptr(), stmt.constraints.len()) };
    if ret != 0 {
        return Err(format!("init_smplstmnt_raw failed with code {ret}"));
    }
    unsafe { rb_smplstmnt_set_digest(raw.0, stmt.digest.as_ptr()) };
    for (ci, c) in stmt.constraints.iter().enumerate() {
        let phi_flat: Vec<i64> = c.phi.iter().flatten().map(|&x| x as i64).collect();
        let b_flat: Option<Vec<i64>> = c.b.map(|b| b.iter().map(|&x| x as i64).collect());
        unsafe {
            rb_smplstmnt_add_constraint(
                raw.0,
                ci,
                c.idx.len(),
                c.idx.as_ptr(),
                c.off.as_ptr(),
                c.len.as_ptr(),
                b_flat.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                phi_flat.as_ptr(),
            );
        }
    }
    Ok(raw)
}

fn build_raw_witness(stmt: &Statement, wit: &Witness) -> Result<RawWitness, String> {
    let n: Vec<usize> = stmt.vectors.iter().map(|v| v.n).collect();
    let ptr = unsafe { rb_alloc_witness() };
    if ptr.is_null() {
        return Err("out of memory allocating witness".into());
    }
    let raw = RawWitness(ptr);
    unsafe { labrador50_init_witness_raw(raw.0, n.len(), n.as_ptr()) };
    for (i, (v, coeffs)) in stmt.vectors.iter().zip(wit.vectors.iter()).enumerate() {
        let ret = unsafe { labrador50_set_witness_vector_raw(raw.0, i, v.n, 1, coeffs.as_ptr()) };
        if ret != 0 {
            return Err(format!("set_witness_vector_raw failed for vector {i} with code {ret}"));
        }
        let normsq = unsafe { rb_witness_normsq(raw.0, i) };
        if normsq > v.betasq {
            return Err(format!("witness vector {i} recomputed normsq {normsq} exceeds statement betasq {}", v.betasq));
        }
    }
    Ok(raw)
}

pub fn prove(stmt: &Statement, wit: &Witness) -> Result<(ProofHandle, f64), String> {
    check_statement(stmt)?;
    check_witness(stmt, wit)?;
    let raw_stmt = build_raw_statement(stmt)?;
    let raw_wit = build_raw_witness(stmt, wit)?;

    let ok = unsafe { labrador50_simple_verify(raw_stmt.0, raw_wit.0) };
    if ok != 0 {
        return Err(format!("simple_verify: FAIL (code {ok})"));
    }

    let composite = unsafe { rb_alloc_composite() };
    let commitment = unsafe { rb_alloc_commitment() };
    if composite.is_null() || commitment.is_null() {
        unsafe {
            rb_free(composite);
            rb_free(commitment);
        }
        return Err("out of memory allocating composite/commitment".into());
    }
    let composite_guard = RawComposite(composite);
    let commitment_guard = RawCommitment(commitment);
    let ret = unsafe { labrador50_composite_prove_simple(composite_guard.0, commitment_guard.0, raw_stmt.0, raw_wit.0) };
    if ret != 0 {
        return Err(format!("composite_prove_simple: FAIL (code {ret})"));
    }
    let pack_kb = unsafe { rb_composite_size(composite_guard.0) };
    let composite = composite_guard.0;
    let commitment = commitment_guard.0;
    std::mem::forget(composite_guard);
    std::mem::forget(commitment_guard);
    Ok((ProofHandle { composite, commitment }, pack_kb))
}

pub fn verify(stmt: &Statement, handle: &ProofHandle) -> Result<(), String> {
    check_statement(stmt)?;
    let raw_stmt = build_raw_statement(stmt)?;
    let ret = unsafe { labrador50_composite_verify_simple(handle.composite, handle.commitment, raw_stmt.0) };
    if ret != 0 {
        return Err(format!("composite_verify_simple: FAIL (code {ret})"));
    }
    Ok(())
}
