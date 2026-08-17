use std::path::Path;

use rokoko::common::config::MOD_Q;
use rokoko::common::matrix::VerticallyAlignedMatrix;
use rokoko::common::ring_arithmetic::{Representation, RingElement};
use rokoko::common::structured_row::PreprocessedRow;
use rokoko::protocol::boundary::{ProverBoundary, VerifierBoundary};
use rokoko::protocol::commitment::RecursiveCommitmentWithAux;
use rokoko::protocol::config::{Config, Projection, SumcheckConfig, CONFIG};
use rokoko::protocol::crs::{VerifierCRS, CRS};
use rokoko::protocol::open::{evaluation_point_to_structured_row, evaluation_point_to_structured_row_conjugate};

use crate::r64;

const MAGIC_STMT: u32 = 0x524B_424C;
const MAGIC_WIT: u32 = 0x524B_4257;
const VERSION: u32 = 2;
const INNER_FLAG: u32 = 1;
const ROLE_W: u32 = 0;

fn round_config(cut: usize) -> &'static SumcheckConfig {
    let mut cfg = match &*CONFIG {
        Config::Sumcheck(c) => c,
        _ => panic!("rokoblador cut requires a Sumcheck config at the chain root"),
    };
    for _ in 1..cut {
        cfg = match cfg.next.as_deref() {
            Some(Config::Sumcheck(nc)) => nc,
            _ => panic!("rokoblador cut requires a Sumcheck config right after the cut round"),
        };
    }
    cfg
}

fn ring_eo(el: &RingElement) -> (r64::R64, r64::R64) {
    let mut tmp = el.clone();
    tmp.to_representation(Representation::EvenOddCoefficients);
    let mut e = r64::zero();
    let mut o = r64::zero();
    e.copy_from_slice(&tmp.v[0..64]);
    o.copy_from_slice(&tmp.v[64..128]);
    (e, o)
}

fn pow2_bk(base_log: usize, k: usize) -> u64 {
    1u64 << (base_log * k)
}

fn digit_bound_sq(base_log: usize) -> u64 {
    let d_max = 1u64 << (base_log - 1);
    d_max * d_max
}

struct ChainShape {
    a1_rank: usize,
    a1_rank_padded: usize,
    num_digits_y: usize,
    a2_rank: usize,
    num_digits_c1: usize,
    has_c1dec: bool,
    width: usize,
    height: usize,
}

fn chain_shape(nc: &SumcheckConfig) -> ChainShape {
    let a2_cfg = &nc.commitment_recursion;
    let has_c1dec = a2_cfg.next.is_some();
    let num_digits_c1 = if has_c1dec { a2_cfg.next.as_deref().unwrap().decomposition_chunks } else { 0 };
    ChainShape {
        a1_rank: nc.basic_commitment_rank,
        a1_rank_padded: nc.basic_commitment_rank.next_power_of_two(),
        num_digits_y: a2_cfg.decomposition_chunks,
        a2_rank: a2_cfg.rank,
        num_digits_c1,
        has_c1dec,
        width: nc.witness_width,
        height: nc.witness_height,
    }
}

fn prefix_range(p: &rokoko::protocol::commitment::Prefix, total_vars: usize) -> (usize, usize) {
    let size = 1usize << (total_vars - p.length);
    let start = p.prefix << (total_vars - p.length);
    (start, start + size)
}

fn most_inner_ranges(round_cfg: &SumcheckConfig) -> Vec<(usize, usize)> {
    let total_vars = round_cfg.composed_witness_length.ilog2() as usize;
    let mut ranges = vec![
        prefix_range(&round_cfg.commitment_recursion.most_inner_config().prefix, total_vars),
        prefix_range(&round_cfg.opening_recursion.most_inner_config().prefix, total_vars),
    ];
    match &round_cfg.projection_recursion {
        Projection::Coarse(c) => ranges.push(prefix_range(&c.most_inner_config().prefix, total_vars)),
        Projection::Fine(f) => {
            ranges.push(prefix_range(&f.recursion_constant_term.most_inner_config().prefix, total_vars));
            ranges.push(prefix_range(&f.recursion_batched_projection.most_inner_config().prefix, total_vars));
        }
        Projection::Skip => {}
    }
    ranges
}

struct Layout {
    total: usize,
    v0_start: usize,
    v0_end: usize,
    w_before_len: usize,
    w_after_len: usize,
    ydec_len: usize,
    c1dec_len: usize,
}

fn compute_layout(round_cfg: &SumcheckConfig, shape: &ChainShape) -> Layout {
    let total = shape.height * shape.width;
    let ranges = most_inner_ranges(round_cfg);
    let is_inner = |g: usize| ranges.iter().any(|&(s, e)| g >= s && g < e);

    let mut inner_start: Option<usize> = None;
    let mut inner_end: Option<usize> = None;
    let mut pos = 0usize;
    while pos < total {
        let inner = is_inner(pos);
        let mut end = pos + 1;
        while end < total && is_inner(end) == inner {
            end += 1;
        }
        if inner {
            inner_start = Some(inner_start.map_or(pos, |s| s.min(pos)));
            inner_end = Some(inner_end.map_or(end, |e| e.max(end)));
        }
        pos = end;
    }
    let (v0_start, v0_end) = match (inner_start, inner_end) {
        (Some(s), Some(e)) => (s, e),
        _ => (0, total / 2),
    };

    let w_before_len = 2 * v0_start;
    let w_after_len = 2 * (total - v0_end);
    let ydec_len = shape.width * shape.a1_rank_padded * shape.num_digits_y * 2;
    let c1dec_len = if shape.has_c1dec { shape.a2_rank * shape.num_digits_c1 * 2 } else { 0 };
    Layout { total, v0_start, v0_end, w_before_len, w_after_len, ydec_len, c1dec_len }
}

struct VectorSpec {
    n: usize,
    role: u32,
    flags: u32,
}

fn vector_specs(layout: &Layout) -> [VectorSpec; 2] {
    let n0 = 2 * (layout.v0_end - layout.v0_start);
    let n1 = layout.w_before_len + layout.w_after_len + layout.ydec_len + layout.c1dec_len;
    [
        VectorSpec { n: n0, role: ROLE_W, flags: INNER_FLAG },
        VectorSpec { n: n1, role: ROLE_W, flags: 0 },
    ]
}

fn prover_rows_eo(crs: &CRS, dim: usize, rank: usize) -> Vec<Vec<(r64::R64, r64::R64)>> {
    let ck = crs.ck_for_wit_dim(dim);
    (0..rank)
        .map(|i| ck[i].preprocessed_row.iter().map(ring_eo).collect())
        .collect()
}

fn verifier_rows_eo(crs: &VerifierCRS, dim: usize, rank: usize) -> Vec<Vec<(r64::R64, r64::R64)>> {
    let sck = crs.structured_ck_for_wit_dim(dim);
    (0..rank)
        .map(|i| {
            PreprocessedRow::from_structured_row(&sck[i])
                .preprocessed_row
                .iter()
                .map(ring_eo)
                .collect()
        })
        .collect()
}

struct ConstraintSpec {
    idx: Vec<usize>,
    off: Vec<usize>,
    len: Vec<usize>,
    b: Option<r64::R64>,
    phi: Vec<r64::R64>,
}

fn eval_tensors(evaluation_points: &[RingElement], width: usize) -> (Vec<RingElement>, Vec<RingElement>, Vec<RingElement>, Vec<RingElement>) {
    let split = width.ilog2() as usize;
    let (outer_layers, inner_layers) = evaluation_points.split_at(split);
    let outer0 = PreprocessedRow::from_structured_row(&evaluation_point_to_structured_row(outer_layers)).preprocessed_row;
    let inner0 = PreprocessedRow::from_structured_row(&evaluation_point_to_structured_row(inner_layers)).preprocessed_row;
    let outer1 = PreprocessedRow::from_structured_row(&evaluation_point_to_structured_row_conjugate(outer_layers)).preprocessed_row;
    let inner1 = PreprocessedRow::from_structured_row(&evaluation_point_to_structured_row_conjugate(inner_layers)).preprocessed_row;
    (inner0, outer0, inner1, outer1)
}

fn intersect(a_s: usize, a_e: usize, b_s: usize, b_e: usize) -> Option<(usize, usize)> {
    let s = a_s.max(b_s);
    let e = a_e.min(b_e);
    if s < e {
        Some((s, e))
    } else {
        None
    }
}

fn w_blocks_r2(layout: &Layout, q_start: usize, q_end: usize) -> Vec<(usize, usize, usize, usize)> {
    let mut blocks = Vec::new();
    if let Some((s, e)) = intersect(q_start, q_end, layout.v0_start, layout.v0_end) {
        blocks.push((0, 2 * (s - layout.v0_start), 2 * (e - s), s));
    }
    if let Some((s, e)) = intersect(q_start, q_end, 0, layout.v0_start) {
        blocks.push((1, 2 * s, 2 * (e - s), s));
    }
    if let Some((s, e)) = intersect(q_start, q_end, layout.v0_end, layout.total) {
        blocks.push((1, layout.w_before_len + 2 * (s - layout.v0_end), 2 * (e - s), s));
    }
    blocks
}

fn push_range_block(idx: &mut Vec<usize>, off: &mut Vec<usize>, len: &mut Vec<usize>, phi: &mut Vec<r64::R64>, full: &[r64::R64], layout: &Layout, q_start: usize, q_end: usize) {
    for (bi, boff, blen, gstart) in w_blocks_r2(layout, q_start, q_end) {
        idx.push(bi);
        off.push(boff);
        len.push(blen);
        let local = 2 * (gstart - q_start);
        phi.extend_from_slice(&full[local..local + blen]);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_public(
    layout: &Layout,
    shape: &ChainShape,
    a1: &[Vec<(r64::R64, r64::R64)>],
    a2: &[Vec<(r64::R64, r64::R64)>],
    a3: &[(r64::R64, r64::R64)],
    a2_base_log: usize,
    a3_base_log: usize,
    inner0: &[RingElement],
    outer0: &[RingElement],
    inner1: &[RingElement],
    outer1: &[RingElement],
    c_eo_vec: &[(r64::R64, r64::R64)],
    z0_eo: (r64::R64, r64::R64),
    z1_eo: (r64::R64, r64::R64),
) -> Vec<ConstraintSpec> {
    let mut constraints = Vec::new();
    let ydec_base_off = layout.w_before_len + layout.w_after_len;
    let c1dec_base_off = ydec_base_off + layout.ydec_len;

    for col in 0..shape.width {
        for t in 0..shape.a1_rank {
            for p in 0..2 {
                let mut full = Vec::with_capacity(2 * shape.height);
                for row in 0..shape.height {
                    let (ae, ao) = a1[t][row];
                    let (pe, po) = r64::phi_for_part(&ae, &ao, p);
                    full.push(pe);
                    full.push(po);
                }
                let mut idx = Vec::new();
                let mut off = Vec::new();
                let mut len = Vec::new();
                let mut phi = Vec::new();
                push_range_block(&mut idx, &mut off, &mut len, &mut phi, &full, layout, col * shape.height, col * shape.height + shape.height);

                let mut yblock = vec![r64::zero(); shape.num_digits_y * 2];
                for kk in 0..shape.num_digits_y {
                    yblock[kk * 2 + p] = r64::const_elem_neg(pow2_bk(a2_base_log, kk));
                }
                idx.push(1);
                off.push(ydec_base_off + (col * shape.a1_rank_padded + t) * shape.num_digits_y * 2);
                len.push(shape.num_digits_y * 2);
                phi.extend(yblock);
                constraints.push(ConstraintSpec { idx, off, len, b: None, phi });
            }
        }
    }

    for u in 0..shape.a2_rank {
        for p in 0..2 {
            let mut yblock = vec![r64::zero(); layout.ydec_len];
            for col in 0..shape.width {
                for t in 0..shape.a1_rank_padded {
                    for kk in 0..shape.num_digits_y {
                        let flat = (t * shape.width + col) * shape.num_digits_y + kk;
                        let (ae, ao) = a2[u][flat];
                        let (pe, po) = r64::phi_for_part(&ae, &ao, p);
                        let pos = ((col * shape.a1_rank_padded + t) * shape.num_digits_y + kk) * 2;
                        yblock[pos] = pe;
                        yblock[pos + 1] = po;
                    }
                }
            }
            if shape.has_c1dec {
                let mut cblock = vec![r64::zero(); shape.num_digits_c1 * 2];
                for kk in 0..shape.num_digits_c1 {
                    cblock[kk * 2 + p] = r64::const_elem_neg(pow2_bk(a3_base_log, kk));
                }
                let mut phi = yblock;
                phi.extend(cblock);
                constraints.push(ConstraintSpec {
                    idx: vec![1, 1],
                    off: vec![ydec_base_off, c1dec_base_off + u * shape.num_digits_c1 * 2],
                    len: vec![layout.ydec_len, shape.num_digits_c1 * 2],
                    b: None,
                    phi,
                });
            } else {
                let b = if p == 0 { c_eo_vec[u].0 } else { c_eo_vec[u].1 };
                constraints.push(ConstraintSpec {
                    idx: vec![1],
                    off: vec![ydec_base_off],
                    len: vec![layout.ydec_len],
                    b: Some(b),
                    phi: yblock,
                });
            }
        }
    }

    if shape.has_c1dec {
        for p in 0..2 {
            let mut block = vec![r64::zero(); layout.c1dec_len];
            for i in 0..(shape.a2_rank * shape.num_digits_c1) {
                let (ae, ao) = a3[i];
                let (pe, po) = r64::phi_for_part(&ae, &ao, p);
                block[2 * i] = pe;
                block[2 * i + 1] = po;
            }
            let b = if p == 0 { c_eo_vec[0].0 } else { c_eo_vec[0].1 };
            constraints.push(ConstraintSpec { idx: vec![1], off: vec![c1dec_base_off], len: vec![layout.c1dec_len], b: Some(b), phi: block });
        }
    }

    for j in 0..2 {
        let (inner, outer) = if j == 0 { (inner0, outer0) } else { (inner1, outer1) };
        for p in 0..2 {
            let mut full = Vec::with_capacity(2 * shape.width * shape.height);
            for col in 0..shape.width {
                for row in 0..shape.height {
                    let mut prod = RingElement::zero(Representation::IncompleteNTT);
                    prod *= (&inner[row], &outer[col]);
                    let (de, do_) = ring_eo(&prod);
                    let (pe, po) = r64::phi_for_part(&de, &do_, p);
                    full.push(pe);
                    full.push(po);
                }
            }
            let mut idx = Vec::new();
            let mut off = Vec::new();
            let mut len = Vec::new();
            let mut phi = Vec::new();
            push_range_block(&mut idx, &mut off, &mut len, &mut phi, &full, layout, 0, shape.width * shape.height);
            let z = if j == 0 { z0_eo } else { z1_eo };
            let b = if p == 0 { z.0 } else { z.1 };
            constraints.push(ConstraintSpec { idx, off, len, b: Some(b), phi });
        }
    }

    constraints
}

struct StatementHeader {
    q: u64,
    digest: [u8; 16],
    betasq_w_total: u64,
    betasq_inner_total: u64,
}

struct VectorRecord {
    n: usize,
    betasq: u64,
    role: u32,
    flags: u32,
}

struct WitnessVector {
    n: usize,
    coeffs: Vec<i64>,
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_statement(path: &Path, header: &StatementHeader, vectors: &[VectorRecord], constraints: &[ConstraintSpec]) {
    let mut buf = Vec::new();
    put_u32(&mut buf, MAGIC_STMT);
    put_u32(&mut buf, VERSION);
    put_u64(&mut buf, header.q);
    buf.extend_from_slice(&header.digest);
    put_u64(&mut buf, vectors.len() as u64);
    put_u64(&mut buf, constraints.len() as u64);
    put_u64(&mut buf, header.betasq_w_total);
    put_u64(&mut buf, header.betasq_inner_total);
    for v in vectors {
        put_u64(&mut buf, v.n as u64);
        put_u64(&mut buf, v.betasq);
        put_u32(&mut buf, v.role);
        put_u32(&mut buf, v.flags);
    }
    for c in constraints {
        put_u64(&mut buf, c.idx.len() as u64);
        for i in 0..c.idx.len() {
            put_u64(&mut buf, c.idx[i] as u64);
            put_u64(&mut buf, c.off[i] as u64);
            put_u64(&mut buf, c.len[i] as u64);
        }
        put_u64(&mut buf, if c.b.is_some() { 1 } else { 0 });
        if let Some(b) = &c.b {
            for &x in b {
                put_i64(&mut buf, x as i64);
            }
        }
        for el in &c.phi {
            for &x in el {
                put_i64(&mut buf, x as i64);
            }
        }
    }
    std::fs::write(path, &buf).unwrap_or_else(|e| panic!("failed to write {path:?}: {e}"));
}

fn write_witness(path: &Path, q: u64, vectors: &[WitnessVector]) {
    let mut buf = Vec::new();
    put_u32(&mut buf, MAGIC_WIT);
    put_u32(&mut buf, VERSION);
    put_u64(&mut buf, q);
    put_u64(&mut buf, vectors.len() as u64);
    for v in vectors {
        put_u64(&mut buf, v.n as u64);
        for &c in &v.coeffs {
            put_i64(&mut buf, c);
        }
    }
    std::fs::write(path, &buf).unwrap_or_else(|e| panic!("failed to write {path:?}: {e}"));
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        v
    }
    fn u64(&mut self) -> u64 {
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        v
    }
    fn i64(&mut self) -> i64 {
        let v = i64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        v
    }
    fn bytes(&mut self, n: usize) -> &'a [u8] {
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        s
    }
}

struct ParsedStatement {
    q: u64,
    betasq_w_total: u64,
    betasq_inner_total: u64,
    vectors: Vec<VectorRecord>,
    constraints: Vec<ConstraintSpec>,
}

fn read_statement(path: &Path) -> ParsedStatement {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    let mut r = Reader::new(&data);
    assert_eq!(r.u32(), MAGIC_STMT, "bad statement magic in {path:?}");
    assert_eq!(r.u32(), VERSION, "bad statement version in {path:?}");
    let q = r.u64();
    let _digest = r.bytes(16);
    let nvec = r.u64() as usize;
    let ncon = r.u64() as usize;
    let betasq_w_total = r.u64();
    let betasq_inner_total = r.u64();
    let mut vectors = Vec::with_capacity(nvec);
    for _ in 0..nvec {
        let n = r.u64() as usize;
        let betasq = r.u64();
        let role = r.u32();
        let flags = r.u32();
        vectors.push(VectorRecord { n, betasq, role, flags });
    }
    let mut constraints = Vec::with_capacity(ncon);
    for _ in 0..ncon {
        let nz = r.u64() as usize;
        let mut idx = Vec::with_capacity(nz);
        let mut off = Vec::with_capacity(nz);
        let mut len = Vec::with_capacity(nz);
        for _ in 0..nz {
            idx.push(r.u64() as usize);
            off.push(r.u64() as usize);
            len.push(r.u64() as usize);
        }
        let has_b = r.u64();
        let b = if has_b == 1 {
            let mut arr = r64::zero();
            for slot in arr.iter_mut() {
                *slot = r.i64() as u64;
            }
            Some(arr)
        } else {
            None
        };
        let total: usize = len.iter().sum();
        let mut phi = Vec::with_capacity(total);
        for _ in 0..total {
            let mut arr = r64::zero();
            for slot in arr.iter_mut() {
                *slot = r.i64() as u64;
            }
            phi.push(arr);
        }
        constraints.push(ConstraintSpec { idx, off, len, b, phi });
    }
    ParsedStatement { q, betasq_w_total, betasq_inner_total, vectors, constraints }
}

fn read_witness(path: &Path) -> (u64, Vec<WitnessVector>) {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    let mut r = Reader::new(&data);
    assert_eq!(r.u32(), MAGIC_WIT, "bad witness magic in {path:?}");
    assert_eq!(r.u32(), VERSION, "bad witness version in {path:?}");
    let q = r.u64();
    let nvec = r.u64() as usize;
    let mut vectors = Vec::with_capacity(nvec);
    for _ in 0..nvec {
        let n = r.u64() as usize;
        let coeffs: Vec<i64> = (0..n * 64).map(|_| r.i64()).collect();
        vectors.push(WitnessVector { n, coeffs });
    }
    (q, vectors)
}

fn w_range_witness(w: &VerticallyAlignedMatrix<RingElement>, start: usize, end: usize) -> (Vec<i64>, u64) {
    let mut coeffs = Vec::with_capacity(2 * (end - start) * 64);
    let mut betasq: u128 = 0;
    for i in start..end {
        let (e, o) = ring_eo(&w.data[i]);
        for &c in e.iter().chain(o.iter()) {
            let s = r64::center(c);
            betasq += (s as i128 * s as i128) as u128;
            coeffs.push(s);
        }
    }
    (coeffs, betasq as u64)
}

fn ydec_witness(rc: &RecursiveCommitmentWithAux, shape: &ChainShape) -> (Vec<i64>, u64) {
    let mut coeffs = Vec::with_capacity(shape.width * shape.a1_rank_padded * shape.num_digits_y * 64);
    let mut betasq: u128 = 0;
    for col in 0..shape.width {
        for t in 0..shape.a1_rank_padded {
            for kk in 0..shape.num_digits_y {
                let flat = (t * shape.width + col) * shape.num_digits_y + kk;
                let (e, o) = ring_eo(&rc.committed_data[flat]);
                for &c in e.iter().chain(o.iter()) {
                    let s = r64::center(c);
                    betasq += (s as i128 * s as i128) as u128;
                    coeffs.push(s);
                }
            }
        }
    }
    (coeffs, betasq as u64)
}

fn c1dec_witness(rc_inner: &RecursiveCommitmentWithAux, shape: &ChainShape) -> (Vec<i64>, u64) {
    let mut coeffs = Vec::with_capacity(shape.a2_rank * shape.num_digits_c1 * 64);
    let mut betasq: u128 = 0;
    for u in 0..shape.a2_rank {
        for kk in 0..shape.num_digits_c1 {
            let flat = u * shape.num_digits_c1 + kk;
            let (e, o) = ring_eo(&rc_inner.committed_data[flat]);
            for &c in e.iter().chain(o.iter()) {
                let s = r64::center(c);
                betasq += (s as i128 * s as i128) as u128;
                coeffs.push(s);
            }
        }
    }
    (coeffs, betasq as u64)
}

fn caps(shape: &ChainShape, a2_base_log: usize, a3_base_log: usize, layout: &Layout) -> u128 {
    let ydec_cap = layout.ydec_len as u128 * 64 * digit_bound_sq(a2_base_log) as u128;
    let c1dec_cap = if shape.has_c1dec { layout.c1dec_len as u128 * 64 * digit_bound_sq(a3_base_log) as u128 } else { 0 };
    ydec_cap + c1dec_cap
}

pub fn export_prover(dir: &Path, cut: usize, boundary: &mut ProverBoundary, crs: &CRS) {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("failed to create {dir:?}: {e}"));

    let mut digest = [0u8; 16];
    boundary.transcript.fill_from_xof(b"rokoblador-handoff", &mut digest);

    let nc = &boundary.config;
    let round_cfg = round_config(cut);
    let shape = chain_shape(nc);
    let layout = compute_layout(round_cfg, &shape);
    let a2_cfg = &nc.commitment_recursion;

    let rc = &boundary.commitment;
    let a1 = prover_rows_eo(crs, shape.height, shape.a1_rank);
    let a2 = prover_rows_eo(crs, rc.committed_data.len(), shape.a2_rank);
    let (rc_inner, a3, a3_base_log) = if shape.has_c1dec {
        let rc_inner = rc.next.as_deref().expect("round commitment recursion missing its inner level");
        let a3_cfg = a2_cfg.next.as_deref().unwrap();
        let a3 = prover_rows_eo(crs, rc_inner.committed_data.len(), a3_cfg.rank).remove(0);
        (Some(rc_inner), a3, a3_cfg.decomposition_base_log)
    } else {
        (None, Vec::new(), 0)
    };

    let (inner0, outer0, inner1, outer1) = eval_tensors(&boundary.evaluation_points, shape.width);

    let c_vals = rc.most_inner_commitment().clone();
    let c_eo_vec: Vec<(r64::R64, r64::R64)> = c_vals.iter().map(ring_eo).collect();
    let z0 = boundary.claims[0].clone();
    let z1 = boundary.claims[1].conjugate();
    let z0_eo = ring_eo(&z0);
    let z1_eo = ring_eo(&z1);

    let constraints = build_public(&layout, &shape, &a1, &a2, &a3, a2_cfg.decomposition_base_log, a3_base_log, &inner0, &outer0, &inner1, &outer1, &c_eo_vec, z0_eo, z1_eo);
    let specs = vector_specs(&layout);

    let betasq_w_total = (round_cfg.norm_bound.powi(2).floor() as u128 + caps(&shape, a2_cfg.decomposition_base_log, a3_base_log, &layout)) as u64;
    let betasq_inner_total = round_cfg.most_inner_norm_bound.powi(2).floor() as u64;

    let (v0_coeffs, v0_honest) = w_range_witness(&boundary.witness, layout.v0_start, layout.v0_end);
    let (wb_coeffs, wb_honest) = w_range_witness(&boundary.witness, 0, layout.v0_start);
    let (wa_coeffs, wa_honest) = w_range_witness(&boundary.witness, layout.v0_end, layout.total);
    let (yd_coeffs, yd_honest) = ydec_witness(rc, &shape);
    let (c1_coeffs, c1_honest) = if let Some(rci) = rc_inner { c1dec_witness(rci, &shape) } else { (Vec::new(), 0) };

    let v1_honest = wb_honest as u128 + wa_honest as u128 + yd_honest as u128 + c1_honest as u128;

    let v0_betasq = (v0_honest as u128).max(1) as u64;
    let v1_betasq = v1_honest.max(1) as u64;

    let mut v1_coeffs = Vec::with_capacity(wb_coeffs.len() + wa_coeffs.len() + yd_coeffs.len() + c1_coeffs.len());
    v1_coeffs.extend(wb_coeffs);
    v1_coeffs.extend(wa_coeffs);
    v1_coeffs.extend(yd_coeffs);
    v1_coeffs.extend(c1_coeffs);

    let vectors = vec![
        VectorRecord { n: specs[0].n, betasq: v0_betasq, role: specs[0].role, flags: specs[0].flags },
        VectorRecord { n: specs[1].n, betasq: v1_betasq, role: specs[1].role, flags: specs[1].flags },
    ];
    let witness_vectors = vec![
        WitnessVector { n: specs[0].n, coeffs: v0_coeffs },
        WitnessVector { n: specs[1].n, coeffs: v1_coeffs },
    ];

    assert!(v0_betasq as u128 <= betasq_inner_total as u128, "B0 exceeds betasq_inner_total");
    assert!(v0_betasq as u128 + v1_betasq as u128 <= betasq_w_total as u128, "B0+B1 exceeds betasq_w_total");

    let header = StatementHeader { q: MOD_Q, digest, betasq_w_total, betasq_inner_total };
    let stmt_path = dir.join("statement.bin");
    let wit_path = dir.join("witness.bin");
    write_statement(&stmt_path, &header, &vectors, &constraints);
    write_witness(&wit_path, MOD_Q, &witness_vectors);

    self_check(&stmt_path, &wit_path);

    println!("EXPORT SELF-CHECK OK");
}

fn self_check(stmt_path: &Path, wit_path: &Path) {
    let stmt = read_statement(stmt_path);
    let (wq, wit) = read_witness(wit_path);
    assert_eq!(stmt.q, wq, "statement/witness modulus mismatch");
    assert_eq!(stmt.vectors.len(), wit.len(), "statement/witness vector count mismatch");

    let mut role0_sum: u128 = 0;
    let mut inner_sum: u128 = 0;
    for (i, (v, wv)) in stmt.vectors.iter().zip(wit.iter()).enumerate() {
        assert_eq!(v.n, wv.n, "vector {i}: rank mismatch");
        assert_eq!(wv.coeffs.len(), wv.n * 64);
        let mut sum: u128 = 0;
        for &c in &wv.coeffs {
            assert!(c.abs() <= 23170, "vector {i}: |coeff| = {} exceeds 23170", c.abs());
            sum += (c as i128 * c as i128) as u128;
        }
        assert!(sum as u64 <= v.betasq, "vector {i}: recomputed betasq {sum} exceeds claimed {}", v.betasq);
        if v.role == ROLE_W {
            role0_sum += v.betasq as u128;
            if v.flags & INNER_FLAG != 0 {
                inner_sum += v.betasq as u128;
            }
        }
    }
    assert!(role0_sum <= stmt.betasq_w_total as u128, "sum betasq (role 0) exceeds betasq_w_total");
    assert!(inner_sum <= stmt.betasq_inner_total as u128, "sum betasq (INNER) exceeds betasq_inner_total");

    for (ci, c) in stmt.constraints.iter().enumerate() {
        let mut acc = r64::zero();
        let mut phi_pos = 0usize;
        for j in 0..c.idx.len() {
            let vi = c.idx[j];
            let boff = c.off[j];
            let blen = c.len[j];
            assert!(boff + blen <= stmt.vectors[vi].n, "constraint {ci}: block exceeds vector {vi} rank");
            let phi_slice = &c.phi[phi_pos..phi_pos + blen];
            phi_pos += blen;
            let s: Vec<r64::R64> = wit[vi].coeffs[boff * 64..(boff + blen) * 64]
                .chunks_exact(64)
                .map(|ch| {
                    let mut a = r64::zero();
                    for (dst, &src) in a.iter_mut().zip(ch) {
                        *dst = r64::uncenter(src);
                    }
                    a
                })
                .collect();
            acc = r64::add(&acc, &r64::dot(phi_slice, &s));
        }
        let target = c.b.unwrap_or_else(r64::zero);
        assert_eq!(acc, target, "constraint {ci}: LHS != b");
    }
}

pub fn export_verifier(dir: &Path, cut: usize, boundary: &mut VerifierBoundary, crs: &VerifierCRS) {
    let mut digest = [0u8; 16];
    boundary.transcript.fill_from_xof(b"rokoblador-handoff", &mut digest);

    let nc = &boundary.config;
    let round_cfg = round_config(cut);
    let shape = chain_shape(nc);
    let layout = compute_layout(round_cfg, &shape);
    let a2_cfg = &nc.commitment_recursion;

    let y_dec_len_padded = shape.a1_rank_padded * shape.width * shape.num_digits_y;
    let a1 = verifier_rows_eo(crs, shape.height, shape.a1_rank);
    let a2 = verifier_rows_eo(crs, y_dec_len_padded, shape.a2_rank);
    let (a3, a3_base_log) = if shape.has_c1dec {
        let a3_cfg = a2_cfg.next.as_deref().unwrap();
        let c1_dec_len = shape.a2_rank * shape.num_digits_c1;
        let a3 = verifier_rows_eo(crs, c1_dec_len, a3_cfg.rank).remove(0);
        (a3, a3_cfg.decomposition_base_log)
    } else {
        (Vec::new(), 0)
    };

    let (inner0, outer0, inner1, outer1) = eval_tensors(&boundary.evaluation_points, shape.width);

    let c_eo_vec: Vec<(r64::R64, r64::R64)> = boundary.commitment_root.iter().map(ring_eo).collect();
    let z0_eo = ring_eo(&boundary.claims[0]);
    let z1_eo = ring_eo(&boundary.claims[1]);

    let constraints = build_public(&layout, &shape, &a1, &a2, &a3, a2_cfg.decomposition_base_log, a3_base_log, &inner0, &outer0, &inner1, &outer1, &c_eo_vec, z0_eo, z1_eo);
    let specs = vector_specs(&layout);

    let betasq_w_total = (round_cfg.norm_bound.powi(2).floor() as u128 + caps(&shape, a2_cfg.decomposition_base_log, a3_base_log, &layout)) as u64;
    let betasq_inner_total = round_cfg.most_inner_norm_bound.powi(2).floor() as u64;

    let prover_stmt = read_statement(&dir.join("statement.bin"));
    assert_eq!(prover_stmt.vectors.len(), 2, "verifier-derived vector count differs from prover statement.bin");

    let mut role0_sum: u128 = 0;
    let mut inner_sum: u128 = 0;
    let mut vectors = Vec::with_capacity(2);
    for i in 0..2 {
        let spec = &specs[i];
        let pv = &prover_stmt.vectors[i];
        assert_eq!(pv.n, spec.n, "vector {i}: n mismatch vs prover statement.bin");
        assert_eq!(pv.role, spec.role, "vector {i}: role mismatch vs prover statement.bin");
        assert_eq!(pv.flags, spec.flags, "vector {i}: flags mismatch vs prover statement.bin");
        role0_sum += pv.betasq as u128;
        if spec.flags & INNER_FLAG != 0 {
            inner_sum += pv.betasq as u128;
        }
        vectors.push(VectorRecord { n: spec.n, betasq: pv.betasq, role: spec.role, flags: spec.flags });
    }
    assert!(inner_sum <= betasq_inner_total as u128, "verifier: B0 exceeds betasq_inner_total");
    assert!(role0_sum <= betasq_w_total as u128, "verifier: B0+B1 exceeds betasq_w_total");

    let header = StatementHeader { q: MOD_Q, digest, betasq_w_total, betasq_inner_total };
    write_statement(&dir.join("statement.verifier.bin"), &header, &vectors, &constraints);
}

pub fn finalize(dir: &Path, truncated_kb: f64) {
    println!("Truncated rokoko proof size: {truncated_kb} KB");
    let a = std::fs::read(dir.join("statement.bin")).expect("missing statement.bin");
    let b = std::fs::read(dir.join("statement.verifier.bin")).expect("missing statement.verifier.bin");
    assert_eq!(a, b, "statement.bin != statement.verifier.bin");
    println!("STATEMENT MATCH OK: statement.bin == statement.verifier.bin byte-for-byte ({} bytes)", a.len());
}

extern "C" {
    fn rokoblador_run(statement_path: *const std::ffi::c_char, witness_path: *const std::ffi::c_char, pack_kb_out: *mut f64) -> i32;
}

pub fn run_labrador(stmt_path: &Path, wit_path: &Path) -> (i32, f64) {
    let stmt = std::ffi::CString::new(stmt_path.to_str().expect("non-utf8 export path")).expect("nul byte in export path");
    let wit = std::ffi::CString::new(wit_path.to_str().expect("non-utf8 export path")).expect("nul byte in export path");
    let mut pack_kb: f64 = 0.0;
    let ret = unsafe { rokoblador_run(stmt.as_ptr(), wit.as_ptr(), &mut pack_kb) };
    (ret, pack_kb)
}
