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

pub const ROLE_W: u32 = 0;
pub const INNER_FLAG: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorDesc {
    pub n: usize,
    pub betasq: u64,
    pub role: u32,
    pub flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    pub idx: Vec<usize>,
    pub off: Vec<usize>,
    pub len: Vec<usize>,
    pub b: Option<r64::R64>,
    pub phi: Vec<r64::R64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub q: u64,
    pub digest: [u8; 16],
    pub betasq_w_total: u64,
    pub betasq_inner_total: u64,
    pub vectors: Vec<VectorDesc>,
    pub constraints: Vec<Constraint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub vectors: Vec<Vec<i64>>,
}

fn u64_from_u128(x: u128, what: &str) -> u64 {
    u64::try_from(x).unwrap_or_else(|_| panic!("{what} overflowed u64: {x}"))
}

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

    let inner_positions: Vec<usize> = (0..total).filter(|&g| is_inner(g)).collect();
    let (v0_start, v0_end) = if inner_positions.is_empty() {
        (0, total / 2)
    } else {
        let start = inner_positions[0];
        let end = *inner_positions.last().unwrap() + 1;
        assert_eq!(
            inner_positions.len(),
            end - start,
            "most-inner ranges are not contiguous: {} inner positions span [{start},{end}) \
             which would silently include non-inner gaps as inner",
            inner_positions.len(),
        );
        (start, end)
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

pub fn estimate_total_rank(cut: usize) -> usize {
    let nc = round_config(cut + 1);
    let round_cfg = round_config(cut);
    let shape = chain_shape(nc);
    let layout = compute_layout(round_cfg, &shape);
    let specs = vector_specs(&layout);
    specs[0].n + specs[1].n
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
) -> Vec<Constraint> {
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
                constraints.push(Constraint { idx, off, len, b: None, phi });
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
                constraints.push(Constraint {
                    idx: vec![1, 1],
                    off: vec![ydec_base_off, c1dec_base_off + u * shape.num_digits_c1 * 2],
                    len: vec![layout.ydec_len, shape.num_digits_c1 * 2],
                    b: None,
                    phi,
                });
            } else {
                let b = if p == 0 { c_eo_vec[u].0 } else { c_eo_vec[u].1 };
                constraints.push(Constraint {
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
            constraints.push(Constraint { idx: vec![1], off: vec![c1dec_base_off], len: vec![layout.c1dec_len], b: Some(b), phi: block });
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
            constraints.push(Constraint { idx, off, len, b: Some(b), phi });
        }
    }

    constraints
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
    (coeffs, u64_from_u128(betasq, "w-range betasq"))
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
    (coeffs, u64_from_u128(betasq, "ydec betasq"))
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
    (coeffs, u64_from_u128(betasq, "c1dec betasq"))
}

fn caps(shape: &ChainShape, a2_base_log: usize, a3_base_log: usize, layout: &Layout) -> u128 {
    let ydec_cap = layout.ydec_len as u128 * 64 * digit_bound_sq(a2_base_log) as u128;
    let c1dec_cap = if shape.has_c1dec { layout.c1dec_len as u128 * 64 * digit_bound_sq(a3_base_log) as u128 } else { 0 };
    ydec_cap + c1dec_cap
}

fn encode_shape(buf: &mut Vec<u8>, q: u64, vectors: &[VectorDesc], betasq_w_total: u64, betasq_inner_total: u64, constraints: &[Constraint]) {
    buf.extend_from_slice(&q.to_le_bytes());
    buf.extend_from_slice(&(vectors.len() as u64).to_le_bytes());
    for v in vectors {
        buf.extend_from_slice(&(v.n as u64).to_le_bytes());
        buf.extend_from_slice(&v.betasq.to_le_bytes());
        buf.extend_from_slice(&v.role.to_le_bytes());
        buf.extend_from_slice(&v.flags.to_le_bytes());
    }
    buf.extend_from_slice(&betasq_w_total.to_le_bytes());
    buf.extend_from_slice(&betasq_inner_total.to_le_bytes());
    buf.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    for c in constraints {
        buf.extend_from_slice(&(c.idx.len() as u64).to_le_bytes());
        for &x in &c.idx {
            buf.extend_from_slice(&(x as u64).to_le_bytes());
        }
        for &x in &c.off {
            buf.extend_from_slice(&(x as u64).to_le_bytes());
        }
        for &x in &c.len {
            buf.extend_from_slice(&(x as u64).to_le_bytes());
        }
        buf.push(c.b.is_some() as u8);
    }
}

fn compute_digest(
    transcript_xof16: &[u8; 16],
    q: u64,
    vectors: &[VectorDesc],
    betasq_w_total: u64,
    betasq_inner_total: u64,
    constraints: &[Constraint],
) -> [u8; 16] {
    let mut buf = Vec::new();
    buf.extend_from_slice(transcript_xof16);
    encode_shape(&mut buf, q, vectors, betasq_w_total, betasq_inner_total, constraints);
    let hash = blake3::hash(&buf);
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&hash.as_bytes()[..16]);
    digest
}

pub fn fingerprint(stmt: &Statement, wit: &Witness) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&stmt.digest);
    encode_shape(&mut buf, stmt.q, &stmt.vectors, stmt.betasq_w_total, stmt.betasq_inner_total, &stmt.constraints);
    for c in &stmt.constraints {
        if let Some(b) = &c.b {
            for &x in b {
                buf.extend_from_slice(&x.to_le_bytes());
            }
        }
        for el in &c.phi {
            for &x in el {
                buf.extend_from_slice(&x.to_le_bytes());
            }
        }
    }
    buf.extend_from_slice(&(wit.vectors.len() as u64).to_le_bytes());
    for v in &wit.vectors {
        buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        for &x in v {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    *blake3::hash(&buf).as_bytes()
}

pub fn export_prover(cut: usize, boundary: &mut ProverBoundary, crs: &CRS) -> (Statement, Witness) {
    let mut transcript_xof16 = [0u8; 16];
    boundary.transcript.fill_from_xof(b"rokoblador-handoff", &mut transcript_xof16);

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

    let betasq_w_total = u64_from_u128(
        round_cfg.norm_bound.powi(2).floor() as u128 + caps(&shape, a2_cfg.decomposition_base_log, a3_base_log, &layout),
        "betasq_w_total",
    );
    let betasq_inner_total = u64_from_u128(round_cfg.most_inner_norm_bound.powi(2).floor() as u128, "betasq_inner_total");

    let (v0_coeffs, v0_honest) = w_range_witness(&boundary.witness, layout.v0_start, layout.v0_end);
    let (wb_coeffs, wb_honest) = w_range_witness(&boundary.witness, 0, layout.v0_start);
    let (wa_coeffs, wa_honest) = w_range_witness(&boundary.witness, layout.v0_end, layout.total);
    let (yd_coeffs, yd_honest) = ydec_witness(rc, &shape);
    let (c1_coeffs, c1_honest) = if let Some(rci) = rc_inner { c1dec_witness(rci, &shape) } else { (Vec::new(), 0) };

    let v1_honest = wb_honest as u128 + wa_honest as u128 + yd_honest as u128 + c1_honest as u128;

    let v0_betasq = u64_from_u128((v0_honest as u128).max(1), "v0_betasq");
    let v1_betasq = u64_from_u128(v1_honest.max(1), "v1_betasq");

    let mut v1_coeffs = Vec::with_capacity(wb_coeffs.len() + wa_coeffs.len() + yd_coeffs.len() + c1_coeffs.len());
    v1_coeffs.extend(wb_coeffs);
    v1_coeffs.extend(wa_coeffs);
    v1_coeffs.extend(yd_coeffs);
    v1_coeffs.extend(c1_coeffs);

    let vectors = vec![
        VectorDesc { n: specs[0].n, betasq: v0_betasq, role: specs[0].role, flags: specs[0].flags },
        VectorDesc { n: specs[1].n, betasq: v1_betasq, role: specs[1].role, flags: specs[1].flags },
    ];
    let witness = Witness { vectors: vec![v0_coeffs, v1_coeffs] };

    assert!(v0_betasq as u128 <= betasq_inner_total as u128, "B0 exceeds betasq_inner_total");
    assert!(v0_betasq as u128 + v1_betasq as u128 <= betasq_w_total as u128, "B0+B1 exceeds betasq_w_total");

    let digest = compute_digest(&transcript_xof16, MOD_Q, &vectors, betasq_w_total, betasq_inner_total, &constraints);
    let stmt = Statement { q: MOD_Q, digest, betasq_w_total, betasq_inner_total, vectors, constraints };

    self_check(&stmt, &witness).expect("EXPORT SELF-CHECK failed");
    println!("EXPORT SELF-CHECK OK");

    (stmt, witness)
}

fn self_check(stmt: &Statement, wit: &Witness) -> Result<(), String> {
    if stmt.vectors.len() != wit.vectors.len() {
        return Err("statement/witness vector count mismatch".into());
    }
    for (ci, c) in stmt.constraints.iter().enumerate() {
        let mut acc = r64::zero();
        let mut phi_pos = 0usize;
        for j in 0..c.idx.len() {
            let vi = c.idx[j];
            let boff = c.off[j];
            let blen = c.len[j];
            if boff + blen > stmt.vectors[vi].n {
                return Err(format!("constraint {ci}: block exceeds vector {vi} rank"));
            }
            let phi_slice = &c.phi[phi_pos..phi_pos + blen];
            phi_pos += blen;
            let s: Vec<r64::R64> = wit.vectors[vi][boff * 64..(boff + blen) * 64]
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
        if acc != target {
            return Err(format!("constraint {ci}: LHS != b"));
        }
    }
    Ok(())
}

pub fn export_verifier(cut: usize, boundary: &mut VerifierBoundary, crs: &VerifierCRS, prover_betasq: &[u64]) -> Statement {
    let mut transcript_xof16 = [0u8; 16];
    boundary.transcript.fill_from_xof(b"rokoblador-handoff", &mut transcript_xof16);

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

    let betasq_w_total = u64_from_u128(
        round_cfg.norm_bound.powi(2).floor() as u128 + caps(&shape, a2_cfg.decomposition_base_log, a3_base_log, &layout),
        "betasq_w_total",
    );
    let betasq_inner_total = u64_from_u128(round_cfg.most_inner_norm_bound.powi(2).floor() as u128, "betasq_inner_total");

    assert_eq!(prover_betasq.len(), 2, "verifier-derived vector count differs from the transmitted betasq claims");
    let vectors = vec![
        VectorDesc { n: specs[0].n, betasq: prover_betasq[0], role: specs[0].role, flags: specs[0].flags },
        VectorDesc { n: specs[1].n, betasq: prover_betasq[1], role: specs[1].role, flags: specs[1].flags },
    ];

    let digest = compute_digest(&transcript_xof16, MOD_Q, &vectors, betasq_w_total, betasq_inner_total, &constraints);
    Statement { q: MOD_Q, digest, betasq_w_total, betasq_inner_total, vectors, constraints }
}
