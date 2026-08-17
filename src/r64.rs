use rokoko::common::config::MOD_Q;
use rokoko::hexl::bindings::{add_mod, multiply_mod, sub_mod};

pub const N: usize = 64;
pub type R64 = [u64; N];

pub fn zero() -> R64 {
    [0u64; N]
}

pub fn add(a: &R64, b: &R64) -> R64 {
    let mut r = zero();
    for i in 0..N {
        r[i] = unsafe { add_mod(a[i], b[i], MOD_Q) };
    }
    r
}

pub fn const_elem_neg(v: u64) -> R64 {
    let mut r = zero();
    r[0] = unsafe { sub_mod(0, v, MOD_Q) };
    r
}

pub fn shift_y(a: &R64) -> R64 {
    let mut r = zero();
    r[0] = unsafe { sub_mod(0, a[N - 1], MOD_Q) };
    r[1..N].copy_from_slice(&a[0..N - 1]);
    r
}

pub fn phi_for_part(a_e: &R64, a_o: &R64, part: usize) -> (R64, R64) {
    if part == 0 {
        (*a_e, shift_y(a_o))
    } else {
        (*a_o, *a_e)
    }
}

pub fn mul(a: &R64, b: &R64) -> R64 {
    let mut acc = zero();
    for i in 0..N {
        for j in 0..N {
            let p = unsafe { multiply_mod(a[i], b[j], MOD_Q) };
            let idx = i + j;
            if idx < N {
                acc[idx] = unsafe { add_mod(acc[idx], p, MOD_Q) };
            } else {
                acc[idx - N] = unsafe { sub_mod(acc[idx - N], p, MOD_Q) };
            }
        }
    }
    acc
}

pub fn dot(phis: &[R64], ss: &[R64]) -> R64 {
    let mut acc = zero();
    for (p, s) in phis.iter().zip(ss.iter()) {
        acc = add(&acc, &mul(p, s));
    }
    acc
}

pub fn center(v: u64) -> i64 {
    if v > MOD_Q / 2 {
        v as i64 - MOD_Q as i64
    } else {
        v as i64
    }
}

pub fn uncenter(v: i64) -> u64 {
    if v < 0 {
        (v + MOD_Q as i64) as u64
    } else {
        v as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shift_y_matches_mul_by_y() {
        let mut y = zero();
        y[1] = 1;
        for _ in 0..8 {
            let a: R64 = std::array::from_fn(|i| ((i as u64) * 97 + 31) % MOD_Q);
            assert_eq!(shift_y(&a), mul(&y, &a));
        }
    }

    #[test]
    fn center_uncenter_roundtrip() {
        for v in [0u64, 1, MOD_Q / 2, MOD_Q / 2 + 1, MOD_Q - 1] {
            assert_eq!(uncenter(center(v)), v);
        }
    }
}
