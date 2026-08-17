use std::num::NonZeroUsize;
use std::time::Instant;

use rokoko::common::init_common;
use rokoko::protocol::config::{to_kb, SizeableProof};

use rokoblador::proof::CombinedProof;
use rokoblador::{driver, export, labrador};

fn usage() -> ! {
    eprintln!("usage: rokoblador [--cut K]");
    std::process::exit(2);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(cut: usize) -> Result<(), String> {
    let cut_nz = NonZeroUsize::new(cut).ok_or("--cut must be nonzero")?;

    init_common();

    let total_rank_estimate = export::estimate_total_rank(cut);
    let precomputed_len = labrador::precomputed_len_for_rank(total_rank_estimate);
    let comkey_thread = labrador::warm_comkey(precomputed_len);

    let t_rokoko_setup = Instant::now();
    let mut setup = driver::setup();
    let rokoko_setup_s = t_rokoko_setup.elapsed().as_secs_f64();

    let labrador_setup_s = comkey_thread
        .join()
        .map_err(|_| "comkey warm-up thread panicked".to_string())?
        .as_secs_f64();
    println!("setup: rokoko {rokoko_setup_s:.3} s \u{2225} labrador {labrador_setup_s:.3} s");

    let t_prove = Instant::now();
    let mut prove_output = driver::prove(&mut setup, cut_nz);
    let rokoko_prove_s = t_prove.elapsed().as_secs_f64();

    let t_export = Instant::now();
    let (stmt, wit) = export::export_prover(cut, &mut prove_output.prover_boundary, setup.crs());
    let export_s = t_export.elapsed().as_secs_f64();

    let truncated_kb = to_kb(prove_output.handoff.proof.size_in_bits());

    let t_lab_prove = Instant::now();
    let (handle, pack_kb) = labrador::prove(&stmt, &wit)?;
    let lab_prove_s = t_lab_prove.elapsed().as_secs_f64();

    println!("PROVE phase: rokoko {rokoko_prove_s:.3} s + export {export_s:.3} s + labrador {lab_prove_s:.3} s");
    println!("Truncated rokoko proof size: {truncated_kb} KB");
    println!("COMBINED proof size: {truncated_kb} + {pack_kb} = {} KB", truncated_kb + pack_kb);
    println!("MODEL FINGERPRINT: {}", hex(&export::fingerprint(&stmt, &wit)));

    let per_vector_betasq: Vec<u64> = stmt.vectors.iter().map(|v| v.betasq).collect();
    let combined = CombinedProof {
        rokoko: prove_output.handoff,
        per_vector_betasq,
        labrador: handle,
    };

    let t_verify = Instant::now();
    let mut verifier_boundary = driver::verify(&mut setup, cut_nz, &combined.rokoko);
    let rokoko_verify_s = t_verify.elapsed().as_secs_f64();

    let t_derive = Instant::now();
    let verifier_stmt = export::export_verifier(cut, &mut verifier_boundary, setup.verifier_crs(), &combined.per_vector_betasq);
    if verifier_stmt != stmt {
        return Err("STATEMENT MATCH FAILED: prover and verifier models differ".into());
    }
    println!("STATEMENT MATCH OK");
    let derive_s = t_derive.elapsed().as_secs_f64();

    let t_lab_verify = Instant::now();
    let verify_result = labrador::verify(&verifier_stmt, &combined.labrador);
    let lab_verify_s = t_lab_verify.elapsed().as_secs_f64();

    drop(combined);
    labrador::free_comkey();

    println!("VERIFY phase: rokoko {rokoko_verify_s:.3} s + derive {derive_s:.3} s + labrador {lab_verify_s:.3} s");

    verify_result?;
    Ok(())
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut cut: usize = 3;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cut" => {
                i += 1;
                cut = args.get(i).unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
            }
            _ => usage(),
        }
        i += 1;
    }

    run(cut)
}
