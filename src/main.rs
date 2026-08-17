use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use rokoko::common::init_common;
use rokoko::protocol::config::to_kb;
use rokoko::protocol::parties::executor::execute_to_boundary;

mod export;
mod r64;

fn usage() -> ! {
    eprintln!("usage: rokoblador [--cut K] [--out DIR]");
    eprintln!("       rokoblador check <statement.bin> <witness.bin>");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("check") {
        if args.len() != 3 {
            usage();
        }
        let (ret, _pack_kb) = export::run_labrador(Path::new(&args[1]), Path::new(&args[2]));
        std::process::exit(ret);
    }

    let mut cut: usize = 3;
    let mut out_dir = PathBuf::from("rokoblador-export");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cut" => {
                i += 1;
                cut = args.get(i).unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
            }
            "--out" => {
                i += 1;
                out_dir = PathBuf::from(args.get(i).unwrap_or_else(|| usage()));
            }
            _ => usage(),
        }
        i += 1;
    }
    let cut_nz = NonZeroUsize::new(cut).unwrap_or_else(|| usage());

    init_common();

    let mut run = execute_to_boundary(cut_nz);

    export::export_prover(&out_dir, cut, &mut run.prover, &run.crs);
    export::export_verifier(&out_dir, cut, &mut run.verifier, &run.verifier_crs);

    let truncated_kb = to_kb(run.proof_size_bits);
    export::finalize(&out_dir, truncated_kb);

    let (ret, pack_kb) = export::run_labrador(&out_dir.join("statement.verifier.bin"), &out_dir.join("witness.bin"));
    if ret != 0 {
        std::process::exit(ret);
    }
    println!("COMBINED proof size: {truncated_kb} + {pack_kb} = {} KB", truncated_kb + pack_kb);
}
