use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let labrador_dir = env::var("ROKOBLADOR_LABRADOR_DIR")
        .unwrap_or_else(|_| format!("{manifest_dir}/../labrador"));

    let status = Command::new("make")
        .args(["-C", &labrador_dir, "LOGQ=50", "liblabrador.a"])
        .status()
        .expect("failed to invoke make for liblabrador.a");
    assert!(status.success(), "make -C {labrador_dir} LOGQ=50 liblabrador.a failed");
    println!("cargo:rerun-if-changed={labrador_dir}");

    let c_src = format!("{manifest_dir}/csrc/rokoblador.c");
    let c_hdr = format!("{manifest_dir}/csrc/rokoblador.h");
    let c_obj = out_dir.join("rokoblador.o");
    let status = Command::new("gcc")
        .args([
            "-std=c2x",
            "-O3",
            "-march=native",
            "-mtune=native",
            "-fwrapv",
            "-Wall",
            "-Wextra",
            "-DLOGQ=50",
            "-I",
            &labrador_dir,
            "-c",
            &c_src,
            "-o",
        ])
        .arg(&c_obj)
        .status()
        .expect("failed to invoke gcc for csrc/rokoblador.c");
    assert!(status.success(), "gcc failed to compile csrc/rokoblador.c");
    println!("cargo:rerun-if-changed={c_src}");
    println!("cargo:rerun-if-changed={c_hdr}");

    let c_lib = out_dir.join("librokoblador_c.a");
    let status = Command::new("ar")
        .arg("rcs")
        .arg(&c_lib)
        .arg(&c_obj)
        .status()
        .expect("failed to invoke ar for librokoblador_c.a");
    assert!(status.success(), "ar failed to archive librokoblador_c.a");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-search=native={labrador_dir}");
    println!("cargo:rustc-link-lib=static=rokoblador_c");
    println!("cargo:rustc-link-lib=static=labrador");
    println!("cargo:rustc-link-lib=m");
}
