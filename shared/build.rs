use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let input =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir")).join("schema.ergot");
    let output = out_dir.join("schema.rs");

    println!("cargo:rerun-if-changed={}", input.display());

    fs::copy(&input, &output).expect("copy schema");
}
