//! Cargo entry point for generating the baked Pasta parameters.

use std::{env, path::PathBuf};

#[path = "src/pasta/generate.rs"]
mod generate;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/pasta/generate.rs");
    println!("cargo:rerun-if-env-changed=RAGU_PCD_NIGHTLY_TESTS");
    println!("cargo:rustc-check-cfg=cfg(ragu_pcd_nightly_tests)");
    if env::var("RAGU_PCD_NIGHTLY_TESTS").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=ragu_pcd_nightly_tests");
    }
    println!("cargo:rerun-if-env-changed=RAGU_PCD_TARGETED_TESTS");
    println!("cargo:rustc-check-cfg=cfg(ragu_pcd_targeted_tests)");
    if env::var("RAGU_PCD_TARGETED_TESTS").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=ragu_pcd_targeted_tests");
    }
    println!("cargo:rerun-if-env-changed=RAGU_PCD_PAGING_CENSUS_BATCH");
    println!("cargo:rustc-check-cfg=cfg(ragu_pcd_paging_census)");
    let batches = (0..13)
        .map(|batch| format!("\"{batch}\""))
        .collect::<Vec<_>>()
        .join(", ");
    println!("cargo:rustc-check-cfg=cfg(ragu_pcd_paging_census_batch, values({batches}))");
    if let Ok(batch) = env::var("RAGU_PCD_PAGING_CENSUS_BATCH") {
        let batch: usize = batch.parse().expect("paging census batch is an integer");
        assert!(batch < 13, "paging census batch is between 0 and 12");
        println!("cargo:rustc-cfg=ragu_pcd_paging_census");
        println!("cargo:rustc-cfg=ragu_pcd_paging_census_batch=\"{batch}\"");
    }

    if env::var("CARGO_FEATURE_BAKED").is_err() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    generate::write_parameters(
        &out_dir,
        env::var_os("CARGO_FEATURE_BAKED_AGGREGATOR").is_some(),
    )
    .unwrap();
}
