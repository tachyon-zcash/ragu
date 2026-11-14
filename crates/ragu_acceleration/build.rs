//! Compiles the CUDA engine when the `gpu` feature is selected.
//!
//! The crate's device code is compiled under `cfg(ragu_cuda)`, which this
//! script sets once the engine is built. Without the CUDA compiler the
//! feature builds the CPU kernels alone, with a warning, so that a build
//! with every feature selected does not need the toolkit.
//!
//! The toolkit is found through `CUDA_HOME`, then `CUDA_PATH`, then
//! `/usr/local/cuda`. `RAGU_CUDA_ARCH` selects the `nvcc -arch` value and
//! defaults to `native`, the device of the build machine: code generated
//! for the device itself does not depend on the driver's PTX compiler, which
//! rejects output of a toolkit newer than the driver.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(ragu_cuda)");
    if env::var_os("CARGO_FEATURE_GPU").is_none() {
        return;
    }
    for name in ["CUDA_HOME", "CUDA_PATH", "RAGU_CUDA_ARCH"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for source in ["gpu/ragu_gpu.cu", "gpu/ragu_gpu.h"] {
        println!("cargo:rerun-if-changed={source}");
    }

    let cuda = env::var_os("CUDA_HOME")
        .or_else(|| env::var_os("CUDA_PATH"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/cuda"));
    let nvcc = cuda.join("bin").join("nvcc");
    if !nvcc.is_file() {
        println!(
            "cargo:warning=the `gpu` feature is selected but {} does not exist; building \
             without the device (set CUDA_HOME to the CUDA toolkit)",
            nvcc.display()
        );
        return;
    }
    let arch = env::var("RAGU_CUDA_ARCH").unwrap_or_else(|_| "native".into());
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let object = out.join("ragu_gpu.o");
    let archive = out.join("libragu_gpu.a");

    let status = Command::new(&nvcc)
        .args(["-O3", "-std=c++17", "-Xcompiler", "-fPIC"])
        .arg(format!("-arch={arch}"))
        .args(["-c", "gpu/ragu_gpu.cu", "-o"])
        .arg(&object)
        .status()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", nvcc.display()));
    assert!(status.success(), "nvcc failed on gpu/ragu_gpu.cu");

    let status = Command::new("ar")
        .arg("crs")
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("cannot run ar");
    assert!(status.success(), "ar failed on libragu_gpu.a");

    println!("cargo:rustc-cfg=ragu_cuda");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=ragu_gpu");
    println!(
        "cargo:rustc-link-search=native={}",
        cuda.join("lib64").display()
    );
    println!("cargo:rustc-link-lib=static=cudart_static");
    for library in ["stdc++", "dl", "rt", "pthread"] {
        println!("cargo:rustc-link-lib=dylib={library}");
    }
}
