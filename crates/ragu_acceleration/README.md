<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_acceleration`

This crate provides Ragu's accelerated computational backend. It inherits the
defaults from `ragu_backend`, which call Udon's MSM and FFT implementations,
except for individually tested overrides.

With the `gpu` feature, `AcceleratedProver` commits to polynomials on a CUDA
device and offers the device as a `PolyDevice`, a store of polynomials that
`ragu_pcd`'s fuse keeps its work on. The engine is `gpu/ragu_gpu.cu`, which
`build.rs` compiles when it finds the CUDA toolkit (`CUDA_HOME`, then
`CUDA_PATH`, then `/usr/local/cuda`); without the toolkit the crate builds
without the device. A machine with no usable device, or a process run with
`RAGU_GPU=0`, uses the CPU kernels. Every result is the group or field element
the reference backend computes.

An override arrives with its differential test against `ReferenceBackend`:
`tests/gpu.rs` checks each device operation against host arithmetic, and
passes trivially where there is no device. `ragu_pcd`'s `backend_equivalence`
tests hold `AcceleratedProver` to the reference end to end, in the `backend
equivalence` CI lane behind the required `backend-required` check. CI has no
CUDA device, so the device path is exercised only on a machine that has one.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
