# Requirements

* The minimum supported [Rust](https://rust-lang.org/) version is currently
  **1.97.1**.
* Ragu requires minimal dependencies and currently strives to avoid using
  dependencies that are not already used in
  [Zebra](https://github.com/ZcashFoundation/zebra).

## `no_std` Support {#no-std}

None of Ragu's library code requires the standard library. Every
library crate is `#![no_std]`.

Ragu does need a global allocator, since the library uses `Vec`,
`Box`, and similar heap types from the [`alloc`] crate. That means it
is happy on targets with an allocator but no full `std` runtime —
WebAssembly and embedded platforms, for example.

`ragu_core`, `ragu_primitives`, and `ragu_circuits` enable only `alloc` by
default. `ragu_pcd` enables `alloc` and `asm`: Udon's AArch64 field arithmetic.
On x86-64, Udon uses its own assembly only in a build whose target features
include BMI2 and ADX (for example with `-C target-cpu=native` on a supporting
CPU) or with its `x86_64-asm` feature. It does not detect the CPU at run time,
so such a binary faults on a CPU without those extensions, and any other
x86-64 build uses portable Rust. Other targets and Miri use portable Rust too.
Assembly does not require `std`. To use portable arithmetic on AArch64, disable
default features and retain `alloc`; no dependency may enable Udon's
`aarch64-asm` feature in that build. On x86-64, a build compiled for those
extensions stays portable with Udon's `portable` feature. The
`multicore` feature of `ragu_pcd` is opt-in; it pulls in `std` via
[maybe-rayon] for multi-threaded parallelism.

The `ragu` crate enables `asm` and `multicore` by default and forwards each to
`ragu_pcd`. A `no_std` build of `ragu` disables default features, which also
selects the portable arithmetic on AArch64; add `asm` back to keep the
assembly.

[`alloc`]: https://doc.rust-lang.org/alloc/
[maybe-rayon]: https://crates.io/crates/maybe-rayon
