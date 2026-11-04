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
default. `ragu_pcd` enables `alloc` and `asm`: Udon's AArch64 field arithmetic,
with portable Rust on other targets and in Miri. Assembly does not require
`std`. To use portable arithmetic on AArch64, disable default features and
retain `alloc`; no dependency may enable Udon's `aarch64-asm` feature in that
build. The `multicore` feature of `ragu_pcd` is opt-in; it pulls in `std` via
[maybe-rayon] for multi-threaded parallelism.

[`alloc`]: https://doc.rust-lang.org/alloc/
[maybe-rayon]: https://crates.io/crates/maybe-rayon
