# Requirements

* The minimum supported [Rust](https://rust-lang.org/) version is currently
  **1.90.0**.
* Ragu requires minimal dependencies and currently strives to avoid using
  dependencies that are not already used in
  [Zebra](https://github.com/ZcashFoundation/zebra).

## `no_std` Support

Ragu's approach to `std` and `no_std` follows four principles:

1. **No `std` by default.** All library crates are `#![no_std]` and expose
   an optional `std` feature flag for opting in.
2. **`alloc` is required.** All library crates depend on the [`alloc`]
   crate for heap-allocated types such as `Vec` and `Box`. In practice
   this means Ragu can target environments that provide a global
   allocator but lack a full `std` runtime, such as WebAssembly or
   embedded platforms.
3. **Performance features may depend on `std`.** Optional features like
   `multicore` enable multi-threaded parallelism and imply `std`.
4. **`std` is required on the host.** Build scripts, procedural macros,
   tests, and benchmarks all run on the host and require `std`. This is a
   common requirement even for `no_std` libraries in the Rust
   ecosystem.

[`alloc`]: https://doc.rust-lang.org/alloc/
