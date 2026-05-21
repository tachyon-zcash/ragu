# Requirements

* The minimum supported [Rust](https://rust-lang.org/) version is currently
  **1.90.0**.
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

By default, the `multicore` feature is enabled; it pulls in `std`
via [maybe-rayon] for multi-threaded parallelism. Build with
`--no-default-features` to drop it.

[`alloc`]: https://doc.rust-lang.org/alloc/
[maybe-rayon]: https://crates.io/crates/maybe-rayon
