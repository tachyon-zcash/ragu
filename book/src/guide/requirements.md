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

Features belong to individual crates. `ragu_core`, `ragu_primitives`,
`ragu_circuits`, and `ragu_pcd` enable `alloc` by default, without enabling
`multicore`. When disabling their default features, keep `alloc` enabled.

| Crate and feature | Effect |
| --- | --- |
| `ragu_pcd/alloc` | Enables the allocation support required by the crate; enabled by default. |
| `ragu_pcd/std` | Enables `alloc` and standard-library support in `ragu_core`. |
| `ragu_pcd/multicore` | Enables parallel execution through [maybe-rayon] and the backend and circuit crates; also enables `std`. |
| `ragu/multicore` | Enabled by default on the root crate, but retained only for compatibility; it enables neither parallel execution nor `std`. |

For example, these commands select allocation support without enabling
standard-library or parallel execution features:

```sh
cargo check -p ragu_pcd --no-default-features --features alloc
cargo check -p ragu_core --no-default-features --features alloc
```

Cargo combines features requested for the same dependency. Check the other
dependencies in your application as well: another dependency enabling
`std` or `multicore` can enable those features in the combined build.

[`alloc`]: https://doc.rust-lang.org/alloc/
[maybe-rayon]: https://crates.io/crates/maybe-rayon
