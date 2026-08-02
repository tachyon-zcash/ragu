# Requirements

* The minimum supported [Rust](https://rust-lang.org/) version is currently
  **1.90.0**.
* Ragu requires minimal dependencies and currently strives to avoid using
  dependencies that are not already used in
  [Zebra](https://github.com/ZcashFoundation/zebra).

## Circuits Are Defined at Compile Time {#compile-time-circuits}

Ragu circuits are described in Rust and are built during `cargo build`,
so they end up inside your binary rather than in a data file alongside
it.

```admonish warning
There is no serialization path for circuits. Ragu does not support
writing a circuit to a file or reading one back, and it does not
provide serializable verifying keys.
```

The practical consequence is that the binary carries the circuit. A
verifier has to be built from the same circuit definitions as the
prover, rather than loading a key file at startup.

[halo2] works this way too, for the same reason.

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
[halo2]: https://github.com/zcash/halo2
[maybe-rayon]: https://crates.io/crates/maybe-rayon
