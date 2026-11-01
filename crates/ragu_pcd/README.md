<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_pcd`

This crate contains internal implementation code for the [`ragu`](https://crates.io/crates/ragu) crate.

The [`pasta`](src/pasta/) module owns Ragu's fixed generator derivation and
loading. With the `baked` feature, `build.rs` derives the generators on the host
using `pasta_curves` only for hash-to-curve, converts them to checked Udon points,
and writes them through Bento POD. The runtime embeds those typed points with
Bento; `pasta::baked()` adapts them once into Udon's parameter containers without
decoding coordinates. The derivation preserves Ragu's existing generators. The
feature enables `alloc` and supports `no_std`.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
