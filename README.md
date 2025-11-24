<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1_github600x160.png">
</p>

---

# `ragu` ![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg) [![codecov](https://codecov.io/gh/tachyon-zcash/ragu/graph/badge.svg?token=HJARL1P2O4)](https://codecov.io/gh/tachyon-zcash/ragu)

**Ragu** is a Rust-language [proof-carrying data (PCD)](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) framework that implements a modified version of the ECDLP-based recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Ragu does not use a trusted setup. Developed for use with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) used in [Zcash](https://z.cash/), and designed specifically for use in [Project Tachyon](https://tachyon.z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370) schemes without complicated circuit arithmetizations.

> ⚠️ **Ragu is under heavy development and has not undergone auditing.** Do not use this software in production.

## Resources

The Ragu Book provides high-level documentation about Ragu, how it can be used, how it is designed, and how to contribute. The source code for the book lives in this repository in the [`book`](https://github.com/tachyon-zcash/ragu/tree/main/book) subdirectory.

#### [Documentation](https://docs.rs/ragu/)

> 📖 We also host a copy of the internal documentation that is continually rendered based on the `main` branch. This is primarily for developers of Ragu.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
