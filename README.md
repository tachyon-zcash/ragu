<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1_github600x160.png">
</p>

---

# `ragu` ![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)

**Ragu** is a Rust-language [proof-carrying data (PCD)](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) framework that implements a modified version of the recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Developed for use with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) used in [Zcash](https://z.cash/), and designed specifically for use in [Project Tachyon](https://tachyon.z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370) schemes without complicated circuit arithmetizations. Ragu does not require a trusted setup.

> **Ragu is under heavy development and has not undergone auditing.** Do not use this software in production.

## Cryptographic Overview

Ragu implements a modified version of the recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021), which uses a [Sonic [MBKM19]](https://eprint.iacr.org/2019/099)-based protocol that stems from the [[BCCGP16]](https://eprint.iacr.org/2016/263) lineage of R1CS-based argument systems also used in [Bulletproofs [BBBPWM17]](https://eprint.iacr.org/2017/1066). The protocol is modified slightly to better adapt to [split accumulation [BCLMS20]](https://eprint.iacr.org/2020/1618) techniques and continues to rely on [univariate polynomial commitment schemes](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) based on Pedersen vector commitments, and on Halo's techniques to avoid circuit preprocessing.

* **R1CS-based arithmetization:** We do not support "custom gates", lookup arguments and other kinds of flexibility seen in projects like [`halo2`](https://github.com/zcash/halo2). Instead, we offer a simple R1CS protocol (familiar to users of QAP-based SNARKs like [[Groth16]](https://eprint.iacr.org/2016/260)) that does not require sparse matrices and thus supports unlimited fan-in addition gates.
* **Univariate polynomial IOPs:** Ragu reduces nearly all of its internal protocol to claims about linearly homomorphic _univariate_ polynomial commitments, which are resolved using the specialized inner product argument protocol seen in [`halo2`](https://github.com/zcash/halo2). We do not use the Lagrange basis to encode witnesses (like in [PLONK [GWC19]](https://eprint.iacr.org/2019/953)) and we do not commonly perform polynomial multiplications, and so we do not _strictly_ depend on highly 2-adic fields. We also do not use multilinear polynomials or the sum-check protocol.
* **First class polynomial oracles:** Applications using Ragu have first-class access to the underlying accumulation scheme's univariate polynomial oracles, and so applications can implement (foldable) protocols involving [dynamic memory checking](https://eprint.iacr.org/2024/979).
* **Non-uniform circuits:** Ragu allows thousands of different specialized circuits to exist within the PCD graph, without requiring pre-processing (or the use of "verification keys") by instead using an overlooked post-processing technique from Halo.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).