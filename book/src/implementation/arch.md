# Architecture Overview

> add diagram of overall flow and core components

## Project Structure

Ragu is developed as a Cargo workspace.

* **`ragu`**: This is the primary crate (at the repository root) that is
  intended for users to import. Most of the remaining crates are transitive
  dependencies of `ragu`. This crate aims to present a stable and minimal
  API for the entire construction, and may deliberately expose less
  functionality than the other crates are capable of providing.
* `crates/`
    * **`ragu_arithmetic`**: Contains most of the math traits and utilities
      needed throughout Ragu, and is a dependency of almost every other
      crate in this project.
    * **`ragu_macros`**: Internal crate that contains procedural macros both
      used within the project and exposed to users in other crates.
    * **`ragu_pasta`**: Implements the [`Cycle`] trait for the
      [Pasta curve cycle], providing parameter generation and baked-in
      constants.
    * **`ragu_core`**: The fundamental crate of the library. Presents the
      `Driver` abstraction and related traits and utilities. All circuit
      development and most algorithms are written using the API provided by
      this crate.
    * **`ragu_primitives`**: The standard library for circuit developers.
      Builds on the `Driver` abstraction from `ragu_core` to provide the
      concrete gadgets (`Element`, `Boolean`, `Point`), cryptographic
      primitives (Poseidon hash, endoscalar arithmetic), serialization
      traits, containers, and development tooling (such as the `Simulator`)
      that most circuit code depends on.
    * **`ragu_circuits`**: This crate provides the implementation of the
      Ragu protocol and utilities for building arithmetic circuits in Ragu.
    * **`ragu_gadgets`**: This is just a placeholder, and may be removed in
      the future.
    * **`ragu_pcd`**: Top-level API for proof-carrying data applications,
      providing `ApplicationBuilder`, `Application`, `Step`, `Header`,
      `Proof`, and `Pcd`.
    * **`ragu_testing`**: Test scaffolding and nontrivial example Steps/Headers
      used in integration tests.

> Ragu is still under active development and the crates that have been
> published so far on [`crates.io`](https://crates.io/) are just
> placeholders.

### From Protocol to Code

> mapping from protocol concept to struct/trait in code

[Pasta curve cycle]: https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/
