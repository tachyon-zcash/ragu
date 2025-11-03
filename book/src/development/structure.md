# Project Structure

## Crates

Ragu is developed as a Cargo workspace.

* `ragu`: This is the primary crate that is intended for users to import. Most of the remaining crates are transitive dependencies of `ragu`. This crate aims to present a stable and minimal API for the entire construction, and may deliberately expose less functionality than the remaining crates are capable of providing.
* `crates/`
    * `ragu_arithmetic`: Contains most of the math traits and utilities needed throughout Ragu, and is a dependency of almost every other crate in this project.
    * `ragu_macros`: Internal crate that contains procedural macros both used within the project and exposed to users in other crates.
    * `ragu_pasta`: Compatability shim and parameter generation utilities for the [Pasta curve cycle](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/).
    * `ragu_core`: The fundamental crate of library which presents the `Driver` abstraction and related traits and utilities. All circuit development and most algorithms are written using the API provided by this crate.
    * `ragu_primitives`: This crate provides implementations of many algorithms and abstractions that use the API in `ragu_core`, mainly providing gadget implementations that are useful for building circuits.
    * `ragu_circuits`: This crate provides the implementation of the Ragu protocol and utilities for building arithmetic circuits in Ragu.
    * `ragu_gadgets`: This is just a placeholder, and may be removed in the future.

> Ragu is still under active development and the crates that have been published so far on [`crates.io`](https://crates.io/) are just placeholders.