# Wire encoding fixtures

The scalar (`fp.bin`, `fq.bin`) and point (`pallas.bin`, `vesta.bin`) fixtures
pin the canonical element encodings. Each file holds the low-level encodings
of a few known values, each with its outer version byte, in the order the
`pre_udon_encodings` test in `src/wire/tests.rs` lists them. They were captured
at source commit `887e0abc39e0f04ea6cdb0798a02e6420b056a66`, before the Udon
port, so they check that changing the arithmetic implementation leaves the
wire spelling of field elements and compressed points unchanged.

Every larger value is a fixed concatenation of these elements whose layout
the profile, the rank and the header size determine, so no fixture of a
complete proof is kept: `tests/wire.rs` round-trips freshly proved
production-rank proofs instead, and `WIRE_FORMAT.md` is the specification.
