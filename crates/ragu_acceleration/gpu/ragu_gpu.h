// C interface of the Pasta fixed-base MSM engine. See ragu_gpu.cu.

#ifndef RAGU_GPU_H
#define RAGU_GPU_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAGU_GPU_OK 0
#define RAGU_GPU_ERROR (-1)

#define RAGU_GPU_PALLAS 0
#define RAGU_GPU_VESTA 1

// Builds the device table for `n` nonidentity affine bases of one curve.
// `xy` holds eight limbs per base: x then y, as ordinary integers below the
// coordinate field's modulus. Returns a handle, or a negative value if the
// device is unavailable or lacks the memory.
int ragu_gpu_register_bases(int curve, const uint64_t *xy, size_t n);

// Computes `num_msms` MSMs over one registered base set.
//
// MSM `m` owns the terms `offsets[m] .. offsets[m + 1]`. Term `t` multiplies
// base `indices[t]` by the scalar at `scalars[4t .. 4t + 4]`, given in
// Montgomery form with respect to 2^256 and the curve's scalar field. `out`
// receives twelve limbs per MSM: the projective coordinates X, Y, Z as
// ordinary integers, where the result is (X/Z, Y/Z) and Z = 0 is the
// identity. Returns zero on success.
int ragu_gpu_msm_batch(int handle, const uint64_t *scalars, const uint32_t *indices,
                       const uint32_t *offsets, size_t num_msms, uint64_t *out);

// The same request as a start and a finish, for a caller that has other work
// while the device computes. `ragu_gpu_msm_start` copies its inputs, queues
// the request and returns a ticket, zero or more; it returns a negative
// value on failure, and also while four started requests of the same curve
// are unfinished: each curve takes four at a time, and none of them keeps
// `ragu_gpu_msm_batch` waiting. `ragu_gpu_msm_ready` returns zero while the
// request is computing and one once `ragu_gpu_msm_finish` would return
// without waiting. `ragu_gpu_msm_finish` waits for the request, writes its
// results to `out` as `ragu_gpu_msm_batch` does, or gives them up if `out`
// is null, and returns zero on success. Every ticket must be finished,
// exactly once. The three calls of a request may come from different
// threads, one at a time.
int ragu_gpu_msm_start(int handle, const uint64_t *scalars, const uint32_t *indices,
                       const uint32_t *offsets, size_t num_msms);
int ragu_gpu_msm_ready(int ticket);
int ragu_gpu_msm_finish(int ticket, uint64_t *out);

// The same requests laid out by the caller in the engine's pinned memory,
// which the device is sent them from: the terms are written once, not
// copied in. `ragu_gpu_msm_stage` takes a stage for `num_msms` MSMs, MSM `m`
// of `counts[m]` terms, and returns a staging, zero or more, or a negative
// value if no stage is free: a curve has sixteen for ordinary requests, and
// one for each request that can be started, which a request with `started`
// nonzero takes together with its place among the started ones. It sets
// `scalars` and `indices` to the stage, which is aligned to a page, and
// `starts[m]` to MSM `m`'s first term: the caller writes term `t` of that
// MSM as four limbs at `scalars + 4 * (starts[m] + t)` and its base's index
// at `indices + starts[m] + t`, and nothing else. The staging is then ended
// by exactly one of three calls. `ragu_gpu_msm_batch_staged` computes the
// request as `ragu_gpu_msm_batch` does and is for a staging taken with
// `started` zero. `ragu_gpu_msm_start_staged` queues it and returns a ticket
// as `ragu_gpu_msm_start` does, for one taken with `started` nonzero; the
// ticket is then finished as any other. `ragu_gpu_msm_unstage` gives the
// stage up. The calls of a staging may come from different threads, one at
// a time, and the stage may be written by several threads at once.
int ragu_gpu_msm_stage(int handle, const uint32_t *counts, size_t num_msms, int started,
                       uint64_t **scalars, uint32_t **indices, uint32_t *starts);
int ragu_gpu_msm_batch_staged(int staging, uint64_t *out);
int ragu_gpu_msm_start_staged(int staging);
int ragu_gpu_msm_unstage(int staging);

// ---------------------------------------------------------------------------
// Polynomial stores
//
// A store holds dense polynomials of `n` coefficients over one field, each in
// a numbered slot. Field elements cross this boundary in Montgomery form with
// respect to 2^256, as four limbs: inputs may be any value below twice the
// modulus, outputs are below the modulus. Every function returns zero on
// success. The powers kernel is queued and observed by the next call that
// reads the store; every other call completes before it returns.

#define RAGU_GPU_FP 0
#define RAGU_GPU_FQ 1

// Allocates the store of `field` for `slots` polynomials of `n` coefficients,
// keeping an existing store that is large enough.
int ragu_gpu_poly_init(int field, size_t n, size_t slots);

// Clears `num_slots` slots and then writes `num_terms` coefficients, which
// come as `num_runs` runs: stretches of consecutive coefficients of one slot,
// the way a sparse polynomial holds them, so that the caller copies each
// whole. Position p is coefficient `p % n` of slot `p / n`. The store's one
// caller stages the upload itself: `ragu_gpu_poly_upload_buffer` returns a
// pinned buffer of at least `words` 64-bit words, valid until the next
// request for it. The caller writes, in order: one word per run, the
// position of the run's first coefficient in its low half and the number of
// terms in the runs before it in its high half; one more such word whose
// high half is `num_terms`; padding to a multiple of four words, so that
// every coefficient is on a 32-byte boundary of the buffer, which is aligned
// to a page; four limbs per term, run after run; and `num_slots` slots as
// 32-bit values. It then calls
// `ragu_gpu_poly_upload_staged`, which queues the upload and returns: the
// runs must be inside the listed slots, which the engine does not check.
int ragu_gpu_poly_upload_buffer(int field, size_t words, uint64_t **buffer, int apart);
int ragu_gpu_poly_upload_staged(int field, size_t num_slots, size_t num_runs, size_t num_terms,
                                int apart);

// With `apart` set, in both calls, a staged upload has one of two buffers of
// its own, handed out in turn, and is taken in on a stream of its own, and
// the store's other calls neither wait for it nor see what it writes until
// `ragu_gpu_poly_join`, which makes every later call of the store wait for
// the uploads taken in apart so far. The caller joins before any call that
// reads a slot such an upload wrote.
int ragu_gpu_poly_join(int field);

// Writes z^k at coefficient k of slot `dst`.
int ragu_gpu_poly_powers(int field, uint32_t dst, const uint64_t *z);

// For each job j, writes to slot `dst[j]` the sum over its terms
// `offsets[j] .. offsets[j + 1]` of `scalars[t] * slot srcs[t]`. A job's
// destination must not be among its sources.
int ragu_gpu_poly_lincomb(int field, size_t jobs, const uint32_t *dst, const uint32_t *offsets,
                          const uint32_t *srcs, const uint64_t *scalars);

// For each job j, writes to slot `dst[j]` the polynomial with coefficients
// a[j][k] * powers[k] + s[j][k] + t[k].
int ragu_gpu_poly_dilate_add(int field, size_t jobs, const uint32_t *dst, const uint32_t *a,
                             const uint32_t *s, uint32_t powers, uint32_t t);

// For each pair, the sum over k of a[k] * b[n - 1 - k], or with `reversed`
// zero the sum of a[k] * b[k].
int ragu_gpu_poly_revdot(int field, size_t pairs, const uint32_t *a, const uint32_t *b,
                         int reversed, uint64_t *out);

// Divides each of the `jobs` slots `slots[j]` by X - points[j], dropping the
// remainder, and writes the sum of the quotients to slot `dst`. The divided
// slots are left with values of no meaning, and `dst` must not be one of
// them. Points are four limbs each, in the host's loose representation.
int ragu_gpu_poly_quotients(int field, size_t jobs, uint32_t dst, const uint32_t *slots,
                            const uint64_t *points);

// Reads back whole slots, `4n` limbs each. `ragu_gpu_poly_download_view`
// leaves them in the engine's memory and sets `view` to them, where they
// stay until the store's next call: its one caller reads them there, not
// from a copy.
int ragu_gpu_poly_download(int field, size_t count, const uint32_t *slots, uint64_t *out);
int ragu_gpu_poly_download_view(int field, size_t count, const uint32_t *slots,
                                const uint64_t **view);

// Computes, for each slot, the MSM of its `n` coefficients over the first
// `n` bases of the registered set `handle`, whose curve's scalar field must
// be the store's, and writes the results to `out` as `ragu_gpu_msm_batch`
// does. If `polys` is not null the slots are also read back to it, as
// `ragu_gpu_poly_download` reads them. One request does both, on the store's
// own stream: a caller that needs a polynomial's commitment and its
// coefficients does not send the coefficients back to have them committed.
// `ragu_gpu_poly_commit_view` reads the slots back as
// `ragu_gpu_poly_download_view` does, setting `polys`, if it is not null, to
// where they are.
int ragu_gpu_poly_commit(int field, int handle, size_t count, const uint32_t *slots,
                         uint64_t *polys, uint64_t *out);
int ragu_gpu_poly_commit_view(int field, int handle, size_t count, const uint32_t *slots,
                              const uint64_t **polys, uint64_t *out);

// ---------------------------------------------------------------------------
// Wiring matrices
//
// The wiring polynomials s_c(X, Y) of `circuits` circuits as one sparse
// matrix by column. Column `c * n + j` holds the terms of circuit c at X^j,
// as the chunks `column_chunks[c * n + j] .. column_chunks[c * n + j + 1]`;
// chunk k holds the terms `chunk_terms[k] .. chunk_terms[k + 1]`, which share
// one coefficient, the `chunk_values[k]`-th of the `distinct` in `values`
// (four words each, in Montgomery form below twice the modulus); term t is
// that coefficient times `Y^rows[t]`. Chunks should be short: one thread sums
// each.

// Copies a matrix to the device and returns its handle, or a negative value.
int ragu_gpu_wiring_register(int field, size_t n, size_t circuits,
                             const uint32_t *column_chunks, size_t chunks,
                             const uint32_t *chunk_terms, const uint32_t *chunk_values,
                             size_t terms, const uint32_t *rows, const uint64_t *values,
                             size_t distinct);

// Writes s_c(X, y) to slot `dst + c` of the matrix's field store for every
// circuit c, where slot `powers` holds the powers of y. Like the powers
// kernel, the request is queued and observed by the next call that reads the
// store.
//
// The engine does not know which variable a matrix is laid out by: a matrix
// registered by row instead, with the roles of X and Y exchanged, gives
// s_c(x, Y) from the powers of x through the same call.
int ragu_gpu_wiring_sy(int handle, uint32_t powers, uint32_t dst);

#ifdef __cplusplus
}
#endif

#endif
