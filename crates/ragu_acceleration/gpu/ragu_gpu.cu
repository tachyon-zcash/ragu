// Fixed-base multiscalar multiplication for the Pasta curves on one CUDA
// device.
//
// A registered base set owns a device table holding, for every base G_i and
// every 8-bit window j, the affine points d * 2^(8j) * G_i for d in 1..=128.
// An MSM then needs no doublings: each term recodes its scalar into 32 signed
// digits and adds one table point per nonzero digit. Terms run one per
// thread. Each block of threads belongs to one MSM and sums its terms as a
// tree; a second kernel sums an MSM's blocks the same way.
//
// Every group operation uses the complete addition formulas of Renes, Costello
// and Batina for curves with a = 0 (https://eprint.iacr.org/2015/1060,
// algorithms 7 and 8). They have no exceptional cases on a prime-order curve,
// so the result is the exact group element for every input, including
// doublings, inverses and the identity.
//
// Field elements cross the C boundary as four little-endian 64-bit limbs.
// Scalars arrive in the caller's Montgomery form (any value below 2^256);
// coordinates arrive and leave as ordinary integers below the modulus.

#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <mutex>
#include <vector>

#include "ragu_gpu.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned __int128 u128;

#define WINDOW_BITS 8
#define NUM_WINDOWS 32
#define ROW_ENTRIES 128
#define ENTRIES_PER_BASE (NUM_WINDOWS * ROW_ENTRIES)
// Threads per block.
#define BLOCK 128
// A request's terms are given as many threads each as keep it within
// SPLIT_BLOCKS blocks, up to one thread to a window. A request that leaves
// the device idle then waits for a shorter chain of additions, and one that
// fills it is not slowed. On an RTX 5090 a request waits no less with more
// than 256 blocks, and longer from 512: one of 8192 terms takes 0.19 ms at
// 256 blocks and 0.25 ms at 512, and one of 40 to 240 terms 0.10 ms at 32 to
// 64 blocks.
#ifndef SPLIT_BLOCKS
#define SPLIT_BLOCKS 256
#endif

// ---------------------------------------------------------------------------
// Fields

// The Pallas base field, which is also the Vesta scalar field.
struct Fp {
    static constexpr u64 M0 = 0x992d30ed00000001ULL, M1 = 0x224698fc094cf91bULL,
                         M2 = 0x0000000000000000ULL, M3 = 0x4000000000000000ULL;
    static constexpr u64 INV = 0x992d30ecffffffffULL;
    static constexpr u64 ONE0 = 0x34786d38fffffffdULL, ONE1 = 0x992c350be41914adULL,
                         ONE2 = 0xffffffffffffffffULL, ONE3 = 0x3fffffffffffffffULL;
    static constexpr u64 RR0 = 0x8c78ecb30000000fULL, RR1 = 0xd7d30dbd8b0de0e7ULL,
                         RR2 = 0x7797a99bc3c95d18ULL, RR3 = 0x096d41af7b9cb714ULL;
};

// The Pallas scalar field, which is also the Vesta base field.
struct Fq {
    static constexpr u64 M0 = 0x8c46eb2100000001ULL, M1 = 0x224698fc0994a8ddULL,
                         M2 = 0x0000000000000000ULL, M3 = 0x4000000000000000ULL;
    static constexpr u64 INV = 0x8c46eb20ffffffffULL;
    static constexpr u64 ONE0 = 0x5b2b3e9cfffffffdULL, ONE1 = 0x992c350be3420567ULL,
                         ONE2 = 0xffffffffffffffffULL, ONE3 = 0x3fffffffffffffffULL;
    static constexpr u64 RR0 = 0xfc9678ff0000000fULL, RR1 = 0x67bb433d891a16e3ULL,
                         RR2 = 0x7fae231004ccf590ULL, RR3 = 0x096d41af7ccfdaa9ULL;
};

// An element of the field F. Montgomery form below the modulus unless a
// comment says otherwise.
template <class F> struct Fe {
    u64 l[4];
};

template <class F> __device__ __forceinline__ Fe<F> fe_zero() {
    Fe<F> r = {{0, 0, 0, 0}};
    return r;
}

template <class F> __device__ __forceinline__ Fe<F> fe_one() {
    Fe<F> r = {{F::ONE0, F::ONE1, F::ONE2, F::ONE3}};
    return r;
}

// The integer one, which is not the Montgomery one: multiplying by it takes
// a value out of Montgomery form.
template <class F> __device__ __forceinline__ Fe<F> fe_raw_one() {
    Fe<F> r = {{1, 0, 0, 0}};
    return r;
}

template <class F> __device__ __forceinline__ Fe<F> fe_rr() {
    Fe<F> r = {{F::RR0, F::RR1, F::RR2, F::RR3}};
    return r;
}

// Subtracts the modulus once if `t` (with carry limb `hi`) is at least it.
template <class F>
__device__ __forceinline__ Fe<F> fe_final_sub(const u64 t[4], u64 hi) {
    const u64 m[4] = {F::M0, F::M1, F::M2, F::M3};
    u64 r[4];
    u64 borrow = 0;
    for (int j = 0; j < 4; j++) {
        u128 d = (u128)t[j] - m[j] - borrow;
        r[j] = (u64)d;
        borrow = (u64)(d >> 64) & 1;
    }
    bool ge = (hi != 0) | (borrow == 0);
    Fe<F> out;
    for (int j = 0; j < 4; j++) out.l[j] = ge ? r[j] : t[j];
    return out;
}

// Montgomery product a * b / 2^256 mod m, below the modulus. Correct for any
// `a` below 2^256 when `b` is below the modulus.
template <class F>
__device__ __forceinline__ Fe<F> fe_mul(const Fe<F> &a, const Fe<F> &b) {
    const u64 m[4] = {F::M0, F::M1, F::M2, F::M3};
    u64 t[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        u128 c = 0;
        for (int j = 0; j < 4; j++) {
            c += (u128)a.l[j] * b.l[i] + t[j];
            t[j] = (u64)c;
            c >>= 64;
        }
        u128 top = (u128)t[4] + c;
        u64 k = t[0] * F::INV;
        c = ((u128)k * m[0] + t[0]) >> 64;
        for (int j = 1; j < 4; j++) {
            c += (u128)k * m[j] + t[j];
            t[j - 1] = (u64)c;
            c >>= 64;
        }
        top += c;
        t[3] = (u64)top;
        t[4] = (u64)(top >> 64);
    }
    return fe_final_sub<F>(t, t[4]);
}

template <class F>
__device__ __forceinline__ Fe<F> fe_add(const Fe<F> &a, const Fe<F> &b) {
    u64 t[4];
    u128 c = 0;
    for (int j = 0; j < 4; j++) {
        c += (u128)a.l[j] + b.l[j];
        t[j] = (u64)c;
        c >>= 64;
    }
    // Both operands are below a 255-bit modulus, so the sum fits 256 bits.
    return fe_final_sub<F>(t, 0);
}

template <class F>
__device__ __forceinline__ Fe<F> fe_sub(const Fe<F> &a, const Fe<F> &b) {
    const u64 m[4] = {F::M0, F::M1, F::M2, F::M3};
    u64 t[4];
    u64 borrow = 0;
    for (int j = 0; j < 4; j++) {
        u128 d = (u128)a.l[j] - b.l[j] - borrow;
        t[j] = (u64)d;
        borrow = (u64)(d >> 64) & 1;
    }
    u64 mask = (u64)0 - borrow;
    Fe<F> out;
    u128 c = 0;
    for (int j = 0; j < 4; j++) {
        c += (u128)t[j] + (m[j] & mask);
        out.l[j] = (u64)c;
        c >>= 64;
    }
    return out;
}

template <class F> __device__ __forceinline__ Fe<F> fe_neg(const Fe<F> &a) {
    return fe_sub<F>(fe_zero<F>(), a);
}

// Multiplies by 3b = 15, the only curve constant the formulas need.
template <class F> __device__ __forceinline__ Fe<F> fe_mul15(const Fe<F> &a) {
    Fe<F> t = fe_add<F>(a, a);
    t = fe_add<F>(t, t);
    t = fe_add<F>(t, t);
    t = fe_add<F>(t, t);
    return fe_sub<F>(t, a);
}

// The inverse by Fermat's little theorem. Zero maps to zero.
template <class F> __device__ __noinline__ Fe<F> fe_inv(const Fe<F> &a) {
    const u64 e[4] = {F::M0 - 2, F::M1, F::M2, F::M3};
    Fe<F> r = fe_one<F>();
    for (int bit = 254; bit >= 0; bit--) {
        r = fe_mul<F>(r, r);
        if ((e[bit >> 6] >> (bit & 63)) & 1) r = fe_mul<F>(r, a);
    }
    return r;
}

// ---------------------------------------------------------------------------
// Curve points over F, on y^2 = x^3 + 5

template <class F> struct Aff {
    Fe<F> x, y;
};

// Homogeneous projective coordinates: the affine point is (x/z, y/z) and the
// identity is (0 : 1 : 0).
template <class F> struct Proj {
    Fe<F> x, y, z;
};

template <class F> __device__ __forceinline__ Proj<F> pt_identity() {
    Proj<F> r;
    r.x = fe_zero<F>();
    r.y = fe_one<F>();
    r.z = fe_zero<F>();
    return r;
}

// Algorithm 7: complete addition of two projective points.
template <class F>
__device__ __forceinline__ Proj<F> pt_add(const Proj<F> &p, const Proj<F> &q) {
    Fe<F> t0 = fe_mul<F>(p.x, q.x);
    Fe<F> t1 = fe_mul<F>(p.y, q.y);
    Fe<F> t2 = fe_mul<F>(p.z, q.z);
    Fe<F> t3 = fe_add<F>(p.x, p.y);
    Fe<F> t4 = fe_add<F>(q.x, q.y);
    t3 = fe_mul<F>(t3, t4);
    t4 = fe_add<F>(t0, t1);
    t3 = fe_sub<F>(t3, t4);
    t4 = fe_add<F>(p.y, p.z);
    Fe<F> x3 = fe_add<F>(q.y, q.z);
    t4 = fe_mul<F>(t4, x3);
    x3 = fe_add<F>(t1, t2);
    t4 = fe_sub<F>(t4, x3);
    x3 = fe_add<F>(p.x, p.z);
    Fe<F> y3 = fe_add<F>(q.x, q.z);
    x3 = fe_mul<F>(x3, y3);
    y3 = fe_add<F>(t0, t2);
    y3 = fe_sub<F>(x3, y3);
    x3 = fe_add<F>(t0, t0);
    t0 = fe_add<F>(x3, t0);
    t2 = fe_mul15<F>(t2);
    Fe<F> z3 = fe_add<F>(t1, t2);
    t1 = fe_sub<F>(t1, t2);
    y3 = fe_mul15<F>(y3);
    x3 = fe_mul<F>(t4, y3);
    t2 = fe_mul<F>(t3, t1);
    x3 = fe_sub<F>(t2, x3);
    y3 = fe_mul<F>(y3, t0);
    t1 = fe_mul<F>(t1, z3);
    y3 = fe_add<F>(t1, y3);
    t0 = fe_mul<F>(t0, t3);
    z3 = fe_mul<F>(z3, t4);
    z3 = fe_add<F>(z3, t0);
    Proj<F> r;
    r.x = x3;
    r.y = y3;
    r.z = z3;
    return r;
}

// Algorithm 8: complete addition of a projective point and an affine point.
// The affine operand cannot be the identity; the projective one can.
template <class F>
__device__ __forceinline__ Proj<F> pt_add_mixed(const Proj<F> &p, const Aff<F> &q) {
    Fe<F> t0 = fe_mul<F>(p.x, q.x);
    Fe<F> t1 = fe_mul<F>(p.y, q.y);
    Fe<F> t3 = fe_add<F>(q.x, q.y);
    Fe<F> t4 = fe_add<F>(p.x, p.y);
    t3 = fe_mul<F>(t3, t4);
    t4 = fe_add<F>(t0, t1);
    t3 = fe_sub<F>(t3, t4);
    t4 = fe_mul<F>(q.y, p.z);
    t4 = fe_add<F>(t4, p.y);
    Fe<F> y3 = fe_mul<F>(q.x, p.z);
    y3 = fe_add<F>(y3, p.x);
    Fe<F> x3 = fe_add<F>(t0, t0);
    t0 = fe_add<F>(x3, t0);
    Fe<F> t2 = fe_mul15<F>(p.z);
    Fe<F> z3 = fe_add<F>(t1, t2);
    t1 = fe_sub<F>(t1, t2);
    y3 = fe_mul15<F>(y3);
    x3 = fe_mul<F>(t4, y3);
    t2 = fe_mul<F>(t3, t1);
    x3 = fe_sub<F>(t2, x3);
    y3 = fe_mul<F>(y3, t0);
    t1 = fe_mul<F>(t1, z3);
    y3 = fe_add<F>(t1, y3);
    t0 = fe_mul<F>(t0, t3);
    z3 = fe_mul<F>(z3, t4);
    z3 = fe_add<F>(z3, t0);
    Proj<F> r;
    r.x = x3;
    r.y = y3;
    r.z = z3;
    return r;
}

// ---------------------------------------------------------------------------
// Table construction

// One thread per base: writes 2^(8j) * G for every window j.
template <class F>
__global__ void k_window_bases(const u64 *__restrict__ xy, Proj<F> *__restrict__ bases, u32 n) {
    u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    Fe<F> x, y;
    for (int k = 0; k < 4; k++) {
        x.l[k] = xy[(size_t)i * 8 + k];
        y.l[k] = xy[(size_t)i * 8 + 4 + k];
    }
    Proj<F> p;
    p.x = fe_mul<F>(x, fe_rr<F>());
    p.y = fe_mul<F>(y, fe_rr<F>());
    p.z = fe_one<F>();
    for (int j = 0; j < NUM_WINDOWS; j++) {
        bases[(size_t)i * NUM_WINDOWS + j] = p;
        if (j + 1 < NUM_WINDOWS) {
            for (int k = 0; k < WINDOW_BITS; k++) p = pt_add<F>(p, p);
        }
    }
}

// One thread per (base, window) row: writes d * B for d in 1..=128 in affine
// form, where B is the row's window base. `multiples` and `prefix` are
// scratch with ROW_ENTRIES slots per row.
template <class F>
__global__ void k_table_rows(const Proj<F> *__restrict__ bases, Aff<F> *__restrict__ table,
                             Proj<F> *__restrict__ multiples, Fe<F> *__restrict__ prefix,
                             u32 rows) {
    u32 r = blockIdx.x * blockDim.x + threadIdx.x;
    if (r >= rows) return;
    const Proj<F> base = bases[r];
    Proj<F> *mine = multiples + (size_t)r * ROW_ENTRIES;
    Fe<F> *pre = prefix + (size_t)r * ROW_ENTRIES;
    Proj<F> acc = base;
    Fe<F> product = fe_one<F>();
    for (int d = 0; d < ROW_ENTRIES; d++) {
        if (d > 0) acc = pt_add<F>(acc, base);
        mine[d] = acc;
        product = fe_mul<F>(product, acc.z);
        pre[d] = product;
    }
    // One inversion for the whole row. No multiple is the identity: the
    // group has prime order and every multiplier is below it.
    Fe<F> inv = fe_inv<F>(product);
    for (int d = ROW_ENTRIES - 1; d >= 0; d--) {
        const Proj<F> m = mine[d];
        Fe<F> zinv = d > 0 ? fe_mul<F>(inv, pre[d - 1]) : inv;
        inv = fe_mul<F>(inv, m.z);
        Aff<F> a;
        a.x = fe_mul<F>(m.x, zinv);
        a.y = fe_mul<F>(m.y, zinv);
        table[(size_t)r * ROW_ENTRIES + d] = a;
    }
}

// ---------------------------------------------------------------------------
// Multiscalar multiplication

// Sums the block's `buf` entries into `buf[0]` as a binary tree. Every
// thread of the block must call it, after writing its own entry.
template <class F> __device__ __forceinline__ void block_sum(Proj<F> *buf) {
    __syncthreads();
    for (u32 stride = BLOCK / 2; stride > 0; stride >>= 1) {
        // A level reads the upper half of its range and writes the lower.
        if (threadIdx.x < stride) {
            buf[threadIdx.x] = pt_add<F>(buf[threadIdx.x], buf[threadIdx.x + stride]);
        }
        __syncthreads();
    }
}

// One thread per part of a term: the term's scalar * base is a sum of at
// most 32 table points, one per window, and each of the term's `parts`
// threads adds the points of an equal share of the windows. Then one sum per
// block. The terms come in groups of BLOCK, and block `g * parts + p` holds
// part `p` of group `g`, so that the threads of a block, and of each of its
// warps, all work on the same windows; a term with a zero scalar contributes
// the identity. `parts` is a power of two up to NUM_WINDOWS. B is the
// coordinate field and S the scalar field.
//
// A thread's chain of additions is what a small request waits for: on an RTX
// 5090 the 32 additions of an unsplit term take about 0.16 ms whatever the
// number of terms. More parts shorten the chain and add a few additions to
// the sums of blocks, which is what a large request pays for.
template <class B, class S>
__global__ void k_terms(const u64 *__restrict__ scalars, const u32 *__restrict__ indices,
                        const Aff<B> *__restrict__ table, Proj<B> *__restrict__ block_sums,
                        u32 parts) {
    __shared__ Proj<B> buf[BLOCK];
    u32 t = (blockIdx.x / parts) * BLOCK + threadIdx.x;
    u32 per_part = NUM_WINDOWS / parts;
    u32 first = (blockIdx.x % parts) * per_part;
    Fe<S> s;
    for (int k = 0; k < 4; k++) s.l[k] = scalars[(size_t)t * 4 + k];
    // Out of Montgomery form: the ordinary integer below the modulus.
    s = fe_mul<S>(s, fe_raw_one<S>());
    const Aff<B> *row = table + (size_t)indices[t] * ENTRIES_PER_BASE;
    // Signed digits in [-127, 128]. The scalar is below 2^255 and its top
    // byte is at most 0x40, so the last window never carries out. A part
    // first recodes the windows below its own, for their carry.
    u32 carry = 0;
    for (u32 j = 0; j < first; j++) {
        u32 w = (u32)((s.l[j >> 3] >> ((j & 7) * WINDOW_BITS)) & 0xff) + carry;
        carry = w > 128 ? 1 : 0;
    }
    Proj<B> acc = pt_identity<B>();
    for (u32 j = first; j < first + per_part; j++) {
        u32 w = (u32)((s.l[j >> 3] >> ((j & 7) * WINDOW_BITS)) & 0xff) + carry;
        bool negative = w > 128;
        u32 magnitude = negative ? 256 - w : w;
        carry = negative ? 1 : 0;
        if (magnitude != 0) {
            Aff<B> p = row[j * ROW_ENTRIES + magnitude - 1];
            if (negative) p.y = fe_neg<B>(p.y);
            acc = pt_add_mixed<B>(acc, p);
        }
    }
    buf[threadIdx.x] = acc;
    block_sum<B>(buf);
    if (threadIdx.x == 0) block_sums[blockIdx.x] = buf[0];
}

// One block per MSM: the sum of block_sums[offsets[m] .. offsets[m + 1]],
// written as ordinary integers. Each thread first sums every BLOCK-th entry
// from its own, and the tree over the threads is as deep as the threads that
// hold an entry need. An empty range gives the identity.
template <class F>
__global__ void k_finish(const Proj<F> *__restrict__ block_sums, const u32 *__restrict__ offsets,
                         Proj<F> *__restrict__ out) {
    __shared__ Proj<F> buf[BLOCK];
    u32 m = blockIdx.x;
    u32 begin = offsets[m], end = offsets[m + 1];
    Proj<F> acc = pt_identity<F>();
    bool any = false;
    for (u32 i = begin + threadIdx.x; i < end; i += BLOCK) {
        acc = any ? pt_add<F>(acc, block_sums[i]) : block_sums[i];
        any = true;
    }
    buf[threadIdx.x] = acc;
    u32 width = 1;
    while (width < BLOCK && width < end - begin) width <<= 1;
    __syncthreads();
    for (u32 stride = width / 2; stride > 0; stride >>= 1) {
        if (threadIdx.x < stride) {
            buf[threadIdx.x] = pt_add<F>(buf[threadIdx.x], buf[threadIdx.x + stride]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        Proj<F> sum = buf[0];
        sum.x = fe_mul<F>(sum.x, fe_raw_one<F>());
        sum.y = fe_mul<F>(sum.y, fe_raw_one<F>());
        sum.z = fe_mul<F>(sum.z, fe_raw_one<F>());
        out[m] = sum;
    }
}

// ---------------------------------------------------------------------------
// Polynomial store
//
// A store holds dense polynomials of `n` coefficients over one field, each
// in a slot, in Montgomery form below the modulus. Its kernels are the
// coefficientwise operations the fuse applies to whole polynomials; each
// gives exactly the field elements the host computes.

template <class F> __device__ __forceinline__ Fe<F> fe_load(const u64 *p) {
    Fe<F> r = {{p[0], p[1], p[2], p[3]}};
    return r;
}

template <class F> __device__ __forceinline__ void fe_store(u64 *p, const Fe<F> &v) {
    p[0] = v.l[0];
    p[1] = v.l[1];
    p[2] = v.l[2];
    p[3] = v.l[3];
}

// Sums the block's `buf` entries into `buf[0]` as a binary tree.
template <class F> __device__ __forceinline__ void block_sum_fe(Fe<F> *buf) {
    __syncthreads();
    for (u32 stride = BLOCK / 2; stride > 0; stride >>= 1) {
        if (threadIdx.x < stride) {
            buf[threadIdx.x] = fe_add<F>(buf[threadIdx.x], buf[threadIdx.x + stride]);
        }
        __syncthreads();
    }
}

// Clears the listed slots. One block per BLOCK coefficients of a slot.
__global__ void k_poly_zero(u64 *__restrict__ data, const u32 *__restrict__ slots, u32 n) {
    u32 per_slot = n / BLOCK;
    u32 slot = slots[blockIdx.x / per_slot];
    size_t k = (size_t)(blockIdx.x % per_slot) * BLOCK + threadIdx.x;
    u64 *dst = data + ((size_t)slot * n + k) * 4;
    dst[0] = 0;
    dst[1] = 0;
    dst[2] = 0;
    dst[3] = 0;
}

// Writes each stored coefficient to its position, reducing the host's loose
// representation (below twice the modulus) to the store's. The coefficients
// come as runs, each a stretch of consecutive coefficients of one slot: run r
// is the terms from `runs[r] >> 32` up to the next run's first, and its
// first coefficient's position is the low half of `runs[r]`. A last entry
// past the runs holds the number of terms. A thread finds its term's run.
template <class F>
__global__ void k_poly_place(u64 *__restrict__ data, const u64 *__restrict__ runs,
                             const u64 *__restrict__ limbs, u32 num_runs, u32 terms) {
    u32 t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= terms) return;
    // The last run that starts at or before term t.
    u32 lo = 0, hi = num_runs;
    while (hi - lo > 1) {
        u32 mid = (lo + hi) / 2;
        if ((u32)(runs[mid] >> 32) <= t) lo = mid; else hi = mid;
    }
    u64 run = runs[lo];
    size_t position = (size_t)(u32)run + (t - (u32)(run >> 32));
    const u64 *src = limbs + (size_t)t * 4;
    u64 loose[4] = {src[0], src[1], src[2], src[3]};
    fe_store<F>(data + position * 4, fe_final_sub<F>(loose, 0));
}

// Writes z^k at coefficient k of `dst`.
template <class F> __global__ void k_poly_powers(u64 *__restrict__ dst, Fe<F> z_loose, u32 n) {
    u32 k = blockIdx.x * blockDim.x + threadIdx.x;
    if (k >= n) return;
    Fe<F> z = fe_final_sub<F>(z_loose.l, 0);
    Fe<F> r = fe_one<F>();
    for (int bit = 31 - __clz(k | 1); bit >= 0; bit--) {
        r = fe_mul<F>(r, r);
        if ((k >> bit) & 1) r = fe_mul<F>(r, z);
    }
    fe_store<F>(dst + (size_t)k * 4, r);
}

// For each job, dst = sum of scalar * src over the job's terms. Scalars are
// in the host's loose representation.
template <class F>
__global__ void k_poly_lincomb(u64 *__restrict__ data, const u32 *__restrict__ dst,
                               const u32 *__restrict__ offsets, const u32 *__restrict__ srcs,
                               const u64 *__restrict__ scalars, u32 n) {
    u32 per_slot = n / BLOCK;
    u32 job = blockIdx.x / per_slot;
    size_t k = (size_t)(blockIdx.x % per_slot) * BLOCK + threadIdx.x;
    Fe<F> acc = fe_zero<F>();
    for (u32 t = offsets[job]; t < offsets[job + 1]; t++) {
        Fe<F> scalar = fe_load<F>(scalars + (size_t)t * 4);
        Fe<F> coeff = fe_load<F>(data + ((size_t)srcs[t] * n + k) * 4);
        acc = fe_add<F>(acc, fe_mul<F>(scalar, coeff));
    }
    fe_store<F>(data + ((size_t)dst[job] * n + k) * 4, acc);
}

// For each job, dst[k] = a[k] * powers[k] + s[k] + t[k].
template <class F>
__global__ void k_poly_dilate_add(u64 *__restrict__ data, const u32 *__restrict__ dst,
                                  const u32 *__restrict__ a, const u32 *__restrict__ s,
                                  u32 powers, u32 t, u32 n) {
    u32 per_slot = n / BLOCK;
    u32 job = blockIdx.x / per_slot;
    size_t k = (size_t)(blockIdx.x % per_slot) * BLOCK + threadIdx.x;
    Fe<F> value = fe_mul<F>(fe_load<F>(data + ((size_t)a[job] * n + k) * 4),
                            fe_load<F>(data + ((size_t)powers * n + k) * 4));
    value = fe_add<F>(value, fe_load<F>(data + ((size_t)s[job] * n + k) * 4));
    value = fe_add<F>(value, fe_load<F>(data + ((size_t)t * n + k) * 4));
    fe_store<F>(data + ((size_t)dst[job] * n + k) * 4, value);
}

// One block per pair: the sum over k of a[k] * b[n - 1 - k], or of
// a[k] * b[k] when `reversed` is zero.
template <class F>
__global__ void k_poly_revdot(const u64 *__restrict__ data, const u32 *__restrict__ a,
                              const u32 *__restrict__ b, u64 *__restrict__ out, u32 n,
                              int reversed) {
    __shared__ Fe<F> buf[BLOCK];
    const u64 *pa = data + (size_t)a[blockIdx.x] * n * 4;
    const u64 *pb = data + (size_t)b[blockIdx.x] * n * 4;
    Fe<F> acc = fe_zero<F>();
    for (u32 k = threadIdx.x; k < n; k += BLOCK) {
        u32 other = reversed ? n - 1 - k : k;
        acc = fe_add<F>(acc, fe_mul<F>(fe_load<F>(pa + (size_t)k * 4),
                                       fe_load<F>(pb + (size_t)other * 4)));
    }
    buf[threadIdx.x] = acc;
    block_sum_fe<F>(buf);
    if (threadIdx.x == 0) fe_store<F>(out + (size_t)blockIdx.x * 4, buf[0]);
}

// One block per job, in place on slot `slots[job]`: divides the slot's
// polynomial by X - point and leaves the quotient's coefficient of degree k
// at index k + 1; index 0 is left with a value of no meaning.
//
// The quotient of c by X - x has, at degree k - 1, the sum over j >= k of
// c[j] * x^(j - k). Each thread takes a run of n / BLOCK coefficients: it
// forms those sums over its own run, the block then carries each run's total
// down to the runs below it, and each thread adds what was carried into its
// run. The sums are those of the host's single pass, regrouped.
template <class F>
__global__ void k_poly_divide(u64 *__restrict__ data, const u32 *__restrict__ slots,
                              const u64 *__restrict__ points, u32 n) {
    __shared__ Fe<F> carry[BLOCK];
    u32 run = n / BLOCK;
    u64 *p = data + (size_t)slots[blockIdx.x] * n * 4;
    const u64 *px = points + (size_t)blockIdx.x * 4;
    u64 loose[4] = {px[0], px[1], px[2], px[3]};
    Fe<F> x = fe_final_sub<F>(loose, 0);
    u32 start = threadIdx.x * run, end = start + run;

    Fe<F> acc = fe_zero<F>();
    for (u32 k = end; k-- > start;) {
        acc = fe_add<F>(fe_mul<F>(acc, x), fe_load<F>(p + (size_t)k * 4));
        fe_store<F>(p + (size_t)k * 4, acc);
    }
    carry[threadIdx.x] = acc;
    __syncthreads();

    // carry[t] becomes the sum over j past run t of c[j] * x^(j - end of t).
    if (threadIdx.x == 0) {
        Fe<F> x_run = fe_one<F>();
        for (u32 i = 0; i < run; i++) x_run = fe_mul<F>(x_run, x);
        Fe<F> above = fe_zero<F>();
        for (u32 t = BLOCK; t-- > 0;) {
            Fe<F> own = carry[t];
            carry[t] = above;
            above = fe_add<F>(fe_mul<F>(above, x_run), own);
        }
    }
    __syncthreads();

    Fe<F> above = carry[threadIdx.x];
    Fe<F> power = x;
    for (u32 k = end; k-- > start;) {
        Fe<F> value = fe_add<F>(fe_load<F>(p + (size_t)k * 4), fe_mul<F>(power, above));
        fe_store<F>(p + (size_t)k * 4, value);
        power = fe_mul<F>(power, x);
    }
}

// The runs the wide division cuts a slot into, and the fewest coefficients of
// a slot it divides.
#define WIDE 1024

// z^k.
template <class F> __device__ __forceinline__ Fe<F> fe_pow(const Fe<F> &z, u32 k) {
    Fe<F> r = fe_one<F>();
    for (int bit = 31 - __clz(k | 1); bit >= 0; bit--) {
        r = fe_mul<F>(r, r);
        if ((k >> bit) & 1) r = fe_mul<F>(r, z);
    }
    return r;
}

// A job's point.
template <class F>
__device__ __forceinline__ Fe<F> job_point(const u64 *__restrict__ points, u32 job) {
    const u64 *px = points + (size_t)job * 4;
    u64 loose[4] = {px[0], px[1], px[2], px[3]};
    return fe_final_sub<F>(loose, 0);
}

// The same division for slots whose length is a multiple of WIDE, as three
// kernels. `k_poly_divide` gives a slot one block, whose threads each make
// two long passes and wait on one thread's pass between them; a block runs
// on one multiprocessor, so more threads in it would only take turns. Here a
// slot's WIDE runs of n / WIDE coefficients have a thread each, in
// WIDE / BLOCK blocks: this kernel leaves each run's own sum, over its j of
// c[j] * x^(j - start), in `carries`; `k_poly_divide_carries` turns the sums
// into what is carried into each run; and `k_poly_divide_finish` makes the
// pass that writes the quotient. The sums are the same ones, regrouped.
template <class F>
__global__ void k_poly_divide_sums(const u64 *__restrict__ data, const u32 *__restrict__ slots,
                                   const u64 *__restrict__ points, u64 *__restrict__ carries,
                                   u32 n) {
    const u32 blocks = WIDE / BLOCK;
    u32 job = blockIdx.x / blocks, t = (blockIdx.x % blocks) * BLOCK + threadIdx.x;
    u32 run = n / WIDE, start = t * run, end = start + run;
    const u64 *p = data + (size_t)slots[job] * n * 4;
    Fe<F> x = job_point<F>(points, job);
    Fe<F> acc = fe_zero<F>();
    for (u32 k = end; k-- > start;) {
        acc = fe_add<F>(fe_mul<F>(acc, x), fe_load<F>(p + (size_t)k * 4));
    }
    fe_store<F>(carries + ((size_t)job * WIDE + t) * 4, acc);
}

// Replaces each run's sum in `carries` by what the runs above it carry into
// it: the sum over j from the run's end on of c[j] * x^(j - end). A block
// takes a job and a thread WIDE / BLOCK of its runs in a row: it gathers
// them, the block combines what the threads gathered, each step reaching
// twice as far, and the thread walks back down its runs.
template <class F>
__global__ void k_poly_divide_carries(const u64 *__restrict__ points, u64 *__restrict__ carries,
                                      u32 n) {
    __shared__ Fe<F> gathered[BLOCK];
    const u32 group = WIDE / BLOCK;
    u32 t = threadIdx.x;
    u64 *own = carries + ((size_t)blockIdx.x * WIDE + (size_t)t * group) * 4;
    // A run further on is x^(n / WIDE) away.
    Fe<F> by_run = fe_pow<F>(job_point<F>(points, blockIdx.x), n / WIDE);

    Fe<F> sums[WIDE / BLOCK];
    Fe<F> acc = fe_zero<F>();
    for (u32 i = group; i-- > 0;) {
        sums[i] = fe_load<F>(own + (size_t)i * 4);
        acc = fe_add<F>(fe_mul<F>(acc, by_run), sums[i]);
    }
    gathered[t] = acc;
    __syncthreads();

    // gathered[t] becomes the sum from thread t's first run on.
    Fe<F> shift = fe_pow<F>(by_run, group);
    for (u32 reach = 1; reach < BLOCK; reach *= 2) {
        Fe<F> further = t + reach < BLOCK ? gathered[t + reach] : fe_zero<F>();
        __syncthreads();
        gathered[t] = fe_add<F>(gathered[t], fe_mul<F>(further, shift));
        __syncthreads();
        shift = fe_mul<F>(shift, shift);
    }

    acc = t + 1 < BLOCK ? gathered[t + 1] : fe_zero<F>();
    for (u32 i = group; i-- > 0;) {
        fe_store<F>(own + (size_t)i * 4, acc);
        acc = fe_add<F>(fe_mul<F>(acc, by_run), sums[i]);
    }
}

// The pass over each run from what is carried into it, which leaves the
// quotient as `k_poly_divide` does.
template <class F>
__global__ void k_poly_divide_finish(u64 *__restrict__ data, const u32 *__restrict__ slots,
                                     const u64 *__restrict__ points,
                                     const u64 *__restrict__ carries, u32 n) {
    const u32 blocks = WIDE / BLOCK;
    u32 job = blockIdx.x / blocks, t = (blockIdx.x % blocks) * BLOCK + threadIdx.x;
    u32 run = n / WIDE, start = t * run, end = start + run;
    u64 *p = data + (size_t)slots[job] * n * 4;
    Fe<F> x = job_point<F>(points, job);
    Fe<F> acc = fe_load<F>(carries + ((size_t)job * WIDE + t) * 4);
    for (u32 k = end; k-- > start;) {
        acc = fe_add<F>(fe_mul<F>(acc, x), fe_load<F>(p + (size_t)k * 4));
        fe_store<F>(p + (size_t)k * 4, acc);
    }
}

// The slots a thread of `k_poly_shift_sum_wide` leaves between two it reads.
#define SUM_LANES 8

// `k_poly_shift_sum` for many slots: BLOCK / SUM_LANES coefficients to a
// block, each summed by SUM_LANES threads that share the slots out, so that
// a thread reads an eighth of them.
template <class F>
__global__ void k_poly_shift_sum_wide(u64 *__restrict__ data, u32 dst,
                                      const u32 *__restrict__ slots, u32 count, u32 n) {
    __shared__ Fe<F> partial[BLOCK];
    const u32 per_block = BLOCK / SUM_LANES;
    u32 lane = threadIdx.x / per_block, place = threadIdx.x % per_block;
    u32 k = blockIdx.x * per_block + place;
    Fe<F> acc = fe_zero<F>();
    if (k + 1 < n) {
        for (u32 j = lane; j < count; j += SUM_LANES) {
            acc = fe_add<F>(acc, fe_load<F>(data + ((size_t)slots[j] * n + k + 1) * 4));
        }
    }
    partial[threadIdx.x] = acc;
    __syncthreads();
    if (lane == 0) {
        for (u32 other = 1; other < SUM_LANES; other++) {
            acc = fe_add<F>(acc, partial[other * per_block + place]);
        }
        fe_store<F>(data + ((size_t)dst * n + k) * 4, acc);
    }
}

// dst[k] = the sum over the slots of slot[k + 1], and zero at k = n - 1:
// the sum of the quotients `k_poly_divide` left in the slots.
template <class F>
__global__ void k_poly_shift_sum(u64 *__restrict__ data, u32 dst,
                                 const u32 *__restrict__ slots, u32 count, u32 n) {
    u32 k = blockIdx.x * BLOCK + threadIdx.x;
    Fe<F> acc = fe_zero<F>();
    if (k + 1 < n) {
        for (u32 j = 0; j < count; j++) {
            acc = fe_add<F>(acc, fe_load<F>(data + ((size_t)slots[j] * n + k + 1) * 4));
        }
    }
    fe_store<F>(data + ((size_t)dst * n + k) * 4, acc);
}

// ---------------------------------------------------------------------------
// Wiring matrices
//
// A registered set holds the wiring polynomials s_c(X, Y) of several circuits
// as one sparse matrix by column: for circuit c and degree j of X, the terms
// u * Y^q. A circuit's coefficients u are few distinct values, so each column
// is cut into chunks of one coefficient and of bounded length: a chunk is
// then a short sum and one product, however many constraints a wire appears
// in.

// One thread per chunk: its coefficient times the sum of its terms' y^q, with
// the powers of y read from a store slot.
template <class F>
__global__ void k_wiring_partials(const u32 *__restrict__ chunk_terms,
                                  const u32 *__restrict__ chunk_values,
                                  const u32 *__restrict__ rows, const u64 *__restrict__ values,
                                  const u64 *__restrict__ powers, u64 *__restrict__ partials,
                                  u32 chunks) {
    u32 chunk = blockIdx.x * blockDim.x + threadIdx.x;
    if (chunk >= chunks) return;
    Fe<F> acc = fe_zero<F>();
    for (u32 t = chunk_terms[chunk]; t < chunk_terms[chunk + 1]; t++) {
        acc = fe_add<F>(acc, fe_load<F>(powers + (size_t)rows[t] * 4));
    }
    acc = fe_mul<F>(acc, fe_load<F>(values + (size_t)chunk_values[chunk] * 4));
    fe_store<F>(partials + (size_t)chunk * 4, acc);
}

// One thread per coefficient of each circuit's restriction: the sum of its
// column's chunks. Circuit c's restriction goes to slot `dst + c`.
template <class F>
__global__ void k_wiring_columns(const u32 *__restrict__ column_chunks,
                                 const u64 *__restrict__ partials, u64 *__restrict__ data,
                                 u32 dst, u32 n) {
    u32 per_slot = n / BLOCK;
    u32 circuit = blockIdx.x / per_slot;
    size_t k = (size_t)(blockIdx.x % per_slot) * BLOCK + threadIdx.x;
    size_t column = (size_t)circuit * n + k;
    Fe<F> acc = fe_zero<F>();
    for (u32 c = column_chunks[column]; c < column_chunks[column + 1]; c++) {
        acc = fe_add<F>(acc, fe_load<F>(partials + (size_t)c * 4));
    }
    fe_store<F>(data + ((size_t)(dst + circuit) * n + k) * 4, acc);
}

// ---------------------------------------------------------------------------
// Host

namespace {

struct BaseSet {
    int curve;
    size_t n;
    void *table;
};

// The polynomial store of one field.
struct Store {
    u64 *data = nullptr;
    size_t n = 0, slots = 0;
    // The staging of this store's uploads, on its own stream and on the one
    // it keeps for uploads taken in apart from its other work: a buffer its
    // one caller fills between calls, its device mirror, and an event
    // recorded behind the last copy out of the buffer, after which the
    // buffer can be filled again. The uploads taken in apart have two, used
    // in turn, so that one is filled while the other is copied from.
    struct Staging {
        u64 *host = nullptr, *device = nullptr;
        size_t capacity = 0;
        cudaEvent_t copied = nullptr;
    } staging[3];
    // Which of its two the last upload taken in apart was handed.
    int apart_turn = 0;
    // The stream for uploads taken in apart, and the event recorded behind
    // the last of them: the store's own stream is made to wait for it before
    // anything reads what they wrote.
    cudaStream_t apart = nullptr;
    cudaEvent_t apart_done = nullptr;
};

// What one kind of call uses: the MSMs of one curve, or the polynomial store
// of one field. The calls of a lane are serialized on its mutex and queued
// on its stream; the lanes run alongside one another, as a prover's two
// sides do, and as a side's commitments do next to its polynomial
// arithmetic.
struct Lane {
    std::mutex mutex;
    cudaStream_t stream = nullptr;

    // A curve's lane for started requests is held from a request's start to
    // its finish, which are separate calls and may be on separate threads.
    std::atomic<bool> held{false};
    // The number of MSMs of the request it is held for.
    size_t started_msms = 0;

    // An MSM lane's grow-only device buffers, and the pinned host buffers of
    // the requests that are not laid out in a stage.
    size_t term_capacity = 0, block_capacity = 0, msm_capacity = 0;
    u64 *d_scalars = nullptr;
    u32 *d_indices = nullptr, *h_indices = nullptr;
    void *d_block_sums = nullptr;
    u32 *d_offsets = nullptr, *h_offsets = nullptr;
    void *d_out = nullptr;
    u64 *h_out = nullptr;
    // The terms from the start of `d_indices` that index the bases in order,
    // over and over every `identity_n`: what a commitment to store slots
    // reads, and leaves there for the next one.
    size_t identity_terms = 0, identity_n = 0;

    // A store lane's store, and the staging buffers of its calls.
    Store store;
    size_t arg_capacity = 0;
    u64 *d_args = nullptr, *h_args = nullptr;
};

// The number of requests of one curve that can be started and not yet
// finished.
const int STARTED_LANES = 4;

// A registered set of wiring matrices. `partials` is scratch of its field's
// lane.
struct Wiring {
    int field;
    size_t n, circuits, chunks, terms;
    u32 *column_chunks, *chunk_terms, *chunk_values, *rows;
    u64 *values, *partials;
};

struct Engine {
    // Guards start-up and the registrations below, which the lanes read
    // copies of.
    std::mutex mutex;
    std::atomic<bool> ready{false};
    bool failed = false;
    // The stream registrations build tables on.
    cudaStream_t stream = nullptr;
    std::vector<BaseSet> sets;
    std::vector<Wiring> wirings;
    // The store lanes, by field, and the MSM lanes: two to a curve so that a
    // short request need not wait behind a long one, and two more for the
    // requests of the curve that are started and finished later, which
    // therefore keep no other request waiting. Two of those let a caller
    // lay the next one out while the device computes the one before.
    Lane lanes[2];
    Lane msms[2][2 + STARTED_LANES];
};

Engine g;

#define CHECK(call)                                                                   \
    do {                                                                              \
        cudaError_t err__ = (call);                                                   \
        if (err__ != cudaSuccess) {                                                   \
            fprintf(stderr, "ragu_gpu: %s failed: %s\n", #call, cudaGetErrorString(err__)); \
            return RAGU_GPU_ERROR;                                                    \
        }                                                                             \
    } while (0)

// Starts the engine. The caller holds the engine's mutex.
int ensure_ready_locked() {
    if (g.ready) return RAGU_GPU_OK;
    if (g.failed) return RAGU_GPU_ERROR;
    g.failed = true;
    int count = 0;
    CHECK(cudaGetDeviceCount(&count));
    if (count < 1) return RAGU_GPU_ERROR;
    CHECK(cudaSetDevice(0));
    CHECK(cudaSetDeviceFlags(cudaDeviceScheduleSpin));
    CHECK(cudaStreamCreate(&g.stream));
    for (Lane &lane : g.lanes) CHECK(cudaStreamCreate(&lane.stream));
    for (auto &curve : g.msms) {
        for (Lane &lane : curve) CHECK(cudaStreamCreate(&lane.stream));
    }
    g.failed = false;
    g.ready = true;
    return RAGU_GPU_OK;
}

int ensure_ready() {
    if (g.ready) return RAGU_GPU_OK;
    std::lock_guard<std::mutex> lock(g.mutex);
    return ensure_ready_locked();
}

// Enters the store lane of `field` for the rest of the calling function.
#define ENTER_LANE(field)                                                         \
    TRY(ensure_ready());                                                          \
    if ((field) != RAGU_GPU_FP && (field) != RAGU_GPU_FQ) return RAGU_GPU_ERROR; \
    Lane &L = g.lanes[(field)];                                                   \
    std::lock_guard<std::mutex> lock(L.mutex)

template <class T> int regrow_device(T *&ptr, size_t bytes) {
    if (ptr) CHECK(cudaFree(ptr));
    ptr = nullptr;
    CHECK(cudaMalloc((void **)&ptr, bytes));
    return RAGU_GPU_OK;
}

template <class T> int regrow_pinned(T *&ptr, size_t bytes) {
    if (ptr) CHECK(cudaFreeHost(ptr));
    ptr = nullptr;
    CHECK(cudaMallocHost((void **)&ptr, bytes));
    return RAGU_GPU_OK;
}

#define TRY(call)                         \
    do {                                  \
        int rc__ = (call);                \
        if (rc__ != RAGU_GPU_OK) return rc__; \
    } while (0)

template <class F> int build_table(const u64 *xy, size_t n, void **table_out) {
    const size_t rows = n * NUM_WINDOWS;
    u64 *d_xy = nullptr;
    Proj<F> *d_bases = nullptr, *d_multiples = nullptr;
    Fe<F> *d_prefix = nullptr;
    Aff<F> *d_table = nullptr;
    // Rows per pass, bounding the scratch at about 270 MB.
    const size_t chunk = rows < (1u << 14) ? rows : (1u << 14);
    CHECK(cudaMalloc((void **)&d_xy, n * 8 * sizeof(u64)));
    CHECK(cudaMalloc((void **)&d_bases, rows * sizeof(Proj<F>)));
    CHECK(cudaMalloc((void **)&d_multiples, chunk * ROW_ENTRIES * sizeof(Proj<F>)));
    CHECK(cudaMalloc((void **)&d_prefix, chunk * ROW_ENTRIES * sizeof(Fe<F>)));
    CHECK(cudaMalloc((void **)&d_table, rows * ROW_ENTRIES * sizeof(Aff<F>)));
    CHECK(cudaMemcpy(d_xy, xy, n * 8 * sizeof(u64), cudaMemcpyHostToDevice));
    k_window_bases<F><<<(u32)((n + BLOCK - 1) / BLOCK), BLOCK, 0, g.stream>>>(d_xy, d_bases, (u32)n);
    CHECK(cudaGetLastError());
    for (size_t first = 0; first < rows; first += chunk) {
        size_t count = rows - first < chunk ? rows - first : chunk;
        k_table_rows<F><<<(u32)((count + BLOCK - 1) / BLOCK), BLOCK, 0, g.stream>>>(
            d_bases + first, d_table + first * ROW_ENTRIES, d_multiples, d_prefix, (u32)count);
        CHECK(cudaGetLastError());
    }
    CHECK(cudaStreamSynchronize(g.stream));
    CHECK(cudaFree(d_xy));
    CHECK(cudaFree(d_bases));
    CHECK(cudaFree(d_multiples));
    CHECK(cudaFree(d_prefix));
    *table_out = d_table;
    return RAGU_GPU_OK;
}

// Launches both kernels over `blocks` blocks of threads, `parts` to a term.
template <class B, class S>
int launch_msm(Lane &L, const BaseSet &set, u32 blocks, u32 num_msms, u32 parts) {
    if (blocks > 0) {
        k_terms<B, S><<<blocks, BLOCK, 0, L.stream>>>(L.d_scalars, L.d_indices,
                                                    (const Aff<B> *)set.table,
                                                    (Proj<B> *)L.d_block_sums, parts);
        CHECK(cudaGetLastError());
    }
    k_finish<B><<<num_msms, BLOCK, 0, L.stream>>>((const Proj<B> *)L.d_block_sums, L.d_offsets,
                                                 (Proj<B> *)L.d_out);
    CHECK(cudaGetLastError());
    return RAGU_GPU_OK;
}

} // namespace

extern "C" int ragu_gpu_register_bases(int curve, const uint64_t *xy, size_t n) {
    std::lock_guard<std::mutex> lock(g.mutex);
    TRY(ensure_ready_locked());
    if (n == 0 || n > (1u << 20) || (curve != RAGU_GPU_PALLAS && curve != RAGU_GPU_VESTA))
        return RAGU_GPU_ERROR;
    size_t need = n * ENTRIES_PER_BASE * sizeof(Aff<Fp>);
    size_t free_bytes = 0, total_bytes = 0;
    CHECK(cudaMemGetInfo(&free_bytes, &total_bytes));
    // Leave room for the construction scratch and the MSM buffers.
    if (need + (size_t(2) << 30) > free_bytes) return RAGU_GPU_ERROR;
    void *table = nullptr;
    if (curve == RAGU_GPU_PALLAS) {
        TRY(build_table<Fp>(xy, n, &table));
    } else {
        TRY(build_table<Fq>(xy, n, &table));
    }
    g.sets.push_back(BaseSet{curve, n, table});
    return (int)g.sets.size() - 1;
}

namespace {

// The number of terms an MSM lane's buffers have room for from its first
// request on: about 9 MB of pinned memory a lane, and as much on the device.
const size_t LANE_TERMS = size_t(1) << 18;

// Looks up a registered base set.
int base_set(int handle, BaseSet &set) {
    TRY(ensure_ready());
    std::lock_guard<std::mutex> registered(g.mutex);
    if (handle < 0 || (size_t)handle >= g.sets.size()) return RAGU_GPU_ERROR;
    set = g.sets[handle];
    return RAGU_GPU_OK;
}

// Makes room on lane `L` for a request of `terms` padded terms in `blocks`
// blocks and `num_msms` MSMs.
//
// A lane's buffers start large enough for most requests: the sizes of the
// requests a prover makes vary from one proof to the next, and a lane that
// grew with each new largest one would stall that proof.
int ensure_msm_buffers(Lane &L, size_t terms, size_t blocks, size_t num_msms) {
    if (terms > L.term_capacity) {
        size_t cap = terms + terms / 2 + 1024;
        if (cap < LANE_TERMS) cap = LANE_TERMS;
        TRY(regrow_device(L.d_scalars, cap * 4 * sizeof(u64)));
        TRY(regrow_device(L.d_indices, cap * sizeof(u32)));
        TRY(regrow_pinned(L.h_indices, cap * sizeof(u32)));
        L.term_capacity = cap;
        L.identity_terms = 0;
    }
    if (blocks > L.block_capacity) {
        size_t cap = blocks + blocks / 2 + 1024;
        if (cap < 2 * LANE_TERMS / BLOCK) cap = 2 * LANE_TERMS / BLOCK;
        TRY(regrow_device(L.d_block_sums, cap * sizeof(Proj<Fp>)));
        L.block_capacity = cap;
    }
    if (num_msms > L.msm_capacity) {
        size_t cap = num_msms + num_msms / 2 + 64;
        if (cap < 256) cap = 256;
        TRY(regrow_device(L.d_offsets, (cap + 1) * sizeof(u32)));
        TRY(regrow_pinned(L.h_offsets, (cap + 1) * sizeof(u32)));
        TRY(regrow_device(L.d_out, cap * sizeof(Proj<Fp>)));
        TRY(regrow_pinned(L.h_out, cap * 12 * sizeof(u64)));
        L.msm_capacity = cap;
    }
    return RAGU_GPU_OK;
}

// How a request's terms are laid out for the kernels: in `groups` groups of
// BLOCK terms, each term split over `parts` threads.
struct Plan {
    size_t groups = 0, blocks = 0, terms = 0;
    u32 parts = 1;
};

// Plans a request of `num_msms` MSMs, MSM `m` of `counts[m]` terms.
int plan_msms(const uint32_t *counts, size_t num_msms, Plan &plan) {
    // Each MSM's terms are padded to whole groups of BLOCK, so a block sums
    // terms of one MSM only.
    size_t groups = 0;
    for (size_t m = 0; m < num_msms; m++) groups += ((size_t)counts[m] + BLOCK - 1) / BLOCK;
    // A request small enough that the device has blocks to spare splits each
    // term over several threads, which shortens the wait; a large one is
    // bound by the total work and keeps one thread per term.
    u32 parts = 1;
    while (parts < NUM_WINDOWS && groups * parts * 2 <= SPLIT_BLOCKS) parts *= 2;
    plan.groups = groups;
    plan.blocks = groups * parts;
    plan.terms = groups * BLOCK;
    plan.parts = parts;
    if (plan.blocks > 0xffffffffu / BLOCK) return RAGU_GPU_ERROR;
    return RAGU_GPU_OK;
}

// Pinned memory a caller lays a request out in, which the lane that runs the
// request copies to the device from: the terms are written once, where the
// transfer reads them.
struct Stage {
    // Taken from the staging of a request to its end. A started lane's
    // stage goes with the lane and is guarded by the lane's `held`.
    std::atomic<bool> taken{false};
    size_t term_capacity = 0, msm_capacity = 0;
    u64 *scalars = nullptr;
    u32 *indices = nullptr, *offsets = nullptr;
    // The request laid out in it.
    BaseSet set{};
    size_t num_msms = 0;
    Plan plan{};
};

// The stages of a curve that any request may take. A request that finds none
// free is declined, never kept waiting: a caller may lay one request out
// while it lays out another.
const int FREE_STAGES = 16;
const int CURVE_STAGES = FREE_STAGES + STARTED_LANES;
Stage g_stages[2][CURVE_STAGES];

// The stage a staging names, with its curve and place.
Stage *stage_of(int staging, int &curve, int &which) {
    if (staging < 0 || staging >= 2 * CURVE_STAGES) return nullptr;
    curve = staging / CURVE_STAGES;
    which = staging % CURVE_STAGES;
    return &g_stages[curve][which];
}

// Gives a stage up, and the started lane it goes with if it has one.
void release_stage(int curve, int which) {
    if (which < FREE_STAGES) {
        g_stages[curve][which].taken.store(false);
    } else {
        g.msms[curve][2 + which - FREE_STAGES].held.store(false);
    }
}

// Makes room in a stage, which starts as large as a lane.
int ensure_stage(Stage &S, size_t terms, size_t num_msms) {
    if (terms > S.term_capacity) {
        size_t cap = terms + terms / 2 + 1024;
        if (cap < LANE_TERMS) cap = LANE_TERMS;
        S.term_capacity = 0;
        TRY(regrow_pinned(S.scalars, cap * 4 * sizeof(u64)));
        TRY(regrow_pinned(S.indices, cap * sizeof(u32)));
        S.term_capacity = cap;
    }
    if (num_msms > S.msm_capacity) {
        size_t cap = num_msms + num_msms / 2 + 64;
        if (cap < 256) cap = 256;
        S.msm_capacity = 0;
        TRY(regrow_pinned(S.offsets, (cap + 1) * sizeof(u32)));
        S.msm_capacity = cap;
    }
    return RAGU_GPU_OK;
}

// Queues on lane `L`, which the caller has to itself, the copy of the
// request laid out in `S` to the device, its kernels and the copy of its
// results to `L.h_out`, without waiting. `S` must stay as it is until the
// lane's stream has passed the copy.
int queue_staged(Lane &L, const Stage &S) {
    const Plan &plan = S.plan;
    const size_t num_msms = S.num_msms;
    TRY(ensure_msm_buffers(L, plan.terms, plan.blocks, num_msms));
    L.identity_terms = 0;
    if (plan.terms > 0) {
        CHECK(cudaMemcpyAsync(L.d_scalars, S.scalars, plan.terms * 4 * sizeof(u64),
                              cudaMemcpyHostToDevice, L.stream));
        CHECK(cudaMemcpyAsync(L.d_indices, S.indices, plan.terms * sizeof(u32),
                              cudaMemcpyHostToDevice, L.stream));
    }
    CHECK(cudaMemcpyAsync(L.d_offsets, S.offsets, (num_msms + 1) * sizeof(u32),
                          cudaMemcpyHostToDevice, L.stream));

    if (S.set.curve == RAGU_GPU_PALLAS) {
        TRY((launch_msm<Fp, Fq>(L, S.set, (u32)plan.blocks, (u32)num_msms, plan.parts)));
    } else {
        TRY((launch_msm<Fq, Fp>(L, S.set, (u32)plan.blocks, (u32)num_msms, plan.parts)));
    }
    CHECK(cudaMemcpyAsync(L.h_out, L.d_out, num_msms * 12 * sizeof(u64), cudaMemcpyDeviceToHost,
                          L.stream));
    return RAGU_GPU_OK;
}

// Frees a curve's lane for started requests when the function holding it
// returns, unless told to keep it.
struct StartedHold {
    Lane &lane;
    bool keep = false;
    ~StartedHold() {
        if (!keep) lane.held.store(false);
    }
};

// The lane of the started request a ticket names.
Lane *started_lane(int ticket) {
    if (ticket < 0 || ticket >= 2 * STARTED_LANES) return nullptr;
    Lane &L = g.msms[ticket / STARTED_LANES][2 + ticket % STARTED_LANES];
    return L.held.load() ? &L : nullptr;
}

// Stages a request given as arrays, copying its terms into the stage.
int stage_copy(int handle, const uint64_t *scalars, const uint32_t *indices,
               const uint32_t *offsets, size_t num_msms, int started) {
    if (num_msms == 0) return RAGU_GPU_ERROR;
    std::vector<uint32_t> counts(num_msms), starts(num_msms);
    for (size_t m = 0; m < num_msms; m++) counts[m] = offsets[m + 1] - offsets[m];
    uint64_t *to_scalars = nullptr;
    uint32_t *to_indices = nullptr;
    int staging = ragu_gpu_msm_stage(handle, counts.data(), num_msms, started, &to_scalars,
                                     &to_indices, starts.data());
    if (staging < 0) return staging;
    for (size_t m = 0; m < num_msms; m++) {
        memcpy(to_scalars + (size_t)starts[m] * 4, scalars + (size_t)offsets[m] * 4,
               (size_t)counts[m] * 4 * sizeof(u64));
        memcpy(to_indices + starts[m], indices + offsets[m], (size_t)counts[m] * sizeof(u32));
    }
    return staging;
}

} // namespace

extern "C" int ragu_gpu_msm_stage(int handle, const uint32_t *counts, size_t num_msms,
                                  int started, uint64_t **scalars, uint32_t **indices,
                                  uint32_t *starts) {
    if (num_msms == 0) return RAGU_GPU_ERROR;
    BaseSet set;
    TRY(base_set(handle, set));
    Plan plan;
    TRY(plan_msms(counts, num_msms, plan));
    const int curve = set.curve == RAGU_GPU_PALLAS ? 0 : 1;
    int which = 0;
    if (started) {
        // A curve takes a few started requests at a time: one more is
        // declined, not kept waiting for a finish that is its caller's to
        // bring about.
        while (which < STARTED_LANES && g.msms[curve][2 + which].held.exchange(true)) which++;
        if (which == STARTED_LANES) return RAGU_GPU_ERROR;
        which += FREE_STAGES;
    } else {
        while (which < FREE_STAGES && g_stages[curve][which].taken.exchange(true)) which++;
        if (which == FREE_STAGES) return RAGU_GPU_ERROR;
    }
    Stage &S = g_stages[curve][which];
    if (ensure_stage(S, plan.terms, num_msms) != RAGU_GPU_OK) {
        release_stage(curve, which);
        return RAGU_GPU_ERROR;
    }
    S.set = set;
    S.num_msms = num_msms;
    S.plan = plan;
    size_t group = 0;
    for (size_t m = 0; m < num_msms; m++) {
        size_t count = counts[m];
        size_t padded = (count + BLOCK - 1) / BLOCK * BLOCK;
        size_t at = group * BLOCK;
        starts[m] = (u32)at;
        S.offsets[m] = (u32)(group * plan.parts);
        memset(S.scalars + (at + count) * 4, 0, (padded - count) * 4 * sizeof(u64));
        memset(S.indices + at + count, 0, (padded - count) * sizeof(u32));
        group += padded / BLOCK;
    }
    S.offsets[num_msms] = (u32)(group * plan.parts);
    *scalars = S.scalars;
    *indices = S.indices;
    return curve * CURVE_STAGES + which;
}

extern "C" int ragu_gpu_msm_unstage(int staging) {
    int curve = 0, which = 0;
    if (!stage_of(staging, curve, which)) return RAGU_GPU_ERROR;
    release_stage(curve, which);
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_msm_batch_staged(int staging, uint64_t *out) {
    int curve = 0, which = 0;
    Stage *stage = stage_of(staging, curve, which);
    if (!stage || which >= FREE_STAGES || !stage->taken.load()) return RAGU_GPU_ERROR;
    // Freed when this returns, by when the lane has read it.
    struct Taken {
        Stage &stage;
        ~Taken() { stage.taken.store(false); }
    } taken{*stage};
    // The curve's first lane if it is free, and otherwise its second, waited
    // for if need be.
    Lane *lanes = g.msms[curve];
    std::unique_lock<std::mutex> lock(lanes[0].mutex, std::try_to_lock);
    if (!lock.owns_lock()) lock = std::unique_lock<std::mutex>(lanes[1].mutex);
    Lane &L = lock.mutex() == &lanes[0].mutex ? lanes[0] : lanes[1];
    int queued = queue_staged(L, *stage);
    // Whatever was queued reads the stage, so it is waited for either way.
    CHECK(cudaStreamSynchronize(L.stream));
    TRY(queued);
    memcpy(out, L.h_out, stage->num_msms * 12 * sizeof(u64));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_msm_start_staged(int staging) {
    int curve = 0, which = 0;
    Stage *stage = stage_of(staging, curve, which);
    if (!stage || which < FREE_STAGES) return RAGU_GPU_ERROR;
    Lane &L = g.msms[curve][2 + which - FREE_STAGES];
    if (!L.held.load()) return RAGU_GPU_ERROR;
    StartedHold hold{L};
    int queued = queue_staged(L, *stage);
    if (queued != RAGU_GPU_OK) {
        // The lane is given up, and with it the stage that what was queued
        // may still read.
        cudaStreamSynchronize(L.stream);
        return queued;
    }
    L.started_msms = stage->num_msms;
    hold.keep = true;
    return curve * STARTED_LANES + (which - FREE_STAGES);
}

extern "C" int ragu_gpu_msm_batch(int handle, const uint64_t *scalars, const uint32_t *indices,
                                  const uint32_t *offsets, size_t num_msms, uint64_t *out) {
    int staging = stage_copy(handle, scalars, indices, offsets, num_msms, 0);
    if (staging < 0) return RAGU_GPU_ERROR;
    return ragu_gpu_msm_batch_staged(staging, out);
}

extern "C" int ragu_gpu_msm_start(int handle, const uint64_t *scalars, const uint32_t *indices,
                                  const uint32_t *offsets, size_t num_msms) {
    int staging = stage_copy(handle, scalars, indices, offsets, num_msms, 1);
    if (staging < 0) return RAGU_GPU_ERROR;
    return ragu_gpu_msm_start_staged(staging);
}

extern "C" int ragu_gpu_msm_ready(int ticket) {
    Lane *lane = started_lane(ticket);
    if (!lane) return RAGU_GPU_ERROR;
    // A failure is the finish's to report.
    return cudaStreamQuery(lane->stream) == cudaErrorNotReady ? 0 : 1;
}

extern "C" int ragu_gpu_msm_finish(int ticket, uint64_t *out) {
    Lane *lane = started_lane(ticket);
    if (!lane) return RAGU_GPU_ERROR;
    Lane &L = *lane;
    StartedHold hold{L};
    CHECK(cudaStreamSynchronize(L.stream));
    if (out) memcpy(out, L.h_out, L.started_msms * 12 * sizeof(u64));
    return RAGU_GPU_OK;
}

// ---------------------------------------------------------------------------
// Polynomial store, host side

namespace {

// Makes room for `words` 64-bit words of call arguments or results.
int ensure_args(Lane &L, size_t words) {
    if (words <= L.arg_capacity) return RAGU_GPU_OK;
    size_t cap = words + words / 2 + 4096;
    TRY(regrow_device(L.d_args, cap * sizeof(u64)));
    TRY(regrow_pinned(L.h_args, cap * sizeof(u64)));
    L.arg_capacity = cap;
    return RAGU_GPU_OK;
}

// Copies `count` 32-bit values into the staging buffer at word `at`,
// returning the number of words used.
size_t stage_u32(Lane &L, size_t at, const u32 *values, size_t count) {
    memcpy(L.h_args + at, values, count * sizeof(u32));
    return (count + 1) / 2;
}

int checked_store(int field, Store **out) {
    if (field != RAGU_GPU_FP && field != RAGU_GPU_FQ) return RAGU_GPU_ERROR;
    Store &store = g.lanes[field].store;
    if (store.data == nullptr) return RAGU_GPU_ERROR;
    *out = &store;
    return RAGU_GPU_OK;
}

bool slots_ok(const Store &store, const u32 *slots, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (slots[i] >= store.slots) return false;
    }
    return true;
}

} // namespace

extern "C" int ragu_gpu_poly_init(int field, size_t n, size_t slots) {
    ENTER_LANE(field);
    if (field != RAGU_GPU_FP && field != RAGU_GPU_FQ) return RAGU_GPU_ERROR;
    if (n < BLOCK || n % BLOCK != 0 || n > (1u << 14) || slots == 0 || slots > (1u << 16))
        return RAGU_GPU_ERROR;
    Store &store = g.lanes[field].store;
    if (store.data != nullptr && store.n == n && store.slots >= slots) return RAGU_GPU_OK;
    size_t bytes = n * slots * 4 * sizeof(u64);
    size_t free_bytes = 0, total_bytes = 0;
    CHECK(cudaMemGetInfo(&free_bytes, &total_bytes));
    if (bytes + (size_t(1) << 30) > free_bytes) return RAGU_GPU_ERROR;
    store.n = 0;
    store.slots = 0;
    TRY(regrow_device(store.data, bytes));
    store.n = n;
    store.slots = slots;
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_upload_buffer(int field, size_t words, uint64_t **buffer,
                                           int apart) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (apart) store->apart_turn ^= 1;
    Store::Staging &staging = store->staging[apart ? 1 + store->apart_turn : 0];
    // An earlier upload may still be reading the buffer. Only its copy is
    // waited for: whatever else is queued goes on while the caller fills
    // the buffer.
    if (staging.copied) CHECK(cudaEventSynchronize(staging.copied));
    if (words > staging.capacity) {
        // The device mirror may still be read by an earlier upload's kernel.
        CHECK(cudaStreamSynchronize(apart && store->apart ? store->apart : L.stream));
        size_t cap = words + words / 2 + 4096;
        staging.capacity = 0;
        TRY(regrow_device(staging.device, cap * sizeof(u64)));
        TRY(regrow_pinned(staging.host, cap * sizeof(u64)));
        staging.capacity = cap;
    }
    *buffer = staging.host;
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_upload_staged(int field, size_t num_slots, size_t num_runs,
                                           size_t num_terms, int apart) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (apart && !store->apart) {
        CHECK(cudaStreamCreate(&store->apart));
        CHECK(cudaEventCreateWithFlags(&store->apart_done, cudaEventDisableTiming));
    }
    cudaStream_t stream = apart ? store->apart : L.stream;
    Store::Staging &staging = store->staging[apart ? 1 + store->apart_turn : 0];
    // The run table is padded to four words, which keeps every coefficient
    // on a 32-byte boundary of the page-aligned buffer.
    size_t run_words = (num_runs + 4) & ~(size_t)3, slot_words = (num_slots + 1) / 2;
    size_t words = run_words + num_terms * 4 + slot_words;
    if (num_slots == 0 || words > staging.capacity || num_terms > 0xffffffffu ||
        (num_terms > 0 && num_runs == 0))
        return RAGU_GPU_ERROR;
    const u32 *h_slots = (const u32 *)(staging.host + run_words + num_terms * 4);
    if (!slots_ok(*store, h_slots, num_slots)) return RAGU_GPU_ERROR;
    CHECK(cudaMemcpyAsync(staging.device, staging.host, words * sizeof(u64),
                          cudaMemcpyHostToDevice, stream));
    if (!staging.copied) {
        CHECK(cudaEventCreateWithFlags(&staging.copied, cudaEventDisableTiming));
    }
    CHECK(cudaEventRecord(staging.copied, stream));
    u32 n = (u32)store->n;
    const u64 *d_runs = staging.device;
    const u64 *d_limbs = staging.device + run_words;
    const u32 *d_slots = (const u32 *)(staging.device + run_words + num_terms * 4);
    k_poly_zero<<<(u32)(num_slots * (n / BLOCK)), BLOCK, 0, stream>>>(store->data, d_slots, n);
    CHECK(cudaGetLastError());
    if (num_terms > 0) {
        u32 grid = (u32)((num_terms + BLOCK - 1) / BLOCK);
        if (field == RAGU_GPU_FP) {
            k_poly_place<Fp><<<grid, BLOCK, 0, stream>>>(store->data, d_runs, d_limbs,
                                                       (u32)num_runs, (u32)num_terms);
        } else {
            k_poly_place<Fq><<<grid, BLOCK, 0, stream>>>(store->data, d_runs, d_limbs,
                                                       (u32)num_runs, (u32)num_terms);
        }
        CHECK(cudaGetLastError());
    }
    // Queued: the next call that reads the store, or asks for this buffer,
    // waits for it; an upload taken in apart is waited for once joined.
    if (apart) CHECK(cudaEventRecord(store->apart_done, stream));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_join(int field) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (store->apart_done) CHECK(cudaStreamWaitEvent(L.stream, store->apart_done, 0));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_powers(int field, uint32_t dst, const uint64_t *z) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (dst >= store->slots) return RAGU_GPU_ERROR;
    u32 n = (u32)store->n;
    u64 *d_dst = store->data + (size_t)dst * n * 4;
    if (field == RAGU_GPU_FP) {
        Fe<Fp> value = {{z[0], z[1], z[2], z[3]}};
        k_poly_powers<Fp><<<n / BLOCK, BLOCK, 0, L.stream>>>(d_dst, value, n);
    } else {
        Fe<Fq> value = {{z[0], z[1], z[2], z[3]}};
        k_poly_powers<Fq><<<n / BLOCK, BLOCK, 0, L.stream>>>(d_dst, value, n);
    }
    CHECK(cudaGetLastError());
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_lincomb(int field, size_t jobs, const uint32_t *dst,
                                     const uint32_t *offsets, const uint32_t *srcs,
                                     const uint64_t *scalars) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (jobs == 0) return RAGU_GPU_OK;
    size_t terms = offsets[jobs];
    if (!slots_ok(*store, dst, jobs) || !slots_ok(*store, srcs, terms)) return RAGU_GPU_ERROR;
    size_t dst_words = (jobs + 1) / 2, offset_words = (jobs + 2) / 2, src_words = (terms + 1) / 2;
    TRY(ensure_args(L, dst_words + offset_words + src_words + terms * 4));
    stage_u32(L, 0, dst, jobs);
    stage_u32(L, dst_words, offsets, jobs + 1);
    stage_u32(L, dst_words + offset_words, srcs, terms);
    memcpy(L.h_args + dst_words + offset_words + src_words, scalars, terms * 4 * sizeof(u64));
    size_t words = dst_words + offset_words + src_words + terms * 4;
    CHECK(cudaMemcpyAsync(L.d_args, L.h_args, words * sizeof(u64), cudaMemcpyHostToDevice,
                          L.stream));
    u32 n = (u32)store->n;
    u32 grid = (u32)(jobs * (n / BLOCK));
    const u32 *d_dst = (const u32 *)L.d_args;
    const u32 *d_offsets = (const u32 *)(L.d_args + dst_words);
    const u32 *d_srcs = (const u32 *)(L.d_args + dst_words + offset_words);
    const u64 *d_scalars = L.d_args + dst_words + offset_words + src_words;
    if (field == RAGU_GPU_FP) {
        k_poly_lincomb<Fp><<<grid, BLOCK, 0, L.stream>>>(store->data, d_dst, d_offsets, d_srcs,
                                                       d_scalars, n);
    } else {
        k_poly_lincomb<Fq><<<grid, BLOCK, 0, L.stream>>>(store->data, d_dst, d_offsets, d_srcs,
                                                       d_scalars, n);
    }
    CHECK(cudaGetLastError());
    CHECK(cudaStreamSynchronize(L.stream));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_dilate_add(int field, size_t jobs, const uint32_t *dst,
                                        const uint32_t *a, const uint32_t *s, uint32_t powers,
                                        uint32_t t) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (jobs == 0) return RAGU_GPU_OK;
    if (!slots_ok(*store, dst, jobs) || !slots_ok(*store, a, jobs) ||
        !slots_ok(*store, s, jobs) || powers >= store->slots || t >= store->slots)
        return RAGU_GPU_ERROR;
    size_t job_words = (jobs + 1) / 2;
    TRY(ensure_args(L, 3 * job_words));
    stage_u32(L, 0, dst, jobs);
    stage_u32(L, job_words, a, jobs);
    stage_u32(L, 2 * job_words, s, jobs);
    CHECK(cudaMemcpyAsync(L.d_args, L.h_args, 3 * job_words * sizeof(u64),
                          cudaMemcpyHostToDevice, L.stream));
    u32 n = (u32)store->n;
    u32 grid = (u32)(jobs * (n / BLOCK));
    const u32 *d_dst = (const u32 *)L.d_args;
    const u32 *d_a = (const u32 *)(L.d_args + job_words);
    const u32 *d_s = (const u32 *)(L.d_args + 2 * job_words);
    if (field == RAGU_GPU_FP) {
        k_poly_dilate_add<Fp><<<grid, BLOCK, 0, L.stream>>>(store->data, d_dst, d_a, d_s, powers,
                                                          t, n);
    } else {
        k_poly_dilate_add<Fq><<<grid, BLOCK, 0, L.stream>>>(store->data, d_dst, d_a, d_s, powers,
                                                          t, n);
    }
    CHECK(cudaGetLastError());
    CHECK(cudaStreamSynchronize(L.stream));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_revdot(int field, size_t pairs, const uint32_t *a, const uint32_t *b,
                                    int reversed, uint64_t *out) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (pairs == 0) return RAGU_GPU_OK;
    if (!slots_ok(*store, a, pairs) || !slots_ok(*store, b, pairs)) return RAGU_GPU_ERROR;
    size_t pair_words = (pairs + 1) / 2;
    TRY(ensure_args(L, 2 * pair_words + pairs * 4));
    stage_u32(L, 0, a, pairs);
    stage_u32(L, pair_words, b, pairs);
    CHECK(cudaMemcpyAsync(L.d_args, L.h_args, 2 * pair_words * sizeof(u64),
                          cudaMemcpyHostToDevice, L.stream));
    u32 n = (u32)store->n;
    const u32 *d_a = (const u32 *)L.d_args;
    const u32 *d_b = (const u32 *)(L.d_args + pair_words);
    u64 *d_out = L.d_args + 2 * pair_words;
    if (field == RAGU_GPU_FP) {
        k_poly_revdot<Fp><<<(u32)pairs, BLOCK, 0, L.stream>>>(store->data, d_a, d_b, d_out, n,
                                                            reversed);
    } else {
        k_poly_revdot<Fq><<<(u32)pairs, BLOCK, 0, L.stream>>>(store->data, d_a, d_b, d_out, n,
                                                            reversed);
    }
    CHECK(cudaGetLastError());
    CHECK(cudaMemcpyAsync(L.h_args + 2 * pair_words, d_out, pairs * 4 * sizeof(u64),
                          cudaMemcpyDeviceToHost, L.stream));
    CHECK(cudaStreamSynchronize(L.stream));
    memcpy(out, L.h_args + 2 * pair_words, pairs * 4 * sizeof(u64));
    return RAGU_GPU_OK;
}

namespace {

// Queues the division of `jobs` staged slots by their staged points and the
// sum of the quotients to `dst`. `d_carries` is room for WIDE values a job,
// if the slots are long enough for the wide division.
template <class F>
int queue_quotients(Lane &L, Store &store, size_t jobs, u32 dst, const u32 *d_slots,
                    const u64 *d_points, u64 *d_carries) {
    const u32 n = (u32)store.n;
    if (jobs > 0 && d_carries) {
        const u32 blocks = (u32)jobs * (WIDE / BLOCK);
        k_poly_divide_sums<F><<<blocks, BLOCK, 0, L.stream>>>(store.data, d_slots, d_points,
                                                           d_carries, n);
        CHECK(cudaGetLastError());
        k_poly_divide_carries<F><<<(u32)jobs, BLOCK, 0, L.stream>>>(d_points, d_carries, n);
        CHECK(cudaGetLastError());
        k_poly_divide_finish<F><<<blocks, BLOCK, 0, L.stream>>>(store.data, d_slots, d_points,
                                                             d_carries, n);
        CHECK(cudaGetLastError());
    } else if (jobs > 0) {
        k_poly_divide<F><<<(u32)jobs, BLOCK, 0, L.stream>>>(store.data, d_slots, d_points, n);
        CHECK(cudaGetLastError());
    }
    if (jobs > SUM_LANES) {
        k_poly_shift_sum_wide<F><<<n / (BLOCK / SUM_LANES), BLOCK, 0, L.stream>>>(
            store.data, dst, d_slots, (u32)jobs, n);
    } else {
        k_poly_shift_sum<F><<<n / BLOCK, BLOCK, 0, L.stream>>>(store.data, dst, d_slots,
                                                             (u32)jobs, n);
    }
    CHECK(cudaGetLastError());
    return RAGU_GPU_OK;
}

} // namespace

extern "C" int ragu_gpu_poly_quotients(int field, size_t jobs, uint32_t dst,
                                       const uint32_t *slots, const uint64_t *points) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (dst >= store->slots || !slots_ok(*store, slots, jobs)) return RAGU_GPU_ERROR;
    for (size_t i = 0; i < jobs; i++) {
        if (slots[i] == dst) return RAGU_GPU_ERROR;
    }
    // Slots long enough are divided by the kernels with more threads to
    // each, which keep what the runs carry after the staged arguments.
    const bool wide = store->n >= WIDE && store->n % WIDE == 0;
    const size_t slot_words = (jobs + 1) / 2, staged = slot_words + jobs * 4;
    TRY(ensure_args(L, staged + (wide ? jobs * WIDE * 4 : 0)));
    stage_u32(L, 0, slots, jobs);
    memcpy(L.h_args + slot_words, points, jobs * 4 * sizeof(u64));
    CHECK(cudaMemcpyAsync(L.d_args, L.h_args, staged * sizeof(u64), cudaMemcpyHostToDevice,
                          L.stream));
    const u32 *d_slots = (const u32 *)L.d_args;
    const u64 *d_points = L.d_args + slot_words;
    u64 *d_carries = wide ? L.d_args + staged : nullptr;
    if (field == RAGU_GPU_FP) {
        TRY(queue_quotients<Fp>(L, *store, jobs, dst, d_slots, d_points, d_carries));
    } else {
        TRY(queue_quotients<Fq>(L, *store, jobs, dst, d_slots, d_points, d_carries));
    }
    // The staged arguments are read by the queued kernels.
    CHECK(cudaStreamSynchronize(L.stream));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_download(int field, size_t count, const uint32_t *slots,
                                      uint64_t *out) {
    const uint64_t *view = nullptr;
    TRY(ragu_gpu_poly_download_view(field, count, slots, &view));
    // The store has one caller, so the view is as the call left it.
    memcpy(out, view, count * g.lanes[field].store.n * 4 * sizeof(u64));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_download_view(int field, size_t count, const uint32_t *slots,
                                           const uint64_t **view) {
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    if (!slots_ok(*store, slots, count)) return RAGU_GPU_ERROR;
    size_t words = store->n * 4;
    TRY(ensure_args(L, count * words));
    for (size_t i = 0; i < count; i++) {
        CHECK(cudaMemcpyAsync(L.h_args + i * words, store->data + (size_t)slots[i] * words,
                              words * sizeof(u64), cudaMemcpyDeviceToHost, L.stream));
    }
    CHECK(cudaStreamSynchronize(L.stream));
    *view = L.h_args;
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_commit(int field, int handle, size_t count, const uint32_t *slots,
                                    uint64_t *polys, uint64_t *out) {
    const uint64_t *view = nullptr;
    TRY(ragu_gpu_poly_commit_view(field, handle, count, slots, polys ? &view : nullptr, out));
    // The store has one caller, so the view is as the call left it.
    if (polys) memcpy(polys, view, count * g.lanes[field].store.n * 4 * sizeof(u64));
    return RAGU_GPU_OK;
}

extern "C" int ragu_gpu_poly_commit_view(int field, int handle, size_t count,
                                         const uint32_t *slots, const uint64_t **polys,
                                         uint64_t *out) {
    if (count == 0) return RAGU_GPU_ERROR;
    BaseSet set;
    TRY(base_set(handle, set));
    ENTER_LANE(field);
    Store *store = nullptr;
    TRY(checked_store(field, &store));
    // The store's field is the scalar field of the set's curve.
    if ((set.curve == RAGU_GPU_PALLAS) != (field == RAGU_GPU_FQ)) return RAGU_GPU_ERROR;
    const size_t n = store->n;
    if (!slots_ok(*store, slots, count) || n % BLOCK != 0 || n > set.n) return RAGU_GPU_ERROR;

    // The MSMs run on the store's own stream, behind whatever was queued to
    // fill the slots, over copies of the slots made on the device.
    const size_t groups = count * (n / BLOCK);
    u32 parts = 1;
    while (parts < NUM_WINDOWS && groups * parts * 2 <= SPLIT_BLOCKS) parts *= 2;
    const size_t blocks = groups * parts, terms = count * n, words = n * 4;
    if (blocks > 0xffffffffu / BLOCK) return RAGU_GPU_ERROR;
    TRY(ensure_msm_buffers(L, terms, blocks, count));
    if (polys) TRY(ensure_args(L, count * words));
    for (size_t i = 0; i < count; i++) {
        L.h_offsets[i] = (u32)(i * (n / BLOCK) * parts);
        CHECK(cudaMemcpyAsync(L.d_scalars + i * words, store->data + (size_t)slots[i] * words,
                              words * sizeof(u64), cudaMemcpyDeviceToDevice, L.stream));
    }
    L.h_offsets[count] = (u32)(groups * parts);
    // A polynomial's coefficient of degree k is the scalar of base k. The
    // indices that say so are sent once and stay on the device: nothing
    // else writes this lane's.
    if (L.identity_n != n || L.identity_terms < terms) {
        for (size_t t = 0; t < terms; t++) L.h_indices[t] = (u32)(t % n);
        CHECK(cudaMemcpyAsync(L.d_indices, L.h_indices, terms * sizeof(u32),
                              cudaMemcpyHostToDevice, L.stream));
        L.identity_n = n;
        L.identity_terms = terms;
    }
    CHECK(cudaMemcpyAsync(L.d_offsets, L.h_offsets, (count + 1) * sizeof(u32),
                          cudaMemcpyHostToDevice, L.stream));
    if (set.curve == RAGU_GPU_PALLAS) {
        TRY((launch_msm<Fp, Fq>(L, set, (u32)blocks, (u32)count, parts)));
    } else {
        TRY((launch_msm<Fq, Fp>(L, set, (u32)blocks, (u32)count, parts)));
    }
    CHECK(cudaMemcpyAsync(L.h_out, L.d_out, count * 12 * sizeof(u64), cudaMemcpyDeviceToHost,
                          L.stream));
    if (polys) {
        for (size_t i = 0; i < count; i++) {
            CHECK(cudaMemcpyAsync(L.h_args + i * words, store->data + (size_t)slots[i] * words,
                                  words * sizeof(u64), cudaMemcpyDeviceToHost, L.stream));
        }
    }
    CHECK(cudaStreamSynchronize(L.stream));
    memcpy(out, L.h_out, count * 12 * sizeof(u64));
    if (polys) *polys = L.h_args;
    return RAGU_GPU_OK;
}

// ---------------------------------------------------------------------------
// Wiring matrices, host side

extern "C" int ragu_gpu_wiring_register(int field, size_t n, size_t circuits,
                                        const uint32_t *column_chunks, size_t chunks,
                                        const uint32_t *chunk_terms,
                                        const uint32_t *chunk_values, size_t terms,
                                        const uint32_t *rows, const uint64_t *values,
                                        size_t distinct) {
    std::lock_guard<std::mutex> lock(g.mutex);
    TRY(ensure_ready_locked());
    if ((field != RAGU_GPU_FP && field != RAGU_GPU_FQ) || circuits == 0 || n < BLOCK ||
        n % BLOCK != 0 || chunks == 0 || terms == 0 || terms > 0xffffffffu || distinct == 0)
        return RAGU_GPU_ERROR;
    if (column_chunks[circuits * n] != chunks || chunk_terms[chunks] != terms)
        return RAGU_GPU_ERROR;
    for (size_t t = 0; t < terms; t++) {
        if (rows[t] >= n) return RAGU_GPU_ERROR;
    }
    for (size_t c = 0; c < chunks; c++) {
        if (chunk_values[c] >= distinct) return RAGU_GPU_ERROR;
    }
    size_t bytes = (circuits * n + 1 + 2 * chunks + 1 + terms) * sizeof(u32) +
                   (distinct + chunks) * 4 * sizeof(u64);
    size_t free_bytes = 0, total_bytes = 0;
    CHECK(cudaMemGetInfo(&free_bytes, &total_bytes));
    if (bytes + (size_t(1) << 30) > free_bytes) return RAGU_GPU_ERROR;

    Wiring w = {};
    w.field = field;
    w.n = n;
    w.circuits = circuits;
    w.chunks = chunks;
    w.terms = terms;
    CHECK(cudaMalloc((void **)&w.column_chunks, (circuits * n + 1) * sizeof(u32)));
    CHECK(cudaMalloc((void **)&w.chunk_terms, (chunks + 1) * sizeof(u32)));
    CHECK(cudaMalloc((void **)&w.chunk_values, chunks * sizeof(u32)));
    CHECK(cudaMalloc((void **)&w.rows, terms * sizeof(u32)));
    CHECK(cudaMalloc((void **)&w.values, distinct * 4 * sizeof(u64)));
    CHECK(cudaMalloc((void **)&w.partials, chunks * 4 * sizeof(u64)));
    CHECK(cudaMemcpy(w.column_chunks, column_chunks, (circuits * n + 1) * sizeof(u32),
                     cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(w.chunk_terms, chunk_terms, (chunks + 1) * sizeof(u32),
                     cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(w.chunk_values, chunk_values, chunks * sizeof(u32),
                     cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(w.rows, rows, terms * sizeof(u32), cudaMemcpyHostToDevice));
    CHECK(cudaMemcpy(w.values, values, distinct * 4 * sizeof(u64), cudaMemcpyHostToDevice));
    g.wirings.push_back(w);
    return (int)g.wirings.size() - 1;
}

extern "C" int ragu_gpu_wiring_sy(int handle, uint32_t powers, uint32_t dst) {
    TRY(ensure_ready());
    Wiring w;
    {
        std::lock_guard<std::mutex> registered(g.mutex);
        if (handle < 0 || (size_t)handle >= g.wirings.size()) return RAGU_GPU_ERROR;
        w = g.wirings[handle];
    }
    ENTER_LANE(w.field);
    Store *store = nullptr;
    TRY(checked_store(w.field, &store));
    if (store->n != w.n || powers >= store->slots || dst > store->slots ||
        w.circuits > store->slots - dst || (powers >= dst && powers < dst + w.circuits))
        return RAGU_GPU_ERROR;
    // Nothing is staged for this request and nothing of it is read back, so
    // it is left queued: the next call that reads the store observes it.
    u32 n = (u32)w.n;
    const u64 *d_powers = store->data + (size_t)powers * n * 4;
    u32 chunk_grid = (u32)((w.chunks + BLOCK - 1) / BLOCK);
    u32 column_grid = (u32)(w.circuits * (n / BLOCK));
    if (w.field == RAGU_GPU_FP) {
        k_wiring_partials<Fp><<<chunk_grid, BLOCK, 0, L.stream>>>(
            w.chunk_terms, w.chunk_values, w.rows, w.values, d_powers, w.partials,
            (u32)w.chunks);
        CHECK(cudaGetLastError());
        k_wiring_columns<Fp><<<column_grid, BLOCK, 0, L.stream>>>(
            w.column_chunks, w.partials, store->data, dst, n);
    } else {
        k_wiring_partials<Fq><<<chunk_grid, BLOCK, 0, L.stream>>>(
            w.chunk_terms, w.chunk_values, w.rows, w.values, d_powers, w.partials,
            (u32)w.chunks);
        CHECK(cudaGetLastError());
        k_wiring_columns<Fq><<<column_grid, BLOCK, 0, L.stream>>>(
            w.column_chunks, w.partials, store->data, dst, n);
    }
    CHECK(cudaGetLastError());
    return RAGU_GPU_OK;
}

