# Optimization notes: three passes over merkletree

This document records the performance work that took `merkletree` from "competitive"
to first place on nine of the fourteen axes in [`benchmarks/ANALYSIS.md`](benchmarks/ANALYSIS.md),
in enough detail to reconstruct the reasoning behind each change. It is organized the
way the work actually happened: three passes, each starting from a measurement, each
verified before the next began.

Ground rules that held throughout:

- **No public API changes**, with one deliberate exception — the `Append` proof methods,
  an addition shipped as 0.5.0. Nothing was renamed, no signature changed, no behavior
  documented to callers moved.
- **No root changes.** Every construction produces byte-for-byte the tree it produced
  before, asserted by golden tests, the RFC 6962 oracle, and cross-library root
  agreement.
- **Measure, change, verify, measure again.** Every change below carries a number, and
  the full battery — unit tests, `-race`, four fuzz targets, the Certificate
  Transparency vectors in [`oracle/`](oracle/), and the cross-implementation checks in
  [`benchmarks/`](benchmarks/) — ran green after each pass.

Numbers are from an Apple M5 Max, Go 1.26, SHA-256, benchstat medians unless marked
otherwise. Ratios are the durable part; absolute values are machine-specific.

## The starting diagnosis

The comparison in `benchmarks/ANALYSIS.md` had already established that construction is
hashing-bound (all six libraries within ~8% serially) and that the library's two real
weaknesses were **allocation-shaped**: per-proof allocation capped concurrent serving at
~2× scaling, and verification allocated per level. A CPU profile of construction
confirmed it from the other direction: ~37% of samples in `runtime.madvise` (the
allocator returning pages), ~6% in SHA-256, and ~5% in tree code. The allocation profile
was blunter still — 98.5% of allocated *objects* during a build were the caller's own
`CalculateHash` digests. The library's job was to get out of the allocator's way.

---

## Pass 1: allocation on the hot paths

### 1. The leaf index is built over one backing string

`WithLeafIndex` builds a `map[string]int` from leaf hash to position. The old loop
inserted with `idx[string(l.Hash)] = i`, and Go's map insert copies the string key —
one heap allocation per leaf, which made the index the single largest allocation source
in an indexed build.

The fix (`buildLeafIndex`, merkle_tree.go): write every leaf hash into one
`strings.Builder`, take the resulting string once, and key the map with **substrings of
that one backing**. Substrings share the parent string's memory, so n keys cost one
allocation instead of n. Every key is retained by the map anyway, so the backing pins
nothing that was not already pinned — the same bytes stay alive in one object instead
of n.

Effect at 65,536 leaves: an indexed build fell from **131,401 to 65,866 allocations
(−50%)** and ~3% in time. A side effect worth keeping: the keys are now contiguous in
memory, and large-tree leaf-index lookups got measurably faster (−4.5% at n=64,000)
from cache locality alone.

### 2. `VerifyContent` walks with one hasher and one buffer

`VerifyContent` climbs from a leaf to the root, recomputing three digests per level
(each child from what sits beneath it, then the parent from the pair). The old code
called `calculateNodeHash` per node, and each call created a fresh hasher and a fresh
digest slice — roughly six allocations per level, so the cost of verifying grew with
depth and was dominated by allocation, not hashing.

The fix mirrors what `verifyNode` (the `VerifyTree` walk) already did: a new internal
`Node.appendCalculatedHash(h, dst)` appends a node's recomputed hash into a caller-owned
buffer using a caller-owned hasher, and `VerifyContent` threads one hasher and one
scratch buffer through the whole climb. The buffer never holds more than one level
(three digests), and the ordering subtlety is inherited from `verifyNode`: children's
digests are written into the hasher *before* `Sum` appends, so buffer growth cannot
invalidate the slices being read.

Effect: allocations went from growing with depth (70 at n=4,096) to a **flat 4**; bytes
−94%; serial time −8% to −28% by size; and the parallel variant — where the allocator
was the shared bottleneck — went **1,176 ns → 327 ns (−72%)**. In the cross-library
tables, the `VerifyContent` gap over plain proof replay narrowed from ~3.7× to ~2.5×,
which is now close to the true algorithmic difference between the two operations.

### 3. Proof slices are exact-fit

`pathFromLeaf` sized the proof's two slices with `bits.Len(uint(len(m.Leafs)))`, which
over-allocates by one entry exactly when the leaf count is a power of two — the common
case. `bits.Len(uint(len(m.Leafs) - 1))` is the tree's depth exactly, for power-of-two,
padded, and RFC-split counts alike. One spare `[][]byte` entry is 24 bytes; at
proof-serving rates on the hottest allocation site in the package, it was measurable.

### 4. Option-less verification stopped allocating its configuration

Package-level `VerifyProof`/`VerifyProofWithDigest` built a fresh config object
(`configFromOptions`) on every call, even with no options. A shared, immutable
`defaultProofConfig` now serves the no-options case; the with-options path is
unchanged. The fast path could not live inside `configFromOptions` itself, because
`NewTreeWithOptions` uses the same function and mutates the result — the constructor
must keep getting a fresh value.

### 5. Smaller cuts in the same spirit

- Parallel `buildIntermediate` created a fresh set of worker hashers **per level**; one
  set is now created lazily and reused across every level large enough to parallelize.
- `treeData.marshalBinary` computed nothing about its output size and let
  `bytes.Buffer` double its way up, re-copying the payload log n times and finishing up
  to 2× oversized. The wire size is exactly computable (a `uvarintLen` helper), so the
  buffer is grown once. With `snapshot` also preallocating its record slice,
  `MarshalBinary` dropped **−26% to −37% in time and −44% to −58% in bytes**.
- `RebuildTree` preallocates its content slice; `MerkleTree.String()` uses a
  `strings.Builder` instead of quadratic string concatenation.

---

## Pass 2: the decoder, the registries, and a pool with a safety argument

Pass 1 left construction at its floor (the remaining bytes are the exported `Node`
graph; the remaining objects are the caller's digests), so pass 2 started from a fresh
profile — which pointed at serialization: per-record registry locks, reflection
lookups, and two copies per record on decode.

### 6. The binary decoder became a cursor, and payloads share an arena

The old decoder wrapped the input in a `bytes.Reader` and copied every field out of it.
Two structural facts made most of that work unnecessary:

- **Fields that are only inspected need not be copied.** The decoder is now a cursor
  (`binaryReader{data, off}`) over the input slice: type names are viewed in place and
  interned (one string per distinct name, not per record), and the recorded Merkle root
  is viewed in place because it is compared once and dropped. Every read is a bounds
  check and a reslice with no interface calls.
- **Payloads must be copies, but not separate ones.** `UnmarshalBinary` implementations
  are permitted to retain the slice they are handed, so payloads must not alias the
  caller's input — but the old one-`make`-per-record approach was n allocations for a
  guarantee one allocation can provide. All payload copies are now carved from a single
  arena sized to the remaining input. Each carve is **capacity-capped** at its own
  length, so an implementation that appends to its payload cannot reach the record
  stored after it, and since all content lives and dies with the decoded tree, the
  shared backing changes no lifetime.

The wire format's guarantees — canonical varints, length-validation before allocation,
trailing-byte rejection — are unchanged, and the fuzz corpus that hammers exactly this
parser passed untouched.

### 7. Type resolution is cached across a marshal or unmarshal

Encode took the content registry's `RWMutex` and did a reflect-map lookup **per leaf**;
decode did the same per record, plus the name lookup. A tree overwhelmingly holds one
concrete content type, so both loops now carry a one-entry `contentTypeCache` — the
lock and lookup are paid once, and because the decoder interns names, the cache check
on decode is usually a pointer-equal string compare.

Combined, passes over the codec: `UnmarshalBinary` **−13% to −18% time and −33%
allocations** (24.6k → 16.4k at n=4,096); `MarshalBinary` another −14% to −19% on top
of pass 1, for a cumulative **247 µs → 133 µs (−46%)** at n=4,096. What remains on both
paths is almost entirely the caller's own marshaling and the rebuild's hashing.

### 8. A hasher pool, but only where immutability makes it safe

The obvious move — pool hashers per tree — was rejected twice, for a reason worth
recording: `hashStrategy` is a mutable field inside the package, and the property tests
pin the semantic that swapping it after construction takes effect immediately on the
verification paths. A pool filled before a swap would keep hashing with the old
strategy. Where that hazard cannot exist is `defaultProofConfig`: private, immutable,
its strategy fixed at `sha256.New` forever. It alone carries a `sync.Pool`, so the
option-less `VerifyProof` path recycles its hasher across calls and goroutines, while
per-tree paths keep creating theirs. (`largestPowerOfTwoBelow` also collapsed from a
loop to `1 << (bits.Len(uint(n-1)) - 1)` in this pass.)

---

## Pass 3: the structural changes

Pass 3 took on the three items that survived two passes of shaving: an algorithmic gap,
the last non-caller allocation in verification, and the API-shaped ceiling the analysis
document had predicted from the start.

### 9. The RFC 6962 interior build forks

`WithParallelism` parallelized leaf hashing in every mode, and interior hashing in the
default mode — but `buildRFC6962` was a serial recursion, so RFC trees (the mode the
documentation steers security-conscious users toward) left roughly half their hash work
single-threaded.

The enabler is a counting argument: an RFC subtree over k leaves owns **exactly k−1
interior nodes**, whatever shape its splits take. That means every subtree's slab
entries and digest-buffer slots can be assigned by position before anything is built —
the subtree over `nl` owns region `[base, base+len(nl)-1)`, its left child the first
k−1 entries, its right child the next len−k−1, the joining node the last one. Sibling
regions are disjoint by construction, so `buildParallel` forks the recursion across
goroutines with **no locks, no channels, and no coordination at all**; the hasher
budget is created up front on the calling goroutine (preserving the guarantee that a
caller-supplied strategy is never invoked concurrently) and split between subtrees in
proportion to their size. Panics out of caller-supplied hashers are carried back and
re-raised on the calling goroutine, and errors are delivered left-subtree-first so the
same input always fails the same way — both matching the serial build's behavior.

Effect at 65,536 short leaves: the parallel RFC build fell from **5.6 ms (leaf hashing
only) to 2.1 ms**, and stands at ~5× the 10.0 ms serial build. The same
`parallelInteriorMinNodes` threshold as the default mode keeps small trees from paying
for goroutines they cannot use.

### 10. Verification's scratch state pooled as a pair

After pass 2, an option-less `VerifyProof` still allocated its replay buffer, because
the internal helper *returned* the computed root and a returned slice cannot go back to
a pool. The helper became `proofReproducesRoot(digest, path, index, root) (bool, error)`
— the comparison moved inside — and the buffer now travels with the pooled hasher as
one `proofScratch` pair on `defaultProofConfig`. One pool `Get` per verification, zero
library-side allocations. Configs built from explicit options keep the old
two-allocation path; a pool that lives for one call is worse than no pool.

Effect: standalone verification is **2 allocations and 56 B/op flat at every size —
both belonging to the caller's `CalculateHash`** — against 32 allocations for the
nearest competitor at depth 16. Concurrent verification went 119 → 82 ns/op across the
two passes.

### 11. The append proof API

The analysis document had said it from the beginning: each proof returns two freshly
allocated slices, ~500 B/op, and at millions of proofs per second the garbage collector
becomes the shared resource every goroutine queues on — "an API that appended into a
caller-supplied buffer would lift this; the current one cannot." Every internal remedy
was exhausted, so the API grew its one addition:

```go
path, index, err = tree.AppendMerklePath(path[:0], index[:0], content)
path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], i)
```

Styled after `strconv.AppendInt`: same proofs, byte for byte, delivered into slices the
caller owns; errors return the slices unchanged. The documented contract is explicit
that appended hashes alias the tree's own storage (as the `Get` forms' results always
did) and that a proof which must outlive its buffer's next reuse must be copied.

Why the effect is as large as it is: in this library, **generating a proof never
computes a hash** — the tree stores every node's digest, so a proof is ~16 pointers to
existing hashes plus 16 side markers, and the walk itself costs ~1 ns per level. The
two slice allocations were most of the remaining per-proof cost, and under concurrency
they were effectively all of it. With them gone, a proof touches no shared state of any
kind:

| | single proof (65,536) | all proofs (4,096) | 18 goroutines (16,384) | scaling |
|---|---|---|---|---|
| slice-returning by-index | 76 ns, 2 allocs | 116 ns/proof | 82 ns/op | 2.05× |
| **append, reused buffers** | **17 ns, 0 allocs** | **25 ns/proof, 0 allocs** | **2.9 ns/op** | **16.4×** |

One accounting honesty note for the writeup: 2.9 ns/op under `RunParallel` is
throughput (wall time over total proofs across 18 goroutines); per-proof CPU is still
~50 ns, consistent with the single-goroutine figure. The claim is near-perfect scaling,
not a magically cheaper proof — and it made merkletree the best *scaler* in the
comparison as well as the fastest, where it had previously ranked 4th of 6 on that
axis.

---

## Changes deliberately not made

These are as much a part of the record as the changes above.

- **Per-tree hasher pools.** Rejected twice; see §8. The internal strategy-swap
  semantic is tested, and stale pooled hashers would silently violate it.
- **Packing a proof's two slices into one allocation.** `([][]byte, []int64)` cannot
  share a backing without `unsafe`. The append API solves the same problem inside the
  rules.
- **Merging per-level slabs in `buildIntermediate`.** The allocation profile showed
  ~40 objects per build at stake — complexity without a payoff.
- **In-place level arrays.** The classic write-index-below-read-index trick races
  against the parallel build's chunk boundaries.
- **Zero-copy decode payloads.** Handing `UnmarshalBinary` implementations subslices
  of the caller's input would violate the documented retention contract; the arena
  keeps the copy but not the per-record allocation.
- **Shrinking `Node` or the `[]int64` side markers.** Both are fixed by the exported
  API. The 640 B vs 516 B wire-size gap against txaty remains the one
  library-attributable weakness in the comparison, and closing it is an API break.

## How correctness was held

The regression surface for this kind of work is silent wrongness, so the apparatus
grew alongside the optimizations:

- **Every pass:** full test suite, `go vet`, `-race` (which drives the parallel
  builds — including the RFC fork-join — across all modes, sizes 1–4097, and worker
  counts up to 4096), all four fuzz targets (which hammer the rewritten wire decoder,
  including canonical-varint and hostile-length rules), the CT reference vectors in
  `oracle/`, and cross-library root agreement in `benchmarks/`.
- **The append API** carries its own suite (`merkle_tree_append_test.go`):
  byte-equivalence with the `Get` forms across every construction and size class,
  prefix preservation, error contracts, end-to-end verification, and the zero-alloc
  property pinned with `testing.AllocsPerRun` so it cannot regress silently.
- **The benchmarked paths are proven, not presumed**
  (`benchmarks/proofcheck_test.go`): the exact serving loops the benchmarks time are
  replayed for every leaf, required to agree across all four forms byte for byte, and
  required to verify against a Merkle root computed by a *different library*
  (wealdtech), including a concurrent variant under `-race`. The timed `append`
  benchmarks additionally verify their final proof after the clock stops, so none of
  them can quietly measure a no-op.

## Results

Library-side costs, before the first pass and after the third (n=4,096 unless noted):

| operation | before | after |
|---|---|---|
| Indexed build, allocations (n=65,536) | 131,401 | 65,866 |
| `VerifyContent` | 10.3 µs, 70 allocs | 9.5 µs, 4 allocs |
| `VerifyContent`, parallel | 1,176 ns | 327 ns |
| `VerifyProof` (n=65,536) | 949 ns, 5 allocs | 934 ns, 2 allocs (both the caller's) |
| `VerifyProof`, 18 goroutines | 119 ns, 248 B | 82 ns, 56 B |
| `MarshalBinary` | 247 µs, 1.06 MB | 133 µs, 0.45 MB |
| `UnmarshalBinary` | 858 µs, 24.6k allocs | 720 µs, 16.4k allocs |
| RFC 6962 parallel build (n=65,536) | 5.6 ms | 2.1 ms |
| Single proof (n=65,536) | 82 ns, 2 allocs | 17 ns, 0 allocs (append) |
| Full proof set, per proof | 113 ns | 25 ns, 0 allocs (append) |
| Concurrent proofs, 18 goroutines | 89.6 ns/op, ~2× scaling | 2.9 ns/op, 16.4× scaling |

Against the field, the refreshed scorecard in `benchmarks/ANALYSIS.md` has merkletree
first on 9 of 14 axes — every proof-generation and verification axis, concurrent
throughput *and* concurrent scaling, parallel construction, dependencies,
specification validation, and serialization — with the remaining gaps (serial
construction within 1%, memory, wire size) each explained there by a deliberate design
choice rather than an implementation deficit.

The arc of the three passes, compressed: the first removed allocations the code did
not need to make; the second removed work the decoder and registries repeated per
record when once sufficed, and pooled the one place immutability made pooling safe;
the third changed structure — a fork-join the RFC construction's own arithmetic makes
coordination-free, and an API form that moves the last two allocations to the caller,
where they happen once instead of per proof. Nothing got a faster hash function and
nothing skipped work: the proofs are byte-identical throughout and hash to roots other
libraries compute.
