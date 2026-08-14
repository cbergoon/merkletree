# Merkle tree libraries in Go: a comparison

This directory benchmarks `cbergoon/merkletree` against the other Merkle tree libraries
in the Go ecosystem, and documents what they actually do differently. It is a separate
module, so nothing here is a dependency of `merkletree` itself.

```
cd benchmarks
go test -bench=. -benchmem ./...     # everything
go test -bench=BenchmarkAllProofs ./...
go test ./...                        # the cross-implementation correctness checks
```

Numbers below are from an Apple M5 Max, Go 1.26, SHA-256 throughout. Treat the ratios as
the durable part and the absolute values as machine-specific.

## Scorecard

Where `merkletree` lands on each axis, against the best of the other five. Sizes are the
largest benchmarked on that axis; the sections below carry the full tables.

This table is mirrored in the repository README, without the note column. Keep the two in
step when any of it is re-measured.

`txaty/go-merkletree` is broken out because it is the closest competitor: the only other
library here with parallel construction, and the one whose published comparisons prompted
this exercise. Where it is also the best of the field, the two columns agree.

| axis | rank | merkletree | txaty | best other | note |
|---|---|---|---|---|---|
| Construction, serial (65,536) | 2 / 6 | 7.67 ms | 9.67 ms | onrik 7.61 ms | within 1%; five of six cluster |
| Construction, parallel (65,536) | **1 / 2** | 3.08 ms | 6.47 ms | txaty 6.47 ms | 2.1× ahead; only two offer it |
| Parallel speedup, 16 KiB leaves | **1 / 2** | 12.8× | 11.9× | txaty 11.9× | grows with the cost of content |
| Construction, allocations (65,536) | 2 / 6 | 131,140 | 328,230 | onrik 131,090 | effectively tied; 2.5× fewer than txaty |
| Construction, bytes (65,536) | 4 / 6 | 18.4 MB | 24.8 MB | wealdtech 11.5 MB | cost of the navigable node graph |
| Single proof (65,536) | **1 / 6** | 16.7 ns | 128 ns | txaty 128 ns | appending; by index 2nd at 76 ns |
| All proofs (4,096) | **1 / 6** | 25.4 ns/proof | 158 ns/proof | txaty 158 | appending, 0 allocs; by index 2nd at 116 |
| Standalone verify (65,536) | **1 / 4** | 934 ns | 1,212 ns | onrik 1,108 ns | from n=256 up; 2 allocs against 32 |
| Concurrent throughput (18 goroutines) | **1 / 6** | 2.9 ns/op | 165 ns/op | jvsteiner 153 ns/op | appending, 0 allocs; by index 82 ns |
| Concurrent scaling | **1 / 6** | 16.4× | 1.14× | wealdtech 13.1× | appending shares nothing, so it scales |
| Proof size on the wire, depth 16 | 2 / 2 | 640 B | 516 B | txaty 516 B | `[]int64` side markers |
| Allocation-free proofs | **1 / 6** | yes | no | none | the `Append` forms; nobody else exposes the buffers |
| Runtime dependencies | **1 / 6** | none | x/sync | onrik none | wealdtech x/crypto, jvsteiner protobuf |
| Specification validated | **1 / 6** | CT vectors | none | none | see the `oracle/` module |
| Serialization | **1 / 6** | binary + JSON | none | none | no other library offers it |

The table hides a few things the sections below spell out. Rankings on the proof axes
depend on how the leaf is addressed: the leading rows are `AppendMerklePathByIndex`
reusing the caller's buffers, `GetMerklePathByIndex` and `WithLeafIndex` follow it, and
without any of the three `merkletree` locates content by scanning and is joint last with
`wealdtech`. Serial construction is a near-tie because every implementation is waiting on
SHA-256, and the tie becomes exact as content grows: at 16 KiB leaves all six land within
3%. And since the odd node policy means these libraries do not all produce the same root,
a faster one is not a drop-in replacement for a slower one.

## The libraries

| | input | leaf lookup | odd node | hash | proof API | standalone verify |
|---|---|---|---|---|---|---|
| **cbergoon/merkletree** | `Content` iface | `Equals` scan, or hash index | duplicate, or RFC 6962 split | any `hash.Hash` | by content, by index, appending | ✓ |
| **txaty/go-merkletree** | `DataBlock` iface | internal map | duplicate | any `func([]byte)` | by block | ✓ |
| **wealdtech/go-merkletree** | `[][]byte` | scan | pad to power of two | any `Hash([]byte)` | by data | ✓ |
| **onrik/gomerkle** | `[][]byte` | index only | promote | `hash.Hash` | by index | ✗ (method) |
| **xsleonard/go-merkle** | `[][]byte` | — | promote, or duplicate | `hash.Hash` | none | — |
| **jvsteiner/merkle** | `[][]byte` | index only | promote | SHA-256 only | by index | ✓ |

Three design axes matter more than the rest.

How you address a leaf. `merkletree` is the only library built around a content interface
with an equality method, which is why locating content historically meant a scan.
Everything else either takes an index or keeps an internal map. This is the single biggest
performance difference in the whole comparison, and it is an API choice rather than an
implementation one. The `Content` interface is also what lets `merkletree` hold arbitrary
typed values and serialize them, which none of the others do.

What happens to a lone node. Covered below; it changes the root.

Whether a proof can be checked without the tree. `txaty`, `wealdtech`, `jvsteiner` and
`merkletree` all expose a package-level verify taking a proof, a root and the data, which
is the canonical Merkle use case: a light client holding a root and a proof and nothing
else. `onrik` exposes it only as a method, so a verifier there has to construct a `Tree`
value it does not otherwise need. `xsleonard` cannot generate proofs at all.

## They do not all compute the same root

This is the first thing to know before reading any benchmark, and it is asserted by
`crosscheck_test.go` rather than claimed here.

With a power-of-two leaf count, all six agree exactly. Same hash, same pairwise
combination, same root. That agreement is what establishes the benchmarks are configured
equivalently rather than accidentally comparing different work.

With any other leaf count, they split into three groups. At n=5:

| root prefix | libraries | policy |
|---|---|---|
| `3ad4abec…` | **cbergoon**, txaty, xsleonard (`DoubleOddNodes`) | duplicate the trailing node |
| `860a3896…` | onrik, xsleonard (default), jvsteiner | promote the lone node unchanged |
| `bb073fbc…` | wealdtech | pad the leaf count out to a power of two |

A proof from one group will not verify against a root from another. If roots are
published, stored, or compared across systems, the library is part of the format.

Group two carries a documentation trap. `xsleonard/go-merkle` describes its default as
using "a null hash as the missing pair", which would put it in a group of its own, but
the code copies the lone node's hash upward unchanged (`merkle.go`, `generateNode`) and
it lands with `onrik` and `jvsteiner`. Anyone predicting that library's roots from its
comments will predict them wrong; the grouping above is measured, not read.

Two consequences worth stating plainly:

- `merkletree`'s default construction agrees with two independent implementations, which
  is the only external validation available for it, since the Bitcoin-style construction
  has no specification to check against. The RFC 6962 mode does, and is validated against
  the Certificate Transparency reference vectors in the sibling `oracle/` module.
- Duplicating the trailing node is [CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459):
  `[A B C]` and `[A B C C]` produce the same root. That affects the first group, this
  library included, and is what `WithRFC6962` exists to avoid. The third group
  (`wealdtech`) has a related collision from zero-padding.

`merkletree`'s sorted-sibling mode is also checked against `txaty`'s OpenZeppelin
compatible mode and matches at every size tested.

## Construction

Time per tree, ns/op:

| n | cbergoon | cbergoon ∥ | txaty | txaty ∥ | wealdtech | onrik | xsleonard | jvsteiner |
|---|---|---|---|---|---|---|---|---|
| 16 | 2,226 | 14,461 | 4,843 | 14,892 | **1,972** | 2,045 | 2,081 | 3,809 |
| 256 | 33,378 | 48,899 | 55,398 | 67,827 | **31,336** | 31,409 | 32,993 | 61,605 |
| 4,096 | 517,370 | 388,280 | 711,940 | 570,660 | 518,400 | 503,990 | 542,970 | 1,086,800 |
| 65,536 | 7,674,500 | **3,075,300** | 9,673,900 | 6,470,500 | 7,993,700 | 7,609,300 | 8,237,500 | 16,424,000 |

Construction is hashing-bound, so the serial implementations land within about 8% of each
other at every size; they are all mostly waiting on SHA-256. The outlier is `jvsteiner`,
roughly 2× slower throughout, which its allocation count explains: 524,570 allocations at
n=65,536 against `merkletree`'s 131,140.

Parallelism is where the spread opens. At 65,536 leaves `merkletree` is 2.5× faster in
parallel and is the fastest tree in the table; `txaty` gains 1.5×. Below a few thousand
leaves of cheap content, parallel construction is *slower* for both, 6.5× slower for
`merkletree` at n=16, which is why it is off by default in both libraries. The option
covers every construction `merkletree` offers: the RFC 6962 mode forks its unbalanced
interior across goroutines the same way, so an RFC build of 65,536 short leaves drops
from 10.4 ms serial to 2.1 ms.

Memory at n=65,536 splits the field along a different line than speed does:

| | bytes | allocations |
|---|---|---|
| wealdtech | **11.5 MB** | 196,610 |
| xsleonard | 13.6 MB | 196,610 |
| onrik | 13.6 MB | **131,090** |
| **cbergoon** | 18.4 MB | 131,140 |
| txaty | 24.8 MB | 328,230 |
| jvsteiner | 34.7 MB | 524,570 |

`merkletree` allocates the fewest objects in the comparison, tied with `onrik` and 2.5×
fewer than `txaty`, because construction hands out nodes from per-level slabs and appends
each level's digests into one buffer rather than allocating per node. It is mid-pack on
total bytes: a `Node` carries `Parent`, `Left`, `Right` and `Tree` pointers alongside its
hash, where the flat-array implementations keep bare levels of digests. That is what pays
for tree walking, rebuilding and serialization, and on a build-and-take-the-root workload
it is pure overhead, but it is 1.4× `wealdtech`, not the blowout the pointer graph might
suggest.

## A single proof, worst-case leaf

ns/op. This is the axis where library choice actually decides the complexity class:

| n | cbergoon scan | cbergoon index | cbergoon by-index | cbergoon append | txaty | wealdtech | onrik | jvsteiner |
|---|---|---|---|---|---|---|---|---|
| 16 | 71.9 | 99.4 | 33.7 | **5.6** | 102 | 64.1 | 353 | 142 |
| 256 | 516 | 120 | 54.4 | **8.4** | 115 | 442 | 711 | 216 |
| 4,096 | 7,802 | 146 | 84.9 | **13.4** | 139 | 5,823 | 1,160 | 299 |
| 65,536 | 129,730 | 135 | 76.3 | **16.7** | 128 | 91,293 | 1,131 | 341 |

Two libraries scan: `merkletree` without `WithLeafIndex`, and `wealdtech`. Both are O(n)
per proof and both cost ~100µs per proof at 65,536 leaves, roughly a thousand times the
cost of the tree walk they are wrapping. `wealdtech` has no opt-out; `merkletree` does.

With `WithLeafIndex` the scan disappears and `merkletree` is flat at ~135ns, slightly
faster than `txaty`. `GetMerklePathByIndex` avoids the query hash as well, and
`AppendMerklePathByIndex` additionally reuses the caller's two proof slices, leaving
nothing but the walk itself: 6–17 ns and zero allocations, the fastest proof generation
in the comparison at every size by roughly 5× over its own by-index form.

## The whole proof set

ns per proof, generating every proof in the tree, which is the operation where an O(n)
lookup becomes O(n²):

| n | cbergoon scan | cbergoon index | cbergoon by-index | cbergoon append | txaty | txaty ProofGen | wealdtech | onrik | jvsteiner |
|---|---|---|---|---|---|---|---|---|---|
| 16 | 52.7 | 96.4 | 35.2 | **6.4** | 102 | 186 | 53.4 | 359 | 153 |
| 256 | 287 | 128 | 58.4 | **11.2** | 123 | 211 | 261 | 719 | 244 |
| 4,096 | 3,762 | 166 | 116 | **25.4** | 158 | 241 | 2,972 | 1,171 | 322 |

At 4,096 leaves the full set costs 15.4 ms by scan, 0.47 ms by index and 0.10 ms
appending into two reused buffers, a 148× spread that is entirely lookup and
allocation, not hashing. Extrapolating the scan to 100,000 leaves gives roughly 10
seconds for a full proof set, which is the gap the `txaty` project's published
comparisons were measuring. The append column allocates nothing at all: every proof
lands in the same two slices the caller keeps handing back.

`txaty`'s `ModeProofGen`, which precomputes every proof during construction, is *slower*
per proof than its own on-demand `Proof()` at every size here (241 vs 158 ns/proof at
n=4,096). Precomputation is not obviously worth it in that implementation.

## Verification

ns/op, checking one proof. The first column is the like-for-like comparison, a proof
replayed against a root with no tree involved, which is what the last three columns do:

| n | **cbergoon `VerifyProof`** | txaty | wealdtech | onrik | cbergoon `VerifyContent` |
|---|---|---|---|---|---|
| 16 | 296 | 367 | 349 | **289** | 691 |
| 256 | **509** | 663 | 644 | 576 | 1,243 |
| 4,096 | **723** | 990 | 944 | 892 | 1,785 |
| 65,536 | **934** | 1,212 | 1,221 | 1,108 | 2,326 |

`VerifyProof` is the fastest standalone verification in the comparison from 256 leaves
up, and allocates a flat 2 objects and 56 bytes at every size where the others grow with
tree depth (32 objects for `onrik` at 65,536). The replay carries one hasher and one
buffer from the leaf to the root, sliding each level's digest down over the last, so its
working set is one digest wide however tall the tree, and the pair is recycled through
a pool across calls, so what remains on the profile is hashing the content and little
else.

The final column is a different operation and is included only to keep it from being
mistaken for this one. `VerifyContent` locates the content and then recomputes every hash
on the path out of the tree, hashing both children at each level: it finds *and* checks
against the tree's own stored hashes, which detects a tree whose interior hashes have
been edited. That is strictly more work than replaying a proof, and the ~2.5× gap is
where it goes.

## Concurrent proof serving

The four axes above all measure one goroutine, which says nothing about the shape a
Merkle tree is usually deployed in: built once, then shared by many goroutines answering
proof requests. Scaling does not follow from single-threaded speed, so it is measured
separately. 16,384 leaves, ns/op at 1, 4 and 18 goroutines, and the speedup across that
range:

| | 1 | 4 | 18 | speedup | limited by |
|---|---|---|---|---|---|
| **cbergoon append** | 48.2 | 11.8 | **2.9** | **16.4×** | nothing shared; 0 allocs |
| **cbergoon by-index** | 168.8 | 73.4 | 82.4 | 2.05× | allocation |
| **cbergoon leaf-index** | 231.7 | 86.5 | 86.5 | 2.68× | allocation |
| jvsteiner | 435.0 | 172.8 | 152.9 | 2.84× | allocation |
| txaty | 189.0 | 106.8 | 165.2 | **1.14×** | lock contention |
| wealdtech | 11,437 | 3,163 | 870.8 | 13.1× | the O(n) scan |
| onrik | 1,372 | 899.9 | 1,095 | 1.25× | allocation |

All the read paths are race-clean under `-race`.

The append form is the only one that actually scales, and it is not close. Each goroutine
hands `AppendMerklePathByIndex` its own two buffers, so a proof touches no shared state at
all: no lock, no allocator, no garbage collector. Eighteen goroutines run 16.4× the speed
of one, serving a proof every 2.9 ns. That is 28× the throughput of the next-best form in
this table and 50× the next-best library.

txaty does not scale, and gets worse past four goroutines. Its leaf lookup takes an
exclusive `sync.Mutex` (`proof.go`, `m.leafMapMu.Lock()`) around a map that is only read
once the tree is built. Four goroutines help; eighteen contend, and throughput falls back
toward the single-goroutine figure. A `sync.RWMutex`, or no lock at all given the map
is immutable after construction, would remove it. This is the one place in the comparison
where a library's single-threaded ranking actively misleads: `txaty` is quick on one
goroutine and close to flat on many.

wealdtech scales almost linearly, since an O(n) scan is pure CPU with no shared state and
parallelizes perfectly. It is still ~10× slower than `merkletree`'s slice-returning
forms in absolute terms at 18 goroutines, and 300× the append form, because scaling a
bad algorithm well is not the same as being fast.

The slice-returning forms are allocator-bound, which is what the append form removes.
Nothing on any `merkletree` read path takes a lock: the leaf index is written during
construction and only read afterwards, which is why `WithLeafIndex` is built eagerly
rather than lazily. What caps `GetMerklePathByIndex` and the leaf-index lookup is that
each proof returns two freshly allocated slices, about 500 B/op, which at these rates
makes the garbage collector the shared resource every goroutine queues on, and holds
their scaling near 2×. `AppendMerklePath` and `AppendMerklePathByIndex` exist to move
that allocation to the caller, where it happens once instead of per proof.

## How much of this survives expensive content

Every section above uses leaves of about seven bytes, which makes hashing a leaf nearly
free and the surrounding tree machinery nearly everything. That ratio is not a detail: it
decides whether these benchmarks are measuring tree code or SHA-256. Repeating
construction at 4,096 leaves across three leaf sizes shows how much of the ranking is
an artifact of tiny content (ns/op):

| | 32 B | 1 KiB | 16 KiB |
|---|---|---|---|
| onrik | **512,910** | 1,668,500 | 19,900,000 |
| wealdtech | 531,460 | 1,677,800 | 20,085,000 |
| **cbergoon** | 540,600 | **1,639,400** | **19,815,000** |
| xsleonard | 558,130 | 1,704,100 | 19,926,000 |
| txaty | 720,820 | 1,787,100 | 19,970,000 |
| jvsteiner | 1,105,700 | 2,128,300 | 20,361,000 |
| spread, fastest to slowest | 2.16× | 1.30× | **1.03×** |

At 16 KiB leaves the choice of library stops mattering for construction. All six land
within 3% of each other at about 3.4 GB/s, because all six are doing the same SHA-256
over the same bytes and nothing else is visible. The 2.16× spread at 32 bytes, including
`jvsteiner` looking twice as slow as everyone else, is a measurement of per-node
overhead, and per-node overhead is only worth arguing about when leaves are small.

Parallelism is the exception, and it grows the other way. It is the one thing that
changes the SHA-256 bill rather than the overhead around it, so the more content costs,
the more it buys:

| leaf size | serial | parallel | speedup |
|---|---|---|---|
| 32 B | 540,600 | 397,560 | 1.36× |
| 1 KiB | 1,639,400 | 522,290 | 3.14× |
| 16 KiB | 19,815,000 | 1,543,600 | **12.84×** |

At 16 KiB that is 43 GB/s against 3.4 GB/s serial. `txaty` gains similarly (11.9×); no
other library offers the option at all, so at large content the field splits into two
that can use the machine and four that cannot.

The break-even moves with it. `WithParallelism` warns that a parallel build is slower
than a serial one on a small tree of cheap content, and that is measured here as the leaf
count where parallel overtakes serial:

| leaf size | n=64 | n=256 | n=1024 | n=4096 | break-even |
|---|---|---|---|---|---|
| 32 B | 0.44× | 0.73× | 0.93× | 1.43× | between 1,024 and 4,096 |
| 1 KiB | 0.94× | 1.40× | 2.02× | 3.16× | between 64 and 256 |
| 16 KiB | 3.29× | 4.52× | 9.70× | 12.78× | below 64; always worth it |

(Ratios above 1 mean parallel wins.) So the documented "a few thousand leaves" figure is
right, and is specific to cheap content: at 1 KiB the threshold drops to somewhere under
256 leaves, and at 16 KiB there is no threshold worth finding.

Looking a leaf up by value gets much worse as content grows; by position it does not
change. Locating content by value means hashing the query, so a lookup pays one
`CalculateHash` whatever the index behind it looks like. Addressing by position pays
nothing (ns/op, n=4,096):

| | 32 B | 1 KiB | 16 KiB |
|---|---|---|---|
| **cbergoon by index** | **84.6** | **64.5** | **51.8** |
| cbergoon leaf index | 146 | 414 | 4,934 |
| txaty | 140 | 409 | 4,897 |
| onrik by index | 1,144 | 920 | 669 |

At seven byte leaves the difference between addressing a leaf by value and by position is
invisible. At 16 KiB it is **95×**, and `GetMerklePathByIndex` is the only sensible choice.
`txaty` tracks `merkletree`'s leaf index almost exactly, for the same reason, since both
hash the block, and it has no by-position equivalent in `ModeTreeBuild`, so that escape
hatch is not available there.

Verification converges the same way: `merkletree` is 1.34× faster than `txaty` at 32 byte
leaves, 1.22× at 1 KiB and 1.05× at 16 KiB, as the single `CalculateHash` on the content
grows to dominate the replay around it.

## Proof size on the wire

A proof's hash material is fixed by the tree, but how the side of each sibling is encoded
is not. At 65,536 leaves (depth 16):

| | hash bytes | side bytes | total |
|---|---|---|---|
| txaty | 512 | 4 | **516** |
| **cbergoon** | 512 | 128 | 640 |

`GetMerklePath` returns `[]int64`, spending eight bytes per level to carry one bit, where
`txaty` packs the whole path into a single `uint32` bitfield. Identical information, 124
bytes apart, and the gap grows with depth. It costs nothing in memory or time locally,
it is a transmission and storage cost for anyone shipping proofs over a network, but it
is real, and changing it would break the signature of `GetMerklePath`.

## Choosing on this evidence

The scorecard at the top ranks the axes. What it cannot express is that the axes are not
equally decisive, and which ones matter is settled by the workload rather than by the
table:

- Cheap content, build once, take the root. Nothing here separates the libraries except
  `jvsteiner`, and the decision should be made on API and maintenance instead.
- Expensive content. Only parallelism matters, and only two libraries have it. At
  16 KiB leaves it is worth 12×, which is larger than every other difference in this
  document combined.
- Serving proofs. Addressing the leaf is the whole decision: without
  `GetMerklePathByIndex`, `AppendMerklePathByIndex` or `WithLeafIndex`, `merkletree` and
  `wealdtech` are quadratic over a full proof set. For expensive content, addressing by
  position rather than by value is worth another 95×, and reusing buffers through the
  `Append` forms another ~5× on top of that.
- Many goroutines. `txaty`'s exclusive lock on the proof path makes it the wrong choice
  regardless of its single-threaded numbers; `merkletree`'s `Append` forms are the only
  proof path here that scales with the goroutine count.
- Roots that are published or stored. The odd node policy decides interoperability, and
  no benchmark is relevant until that agrees.

`merkletree`'s weakest remaining result is that proofs carry 124 more bytes than they
need at depth 16. The other weakness earlier revisions recorded here, per-proof
allocation as the ceiling on concurrent throughput, still applies to the slice-returning
forms, and no longer applies at all to a caller using `AppendMerklePath` or
`AppendMerklePathByIndex` with reused buffers.

## Method and caveats

- Every library gets the same leaf bytes and SHA-256. `merkletree`'s `CalculateHash`
  returns SHA-256 of the data, because every other library hashes its own leaves; using
  the identity function there would build a different tree.
- `xsleonard/go-merkle` is configured with `DoubleOddNodes` so that it builds the same
  tree as `merkletree`'s default. Its own default is in the second group above.
- `txaty` is benchmarked in `ModeTreeBuild` for construction, since `ModeProofGen` does
  strictly more work; `ModeProofGen` appears on the all-proofs axis where it belongs.
- `txaty` rejects a single data block, so no size below 2 is benchmarked.
- `xsleonard` has no proof API and appears only under construction.
- `jvsteiner` hardcodes SHA-256, which is the only reason it is comparable here. It is
  unmaintained since 2018 and generates its types from protobuf.
- The all-proofs axis stops at 4,096: at 65,536 a single iteration of a scanning
  implementation takes minutes.
- Leaves are about seven bytes except in the content cost section, which varies them
  from 32 B to 16 KiB. Read any per-node overhead result as applying to small content
  only; that section says how much of it survives.
- The concurrency axis reports `ns/op` under `testing.B.RunParallel`, so lower is higher
  throughput. Speedups are taken from the same benchmark at `-cpu=1` against `-cpu=18`,
  rather than by comparing against a differently shaped single-threaded benchmark.
- The `cbergoon-append` rows reuse two caller-owned slices across proofs, per goroutine
  on the concurrency axis, which is the documented use of `AppendMerklePathByIndex`.
  Every other row returns freshly allocated proofs, because that is all the other
  libraries' APIs offer.

Comparisons deliberately not made, so their absence is not read as a result: incremental
append, which `jvsteiner` and `onrik` support and `merkletree` does not; behaviour on
adversarial or malformed input; and serialization, which no other library here offers.
