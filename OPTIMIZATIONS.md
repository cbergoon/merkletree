# Optimizations

A record of the performance work that went into v0.5.0: what was slow, how it was found,
what was changed, and what it bought. Written for anyone who wants the reasoning rather
than the diff, including the two changes that measured well and bought almost nothing.

Numbers are from an Apple M5 Max on Go 1.26 with SHA-256, `-count=6` through benchstat
unless stated. Ratios travel; absolute values do not.

---

## 1. The scan: O(n) per proof, O(n²) per set

**The single largest problem in the library, and not an allocation problem at all.**

### Symptom

`GetMerklePath` and `VerifyContent` located content by walking `Leafs` and calling
`Content.Equals` on each one. The walk up the tree afterwards is O(log n). The search in
front of it was O(n).

### How it was isolated

Timing `GetMerklePath` at a fixed tree size says nothing, because the cost of the scan
and the cost of the walk are summed. The way to separate them is to hold the tree
constant and vary only *where the target sits*:

```
GetMerklePath, n=4096, same tree, same 12-level path, identical allocations:
  first leaf    214 ns
  middle leaf  3660 ns
  last leaf    7990 ns
```

Same work in the walk, 37× the time. **97% of the call was the scan.** That single
measurement reframed the whole exercise — every allocation in the proof path could have
gone to zero and it would have moved the number by 3%.

Extended to the full proof set, the quadratic showed plainly:

| n | full proof set | per proof |
|---|---|---|
| 16,000 | 214 ms | 13.4 µs |
| 32,000 | 887 ms | 27.7 µs |
| 100,000 | **9.8 s** | 97.8 µs |

Per-proof cost grows linearly with tree size, so the set grows quadratically. Note the
small-n numbers grow *sub*-linearly (≈ n^0.63 below 16k) — a cache artifact, since the
leaf array still fits. Past 16k it goes strictly linear, which is why extrapolating from
small n underestimates the damage.

### The three fixes

Increasing in what the caller must know, decreasing in cost:

**`WithLeafIndex()`** — a `map[string]int` from leaf hash to lowest position, built at
construction. A lookup becomes one `CalculateHash` on the query plus a map probe.

Two properties make it cheaper than it looks. It needs **no extra hashing to build**:
every leaf hash it records was already computed and stored on the node during
construction, so it is n map inserts. And it is built **eagerly, not lazily** — a lazily
populated map would need a mutex on the read path, and a built tree is otherwise safe for
concurrent reads with no synchronization at all. Eager keeps proof serving lock-free,
which turns out to matter enormously (§6).

It is opt-in for two reasons: ~40 bytes per leaf, and it changes how content is located,
from `Equals` to a hash comparison. The `Content` interface already requires the two to
agree, so any implementation honoring that contract gets the same leaf either way —
including the "earliest matching leaf wins" rule, preserved by storing the lowest index
per hash.

**`GetMerklePathByIndex(i)`** — takes the position directly. No option, no memory, and it
does not hash the query at all.

**`AppendMerklePath` / `AppendMerklePathByIndex`** — the same proofs written into slices
the caller supplies and keeps, so a server reusing its buffers allocates nothing per
proof.

### Result

Single proof, worst-case leaf (ns/op):

| n | scan | `WithLeafIndex` | by index | append |
|---|---|---|---|---|
| 4,096 | 7,802 | 146 | 84.9 | **13.4** |
| 65,536 | 129,730 | 135 | 76.3 | **16.7** |

Full proof set at 64,000 leaves: **3.71 s → 12.8 ms** with the index, **7.9 ms** by
index. The quadratic is gone — per-proof cost is now flat in n.

### The subtlety worth writing down

Hash-based lookup and `Equals`-based lookup differ in **which method can fail**. The
index hashes the query and never calls `Equals`; the scan calls `Equals` and never hashes
the query. So a query whose `CalculateHash` errors fails only when indexed, and content
whose `Equals` errors surfaces only when scanning. This is inherent to replacing a
comparison with a hash, not a defect, but it is observable and is pinned by a test that
asserts both directions.

---

## 2. Verification allocated a hasher per node

### Symptom

`VerifyTree` at 4,096 leaves: **12,286 allocations, 768 KiB**. The construction path had
already been optimized to hand out nodes from per-level slabs; verification had never had
the same treatment.

A memory profile put it beyond doubt:

```
  75.04%  crypto/internal/fips140/sha256.(*Digest).Sum
  23.99%  crypto/internal/fips140/sha256.New (inline)
```

`hashInterior` called `m.hashStrategy()` on every interior node, and `h.Sum(nil)`
allocated a fresh digest for each. The node count is linear in the leaves, so a tree of
any size paid two allocations per node.

### The fix

Thread one hasher and one buffer through the entire recursive walk. The interesting part
is keeping the buffer small. Naively appending every node's digest makes it O(n); the
trick is that a node's children are dead the moment its own hash is computed, so the
result slides down over them:

```go
off := len(dst)
dst, rightMatched, err := n.Right.verifyNode(h, dst)
mid := len(dst)
dst, leftMatched, err := n.Left.verifyNode(h, dst)
end := len(dst)

dst, err = n.Tree.appendInteriorHash(h, dst, dst[mid:end], dst[off:mid])

// children are dead; slide this node's digest down over them
dst = dst[:off+copy(dst[off:], dst[end:])]
```

The buffer stays the **depth** of the tree, not the size of it, so it is preallocated
once at `(bits.Len(len(Leafs))+2) * h.Size()` and never grows.

One ordering detail makes this safe: `appendInteriorHash` writes both children into the
hasher *before* `Sum` appends, so a reallocation of `dst` cannot invalidate the slices
passed into it.

### Result

| n=4,096 | allocations | bytes | time |
|---|---|---|---|
| default | 12,286 → 4,098 (−67%) | 768 KiB → 129 KiB (−83%) | **−15.6%** |
| RFC 6962 | 20,478 → 4,098 (−80%) | 1,408 KiB → 129 KiB (−91%) | **−26.1%** |

The residual 4,098 is entirely the *caller's* `CalculateHash` on the leaves. Library-side
allocation for the whole walk is now about 2. RFC 6962 gains most because it hashes twice
per leaf.

The same sliding-buffer replay is what `VerifyProof` uses, which is why standalone
verification allocates a flat 2 objects at every tree size where other libraries grow
with depth.

---

## 3. Decoding copied every payload twice

`unmarshalRegisteredContent` did:

```go
bu.UnmarshalBinary(bytes.Clone(payload))
```

with the comment that `UnmarshalBinary` implementations may retain the slice they are
handed. True — but `binaryReader.bytes()` already does `make([]byte, n)` + `io.ReadFull`,
so `payload` was **already** a slice nobody else held. The `treeData` carrying it is
transient and dropped once the tree is built. The clone was a second copy of every
content payload on the way in, one wasted allocation per leaf.

The strongest evidence it was safe to drop: the `UnmarshalWith` path had always handed
`record.Payload` straight to the caller's decoder on exactly that reasoning. The registry
path was the inconsistent one.

Separately, every record's type name was re-allocated (`make` + `string()`) though a tree
almost always holds one content type. Interning them costs one string for the whole
payload, and indexing a map with `string(byteSlice)` does not allocate, so a repeat name
costs only the probe.

**Result: −25% allocations, −13% bytes, −8% time** on `UnmarshalBinary`.

---

## 4. A negative result worth keeping

In isolation, the decode fixes above measured **−25% allocations but only −3% time.**

That is the finding, not a footnote. The decode path's cost is `reflect.New` and
interface boxing per leaf, plus the full tree rebuild — not allocation volume. Cutting a
quarter of the allocations moved almost nothing.

The general lesson the whole exercise kept re-teaching: **allocation count is a proxy,
and sometimes a bad one.** It was the right thing to chase in verification (§2), where it
was 75% of the profile. It was the wrong thing to chase in decoding. And in proof
generation (§1) the real problem was algorithmic and no amount of allocation work would
have touched it.

The −8% finally observed on decode came only after parallel construction landed and
changed the mix.

---

## 5. Small, free wins

**Proof slice preallocation.** `GetMerklePath` started `merklePath` and `index` at nil and
grew them by doubling — 10 allocations for a 12-entry path at n=4,096. Sizing both to
`bits.Len(len(m.Leafs))` up front: **10 → 2**.

**One option resolver.** Construction and proof verification now resolve `TreeOption`
through the same `configFromOptions`, so a tree and a proof checked against it cannot
disagree about what an option meant, and the RFC 6962 / sorted conflict is rejected
identically by both. Correctness rather than speed, but it removes a class of drift.

---

## 6. Concurrency: the ceiling moved twice

A built tree is meant to be shared — one tree, many goroutines answering proof requests.
Single-threaded numbers say nothing about that, so it was measured separately, as a
scaling curve at 1, 4 and 18 goroutines rather than by comparing against a
differently-shaped benchmark.

**First ceiling: the allocator.** With the leaf index, nothing on the read path takes a
lock. But each proof allocated its two slices — ~512 B/op, which at 13M proofs/sec is
several GB/s — and the garbage collector became the shared resource instead. Scaling
stalled at ~2× on 18 cores.

**Second ceiling: removed.** The `Append` forms hand the buffers to the caller. A proof
that allocates nothing shares nothing — no lock, no allocator, no collector — and the
curve changes shape:

| | 1 | 4 | 18 | speedup |
|---|---|---|---|---|
| append | 48.2 | 11.8 | **2.9** | **16.4×** |
| by index | 168.8 | 73.4 | 82.4 | 2.05× |
| leaf index | 231.7 | 86.5 | 86.5 | 2.68× |

**2.9 ns per proof under 18 goroutines**, 16.4× the single-goroutine rate. The lesson
generalizes: past a certain point, "lock-free" is not the bar — *allocation-free* is,
because the collector is a lock you did not write.

For contrast, one comparison library guards its leaf lookup with an exclusive mutex
around a map that is only ever read after construction, and gets **slower** past four
goroutines (1.14× across the same range).

---

## 7. Parallel construction

`WithParallelism(n)` spreads content hashing across goroutines. Off by default, because
it calls `Content.CalculateHash` concurrently and only the caller knows whether their
implementation is safe for that — that requirement is the entire cost of the option.

The root is unaffected: every hash lands in a slot fixed by its position, so a
parallel-built tree is byte for byte the serial one. Hashers are created up front, one
per worker, so a caller-supplied strategy is never invoked concurrently even though the
build is.

What it is worth depends almost entirely on what `CalculateHash` costs, and the
break-even moves with it:

| leaf size | n=64 | n=256 | n=1024 | n=4096 | break-even |
|---|---|---|---|---|---|
| 32 B | 0.35× | 0.67× | 0.88× | 1.30× | between 1,024 and 4,096 |
| 1 KiB | 0.87× | 1.48× | 1.97× | 3.07× | between 64 and 256 |
| 16 KiB | 3.06× | 4.47× | 9.43× | 12.10× | always worth it |

At 16 KiB leaves it is 40 GB/s against 3.4 GB/s serial. Below the break-even it is
genuinely slower — 6.5× slower at 16 short leaves — which is why measuring beats
assuming here.

---

## 8. What content cost does to all of it

Every benchmark used ~7-byte leaves, which makes hashing nearly free and the surrounding
machinery nearly everything. That ratio decides what is being measured. Repeating
construction across leaf sizes:

| leaf size | spread, fastest to slowest implementation |
|---|---|
| 32 B | 2.17× |
| 1 KiB | 1.31× |
| 16 KiB | **1.02×** |

**At 16 KiB leaves the implementation stops mattering for construction** — everything
converges on ~3.35 GB/s of SHA-256. Per-node overhead is only worth arguing about when
leaves are small.

Two things move the other way. Parallelism grows with content cost (§7), because it
changes the hashing bill rather than the overhead around it. And **lookup by value
degrades while lookup by position does not**, because locating content by value means
hashing the query:

| | 32 B | 1 KiB | 16 KiB |
|---|---|---|---|
| by index | 85 | 61 | 50 |
| leaf index | 144 | 406 | 4,863 |

A 1.7× gap becomes **97×**. The practical guidance: for expensive content, use
`WithParallelism` and address leaves by position — and specifically *do not* use
`WithLeafIndex`, which pays a full `CalculateHash` per lookup for an index you do not
need if you already track positions.

---

## Method notes

Things that changed conclusions, and would have been missed otherwise.

**Vary position, not just size.** The scan (§1) was invisible in ordinary benchmarks
because it was summed with the walk. Holding the tree fixed and moving the target
separated them in one measurement.

**Vary the input cost.** Every ranking in §8 was an artifact of tiny leaves. A benchmark
suite that only ever uses small inputs is measuring its own harness.

**Measure scaling as a curve.** `-cpu=1,4,18` on the same benchmark shows contention
directly. Comparing a parallel benchmark against a differently-shaped serial one does
not, and invites wrong conclusions in both directions.

**Race detection needs iterations.** A benchmark under `-race` at `-benchtime=1x` catches
nothing — the goroutines barely overlap. A real race in a benchmark was reproduced,
planted back, and confirmed caught only at ≥20 iterations; CI uses 200. The first version
of that CI job would have passed on the very bug it was added for.

**Race-check benchmarks at all.** Some concurrent paths are exercised only by benchmarks,
and `go test -race` never runs them.

**Verify the oracle catches things.** The RFC 6962 cross-check is only worth its runtime
if it fails when the construction is wrong. Transposing two children makes it fail at two
leaves while the entire rest of the suite — property tests, golden files, fuzzing, round
trips — stays green. A transposed tree is perfectly self-consistent.

**Attribute residual allocations.** After §2, verification still allocated ~4,098 per
build at n=4,096. Profiling showed all of it in the caller's `CalculateHash`. Knowing
which allocations are not yours is what tells you when to stop.
