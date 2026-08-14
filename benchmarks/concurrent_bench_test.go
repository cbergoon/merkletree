// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package benchmarks

import (
	"testing"

	cb "github.com/cbergoon/merkletree"
	txaty "github.com/txaty/go-merkletree"
)

// A fifth axis, and the one closest to how a Merkle tree is usually deployed: one tree,
// built once, shared by many goroutines answering proof requests. The four axes in
// bench_test.go all measure a single goroutine, which says nothing about whether a
// library's read path contends.
//
// It does not follow from the single-threaded numbers. A library can be quick on one
// goroutine and refuse to scale on several, and one of them here does exactly that:
// txaty/go-merkletree guards its leaf lookup with an exclusive sync.Mutex rather than a
// read lock (proof.go, `m.leafMapMu.Lock()`), so concurrent proof generation serializes
// on it even though the map is only ever read after the tree is built.
//
// Run with -race as well as -bench to check the read paths are actually safe to share,
// which is the precondition for any of this mattering.

const concurrentSize = 16384

// BenchmarkConcurrentProofs serves proofs from one shared tree across GOMAXPROCS
// goroutines. Compare each result against the corresponding single-goroutine number in
// BenchmarkSingleProof: a read path that scales should be at or below it, and one that
// contends will be well above.
func BenchmarkConcurrentProofs(b *testing.B) {
	d := leafData(concurrentSize)

	b.Run("cbergoon-leafindex", func(b *testing.B) {
		tree, err := buildCB(d, cb.WithLeafIndex())
		if err != nil {
			b.Fatal(err)
		}
		cs := cbContents(d)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, _, err := tree.GetMerklePath(cs[i%len(cs)]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})

	b.Run("cbergoon-byindex", func(b *testing.B) {
		tree, err := buildCB(d)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, _, err := tree.GetMerklePathByIndex(i % concurrentSize); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})

	// The append form with per-goroutine buffers is the zero-allocation way to serve
	// proofs, which takes the garbage collector - the shared resource that caps the
	// two variants above - out of the picture entirely.
	b.Run("cbergoon-append", func(b *testing.B) {
		tree, err := buildCB(d)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			// err is declared here rather than reused from the enclosing scope. The
			// assignment below writes all three variables at once, so an err captured
			// from outside would be written by every goroutine at once - which is a
			// race in the benchmark, not in the tree, but a real one either way.
			var (
				path  [][]byte
				index []int64
				err   error
			)
			i := 0
			for pb.Next() {
				if path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], i%concurrentSize); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
		b.StopTimer()
		// One more proof through the same path, verified, so the timed loop cannot
		// quietly have been a no-op. TestConcurrentAppendProofsVerify covers the
		// concurrent shape itself under -race.
		path, index, err := tree.AppendMerklePathByIndex(nil, nil, concurrentSize-1)
		if err != nil {
			b.Fatal(err)
		}
		if ok, err := cb.VerifyProof(cbContent{data: d[concurrentSize-1]}, path, index, tree.MerkleRoot()); err != nil || !ok {
			b.Fatalf("proof path produced an invalid proof: %v %v", ok, err)
		}
	})

	b.Run("txaty", func(b *testing.B) {
		tree, err := buildTxaty(d, txaty.ModeTreeBuild, false)
		if err != nil {
			b.Fatal(err)
		}
		blocks := txatyBlocks(d)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, err := tree.Proof(blocks[i%len(blocks)]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})

	b.Run("wealdtech", func(b *testing.B) {
		tree, err := buildWeald(d)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, err := tree.GenerateProof(d[i%len(d)]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})

	b.Run("onrik", func(b *testing.B) {
		tree, err := buildOnrik(d)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_ = tree.GetProof(i % concurrentSize)
				i++
			}
		})
	})

	b.Run("jvsteiner", func(b *testing.B) {
		tree := buildJvsteiner(d)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, err := tree.GetChain(i % concurrentSize); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})
}

// BenchmarkConcurrentVerification does the same for the verify path, which for most of
// these libraries touches no shared state at all and should scale cleanly.
func BenchmarkConcurrentVerification(b *testing.B) {
	d := leafData(concurrentSize)
	last := d[len(d)-1]

	b.Run("cbergoon-verifyproof", func(b *testing.B) {
		tree, err := buildCB(d)
		if err != nil {
			b.Fatal(err)
		}
		target := cbContent{data: last}
		path, index, err := tree.GetMerklePath(target)
		if err != nil {
			b.Fatal(err)
		}
		root := tree.MerkleRoot()
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ok, err := cb.VerifyProof(target, path, index, root)
				if err != nil || !ok {
					b.Fatalf("verify failed: %v %v", ok, err)
				}
			}
		})
	})

	b.Run("txaty", func(b *testing.B) {
		tree, err := buildTxaty(d, txaty.ModeTreeBuild, false)
		if err != nil {
			b.Fatal(err)
		}
		target := txatyBlock{data: last}
		proof, err := tree.Proof(target)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ok, err := tree.Verify(target, proof)
				if err != nil || !ok {
					b.Fatalf("verify failed: %v %v", ok, err)
				}
			}
		})
	})
}

// TestProofWireSize is not a benchmark but belongs with them: it reports how many bytes
// each library's proof occupies, which is what a proof costs to transmit and store. The
// hash material is necessarily the same; the difference is entirely in how the side of
// each sibling is encoded.
func TestProofWireSize(t *testing.T) {
	const n = 65536
	d := leafData(n)

	tree, err := buildCB(d)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	path, index, err := tree.GetMerklePathByIndex(n - 1)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	hashBytes := 0
	for _, p := range path {
		hashBytes += len(p)
	}
	// merkletree carries one int64 per level to hold what is a single bit.
	ourSideBytes := len(index) * 8

	tt, err := buildTxaty(d, txaty.ModeTreeBuild, false)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	proof, err := tt.Proof(txatyBlock{data: d[n-1]})
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	txatyHashBytes := 0
	for _, s := range proof.Siblings {
		txatyHashBytes += len(s)
	}
	// txaty packs the same information into one uint32 bitfield for the whole proof.
	txatySideBytes := 4

	t.Logf("depth %d", len(path))
	t.Logf("cbergoon: %d hash bytes + %d side bytes = %d total",
		hashBytes, ourSideBytes, hashBytes+ourSideBytes)
	t.Logf("txaty:    %d hash bytes + %d side bytes = %d total",
		txatyHashBytes, txatySideBytes, txatyHashBytes+txatySideBytes)

	if hashBytes != txatyHashBytes {
		t.Errorf("error: hash material differs: %d vs %d, so the comparison is not like for like",
			hashBytes, txatyHashBytes)
	}
	// Not a failure, just the fact worth recording: the side encoding is the whole
	// difference, and it is 8 bytes per level against 4 bytes per proof.
	if ourSideBytes <= txatySideBytes {
		t.Errorf("error: expected merkletree's side encoding to be the larger one; "+
			"got %d against %d", ourSideBytes, txatySideBytes)
	}
}
