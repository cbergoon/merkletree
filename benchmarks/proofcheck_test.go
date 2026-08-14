// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package benchmarks

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	cb "github.com/cbergoon/merkletree"
)

// The proof benchmarks next door report some numbers that deserve suspicion - a proof
// in nanoseconds with zero allocations invites the question of whether anything real is
// being measured. This file answers it the strong way: the exact proof-serving shapes
// the benchmarks time are replayed here for every leaf, required to agree with each
// other byte for byte, and required to verify against a Merkle root computed by a
// different library. A proof generator that skipped work, returned stale buffers, or
// raced under concurrency could not pass that; hashes do not come out right by luck.

// proofSizes are powers of two so that every library in the comparison computes the
// same root (TestRootAgreementOnPowersOfTwo), which is what makes an independent root
// available to verify against.
var proofSizes = []int{16, 256, 4096}

func TestProofFormsAgreeAndVerifyAgainstIndependentRoot(t *testing.T) {
	for _, n := range proofSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			d := leafData(n)

			plain, err := buildCB(d)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			indexed, err := buildCB(d, cb.WithLeafIndex())
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			// The independent root: computed by wealdtech/go-merkletree from the same
			// leaves, asserted equal to ours by the crosscheck tests, and used here as
			// the value every proof must hash back to.
			wt, err := buildWeald(d)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			independentRoot := wt.Root()
			if !bytes.Equal(independentRoot, plain.MerkleRoot()) {
				t.Fatalf("error: roots disagree before any proof is generated; the premise is broken")
			}

			var (
				path  [][]byte
				index []int64
			)
			for j := 0; j < n; j++ {
				content := cbContent{data: d[j]}

				scanPath, scanIdx, err := plain.GetMerklePath(content)
				if err != nil {
					t.Fatalf("error: scan proof at %d: %v", j, err)
				}
				mapPath, mapIdx, err := indexed.GetMerklePath(content)
				if err != nil {
					t.Fatalf("error: leaf-index proof at %d: %v", j, err)
				}
				posPath, posIdx, err := plain.GetMerklePathByIndex(j)
				if err != nil {
					t.Fatalf("error: by-index proof at %d: %v", j, err)
				}
				// The exact loop the benchmarks time: append into the same two
				// buffers, resliced to zero, reused across the whole set.
				path, index, err = plain.AppendMerklePathByIndex(path[:0], index[:0], j)
				if err != nil {
					t.Fatalf("error: append proof at %d: %v", j, err)
				}

				requireSameProof(t, j, "scan vs append", scanPath, scanIdx, path, index)
				requireSameProof(t, j, "leafindex vs append", mapPath, mapIdx, path, index)
				requireSameProof(t, j, "byindex vs append", posPath, posIdx, path, index)

				ok, err := cb.VerifyProof(content, path, index, independentRoot)
				if err != nil {
					t.Fatalf("error: verifying appended proof at %d: %v", j, err)
				}
				if !ok {
					t.Fatalf("error: appended proof at %d does not reproduce the root wealdtech computed", j)
				}
			}
		})
	}
}

// TestConcurrentAppendProofsVerify is the concurrent benchmark's shape as a correctness
// test: many goroutines serving proofs from one shared tree, each into its own reused
// buffers, every proof checked against the independently computed root. Run under
// -race, this is what stands behind the concurrency claims in ANALYSIS.md.
func TestConcurrentAppendProofsVerify(t *testing.T) {
	const n = 1024
	const workers = 8

	d := leafData(n)
	tree, err := buildCB(d)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	wt, err := buildWeald(d)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	independentRoot := wt.Root()

	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var (
				path  [][]byte
				index []int64
				err   error
			)
			// Each worker starts at a different leaf so the goroutines are never in
			// lockstep, and covers every leaf so nothing depends on the schedule.
			for k := 0; k < n; k++ {
				j := (k + w*(n/workers)) % n
				path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], j)
				if err != nil {
					errs[w] = fmt.Errorf("append at %d: %w", j, err)

					return
				}
				ok, err := cb.VerifyProof(cbContent{data: d[j]}, path, index, independentRoot)
				if err != nil || !ok {
					errs[w] = fmt.Errorf("proof at %d failed to verify: %v %v", j, ok, err)

					return
				}
			}
		}(w)
	}
	wg.Wait()

	for w, err := range errs {
		if err != nil {
			t.Errorf("error: worker %d: %v", w, err)
		}
	}
}

func requireSameProof(t *testing.T, leaf int, label string, aPath [][]byte, aIdx []int64, bPath [][]byte, bIdx []int64) {
	t.Helper()

	if len(aPath) != len(bPath) || len(aIdx) != len(bIdx) {
		t.Fatalf("error: leaf %d, %s: proof shapes differ (%d/%d vs %d/%d)",
			leaf, label, len(aPath), len(aIdx), len(bPath), len(bIdx))
	}
	for k := range aPath {
		if !bytes.Equal(aPath[k], bPath[k]) || aIdx[k] != bIdx[k] {
			t.Fatalf("error: leaf %d, %s: proofs differ at level %d", leaf, label, k)
		}
	}
}
