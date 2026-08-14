// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

// The Append proof methods promise exactly one thing beyond their slice-returning
// counterparts: the same proof, delivered into slices the caller owns. These tests
// hold that equivalence across every construction, then cover what appending adds -
// prefixes survive, reused buffers really do stop allocation, and errors leave the
// caller's slices alone.

func TestAppendMerklePathMatchesGet(t *testing.T) {
	for _, mode := range propModes {
		for _, n := range []int{1, 2, 3, 5, 8, 16, 17, 255, 256, 257} {
			cs := propSeries(n)
			tree, err := mode.build(cs, sha256.New)
			if err != nil {
				t.Fatalf("[%s/n=%d] error: unexpected error: %v", mode.name, n, err)
			}

			for i := range tree.Leafs {
				wantPath, wantIdx, err := tree.GetMerklePathByIndex(i)
				if err != nil {
					t.Fatalf("[%s/n=%d/i=%d] error: unexpected error: %v", mode.name, n, i, err)
				}
				gotPath, gotIdx, err := tree.AppendMerklePathByIndex(nil, nil, i)
				if err != nil {
					t.Fatalf("[%s/n=%d/i=%d] error: unexpected error appending: %v", mode.name, n, i, err)
				}

				assertProofsEqual(t, fmt.Sprintf("[%s/n=%d/i=%d] by index", mode.name, n, i), wantPath, wantIdx, gotPath, gotIdx)
			}

			for i, c := range cs {
				wantPath, wantIdx, err := tree.GetMerklePath(c)
				if err != nil {
					t.Fatalf("[%s/n=%d/i=%d] error: unexpected error: %v", mode.name, n, i, err)
				}
				gotPath, gotIdx, err := tree.AppendMerklePath(nil, nil, c)
				if err != nil {
					t.Fatalf("[%s/n=%d/i=%d] error: unexpected error appending: %v", mode.name, n, i, err)
				}

				assertProofsEqual(t, fmt.Sprintf("[%s/n=%d/i=%d] by content", mode.name, n, i), wantPath, wantIdx, gotPath, gotIdx)
			}
		}
	}
}

func assertProofsEqual(t *testing.T, label string, wantPath [][]byte, wantIdx []int64, gotPath [][]byte, gotIdx []int64) {
	t.Helper()

	if len(wantPath) != len(gotPath) || len(wantIdx) != len(gotIdx) {
		t.Fatalf("%s error: proof shape %d/%d, got %d/%d", label, len(wantPath), len(wantIdx), len(gotPath), len(gotIdx))
	}
	for k := range wantPath {
		if !bytes.Equal(wantPath[k], gotPath[k]) || wantIdx[k] != gotIdx[k] {
			t.Fatalf("%s error: proof element %d differs", label, k)
		}
	}
}

// TestAppendMerklePathExtends checks that appending really appends: entries already in
// the caller's slices stay where they were, in the way strconv.AppendInt would keep
// them.
func TestAppendMerklePathExtends(t *testing.T) {
	cs := propSeries(8)
	tree, err := NewTreeWithOptions(cs)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	sentinelHash := []byte{0xde, 0xad}
	path := [][]byte{sentinelHash}
	index := []int64{7}

	path, index, err = tree.AppendMerklePathByIndex(path, index, 3)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	wantPath, wantIdx, err := tree.GetMerklePathByIndex(3)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if len(path) != len(wantPath)+1 || len(index) != len(wantIdx)+1 {
		t.Fatalf("error: expected the prefix to survive, lengths %d/%d", len(path), len(index))
	}
	if !bytes.Equal(path[0], sentinelHash) || index[0] != 7 {
		t.Fatal("error: appending overwrote the existing entries")
	}
	assertProofsEqual(t, "after prefix", wantPath, wantIdx, path[1:], index[1:])
}

// TestAppendMerklePathReuseDoesNotAllocate pins the property the methods exist for. A
// regression here is not a correctness bug, but it is the entire point of the API.
func TestAppendMerklePathReuseDoesNotAllocate(t *testing.T) {
	cs := propSeries(256)
	tree, err := NewTreeWithOptions(cs)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	var (
		path  [][]byte
		index []int64
	)
	// Warm the buffers to full depth first; the steady state is what is measured.
	if path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], 0); err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	i := 0
	allocs := testing.AllocsPerRun(100, func() {
		path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], i)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		i = (i + 1) % len(tree.Leafs)
	})
	if allocs != 0 {
		t.Errorf("error: expected reused buffers to make proof generation allocation free, measured %.1f allocs", allocs)
	}
}

// TestAppendMerklePathErrorsLeaveSlicesAlone checks the documented error contract: the
// slices come back unchanged, so a caller's loop state survives a bad request.
func TestAppendMerklePathErrorsLeaveSlicesAlone(t *testing.T) {
	cs := propSeries(4)
	tree, err := NewTreeWithOptions(cs)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	path := [][]byte{{0x01}}
	index := []int64{1}

	for _, bad := range []int{-1, len(tree.Leafs), len(tree.Leafs) + 5} {
		gotPath, gotIdx, err := tree.AppendMerklePathByIndex(path, index, bad)
		if !errors.Is(err, ErrContentNotFound) {
			t.Fatalf("error: expected ErrContentNotFound for index %d, got %v", bad, err)
		}
		if len(gotPath) != 1 || len(gotIdx) != 1 || !bytes.Equal(gotPath[0], path[0]) || gotIdx[0] != index[0] {
			t.Errorf("error: an out of range index changed the caller's slices")
		}
	}

	gotPath, gotIdx, err := tree.AppendMerklePath(path, index, TestSHA256Content{x: "not in the tree"})
	if !errors.Is(err, ErrContentNotFound) {
		t.Fatalf("error: expected ErrContentNotFound for absent content, got %v", err)
	}
	if len(gotPath) != 1 || len(gotIdx) != 1 {
		t.Errorf("error: absent content changed the caller's slices")
	}
}

// TestAppendMerklePathProofsVerify closes the loop: a proof generated by the append
// forms must verify exactly as one from the slice-returning forms does.
func TestAppendMerklePathProofsVerify(t *testing.T) {
	for _, mode := range propModes {
		cs := propSeries(33)
		tree, err := mode.build(cs, sha256.New)
		if err != nil {
			t.Fatalf("[%s] error: unexpected error: %v", mode.name, err)
		}

		opts := []TreeOption{}
		if mode.sorted {
			opts = append(opts, WithSortedSiblings())
		}
		if mode.rfc6962 {
			opts = append(opts, WithRFC6962())
		}

		var (
			path  [][]byte
			index []int64
		)
		for i, c := range cs {
			path, index, err = tree.AppendMerklePath(path[:0], index[:0], c)
			if err != nil {
				t.Fatalf("[%s/i=%d] error: unexpected error: %v", mode.name, i, err)
			}
			ok, err := VerifyProof(c, path, index, tree.MerkleRoot(), opts...)
			if err != nil {
				t.Fatalf("[%s/i=%d] error: unexpected error verifying: %v", mode.name, i, err)
			}
			if !ok {
				t.Errorf("[%s/i=%d] error: expected the appended proof to verify", mode.name, i)
			}
		}
	}
}
