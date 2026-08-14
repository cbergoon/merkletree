// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"testing"
)

// The leaf index and GetMerklePathByIndex are both shortcuts around the scan that
// GetMerklePath and VerifyContent otherwise perform. Neither is allowed to change what
// those calls answer, so the tests here are mostly equivalence tests: take a tree, ask
// it the same question by both routes, and require the same reply.

// buildIndexed builds the same tree a propMode would, with the leaf index turned on.
func (m propMode) buildIndexed(cs []Content, hs func() hash.Hash) (*MerkleTree, error) {
	opts := []TreeOption{WithHasher(hs), WithLeafIndex()}
	if m.sorted {
		opts = append(opts, WithSortedSiblings())
	}
	if m.rfc6962 {
		opts = append(opts, WithRFC6962())
	}

	return NewTreeWithOptions(cs, opts...)
}

// TestGetMerklePathByIndexMatchesByContent checks the two ways of asking for a proof
// agree, for every leaf of every construction and size.
func TestGetMerklePathByIndexMatchesByContent(t *testing.T) {
	for _, mode := range propModes {
		for _, n := range propSizes {
			t.Run(fmt.Sprintf("%s/n=%d", mode.name, n), func(t *testing.T) {
				contents := propSeries(n)
				tree, err := mode.build(contents, sha256.New)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}

				for i, c := range contents {
					wantPath, wantIndex, err := tree.GetMerklePath(c)
					if err != nil {
						t.Fatalf("error: GetMerklePath(%d): %v", i, err)
					}
					gotPath, gotIndex, err := tree.GetMerklePathByIndex(i)
					if err != nil {
						t.Fatalf("error: GetMerklePathByIndex(%d): %v", i, err)
					}

					if len(gotPath) != len(wantPath) {
						t.Fatalf("error: leaf %d: path has %d entries, want %d", i, len(gotPath), len(wantPath))
					}
					for k := range wantPath {
						if !bytes.Equal(gotPath[k], wantPath[k]) {
							t.Errorf("error: leaf %d level %d: path %x, want %x", i, k, gotPath[k], wantPath[k])
						}
						if gotIndex[k] != wantIndex[k] {
							t.Errorf("error: leaf %d level %d: index %d, want %d", i, k, gotIndex[k], wantIndex[k])
						}
					}
				}
			})
		}
	}
}

// TestGetMerklePathByIndexReplays confirms a path fetched by position rebuilds the root,
// so the shortcut produces proofs that actually verify rather than merely matching.
func TestGetMerklePathByIndexReplays(t *testing.T) {
	for _, s := range propStrategies {
		for _, mode := range propModes {
			for _, n := range propSizes {
				t.Run(fmt.Sprintf("%s/%s/n=%d", s.name, mode.name, n), func(t *testing.T) {
					contents := propSeries(n)
					tree, err := mode.build(contents, s.fn)
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}

					// Every leaf, including the padding copy an odd count adds.
					for i, leaf := range tree.Leafs {
						path, index, err := tree.GetMerklePathByIndex(i)
						if err != nil {
							t.Fatalf("error: GetMerklePathByIndex(%d): %v", i, err)
						}
						leafDigest, err := leaf.C.CalculateHash()
						if err != nil {
							t.Fatalf("error: hashing leaf %d: %v", i, err)
						}
						got, err := replayProof(leafDigest, path, index, s.fn, mode)
						if err != nil {
							t.Fatalf("error: replaying leaf %d: %v", i, err)
						}
						if !bytes.Equal(got, tree.MerkleRoot()) {
							t.Errorf("error: leaf %d replayed to %x, want root %x", i, got, tree.MerkleRoot())
						}
					}
				})
			}
		}
	}
}

func TestGetMerklePathByIndexOutOfRange(t *testing.T) {
	tree, err := NewTree(propSeries(4))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	for _, i := range []int{-1, 4, 5, 1 << 20} {
		if _, _, err := tree.GetMerklePathByIndex(i); !errors.Is(err, ErrContentNotFound) {
			t.Errorf("error: index %d returned %v, want ErrContentNotFound", i, err)
		}
	}
}

// TestLeafIndexMatchesScan is the central equivalence test: for content that is present
// and content that is not, an indexed tree and a scanning tree answer identically.
func TestLeafIndexMatchesScan(t *testing.T) {
	for _, s := range propStrategies {
		for _, mode := range propModes {
			for _, n := range propSizes {
				t.Run(fmt.Sprintf("%s/%s/n=%d", s.name, mode.name, n), func(t *testing.T) {
					contents := propSeries(n)
					scanned, err := mode.build(contents, s.fn)
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}
					indexed, err := mode.buildIndexed(contents, s.fn)
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}

					if indexed.leafIndex == nil {
						t.Fatal("error: WithLeafIndex produced no index")
					}
					if scanned.leafIndex != nil {
						t.Fatal("error: a tree built without WithLeafIndex has an index")
					}
					if !bytes.Equal(scanned.MerkleRoot(), indexed.MerkleRoot()) {
						t.Fatalf("error: the index changed the root: %x, want %x", indexed.MerkleRoot(), scanned.MerkleRoot())
					}

					for i, c := range contents {
						wantPath, wantIndex, wantErr := scanned.GetMerklePath(c)
						gotPath, gotIndex, gotErr := indexed.GetMerklePath(c)
						if (wantErr == nil) != (gotErr == nil) {
							t.Fatalf("error: leaf %d: indexed err %v, scanned err %v", i, gotErr, wantErr)
						}
						if len(gotPath) != len(wantPath) {
							t.Fatalf("error: leaf %d: path has %d entries, want %d", i, len(gotPath), len(wantPath))
						}
						for k := range wantPath {
							if !bytes.Equal(gotPath[k], wantPath[k]) || gotIndex[k] != wantIndex[k] {
								t.Errorf("error: leaf %d level %d: (%x,%d), want (%x,%d)",
									i, k, gotPath[k], gotIndex[k], wantPath[k], wantIndex[k])
							}
						}

						wantOK, err := scanned.VerifyContent(c)
						if err != nil {
							t.Fatalf("error: scanned VerifyContent(%d): %v", i, err)
						}
						gotOK, err := indexed.VerifyContent(c)
						if err != nil {
							t.Fatalf("error: indexed VerifyContent(%d): %v", i, err)
						}
						if gotOK != wantOK || !gotOK {
							t.Errorf("error: leaf %d: VerifyContent indexed %t, scanned %t", i, gotOK, wantOK)
						}
					}

					// Content the tree does not hold has to miss the same way by
					// both routes: an error for GetMerklePath, false for
					// VerifyContent.
					absent := propContent{x: "absent"}
					if _, _, err := indexed.GetMerklePath(absent); !errors.Is(err, ErrContentNotFound) {
						t.Errorf("error: indexed GetMerklePath of absent content returned %v, want ErrContentNotFound", err)
					}
					if _, _, err := scanned.GetMerklePath(absent); !errors.Is(err, ErrContentNotFound) {
						t.Errorf("error: scanned GetMerklePath of absent content returned %v, want ErrContentNotFound", err)
					}
					ok, err := indexed.VerifyContent(absent)
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}
					if ok {
						t.Error("error: indexed VerifyContent reported absent content as present")
					}
				})
			}
		}
	}
}

// TestLeafIndexEarliestLeafWins covers content stored more than once. Both routes are
// documented to return the earliest matching leaf, and the index keeps the lowest
// position for a hash so that they agree.
func TestLeafIndexEarliestLeafWins(t *testing.T) {
	for _, mode := range propModes {
		t.Run(mode.name, func(t *testing.T) {
			// "dup" appears at positions 1 and 3.
			contents := []Content{
				propContent{x: "a"},
				propContent{x: "dup"},
				propContent{x: "c"},
				propContent{x: "dup"},
				propContent{x: "e"},
			}
			scanned, err := mode.build(contents, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			indexed, err := mode.buildIndexed(contents, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if got := indexed.leafIndex[string(indexed.Leafs[1].Hash)]; got != 1 {
				t.Errorf("error: index points duplicate content at leaf %d, want 1", got)
			}

			wantPath, wantIndex, err := scanned.GetMerklePath(propContent{x: "dup"})
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			gotPath, gotIndex, err := indexed.GetMerklePath(propContent{x: "dup"})
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if len(gotPath) != len(wantPath) {
				t.Fatalf("error: path has %d entries, want %d", len(gotPath), len(wantPath))
			}
			for k := range wantPath {
				if !bytes.Equal(gotPath[k], wantPath[k]) || gotIndex[k] != wantIndex[k] {
					t.Errorf("error: level %d: (%x,%d), want (%x,%d)", k, gotPath[k], gotIndex[k], wantPath[k], wantIndex[k])
				}
			}

			// The proof has to be the one for leaf 1, which is what the scan
			// returns, rather than the one for leaf 3.
			byPos, _, err := indexed.GetMerklePathByIndex(1)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			for k := range byPos {
				if !bytes.Equal(gotPath[k], byPos[k]) {
					t.Fatalf("error: indexed lookup did not return the earliest leaf's proof")
				}
			}
		})
	}
}

// TestLeafIndexPaddingLeafNotPreferred pins the odd count case. The padding copy carries
// the same hash as the leaf it copies, and must not displace it in the index.
func TestLeafIndexPaddingLeafNotPreferred(t *testing.T) {
	contents := propSeries(3)
	tree, err := NewTreeWithOptions(contents, WithLeafIndex())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if len(tree.Leafs) != 4 {
		t.Fatalf("error: tree holds %d leaves, want 4", len(tree.Leafs))
	}
	if !tree.Leafs[3].dup {
		t.Fatal("error: leaf 3 is not the padding copy")
	}

	// Leaf 2 and leaf 3 share a hash; the index must hold 2.
	if got := tree.leafIndex[string(tree.Leafs[3].Hash)]; got != 2 {
		t.Errorf("error: index points the duplicated hash at leaf %d, want 2", got)
	}

	scanned, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	for i, c := range contents {
		want, _, err := scanned.GetMerklePath(c)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		got, _, err := tree.GetMerklePath(c)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		for k := range want {
			if !bytes.Equal(got[k], want[k]) {
				t.Errorf("error: leaf %d level %d: %x, want %x", i, k, got[k], want[k])
			}
		}
	}
}

// TestLeafIndexSurvivesRebuild covers the two rebuild entry points. A rebuilt tree must
// neither keep a stale index nor lose the one it was asked for.
func TestLeafIndexSurvivesRebuild(t *testing.T) {
	contents := propSeries(8)
	tree, err := NewTreeWithOptions(contents, WithLeafIndex())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	if err := tree.RebuildTree(); err != nil {
		t.Fatalf("error: RebuildTree: %v", err)
	}
	if tree.leafIndex == nil {
		t.Fatal("error: RebuildTree dropped the leaf index")
	}
	for i, c := range contents {
		if _, _, err := tree.GetMerklePath(c); err != nil {
			t.Fatalf("error: leaf %d after RebuildTree: %v", i, err)
		}
	}

	replacement := []Content{
		propContent{x: "x"},
		propContent{x: "y"},
		propContent{x: "z"},
	}
	if err := tree.RebuildTreeWith(replacement); err != nil {
		t.Fatalf("error: RebuildTreeWith: %v", err)
	}
	if tree.leafIndex == nil {
		t.Fatal("error: RebuildTreeWith dropped the leaf index")
	}
	// The index must describe the new content, not the old.
	for i, c := range replacement {
		if _, _, err := tree.GetMerklePath(c); err != nil {
			t.Fatalf("error: replacement %d: %v", i, err)
		}
	}
	for _, c := range contents {
		if _, _, err := tree.GetMerklePath(c); !errors.Is(err, ErrContentNotFound) {
			t.Errorf("error: stale index still resolves %v, want ErrContentNotFound", c)
		}
	}
	ok, err := tree.VerifyTree()
	if err != nil || !ok {
		t.Fatalf("error: rebuilt tree does not verify: %t %v", ok, err)
	}
}

// TestLeafIndexAbsentFromSerializedForm pins the documented behaviour that the index is
// a build property rather than part of the tree, exactly as parallelism is.
func TestLeafIndexAbsentFromSerializedForm(t *testing.T) {
	contents := propSeries(8)
	tree, err := NewTreeWithOptions(contents, WithLeafIndex())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	enc := func(c Content) ([]byte, error) { return []byte(c.(propContent).x), nil }
	dec := func(b []byte) (Content, error) { return propContent{x: string(b)}, nil }

	data, err := tree.MarshalWith(enc, WithHashStrategyName("sha256"))
	if err != nil {
		t.Fatalf("error: MarshalWith: %v", err)
	}

	got, err := UnmarshalWith(data, dec)
	if err != nil {
		t.Fatalf("error: UnmarshalWith: %v", err)
	}
	if got.leafIndex != nil {
		t.Error("error: the decoded tree carries a leaf index, which the wire format does not record")
	}
	if !bytes.Equal(got.MerkleRoot(), tree.MerkleRoot()) {
		t.Errorf("error: root %x, want %x", got.MerkleRoot(), tree.MerkleRoot())
	}
	// It still answers correctly, by scanning.
	for i, c := range contents {
		if _, _, err := got.GetMerklePath(c); err != nil {
			t.Fatalf("error: leaf %d: %v", i, err)
		}
	}
}

// TestLeafIndexErrorSurfaces pins which of the two Content methods a lookup can fail
// in, which is the one place the index is observably different from the scan.
//
// The scan calls Equals on each leaf and never hashes the query. The index hashes the
// query and never calls Equals. So a query whose CalculateHash fails is an error only
// on the indexed path, and one whose Equals fails is an error only on the scanning
// path. Neither is a defect - it follows from replacing the comparison with a hash -
// but it is behaviour worth holding still, so WithLeafIndex documents it.
func TestLeafIndexErrorSurfaces(t *testing.T) {
	contents := propSeries(4)
	scanned, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	indexed, err := NewTreeWithOptions(contents, WithLeafIndex())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	t.Run("failing hash", func(t *testing.T) {
		q := failingContent{x: "item-0", failHash: true}

		if _, _, err := indexed.GetMerklePath(q); err == nil {
			t.Error("error: expected the hashing error to surface from the indexed GetMerklePath")
		}
		if _, err := indexed.VerifyContent(q); err == nil {
			t.Error("error: expected the hashing error to surface from the indexed VerifyContent")
		}

		// The scan never hashes the query, so it reports a plain miss.
		if _, _, err := scanned.GetMerklePath(q); !errors.Is(err, ErrContentNotFound) {
			t.Errorf("error: scanned GetMerklePath returned %v, want ErrContentNotFound", err)
		}
	})

	t.Run("failing equals", func(t *testing.T) {
		// propContent.Equals is what the scan actually calls, so the failure has to
		// be planted in the tree rather than in the query.
		tree, err := NewTree([]Content{
			failingContent{x: "a", failEqual: true},
			failingContent{x: "b"},
		})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if _, _, err := tree.GetMerklePath(failingContent{x: "b"}); err == nil {
			t.Error("error: expected the Equals error to surface from the scanning GetMerklePath")
		}

		// With the index, Equals is never reached, so the same tree answers.
		indexedTree, err := NewTreeWithOptions([]Content{
			failingContent{x: "a", failEqual: true},
			failingContent{x: "b"},
		}, WithLeafIndex())
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if _, _, err := indexedTree.GetMerklePath(failingContent{x: "b"}); err != nil {
			t.Errorf("error: the indexed path should not reach the failing Equals, got %v", err)
		}
	})
}
