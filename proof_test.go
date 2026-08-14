// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"testing"
)

// optsFor returns the option list that reproduces a propMode's construction, which is
// what a verifier holding only a root and a proof would have to be told.
func optsFor(mode propMode, hs func() hash.Hash) []TreeOption {
	opts := []TreeOption{WithHasher(hs)}
	if mode.sorted {
		opts = append(opts, WithSortedSiblings())
	}
	if mode.rfc6962 {
		opts = append(opts, WithRFC6962())
	}

	return opts
}

// TestVerifyProofRoundTrip is the property that matters: every proof this package
// produces verifies against the root it was produced from, without the tree.
func TestVerifyProofRoundTrip(t *testing.T) {
	for _, s := range propStrategies {
		for _, mode := range propModes {
			for _, n := range propSizes {
				t.Run(fmt.Sprintf("%s/%s/n=%d", s.name, mode.name, n), func(t *testing.T) {
					contents := propSeries(n)
					tree, err := mode.build(contents, s.fn)
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}
					root := tree.MerkleRoot()
					opts := optsFor(mode, s.fn)

					for i, c := range contents {
						path, index, err := tree.GetMerklePath(c)
						if err != nil {
							t.Fatalf("error: GetMerklePath(%d): %v", i, err)
						}

						ok, err := VerifyProof(c, path, index, root, opts...)
						if err != nil {
							t.Fatalf("error: VerifyProof(%d): %v", i, err)
						}
						if !ok {
							t.Errorf("error: leaf %d: proof did not verify against the root it came from", i)
						}

						// The method form should agree, and needs no options.
						ok, err = tree.VerifyProof(c, path, index)
						if err != nil {
							t.Fatalf("error: tree.VerifyProof(%d): %v", i, err)
						}
						if !ok {
							t.Errorf("error: leaf %d: tree.VerifyProof rejected a proof from the same tree", i)
						}
					}
				})
			}
		}
	}
}

// TestVerifyProofWithDigestMatchesContent checks the two entry points agree, since the
// digest form is the one a verifier with no Content implementation would reach for.
func TestVerifyProofWithDigestMatchesContent(t *testing.T) {
	for _, mode := range propModes {
		t.Run(mode.name, func(t *testing.T) {
			contents := propSeries(12)
			tree, err := mode.build(contents, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			opts := optsFor(mode, sha256.New)

			for i, c := range contents {
				path, index, err := tree.GetMerklePath(c)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				digest, err := c.CalculateHash()
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}

				ok, err := VerifyProofWithDigest(digest, path, index, tree.MerkleRoot(), opts...)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if !ok {
					t.Errorf("error: leaf %d: the digest form rejected a valid proof", i)
				}
			}
		})
	}
}

// TestVerifyProofRejectsTampering is the other half of the property. A verifier that
// accepts everything is worse than none, so each of the ways a proof can be wrong is
// checked to be rejected.
func TestVerifyProofRejectsTampering(t *testing.T) {
	for _, mode := range propModes {
		t.Run(mode.name, func(t *testing.T) {
			contents := propSeries(16)
			tree, err := mode.build(contents, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			root := tree.MerkleRoot()
			opts := optsFor(mode, sha256.New)

			target := contents[5]
			path, index, err := tree.GetMerklePath(target)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if len(path) == 0 {
				t.Fatal("error: expected a non-empty path")
			}

			t.Run("wrong root", func(t *testing.T) {
				bad := append([]byte(nil), root...)
				bad[0] ^= 0xff
				ok, err := VerifyProof(target, path, index, bad, opts...)
				assertRejected(t, ok, err)
			})

			t.Run("tampered sibling", func(t *testing.T) {
				bad := clonePath(path)
				bad[0][0] ^= 0xff
				ok, err := VerifyProof(target, bad, index, root, opts...)
				assertRejected(t, ok, err)
			})

			t.Run("flipped side marker", func(t *testing.T) {
				bad := append([]int64(nil), index...)
				bad[0] ^= 1
				// Flipping the side changes the order the pair is hashed in, so it
				// must be rejected - except under WithSortedSiblings, where the pair
				// is ordered by value before hashing and the side marker carries no
				// information. That is a property of the sorted construction rather
				// than a weakness in verification, and is why a sorted root does not
				// commit to leaf order.
				ok, err := VerifyProof(target, path, bad, root, opts...)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if mode.sorted {
					if !ok {
						t.Error("error: under sorted siblings the side marker should not affect the result")
					}

					return
				}
				if ok {
					t.Error("error: a proof with a flipped side marker verified")
				}
			})

			t.Run("wrong content", func(t *testing.T) {
				ok, err := VerifyProof(propContent{x: "not in the tree"}, path, index, root, opts...)
				assertRejected(t, ok, err)
			})

			t.Run("truncated path", func(t *testing.T) {
				ok, err := VerifyProof(target, path[:len(path)-1], index[:len(index)-1], root, opts...)
				assertRejected(t, ok, err)
			})

			t.Run("proof from another leaf", func(t *testing.T) {
				other, otherIndex, err := tree.GetMerklePath(contents[6])
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				ok, err := VerifyProof(target, other, otherIndex, root, opts...)
				assertRejected(t, ok, err)
			})
		})
	}
}

// TestVerifyProofRejectsWrongConstruction covers the mistake a verifier is most likely
// to actually make: checking a proof under settings that do not match the tree that
// produced it. How completely that is caught depends on which setting is wrong, and the
// difference is worth pinning rather than glossing.
//
// Getting WithRFC6962 wrong is caught for every leaf. The leaf hash is prefixed under
// one construction and bare under the other, so nothing lines up.
//
// Getting WithSortedSiblings wrong is only caught for some. Sorting orders each pair by
// value before hashing, so a proof whose pairs already happen to be in that order at
// every level replays identically either way. Over a tree of any size some proofs are in
// that position and some are not, so the property that holds is that the mismatch is
// caught somewhere, not everywhere. This is not a weakness: a proof still has to
// reproduce the root, which the verifier obtained from somewhere it trusts.
func TestVerifyProofRejectsWrongConstruction(t *testing.T) {
	contents := propSeries(64)

	for _, tc := range []struct {
		name string
		// everyLeaf is set when the mismatch changes the hashing for every leaf,
		// rather than only for those whose pairs are reordered.
		everyLeaf bool
		build     []TreeOption
		check     []TreeOption
	}{
		{name: "default proof checked as rfc6962", everyLeaf: true, check: []TreeOption{WithRFC6962()}},
		{name: "rfc6962 proof checked as default", everyLeaf: true, build: []TreeOption{WithRFC6962()}},
		{name: "default proof checked as sorted", check: []TreeOption{WithSortedSiblings()}},
		{name: "sorted proof checked as default", build: []TreeOption{WithSortedSiblings()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := NewTreeWithOptions(contents, tc.build...)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			rejected := 0
			for i, c := range contents {
				path, index, err := tree.GetMerklePath(c)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				ok, err := VerifyProof(c, path, index, tree.MerkleRoot(), tc.check...)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if !ok {
					rejected++

					continue
				}
				if tc.everyLeaf {
					t.Errorf("error: leaf %d verified under the wrong construction", i)
				}
			}

			if rejected == 0 {
				t.Error("error: no proof was rejected under the wrong construction")
			}
			if tc.everyLeaf && rejected != len(contents) {
				t.Errorf("error: %d of %d proofs rejected, want all of them", rejected, len(contents))
			}
			t.Logf("%d of %d proofs rejected", rejected, len(contents))
		})
	}
}

// TestVerifyProofSingleLeafRFC6962 pins the empty audit path. A one leaf RFC 6962 tree
// has a root equal to its only leaf hash and nothing to walk, and a verifier has to
// handle that rather than treat an empty path as malformed.
func TestVerifyProofSingleLeafRFC6962(t *testing.T) {
	contents := propSeries(1)
	tree, err := NewTreeWithOptions(contents, WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	path, index, err := tree.GetMerklePath(contents[0])
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if len(path) != 0 {
		t.Fatalf("error: expected an empty audit path, got %d entries", len(path))
	}

	ok, err := VerifyProof(contents[0], path, index, tree.MerkleRoot(), WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !ok {
		t.Error("error: the single leaf proof did not verify")
	}
}

// TestVerifyProofMalformed separates "this proof is the wrong shape" from "this proof
// does not verify". The first is an error the caller has a bug to fix; the second is an
// ordinary false.
func TestVerifyProofMalformed(t *testing.T) {
	contents := propSeries(8)
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	path, index, err := tree.GetMerklePath(contents[0])
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	t.Run("length mismatch", func(t *testing.T) {
		if _, err := VerifyProof(contents[0], path, index[:len(index)-1], tree.MerkleRoot()); !errors.Is(err, ErrMalformedProof) {
			t.Errorf("error: got %v, want ErrMalformedProof", err)
		}
	})

	t.Run("bad side marker", func(t *testing.T) {
		bad := append([]int64(nil), index...)
		bad[0] = 7
		if _, err := VerifyProof(contents[0], path, bad, tree.MerkleRoot()); !errors.Is(err, ErrMalformedProof) {
			t.Errorf("error: got %v, want ErrMalformedProof", err)
		}
	})

	t.Run("nil content", func(t *testing.T) {
		if _, err := VerifyProof(nil, path, index, tree.MerkleRoot()); !errors.Is(err, ErrNilContent) {
			t.Errorf("error: got %v, want ErrNilContent", err)
		}
	})

	t.Run("hashing failure", func(t *testing.T) {
		if _, err := VerifyProof(failingContent{x: "a", failHash: true}, path, index, tree.MerkleRoot()); err == nil {
			t.Error("error: expected the hashing error to surface")
		}
	})

	t.Run("conflicting options", func(t *testing.T) {
		if _, err := VerifyProof(contents[0], path, index, tree.MerkleRoot(), WithRFC6962(), WithSortedSiblings()); err == nil {
			t.Error("error: expected the option conflict to be reported")
		}
	})
}

// TestVerifyProofIgnoresBuildOnlyOptions pins that the options describing how a tree is
// built rather than how it hashes are accepted and have no effect, so that one option
// list can be shared between the constructor and the verifier.
func TestVerifyProofIgnoresBuildOnlyOptions(t *testing.T) {
	contents := propSeries(9)
	opts := []TreeOption{WithRFC6962(), WithLeafIndex(), WithParallelism(2)}

	tree, err := NewTreeWithOptions(contents, opts...)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	path, index, err := tree.GetMerklePath(contents[3])
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	ok, err := VerifyProof(contents[3], path, index, tree.MerkleRoot(), opts...)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !ok {
		t.Error("error: the shared option list did not verify")
	}
}

// TestVerifyProofNeedsNoTree is the point of the whole file, written the way a caller
// would: nothing but a root, a proof and the content survives into the check.
func TestVerifyProofNeedsNoTree(t *testing.T) {
	root, path, index, content := func() ([]byte, [][]byte, []int64, Content) {
		contents := propSeries(37)
		tree, err := NewTreeWithOptions(contents, WithRFC6962())
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		p, i, err := tree.GetMerklePath(contents[21])
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}

		return tree.MerkleRoot(), p, i, contents[21]
	}()

	ok, err := VerifyProof(content, path, index, root, WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !ok {
		t.Error("error: the proof did not verify without the tree")
	}
}

func assertRejected(t *testing.T, ok bool, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if ok {
		t.Error("error: an invalid proof verified")
	}
}

func clonePath(path [][]byte) [][]byte {
	out := make([][]byte, 0, len(path))
	for _, p := range path {
		out = append(out, append([]byte(nil), p...))
	}

	return out
}
