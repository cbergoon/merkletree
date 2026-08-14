// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

// Package oracle checks merkletree's RFC 6962 construction against an outside
// implementation of the same specification, rather than against merkletree's own idea
// of what the answer should be.
//
// The rest of the test suite is self-referential in one specific way: it can prove the
// tree is internally consistent, that proofs replay to the root, that the same input
// gives the same output, but it cannot prove the construction is the one RFC 6962
// describes. A transposed pair of children or a leaf prefix on the wrong side of a
// digest would be perfectly self-consistent and would still be the wrong tree. Only
// something computed elsewhere can catch that.
//
// The oracle is github.com/transparency-dev/merkle, the implementation behind
// Certificate Transparency, used here in three independent forms:
//
//   - The known answer vectors in its testonly package. These are constants published
//     with the specification, not something any implementation computes at test time,
//     which makes them the strongest check available: a root either matches the number
//     in the RFC's ecosystem or it does not.
//   - Its reference tree, a deliberately naive implementation kept for testing.
//   - Its compact range implementation, which is what production Certificate
//     Transparency logs use and computes roots by an entirely different method,
//     accumulating perfect subtrees rather than recursing over a node list.
//
// Note that google/certificate-transparency-go is not used as a second oracle. As of
// v1.3.3 it no longer carries a Merkle tree of its own; it imports this same
// transparency-dev/merkle for the purpose. Testing against both would be testing
// against one implementation twice, at the cost of pulling in gRPC and protobuf.
package oracle

import (
	"bytes"
	"fmt"
	"testing"

	mt "github.com/cbergoon/merkletree"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// rawContent is the Content implementation these tests need, and the reason it is worth
// spelling out is that the comparison is only meaningful with this exact one.
//
// RFC 6962 hashes leaf data directly: the leaf hash is SHA-256(0x00 || data). merkletree
// hashes whatever Content.CalculateHash returns, so it computes SHA-256(0x00 ||
// CalculateHash(content)). The two agree only when CalculateHash is the identity
// function on the leaf bytes, which is what this type provides. A Content that digested
// its data first would build a perfectly valid tree that no Certificate Transparency log
// would recognise, and it would not be a defect in either implementation. WithRFC6962
// documents this; these tests depend on it.
type rawContent struct {
	data []byte
}

func (r rawContent) CalculateHash() ([]byte, error) {
	return r.data, nil
}

func (r rawContent) Equals(other mt.Content) (bool, error) {
	o, ok := other.(rawContent)
	if !ok {
		return false, nil
	}

	return bytes.Equal(r.data, o.data), nil
}

func contentsFrom(leaves [][]byte) []mt.Content {
	cs := make([]mt.Content, 0, len(leaves))
	for _, l := range leaves {
		cs = append(cs, rawContent{data: l})
	}

	return cs
}

// seriesLeaves returns n distinct leaves. The contents are arbitrary; what matters is
// that both implementations are fed the same bytes.
func seriesLeaves(n int) [][]byte {
	leaves := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		leaves = append(leaves, []byte(fmt.Sprintf("leaf-%d", i)))
	}

	return leaves
}

// oracleSizes covers the shapes an RFC 6962 tree can take: powers of two, one either
// side of them, primes, and enough odd counts to exercise the split at the largest
// power of two below the length several levels deep.
var oracleSizes = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17,
	23, 31, 32, 33, 47, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 1000,
}

// TestKnownAnswerVectors is the anchor of the file. The roots here are constants from
// the Certificate Transparency test corpus, so agreement is agreement with the
// specification itself rather than with another program's reading of it.
func TestKnownAnswerVectors(t *testing.T) {
	leaves := testonly.LeafInputs()
	roots := testonly.RootHashes()

	// RootHashes is indexed by tree size, starting at the empty tree. merkletree
	// cannot represent an empty tree - NewTree reports ErrNoContent - so the empty
	// root is checked separately below and the loop starts at one.
	for n := 1; n <= len(leaves); n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			tree, err := mt.NewTreeWithOptions(contentsFrom(leaves[:n]), mt.WithRFC6962())
			if err != nil {
				t.Fatalf("error: building a tree of %d leaves: %v", n, err)
			}
			if got, want := tree.MerkleRoot(), roots[n]; !bytes.Equal(got, want) {
				t.Errorf("error: root %x, want the published value %x", got, want)
			}
		})
	}

	t.Run("empty is rejected rather than answered", func(t *testing.T) {
		// The specification defines the root of an empty tree as the hash of the
		// empty string. merkletree declines to build one at all, which is a
		// deliberate difference worth pinning: a caller porting from a CT log
		// should find out here rather than by getting a surprising root.
		if _, err := mt.NewTreeWithOptions(nil, mt.WithRFC6962()); err == nil {
			t.Error("error: expected an empty content list to be rejected")
		}
	})
}

// TestKnownAnswerLeafHashes checks the level below the root. A root can match by luck of
// cancelling errors far more easily than every leaf hash can, and NodeHashes gives the
// published leaf digests directly.
func TestKnownAnswerLeafHashes(t *testing.T) {
	leaves := testonly.LeafInputs()
	nodes := testonly.NodeHashes()
	leafLevel := nodes[0]

	tree, err := mt.NewTreeWithOptions(contentsFrom(leaves), mt.WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if len(tree.Leafs) != len(leafLevel) {
		t.Fatalf("error: tree holds %d leaves, want %d", len(tree.Leafs), len(leafLevel))
	}

	for i, leaf := range tree.Leafs {
		if !bytes.Equal(leaf.Hash, leafLevel[i]) {
			t.Errorf("error: leaf %d hashed to %x, want the published value %x", i, leaf.Hash, leafLevel[i])
		}
	}
}

// TestAgainstReferenceTree compares against the oracle's own reference implementation
// over a wide range of sizes, which the fixed vectors cannot reach: they stop at eight
// leaves, and the interesting splits start above that.
func TestAgainstReferenceTree(t *testing.T) {
	for _, n := range oracleSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := seriesLeaves(n)

			ref := testonly.New(rfc6962.DefaultHasher)
			ref.AppendData(leaves...)

			tree, err := mt.NewTreeWithOptions(contentsFrom(leaves), mt.WithRFC6962())
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if got, want := tree.MerkleRoot(), ref.Hash(); !bytes.Equal(got, want) {
				t.Errorf("error: root %x, want %x", got, want)
			}
		})
	}
}

// TestAgainstCompactRange compares against the compact range implementation. It arrives
// at the root by accumulating perfect subtrees as leaves are appended, where merkletree
// recurses over a complete node list splitting at the largest power of two below its
// length. Two routes to the same number is what makes the agreement worth something.
func TestAgainstCompactRange(t *testing.T) {
	factory := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

	for _, n := range oracleSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := seriesLeaves(n)

			rng := factory.NewEmptyRange(0)
			for _, l := range leaves {
				if err := rng.Append(rfc6962.DefaultHasher.HashLeaf(l), nil); err != nil {
					t.Fatalf("error: appending to the compact range: %v", err)
				}
			}
			want, err := rng.GetRootHash(nil)
			if err != nil {
				t.Fatalf("error: computing the compact range root: %v", err)
			}

			tree, err := mt.NewTreeWithOptions(contentsFrom(leaves), mt.WithRFC6962())
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if got := tree.MerkleRoot(); !bytes.Equal(got, want) {
				t.Errorf("error: root %x, want %x", got, want)
			}
		})
	}
}

// TestInclusionProofsMatchOracle checks the audit paths rather than the roots. A tree
// can have the right root and still hand out proofs in the wrong order or from the
// wrong siblings, and every internal test of the proof path replays it through this
// package's own hashing, so it would not notice.
//
// The oracle returns the sibling hashes bottom up, which is the order GetMerklePath
// produces them in, so the two are compared entry for entry.
func TestInclusionProofsMatchOracle(t *testing.T) {
	for _, n := range oracleSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := seriesLeaves(n)

			ref := testonly.New(rfc6962.DefaultHasher)
			ref.AppendData(leaves...)

			tree, err := mt.NewTreeWithOptions(contentsFrom(leaves), mt.WithRFC6962())
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			for i := 0; i < n; i++ {
				want, err := ref.InclusionProof(uint64(i), uint64(n))
				if err != nil {
					t.Fatalf("error: oracle inclusion proof for leaf %d: %v", i, err)
				}

				got, _, err := tree.GetMerklePathByIndex(i)
				if err != nil {
					t.Fatalf("error: GetMerklePathByIndex(%d): %v", i, err)
				}

				if len(got) != len(want) {
					t.Fatalf("error: leaf %d: proof has %d entries, want %d", i, len(got), len(want))
				}
				for k := range want {
					if !bytes.Equal(got[k], want[k]) {
						t.Errorf("error: leaf %d level %d: sibling %x, want %x", i, k, got[k], want[k])
					}
				}
			}
		})
	}
}

// TestLookupRoutesAgreeWithOracle runs the same comparison through GetMerklePath, so
// that the content lookup and the leaf index are covered by the oracle too rather than
// only by this package's own equivalence tests.
func TestLookupRoutesAgreeWithOracle(t *testing.T) {
	const n = 100
	leaves := seriesLeaves(n)

	ref := testonly.New(rfc6962.DefaultHasher)
	ref.AppendData(leaves...)

	for _, tc := range []struct {
		name string
		opts []mt.TreeOption
	}{
		{name: "scan", opts: []mt.TreeOption{mt.WithRFC6962()}},
		{name: "leafindex", opts: []mt.TreeOption{mt.WithRFC6962(), mt.WithLeafIndex()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := mt.NewTreeWithOptions(contentsFrom(leaves), tc.opts...)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if got, want := tree.MerkleRoot(), ref.Hash(); !bytes.Equal(got, want) {
				t.Fatalf("error: root %x, want %x", got, want)
			}

			for i, l := range leaves {
				want, err := ref.InclusionProof(uint64(i), uint64(n))
				if err != nil {
					t.Fatalf("error: oracle inclusion proof for leaf %d: %v", i, err)
				}
				got, _, err := tree.GetMerklePath(rawContent{data: l})
				if err != nil {
					t.Fatalf("error: GetMerklePath for leaf %d: %v", i, err)
				}
				if len(got) != len(want) {
					t.Fatalf("error: leaf %d: proof has %d entries, want %d", i, len(got), len(want))
				}
				for k := range want {
					if !bytes.Equal(got[k], want[k]) {
						t.Errorf("error: leaf %d level %d: sibling %x, want %x", i, k, got[k], want[k])
					}
				}
			}
		})
	}
}

// rfc6962PathSides derives which side each audit path entry sits on, transcribed from
// the PATH function in RFC 6962 section 2.1.1 rather than taken from the tree under
// test:
//
//	PATH(m, D[n]) = {} for n == 1
//	PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])    for m < k
//	PATH(m, D[n]) = PATH(m-k, D[k:n]) : MTH(D[0:k])  otherwise
//
// where k is the largest power of two less than n. In the first case the appended
// sibling is the right hand subtree, which merkletree records as 1; in the second it is
// the left hand subtree, recorded as 0. The recursion appends as it unwinds, so the
// deepest sibling comes first, which is the order GetMerklePath returns.
func rfc6962PathSides(m, n int) []int64 {
	if n == 1 {
		return nil
	}

	k := 1
	for k<<1 < n {
		k <<= 1
	}
	if m < k {
		return append(rfc6962PathSides(m, k), 1)
	}

	return append(rfc6962PathSides(m-k, n-k), 0)
}

// TestVerifyProofAgainstOracleProofs is the strongest check available for the standalone
// verifier: it replays the oracle's audit paths against the oracle's root, with the side
// markers derived from the specification rather than from the tree being tested.
//
// Every input to VerifyProof here comes from outside merkletree except the content
// itself. If the verifier disagreed with RFC 6962 about the order a pair is hashed in,
// about the leaf prefix, or about which side a sibling sits on, nothing in this call
// would line up and the replay would miss the root.
func TestVerifyProofAgainstOracleProofs(t *testing.T) {
	for _, n := range oracleSizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := seriesLeaves(n)

			ref := testonly.New(rfc6962.DefaultHasher)
			ref.AppendData(leaves...)
			oracleRoot := ref.Hash()

			// Built only to confirm the derived side markers match what this package
			// produces; the verification below uses the oracle's path and root.
			tree, err := mt.NewTreeWithOptions(contentsFrom(leaves), mt.WithRFC6962())
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			for i := 0; i < n; i++ {
				oraclePath, err := ref.InclusionProof(uint64(i), uint64(n))
				if err != nil {
					t.Fatalf("error: oracle inclusion proof for leaf %d: %v", i, err)
				}
				sides := rfc6962PathSides(i, n)

				if len(sides) != len(oraclePath) {
					t.Fatalf("error: leaf %d: derived %d side markers for a path of %d",
						i, len(sides), len(oraclePath))
				}
				_, ourSides, err := tree.GetMerklePathByIndex(i)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				for k := range sides {
					if sides[k] != ourSides[k] {
						t.Errorf("error: leaf %d level %d: this package says side %d, "+
							"RFC 6962 PATH says %d", i, k, ourSides[k], sides[k])
					}
				}

				ok, err := mt.VerifyProof(rawContent{data: leaves[i]}, oraclePath, sides, oracleRoot, mt.WithRFC6962())
				if err != nil {
					t.Fatalf("error: VerifyProof for leaf %d: %v", i, err)
				}
				if !ok {
					t.Errorf("error: leaf %d: the oracle's own proof did not verify against the oracle's own root", i)
				}
			}
		})
	}
}

// TestVerifyProofRejectsOracleProofsForOtherLeaves confirms the check above is not
// passing because the verifier accepts anything.
func TestVerifyProofRejectsOracleProofsForOtherLeaves(t *testing.T) {
	const n = 37
	leaves := seriesLeaves(n)

	ref := testonly.New(rfc6962.DefaultHasher)
	ref.AppendData(leaves...)
	oracleRoot := ref.Hash()

	for i := 0; i < n; i++ {
		oraclePath, err := ref.InclusionProof(uint64(i), uint64(n))
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		sides := rfc6962PathSides(i, n)

		// The proof for leaf i, presented for the content of a different leaf.
		other := (i + 1) % n
		ok, err := mt.VerifyProof(rawContent{data: leaves[other]}, oraclePath, sides, oracleRoot, mt.WithRFC6962())
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if ok {
			t.Errorf("error: leaf %d's proof verified for leaf %d's content", i, other)
		}
	}
}

// TestOracleIsDiscriminating is the negative control, and without it the rest of the
// file proves less than it appears to. If the oracle agreed with merkletree whatever
// merkletree did, every test above would pass while catching nothing.
//
// The default construction differs from RFC 6962 in exactly the two ways WithRFC6962
// documents: no domain separation between leaf and interior hashes, and odd node counts
// duplicated rather than split. So the default tree must disagree with the oracle at
// every size where those differences can show, and the point of asserting it is that a
// regression which quietly turned RFC 6962 mode back into the default one would be
// caught here.
func TestOracleIsDiscriminating(t *testing.T) {
	for _, n := range []int{2, 3, 5, 7, 8, 13, 100} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := seriesLeaves(n)

			ref := testonly.New(rfc6962.DefaultHasher)
			ref.AppendData(leaves...)

			plain, err := mt.NewTree(contentsFrom(leaves))
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if bytes.Equal(plain.MerkleRoot(), ref.Hash()) {
				t.Errorf("error: the default construction matched the RFC 6962 oracle at n=%d, "+
					"which means the oracle cannot tell the two constructions apart", n)
			}
		})
	}
}
