// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
)

// The rest of the suite is largely self-referential: it builds a tree with this
// package and checks the result against something else this package computed. That
// catches inconsistency but not drift - a change that alters every construction at
// once would keep all of those tests green while silently changing the roots users
// have already published.
//
// The tests here close that gap in two ways. referenceRoot reimplements each
// construction straight from its definition, sharing no code with the tree builder,
// and the golden values below were computed by a third implementation outside this
// repository entirely. A change to the hashing has to be made in three places, one
// of which is not in Go, before it can go unnoticed.

// referenceRoot computes the Merkle root of leafHashes the direct way: build a level
// at a time, combining adjacent pairs, until one hash remains. It shares nothing with
// buildIntermediate, buildRFC6962, or hashInterior.
//
// leafHashes are the digests Content.CalculateHash returned, before any RFC 6962 leaf
// prefixing, which this function applies itself.
func referenceRoot(leafHashes [][]byte, mode propMode, hs func() hash.Hash) []byte {
	if mode.rfc6962 {
		prefixed := make([][]byte, 0, len(leafHashes))
		for _, d := range leafHashes {
			h := hs()
			h.Write([]byte{0x00})
			h.Write(d)
			prefixed = append(prefixed, h.Sum(nil))
		}

		return referenceRFC6962(prefixed, hs)
	}

	level := make([][]byte, len(leafHashes))
	copy(level, leafHashes)
	// A lone leaf is paired with itself, so the root of a one item tree is one level
	// up from the leaf rather than the leaf itself.
	if len(level) == 1 {
		level = append(level, level[0])
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // an odd count pairs the last node with itself
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, referenceCombine(left, right, mode.sorted, hs))
		}
		level = next
	}

	return level[0]
}

// referenceRFC6962 is MTH from RFC 6962 section 2.1, transcribed directly.
func referenceRFC6962(d [][]byte, hs func() hash.Hash) []byte {
	if len(d) == 1 {
		return d[0]
	}

	k := 1
	for k*2 < len(d) {
		k *= 2
	}

	h := hs()
	h.Write([]byte{0x01})
	h.Write(referenceRFC6962(d[:k], hs))
	h.Write(referenceRFC6962(d[k:], hs))

	return h.Sum(nil)
}

// referenceCombine hashes a sibling pair. Sorted mode orders the pair ascending,
// which is the OpenZeppelin MerkleProof convention. The package compares the pair as
// big-endian integers; comparing them as bytes is the same ordering for digests of
// equal length, and checking it here also confirms that equivalence holds.
func referenceCombine(left, right []byte, sorted bool, hs func() hash.Hash) []byte {
	if sorted && bytes.Compare(left, right) > 0 {
		left, right = right, left
	}

	h := hs()
	h.Write(left)
	h.Write(right)

	return h.Sum(nil)
}

// TestGoldenRootsMatchAnIndependentImplementation checks every construction, hash
// strategy, and leaf count against referenceRoot. Sizes that pad at the leaf level,
// sizes that pad at an interior level, and RFC 6962's unbalanced splits are all
// covered by propSizes.
func TestGoldenRootsMatchAnIndependentImplementation(t *testing.T) {
	eachTree(t, func(t *testing.T, tree *MerkleTree, contents []Content, hs func() hash.Hash, mode propMode) {
		leafHashes := make([][]byte, 0, len(contents))
		for i, c := range contents {
			d, err := c.CalculateHash()
			if err != nil {
				t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
			}
			leafHashes = append(leafHashes, d)
		}

		want := referenceRoot(leafHashes, mode, hs)
		if !bytes.Equal(tree.MerkleRoot(), want) {
			t.Errorf("error: root disagrees with the reference construction:\n got %x\nwant %x",
				tree.MerkleRoot(), want)
		}
	})
}

// goldenRoots pins concrete roots for concrete inputs. Every value was computed by an
// implementation outside this repository, so a change to the construction shows up
// here as a mismatch rather than as a quietly updated expectation.
var goldenRoots = []struct {
	name  string
	items []string
	mode  propMode
	root  string
}{
	// Bitcoin-style: SHA-256 leaves, odd levels pair the last node with itself.
	{
		name:  "default/Hello,Hi,Hey",
		items: []string{"Hello", "Hi", "Hey"},
		mode:  propMode{},
		root:  "bdd637c523ed5c0eab792b986db18850c239a2e23802b36aff26bb68fb3fe008",
	},
	// Sorted siblings, the ordering OpenZeppelin's MerkleProof library verifies
	// against. A regression here breaks proofs consumed by on-chain verifiers.
	{
		name:  "sorted/A,B,C,D",
		items: []string{"A", "B", "C", "D"},
		mode:  propMode{sorted: true},
		root:  "c8f544cf6452807ca62fe6a50477d19faca3147959aa206efab622d394f40097",
	},
	// RFC 6962 with a leaf count that is not a power of two, so the 4/1 split is
	// part of what the value pins.
	{
		name:  "rfc6962/A,B,C,D,E",
		items: []string{"A", "B", "C", "D", "E"},
		mode:  propMode{rfc6962: true},
		root:  "9cbbb87e40ba63c762506388da6413c90e33f27c9b5c52b0b88e4c524eb5b3d4",
	},
}

func TestGoldenRootsArePinned(t *testing.T) {
	for _, tc := range goldenRoots {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.root)
			if err != nil {
				t.Fatalf("error: bad golden value: %v", err)
			}

			contents := make([]Content, 0, len(tc.items))
			for _, x := range tc.items {
				contents = append(contents, TestSHA256Content{x: x})
			}
			tree, err := tc.mode.build(contents, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if !bytes.Equal(tree.MerkleRoot(), want) {
				t.Errorf("error: root changed:\n got %x\nwant %x", tree.MerkleRoot(), want)
			}
		})
	}
}

// goldenPayloads freezes the binary wire format. TestEncodingIsDeterministic proves
// that one build encodes a tree the same way twice; only a payload written by an
// earlier build can prove that this build still reads what that one wrote. Without
// this, a change to the framing - field order, the flag bytes, the varint lengths -
// would pass the entire suite while orphaning every payload already on disk.
//
// Regenerating these values to make a failing test pass is a wire format break. Bump
// serializationVersion instead, and keep the old payload here as a decode test.
var goldenPayloads = []struct {
	name string
	hex  string
	root string
	// items is what the payload must decode back to, in order.
	items []string
}{
	{
		name:  "v2/default/Hello,Hi,Hey",
		root:  "bdd637c523ed5c0eab792b986db18850c239a2e23802b36aff26bb68fb3fe008",
		items: []string{"Hello", "Hi", "Hey"},
		hex: "4d545245450206736861323536000020bdd637c523ed5c0eab792b986db18850c239a2e2" +
			"3802b36aff26bb68fb3fe00803306769746875622e636f6d2f63626572676f6f6e2f6d6572" +
			"6b6c65747265652e54657374534841323536436f6e74656e740548656c6c6f30676974687" +
			"5622e636f6d2f63626572676f6f6e2f6d65726b6c65747265652e54657374534841323536" +
			"436f6e74656e74024869306769746875622e636f6d2f63626572676f6f6e2f6d65726b6c65" +
			"747265652e54657374534841323536436f6e74656e7403486579",
	},
	{
		name:  "v2/sorted/A,B,C,D",
		root:  "c8f544cf6452807ca62fe6a50477d19faca3147959aa206efab622d394f40097",
		items: []string{"A", "B", "C", "D"},
		hex: "4d545245450206736861323536010020c8f544cf6452807ca62fe6a50477d19faca31479" +
			"59aa206efab622d394f4009704306769746875622e636f6d2f63626572676f6f6e2f6d6572" +
			"6b6c65747265652e54657374534841323536436f6e74656e740141306769746875622e636f" +
			"6d2f63626572676f6f6e2f6d65726b6c65747265652e54657374534841323536436f6e7465" +
			"6e740142306769746875622e636f6d2f63626572676f6f6e2f6d65726b6c65747265652e54" +
			"657374534841323536436f6e74656e740143306769746875622e636f6d2f63626572676f6f" +
			"6e2f6d65726b6c65747265652e54657374534841323536436f6e74656e740144",
	},
	{
		name:  "v2/rfc6962/A,B,C,D,E",
		root:  "9cbbb87e40ba63c762506388da6413c90e33f27c9b5c52b0b88e4c524eb5b3d4",
		items: []string{"A", "B", "C", "D", "E"},
		hex: "4d5452454502067368613235360001209cbbb87e40ba63c762506388da6413c90e33f27c" +
			"9b5c52b0b88e4c524eb5b3d405306769746875622e636f6d2f63626572676f6f6e2f6d6572" +
			"6b6c65747265652e54657374534841323536436f6e74656e740141306769746875622e636f" +
			"6d2f63626572676f6f6e2f6d65726b6c65747265652e54657374534841323536436f6e7465" +
			"6e740142306769746875622e636f6d2f63626572676f6f6e2f6d65726b6c65747265652e54" +
			"657374534841323536436f6e74656e740143306769746875622e636f6d2f63626572676f6f" +
			"6e2f6d65726b6c65747265652e54657374534841323536436f6e74656e74014430676974687" +
			"5622e636f6d2f63626572676f6f6e2f6d65726b6c65747265652e54657374534841323536" +
			"436f6e74656e740145",
	},
}

func TestGoldenPayloadsStillDecode(t *testing.T) {
	for _, tc := range goldenPayloads {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("error: bad golden payload: %v", err)
			}
			wantRoot, err := hex.DecodeString(tc.root)
			if err != nil {
				t.Fatalf("error: bad golden root: %v", err)
			}

			var tree MerkleTree
			if err := tree.UnmarshalBinary(data); err != nil {
				t.Fatalf("error: a payload written by an earlier build no longer decodes: %v", err)
			}
			if !bytes.Equal(tree.MerkleRoot(), wantRoot) {
				t.Errorf("error: root changed:\n got %x\nwant %x", tree.MerkleRoot(), wantRoot)
			}
			if len(tree.Leafs) < len(tc.items) {
				t.Fatalf("error: expected at least %d leaves, got %d", len(tc.items), len(tree.Leafs))
			}
			for i, want := range tc.items {
				got, ok := tree.Leafs[i].C.(TestSHA256Content)
				if !ok {
					t.Fatalf("error: leaf %d decoded to %T, want TestSHA256Content", i, tree.Leafs[i].C)
				}
				if got.x != want {
					t.Errorf("error: leaf %d is %q, want %q", i, got.x, want)
				}
			}

			ok, err := tree.VerifyTree()
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if !ok {
				t.Error("error: a tree decoded from a golden payload failed to verify")
			}

			// The format is canonical, so re-encoding must reproduce the frozen
			// bytes exactly.
			again, err := tree.MarshalBinary()
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if !bytes.Equal(again, data) {
				t.Errorf("error: re-encoding a golden payload changed it:\n got %x\nwant %x", again, data)
			}
		})
	}
}

// TestGoldenProofsReplayToTheGoldenRoot checks the other half of the contract: not
// just that the root is stable, but that the audit paths handed to a third party
// still reconstruct it. replayProof is an independent verifier, so this is the same
// computation a consumer of these proofs would perform.
func TestGoldenProofsReplayToTheGoldenRoot(t *testing.T) {
	for _, tc := range goldenRoots {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.root)
			if err != nil {
				t.Fatalf("error: bad golden value: %v", err)
			}

			contents := make([]Content, 0, len(tc.items))
			for _, x := range tc.items {
				contents = append(contents, TestSHA256Content{x: x})
			}
			tree, err := tc.mode.build(contents, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			for i, c := range contents {
				path, index, err := tree.GetMerklePath(c)
				if err != nil {
					t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
				}
				leafHash, err := c.CalculateHash()
				if err != nil {
					t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
				}
				got, err := replayProof(leafHash, path, index, sha256.New, tc.mode)
				if err != nil {
					t.Fatalf("[content:%d] error: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("[content:%d] error: proof replayed to %x, want %x", i, got, want)
				}
			}
		})
	}
}

// TestReferenceRootRejectsATamperedLeaf is a sanity check on the reference
// implementation itself: a cross-check is only worth having if it can fail. Changing
// any single leaf must change the root it computes, in every construction.
func TestReferenceRootRejectsATamperedLeaf(t *testing.T) {
	for _, mode := range propModes {
		for _, n := range []int{1, 2, 3, 5, 8} {
			t.Run(fmt.Sprintf("%s/n=%d", mode.name, n), func(t *testing.T) {
				leafHashes := make([][]byte, 0, n)
				for i := 0; i < n; i++ {
					d, err := propContent{x: fmt.Sprintf("item-%d", i)}.CalculateHash()
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}
					leafHashes = append(leafHashes, d)
				}
				base := referenceRoot(leafHashes, mode, sha256.New)

				for i := range leafHashes {
					tampered := make([][]byte, len(leafHashes))
					copy(tampered, leafHashes)
					flipped := bytes.Clone(tampered[i])
					flipped[0] ^= 0x01
					tampered[i] = flipped

					if bytes.Equal(referenceRoot(tampered, mode, sha256.New), base) {
						t.Errorf("error: flipping leaf %d left the reference root unchanged", i)
					}
				}
			})
		}
	}
}
