// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"sync"
	"testing"
)

// This file holds property and invariant tests that exercise the tree across the
// full matrix of hash strategies, sort settings and sizes, rather than against a
// handful of fixed vectors. Tests named TestProperty assert guarantees the library
// makes. Tests named TestDocumented pin behaviour that is a deliberate consequence
// of the Bitcoin-style construction: they are characterisation tests, present so
// that changing the behaviour has to be a decision rather than an accident.

// propContent is a well behaved Content implementation: Equals and CalculateHash
// agree, and Equals tolerates being handed a foreign type.
type propContent struct {
	x string
}

func (t propContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (t propContent) Equals(other Content) (bool, error) {
	o, ok := other.(propContent)
	if !ok {
		return false, nil
	}

	return t.x == o.x, nil
}

// staticContent returns a caller supplied hash verbatim, which allows a test to
// place an arbitrary digest at a leaf position.
type staticContent struct {
	name string
	hash []byte
}

func (t staticContent) CalculateHash() ([]byte, error) { return t.hash, nil }

func (t staticContent) Equals(other Content) (bool, error) {
	o, ok := other.(staticContent)

	return ok && t.name == o.name, nil
}

// failingContent fails on demand so error paths can be exercised.
type failingContent struct {
	x         string
	failHash  bool
	failEqual bool
}

func (t failingContent) CalculateHash() ([]byte, error) {
	if t.failHash {
		return nil, errors.New("calculate hash failed")
	}
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (t failingContent) Equals(other Content) (bool, error) {
	if t.failEqual {
		return false, errors.New("equals failed")
	}
	o, ok := other.(failingContent)
	if !ok {
		return false, nil
	}

	return t.x == o.x, nil
}

func propList(xs ...string) []Content {
	cs := make([]Content, 0, len(xs))
	for _, x := range xs {
		cs = append(cs, propContent{x: x})
	}

	return cs
}

func propSeries(n int) []Content {
	cs := make([]Content, 0, n)
	for i := 0; i < n; i++ {
		cs = append(cs, propContent{x: fmt.Sprintf("item-%d", i)})
	}

	return cs
}

var propStrategies = []struct {
	name string
	fn   func() hash.Hash
}{
	{"sha256", sha256.New},
	{"sha512", sha512.New},
	{"sha1", sha1.New},
	{"md5", md5.New},
}

// propSizes covers powers of two, odd counts that trigger leaf padding, and counts
// that force padding at an interior level rather than among the leaves. Under
// RFC 6962 the same counts exercise every shape of unbalanced split.
var propSizes = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 17, 31, 32, 33, 64}

// propMode is one of the constructions the tree supports. Every property below is
// asserted against all of them.
type propMode struct {
	name    string
	sorted  bool
	rfc6962 bool
}

var propModes = []propMode{
	{name: "default"},
	{name: "sorted", sorted: true},
	{name: "rfc6962", rfc6962: true},
}

func (m propMode) build(cs []Content, hs func() hash.Hash) (*MerkleTree, error) {
	opts := []TreeOption{WithHasher(hs)}
	if m.sorted {
		opts = append(opts, WithSortedSiblings())
	}
	if m.rfc6962 {
		opts = append(opts, WithRFC6962())
	}

	return NewTreeWithOptions(cs, opts...)
}

// eachTree runs fn against every combination of strategy, construction and size.
func eachTree(t *testing.T, fn func(t *testing.T, tree *MerkleTree, contents []Content, hs func() hash.Hash, mode propMode)) {
	t.Helper()
	for _, s := range propStrategies {
		for _, mode := range propModes {
			for _, n := range propSizes {
				name := fmt.Sprintf("%s/%s/n=%d", s.name, mode.name, n)
				t.Run(name, func(t *testing.T) {
					contents := propSeries(n)
					tree, err := mode.build(contents, s.fn)
					if err != nil {
						t.Fatalf("error: unexpected error: %v", err)
					}
					fn(t, tree, contents, s.fn, mode)
				})
			}
		}
	}
}

// replayProof recomputes a root from a leaf hash and the proof returned by
// GetMerklePath, mirroring what an independent verifier would do. It deliberately
// reimplements the hashing rather than calling into the package, so a change to the
// construction has to be made in two places to go unnoticed.
func replayProof(leafHash []byte, path [][]byte, index []int64, hs func() hash.Hash, mode propMode) ([]byte, error) {
	if len(path) != len(index) {
		return nil, fmt.Errorf("path has %d entries but index has %d", len(path), len(index))
	}

	current := leafHash
	if mode.rfc6962 {
		h := hs()
		h.Write([]byte{0x00})
		h.Write(leafHash)
		current = h.Sum(nil)
	}

	for k := range path {
		left, right := current, path[k]
		if index[k] != 1 { // sibling is the left hand node
			left, right = path[k], current
		}

		h := hs()
		switch {
		case mode.rfc6962:
			h.Write([]byte{0x01})
			h.Write(left)
			h.Write(right)
		case mode.sorted:
			h.Write(sortAppend(true, current, path[k]))
		default:
			h.Write(left)
			h.Write(right)
		}
		current = h.Sum(nil)
	}

	return current, nil
}

// TestPropertyTreeIsSelfConsistent checks the guarantees that should hold for any
// tree: it verifies, every member verifies, and every proof replays to the root.
func TestPropertyTreeIsSelfConsistent(t *testing.T) {
	eachTree(t, func(t *testing.T, tree *MerkleTree, contents []Content, hs func() hash.Hash, mode propMode) {
		if len(tree.MerkleRoot()) == 0 {
			t.Fatal("error: expected a non empty merkle root")
		}

		ok, err := tree.VerifyTree()
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if !ok {
			t.Error("error: expected tree to verify")
		}

		for i, c := range contents {
			ok, err := tree.VerifyContent(c)
			if err != nil {
				t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
			}
			if !ok {
				t.Errorf("[content:%d] error: expected content to verify", i)
			}

			path, index, err := tree.GetMerklePath(c)
			if err != nil {
				t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
			}
			// A single leaf RFC 6962 tree is its own root, so its audit path is
			// legitimately empty. Every other tree has at least one sibling.
			if len(path) == 0 && !(mode.rfc6962 && len(contents) == 1) {
				t.Fatalf("[content:%d] error: expected a non empty merkle path", i)
			}

			leafHash, err := c.CalculateHash()
			if err != nil {
				t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
			}
			replayed, err := replayProof(leafHash, path, index, hs, mode)
			if err != nil {
				t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
			}
			if !bytes.Equal(replayed, tree.MerkleRoot()) {
				t.Errorf("[content:%d] error: proof replayed to %v, expected %v", i, replayed, tree.MerkleRoot())
			}
		}

		// RFC 6962 splits rather than pads, so Leafs holds exactly what was supplied.
		if mode.rfc6962 && len(tree.Leafs) != len(contents) {
			t.Errorf("error: expected %d leaves, got %d", len(contents), len(tree.Leafs))
		}
		if mode.rfc6962 {
			for i, l := range tree.Leafs {
				if l.dup {
					t.Errorf("[leaf:%d] error: RFC 6962 trees must not contain padding leaves", i)
				}
			}
		}
	})
}

// TestPropertyRootIsDeterministic checks that identical content always yields an
// identical root, and that content absent from the tree is rejected.
func TestPropertyRootIsDeterministic(t *testing.T) {
	eachTree(t, func(t *testing.T, tree *MerkleTree, contents []Content, hs func() hash.Hash, mode propMode) {
		again, err := mode.build(contents, hs)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if !bytes.Equal(tree.MerkleRoot(), again.MerkleRoot()) {
			t.Errorf("error: rebuilding the same content produced a different root")
		}

		ok, err := tree.VerifyContent(propContent{x: "definitely-not-in-the-tree"})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if ok {
			t.Error("error: expected absent content to be rejected")
		}
	})
}

// TestPropertyEveryLeafAffectsTheRoot checks the avalanche property: changing any
// single leaf must change the root.
func TestPropertyEveryLeafAffectsTheRoot(t *testing.T) {
	for _, mode := range propModes {
		for _, n := range []int{1, 2, 3, 5, 8, 17} {
			base := propSeries(n)
			baseTree, err := mode.build(base, sha256.New)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			for i := 0; i < n; i++ {
				mutated := make([]Content, len(base))
				copy(mutated, base)
				mutated[i] = propContent{x: fmt.Sprintf("mutated-%d", i)}

				tree, err := mode.build(mutated, sha256.New)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if bytes.Equal(baseTree.MerkleRoot(), tree.MerkleRoot()) {
					t.Errorf("[%s n:%d leaf:%d] error: changing a leaf left the root unchanged", mode.name, n, i)
				}
			}
		}
	}
}

// TestPropertyUnsortedRootIsOrderSensitive checks that in the default construction
// the root commits to leaf order. The sorted construction deliberately does not;
// see TestDocumentedSortedModeDiscardsOrder.
func TestPropertyUnsortedRootIsOrderSensitive(t *testing.T) {
	base, err := NewTree(propList("A", "B", "C", "D"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	permutations := [][]string{
		{"B", "A", "C", "D"},
		{"A", "B", "D", "C"},
		{"C", "D", "A", "B"},
		{"D", "C", "B", "A"},
		{"A", "C", "B", "D"},
	}
	for _, p := range permutations {
		tree, err := NewTree(propList(p...))
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if bytes.Equal(base.MerkleRoot(), tree.MerkleRoot()) {
			t.Errorf("error: permutation %v produced the same root as the original order", p)
		}
	}
}

// TestPropertyTamperingIsDetected covers the ways a tree can be corrupted in
// memory after construction.
func TestPropertyTamperingIsDetected(t *testing.T) {
	tamperings := []struct {
		name   string
		mutate func(tree *MerkleTree)
		// Both verifiers recompute from Content and check the hashes recorded on the
		// nodes they walk. VerifyTree covers every node; VerifyContent covers the
		// path from the named leaf to the root.
		treeDetects    bool
		contentDetects bool
	}{
		{
			name:           "leaf content replaced",
			mutate:         func(tree *MerkleTree) { tree.Leafs[0].C = propContent{x: "substituted"} },
			treeDetects:    true,
			contentDetects: true,
		},
		{
			name: "two leaves' content swapped",
			mutate: func(tree *MerkleTree) {
				tree.Leafs[0].C, tree.Leafs[1].C = tree.Leafs[1].C, tree.Leafs[0].C
			},
			treeDetects:    true,
			contentDetects: true,
		},
		{
			name:           "recorded merkle root replaced",
			mutate:         func(tree *MerkleTree) { tree.merkleRoot = bytes.Repeat([]byte{1}, 32) },
			treeDetects:    true,
			contentDetects: true,
		},
		{
			name:           "interior node hash replaced",
			mutate:         func(tree *MerkleTree) { tree.Root.Left.Hash = bytes.Repeat([]byte{9}, 32) },
			treeDetects:    true,
			contentDetects: true,
		},
		{
			name:           "leaf node hash replaced",
			mutate:         func(tree *MerkleTree) { tree.Leafs[0].Hash = bytes.Repeat([]byte{7}, 32) },
			treeDetects:    true,
			contentDetects: true,
		},
		{
			// VerifyTree walks every node and so catches damage anywhere. VerifyContent
			// recomputes each sibling on the path from that sibling's own children, so
			// the sibling's recorded hash is never read and editing it alone is
			// invisible to it. Use VerifyTree for whole tree integrity.
			name:           "sibling hash replaced off the verified path",
			mutate:         func(tree *MerkleTree) { tree.Root.Right.Hash = bytes.Repeat([]byte{5}, 32) },
			treeDetects:    true,
			contentDetects: false,
		},
		{
			// One level deeper the damage does feed into the recomputation, so both
			// verifiers catch it.
			name:           "grandchild hash replaced off the verified path",
			mutate:         func(tree *MerkleTree) { tree.Root.Right.Left.Hash = bytes.Repeat([]byte{5}, 32) },
			treeDetects:    true,
			contentDetects: true,
		},
	}

	for _, tc := range tamperings {
		t.Run(tc.name, func(t *testing.T) {
			contents := propList("A", "B", "C", "D")
			tree, err := NewTree(contents)
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			tc.mutate(tree)

			ok, err := tree.VerifyTree()
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if ok == tc.treeDetects {
				t.Errorf("error: VerifyTree returned %v, expected %v", ok, !tc.treeDetects)
			}

			ok, err = tree.VerifyContent(contents[0])
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			if ok == tc.contentDetects {
				t.Errorf("error: VerifyContent returned %v, expected %v", ok, !tc.contentDetects)
			}
		})
	}
}

// TestPropertyErrorsPropagate checks that failures inside a Content implementation
// surface to the caller rather than being swallowed or turned into a bad tree.
func TestPropertyErrorsPropagate(t *testing.T) {
	t.Run("NewTree", func(t *testing.T) {
		_, err := NewTree([]Content{failingContent{x: "a"}, failingContent{x: "b", failHash: true}})
		if err == nil {
			t.Error("error: expected CalculateHash failure to surface")
		}
	})

	t.Run("VerifyTree", func(t *testing.T) {
		tree, err := NewTree([]Content{failingContent{x: "a"}, failingContent{x: "b"}})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		tree.Leafs[0].C = failingContent{x: "a", failHash: true}
		if _, err := tree.VerifyTree(); err == nil {
			t.Error("error: expected CalculateHash failure to surface")
		}
	})

	t.Run("RebuildTree", func(t *testing.T) {
		tree, err := NewTree([]Content{failingContent{x: "a"}, failingContent{x: "b"}})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		tree.Leafs[0].C = failingContent{x: "a", failHash: true}
		if err := tree.RebuildTree(); err == nil {
			t.Error("error: expected CalculateHash failure to surface")
		}
	})

	// Equals is invoked on the content stored in the leaf, not on the query.
	t.Run("VerifyContent", func(t *testing.T) {
		tree, err := NewTree([]Content{failingContent{x: "a", failEqual: true}, failingContent{x: "b"}})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if _, err := tree.VerifyContent(failingContent{x: "a"}); err == nil {
			t.Error("error: expected Equals failure to surface")
		}
	})

	t.Run("GetMerklePath", func(t *testing.T) {
		tree, err := NewTree([]Content{failingContent{x: "a", failEqual: true}, failingContent{x: "b"}})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if _, _, err := tree.GetMerklePath(failingContent{x: "a"}); err == nil {
			t.Error("error: expected Equals failure to surface")
		}
	})
}

// TestPropertyEmptyContentIsRejected checks the documented error for an empty
// content list on every entry point that builds a tree.
func TestPropertyEmptyContentIsRejected(t *testing.T) {
	if _, err := NewTree(nil); !errors.Is(err, ErrNoContent) {
		t.Errorf("error: expected ErrNoContent from NewTree(nil), got %v", err)
	}
	if _, err := NewTree([]Content{}); !errors.Is(err, ErrNoContent) {
		t.Errorf("error: expected ErrNoContent from NewTree(empty), got %v", err)
	}
	if _, err := NewTreeWithHashStrategy(nil, sha256.New); !errors.Is(err, ErrNoContent) {
		t.Errorf("error: expected ErrNoContent from NewTreeWithHashStrategy(nil), got %v", err)
	}
	if _, err := NewTreeWithHashStrategySorted(nil, sha256.New, true); !errors.Is(err, ErrNoContent) {
		t.Errorf("error: expected ErrNoContent from NewTreeWithHashStrategySorted(nil), got %v", err)
	}

	tree, err := NewTree(propList("A", "B"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	before := append([]byte(nil), tree.MerkleRoot()...)

	// A failed rebuild must leave the existing tree usable.
	if err := tree.RebuildTreeWith(nil); !errors.Is(err, ErrNoContent) {
		t.Errorf("error: expected ErrNoContent from RebuildTreeWith(nil), got %v", err)
	}
	if !bytes.Equal(before, tree.MerkleRoot()) {
		t.Error("error: a failed rebuild changed the merkle root")
	}
	ok, err := tree.VerifyTree()
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !ok {
		t.Error("error: expected the tree to still verify after a failed rebuild")
	}
}

// TestPropertyRebuildPreservesConfiguration checks that the hash strategy and sort
// setting chosen at construction survive both rebuild entry points.
func TestPropertyRebuildPreservesConfiguration(t *testing.T) {
	for _, s := range propStrategies {
		for _, sorted := range []bool{false, true} {
			name := fmt.Sprintf("%s/sorted=%v", s.name, sorted)
			t.Run(name, func(t *testing.T) {
				contents := propSeries(7)
				tree, err := NewTreeWithHashStrategySorted(contents, s.fn, sorted)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				original := append([]byte(nil), tree.MerkleRoot()...)

				if err := tree.RebuildTree(); err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if !bytes.Equal(original, tree.MerkleRoot()) {
					t.Error("error: RebuildTree changed the merkle root")
				}

				replacement := propSeries(5)
				if err := tree.RebuildTreeWith(replacement); err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}

				expected, err := NewTreeWithHashStrategySorted(replacement, s.fn, sorted)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if !bytes.Equal(expected.MerkleRoot(), tree.MerkleRoot()) {
					t.Error("error: RebuildTreeWith did not preserve the hash strategy or sort setting")
				}

				ok, err := tree.VerifyTree()
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if !ok {
					t.Error("error: expected the rebuilt tree to verify")
				}
			})
		}
	}
}

// TestPropertyConcurrentReadsAreSafe exercises the read only API from many
// goroutines. Run with -race for this to be meaningful.
func TestPropertyConcurrentReadsAreSafe(t *testing.T) {
	contents := propSeries(33)
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	expected := append([]byte(nil), tree.MerkleRoot()...)

	var wg sync.WaitGroup
	failures := make(chan error, 256)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			if ok, err := tree.VerifyTree(); err != nil || !ok {
				failures <- fmt.Errorf("VerifyTree returned %v, %v", ok, err)
			}
			if ok, err := tree.VerifyContent(contents[i%len(contents)]); err != nil || !ok {
				failures <- fmt.Errorf("VerifyContent returned %v, %v", ok, err)
			}
			if _, _, err := tree.GetMerklePath(contents[i%len(contents)]); err != nil {
				failures <- fmt.Errorf("GetMerklePath returned %v", err)
			}
			if !bytes.Equal(tree.MerkleRoot(), expected) {
				failures <- errors.New("MerkleRoot changed during concurrent reads")
			}
			_ = tree.String()
		}(i)
	}
	wg.Wait()
	close(failures)

	for err := range failures {
		t.Errorf("error: %v", err)
	}
}

// TestPropertyLargeTree exercises a tree big enough to cover many levels of
// recursion and interior padding.
func TestPropertyLargeTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large tree test in short mode")
	}

	const size = 10000
	contents := propSeries(size)
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	ok, err := tree.VerifyTree()
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !ok {
		t.Error("error: expected large tree to verify")
	}

	// Spot check proofs at the edges and the middle rather than all 10000.
	for _, i := range []int{0, 1, size / 2, size - 2, size - 1} {
		path, index, err := tree.GetMerklePath(contents[i])
		if err != nil {
			t.Fatalf("[leaf:%d] error: unexpected error: %v", i, err)
		}
		leafHash, err := contents[i].CalculateHash()
		if err != nil {
			t.Fatalf("[leaf:%d] error: unexpected error: %v", i, err)
		}
		replayed, err := replayProof(leafHash, path, index, sha256.New, propMode{name: "default"})
		if err != nil {
			t.Fatalf("[leaf:%d] error: unexpected error: %v", i, err)
		}
		if !bytes.Equal(replayed, tree.MerkleRoot()) {
			t.Errorf("[leaf:%d] error: proof did not replay to the root", i)
		}
	}
}

// TestDocumentedSortedModeDiscardsOrder pins the fact that the sorted construction
// orders each sibling pair before hashing, so the root no longer commits to the
// order of the leaves. Callers who need order to be significant should use the
// default construction.
func TestDocumentedSortedModeDiscardsOrder(t *testing.T) {
	base, err := NewTreeWithHashStrategySorted(propList("A", "B", "C", "D"), sha256.New, true)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	// Reorderings that survive the sibling sort and leave the root unchanged.
	unchanged := [][]string{
		{"B", "A", "C", "D"},
		{"A", "B", "D", "C"},
		{"C", "D", "A", "B"},
		{"D", "C", "B", "A"},
	}
	for _, p := range unchanged {
		tree, err := NewTreeWithHashStrategySorted(propList(p...), sha256.New, true)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if !bytes.Equal(base.MerkleRoot(), tree.MerkleRoot()) {
			t.Errorf("error: expected %v to share a root with the original order", p)
		}
	}

	// Regrouping which leaves are paired together does change the root.
	regrouped, err := NewTreeWithHashStrategySorted(propList("A", "C", "B", "D"), sha256.New, true)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if bytes.Equal(base.MerkleRoot(), regrouped.MerkleRoot()) {
		t.Error("error: expected regrouping the pairs to change the root")
	}
}

// TestPropertyRFC6962ResistsSecondPreimage is the counterpart to
// TestDocumentedSecondPreimage: the same forgery that succeeds against the default
// construction must fail here, because leaf and interior hashes carry distinct
// prefixes.
func TestPropertyRFC6962ResistsSecondPreimage(t *testing.T) {
	original, err := NewTreeWithOptions(propList("A", "B", "C", "D"), WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	forged, err := NewTreeWithOptions([]Content{
		staticContent{name: "left", hash: original.Root.Left.Hash},
		staticContent{name: "right", hash: original.Root.Right.Hash},
	}, WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	if bytes.Equal(original.MerkleRoot(), forged.MerkleRoot()) {
		t.Error("error: interior hashes presented as leaves reproduced the root")
	}
}

// TestPropertyRFC6962CommitsToLeafCount is the counterpart to
// TestOddNodeCountDuplicatesLastNode: splitting instead of duplicating means an odd
// leaf count no longer collides with the sequence that spells the duplicate out.
func TestPropertyRFC6962CommitsToLeafCount(t *testing.T) {
	pairs := []struct {
		implicit []string
		explicit []string
	}{
		{[]string{"A"}, []string{"A", "A"}},
		{[]string{"A", "B", "C"}, []string{"A", "B", "C", "C"}},
		{[]string{"A", "B", "C", "D", "E"}, []string{"A", "B", "C", "D", "E", "E"}},
		{[]string{"A", "B", "C", "D", "E", "F"}, []string{"A", "B", "C", "D", "E", "F", "E", "F"}},
	}

	for i, pair := range pairs {
		implicit, err := NewTreeWithOptions(propList(pair.implicit...), WithRFC6962())
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", i, err)
		}
		explicit, err := NewTreeWithOptions(propList(pair.explicit...), WithRFC6962())
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", i, err)
		}

		if bytes.Equal(implicit.MerkleRoot(), explicit.MerkleRoot()) {
			t.Errorf("[case:%d] error: %v and %v share a root under RFC 6962", i, pair.implicit, pair.explicit)
		}
	}
}

// TestPropertyRFC6962Shape checks the structural choices RFC 6962 makes: a lone leaf
// is its own root, and node lists split at the largest power of two below their length.
func TestPropertyRFC6962Shape(t *testing.T) {
	single, err := NewTreeWithOptions(propList("A"), WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if single.Root != single.Leafs[0] {
		t.Error("error: expected a one leaf tree to be its own root")
	}
	path, index, err := single.GetMerklePath(propContent{x: "A"})
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if len(path) != 0 || len(index) != 0 {
		t.Errorf("error: expected an empty audit path for a one leaf tree, got %v %v", path, index)
	}

	// Five leaves split 4/1, not 3/2 and not 6 with a duplicate.
	five, err := NewTreeWithOptions(propSeries(5), WithRFC6962())
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if len(five.Leafs) != 5 {
		t.Errorf("error: expected 5 leaves, got %d", len(five.Leafs))
	}
	if got := countLeavesUnder(five.Root.Left); got != 4 {
		t.Errorf("error: expected 4 leaves under the left child, got %d", got)
	}
	if got := countLeavesUnder(five.Root.Right); got != 1 {
		t.Errorf("error: expected 1 leaf under the right child, got %d", got)
	}

	for _, tc := range []struct{ n, want int }{{2, 1}, {3, 2}, {5, 4}, {8, 4}, {9, 8}, {33, 32}} {
		if got := largestPowerOfTwoBelow(tc.n); got != tc.want {
			t.Errorf("error: largestPowerOfTwoBelow(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func countLeavesUnder(n *Node) int {
	if n == nil {
		return 0
	}
	if n.leaf {
		return 1
	}

	return countLeavesUnder(n.Left) + countLeavesUnder(n.Right)
}

// TestPropertyRFC6962RejectsSorting checks that the two mutually exclusive sibling
// orderings cannot be requested together.
func TestPropertyRFC6962RejectsSorting(t *testing.T) {
	if _, err := NewTreeWithOptions(propList("A", "B"), WithRFC6962(), WithSortedSiblings()); err == nil {
		t.Error("error: expected combining WithRFC6962 and WithSortedSiblings to fail")
	}
	if _, err := NewTreeWithOptions(propList("A", "B"), WithSortedSiblings(), WithRFC6962()); err == nil {
		t.Error("error: expected the combination to fail regardless of option order")
	}
}

// TestPropertyNewTreeWithOptionsMatchesLegacyConstructors checks that the options
// constructor is a drop in replacement for the three original ones.
func TestPropertyNewTreeWithOptionsMatchesLegacyConstructors(t *testing.T) {
	contents := propSeries(7)

	plain, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	viaOptions, err := NewTreeWithOptions(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !bytes.Equal(plain.MerkleRoot(), viaOptions.MerkleRoot()) {
		t.Error("error: NewTreeWithOptions with no options did not match NewTree")
	}

	for _, s := range propStrategies {
		strategy, err := NewTreeWithHashStrategy(contents, s.fn)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		opt, err := NewTreeWithOptions(contents, WithHasher(s.fn))
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if !bytes.Equal(strategy.MerkleRoot(), opt.MerkleRoot()) {
			t.Errorf("[%s] error: WithHasher did not match NewTreeWithHashStrategy", s.name)
		}

		sorted, err := NewTreeWithHashStrategySorted(contents, s.fn, true)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		optSorted, err := NewTreeWithOptions(contents, WithHasher(s.fn), WithSortedSiblings())
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if !bytes.Equal(sorted.MerkleRoot(), optSorted.MerkleRoot()) {
			t.Errorf("[%s] error: WithSortedSiblings did not match NewTreeWithHashStrategySorted", s.name)
		}
	}
}

// TestPropertyRFC6962KnownAnswers pins concrete roots so the construction cannot
// drift silently. The values are computed directly from the RFC 6962 definition:
// MTH({d0}) = HASH(0x00 || d0) and MTH(D[n]) = HASH(0x01 || MTH(left) || MTH(right)),
// where the leaf input here is the SHA-256 digest Content.CalculateHash returns.
func TestPropertyRFC6962KnownAnswers(t *testing.T) {
	leaf := func(x string) []byte {
		d := sha256.Sum256([]byte(x))
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write(d[:])

		return h.Sum(nil)
	}
	interior := func(l, r []byte) []byte {
		h := sha256.New()
		h.Write([]byte{0x01})
		h.Write(l)
		h.Write(r)

		return h.Sum(nil)
	}

	cases := []struct {
		contents []string
		want     []byte
	}{
		{[]string{"A"}, leaf("A")},
		{[]string{"A", "B"}, interior(leaf("A"), leaf("B"))},
		// three leaves split 2/1
		{[]string{"A", "B", "C"}, interior(interior(leaf("A"), leaf("B")), leaf("C"))},
		// four leaves split 2/2
		{[]string{"A", "B", "C", "D"}, interior(interior(leaf("A"), leaf("B")), interior(leaf("C"), leaf("D")))},
		// five leaves split 4/1
		{
			[]string{"A", "B", "C", "D", "E"},
			interior(
				interior(interior(leaf("A"), leaf("B")), interior(leaf("C"), leaf("D"))),
				leaf("E"),
			),
		},
	}

	for i, tc := range cases {
		tree, err := NewTreeWithOptions(propList(tc.contents...), WithRFC6962())
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", i, err)
		}
		if !bytes.Equal(tree.MerkleRoot(), tc.want) {
			t.Errorf("[case:%d] error: %v produced %x, expected %x", i, tc.contents, tree.MerkleRoot(), tc.want)
		}
	}
}

// failingHash is a hash.Hash whose Write always fails. The standard library hashes
// never do, so this is the only way to reach the error paths around them and confirm
// a failure is returned rather than ignored or turned into a panic.
type failingHash struct{}

func (failingHash) Write(p []byte) (int, error) {
	return 0, errors.New("hash write failed")
}
func (failingHash) Sum(b []byte) []byte { return append(b, 0) }
func (failingHash) Reset()              {}
func (failingHash) Size() int           { return 1 }
func (failingHash) BlockSize() int      { return 1 }

func newFailingHash() hash.Hash { return failingHash{} }

// nthFailHash accepts writes until the nth, then fails. RFC 6962 hashing writes a
// prefix and then one or two digests into the same hash, so failing on a later write
// is the only way to reach those error paths.
type nthFailHash struct {
	failOn int
	writes int
}

func (h *nthFailHash) Write(p []byte) (int, error) {
	h.writes++
	if h.writes >= h.failOn {
		return 0, errors.New("hash write failed")
	}

	return len(p), nil
}
func (h *nthFailHash) Sum(b []byte) []byte { return append(b, 0) }
func (h *nthFailHash) Reset()              { h.writes = 0 }
func (h *nthFailHash) Size() int           { return 1 }
func (h *nthFailHash) BlockSize() int      { return 1 }

// TestPropertyLateHashWriteFailuresPropagate covers the writes after the first one in
// the multi write hashing paths.
func TestPropertyLateHashWriteFailuresPropagate(t *testing.T) {
	contents := propSeries(4)

	for _, failOn := range []int{2, 3} {
		strategy := func() hash.Hash { return &nthFailHash{failOn: failOn} }

		if _, err := NewTreeWithOptions(contents, WithHasher(strategy), WithRFC6962()); err == nil {
			t.Errorf("[failOn:%d] error: expected the hash failure to surface in RFC 6962 mode", failOn)
		}

		tree, err := NewTreeWithOptions(contents, WithRFC6962())
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		tree.hashStrategy = strategy
		if _, err := tree.VerifyTree(); err == nil {
			t.Errorf("[failOn:%d] error: expected VerifyTree to surface the hash failure", failOn)
		}
		if _, err := tree.VerifyContent(contents[0]); err == nil {
			t.Errorf("[failOn:%d] error: expected VerifyContent to surface the hash failure", failOn)
		}
	}
}

// TestPropertyHashWriteFailuresPropagate checks that a hash strategy which refuses to
// accept bytes produces an error from every entry point rather than a partial tree.
func TestPropertyHashWriteFailuresPropagate(t *testing.T) {
	contents := propSeries(5)

	// Interior hashing is the first thing to touch the strategy in default mode.
	if _, err := NewTreeWithOptions(contents, WithHasher(newFailingHash)); err == nil {
		t.Error("error: expected a failing hash strategy to surface from NewTreeWithOptions")
	}

	// Under RFC 6962 the strategy is reached earlier, while hashing the leaves.
	if _, err := NewTreeWithOptions(contents, WithHasher(newFailingHash), WithRFC6962()); err == nil {
		t.Error("error: expected a failing hash strategy to surface in RFC 6962 mode")
	}

	// A tree whose strategy starts failing after construction must report it from the
	// verification paths instead of quietly answering false.
	for _, mode := range propModes {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			t.Fatalf("[%s] error: unexpected error: %v", mode.name, err)
		}
		tree.hashStrategy = newFailingHash

		if _, err := tree.VerifyTree(); err == nil {
			t.Errorf("[%s] error: expected VerifyTree to surface the hash failure", mode.name)
		}
		if _, err := tree.VerifyContent(contents[0]); err == nil {
			t.Errorf("[%s] error: expected VerifyContent to surface the hash failure", mode.name)
		}
		if err := tree.RebuildTree(); err == nil {
			t.Errorf("[%s] error: expected RebuildTree to surface the hash failure", mode.name)
		}
	}
}

// TestPropertyOptionValidation covers the option paths that reject a configuration
// before any hashing happens.
func TestPropertyOptionValidation(t *testing.T) {
	if _, err := NewTreeWithOptions(propList("A", "B"), WithHasher(nil)); err == nil {
		t.Error("error: expected a nil hash strategy to be rejected")
	}

	// A nil option is skipped rather than dereferenced.
	tree, err := NewTreeWithOptions(propList("A", "B"), nil, WithHasher(sha256.New), nil)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	expected, err := NewTree(propList("A", "B"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !bytes.Equal(tree.MerkleRoot(), expected.MerkleRoot()) {
		t.Error("error: nil options changed the resulting tree")
	}

	// Content failures surface through the options constructor too, in both modes.
	failing := []Content{failingContent{x: "a"}, failingContent{x: "b", failHash: true}}
	if _, err := NewTreeWithOptions(failing); err == nil {
		t.Error("error: expected a CalculateHash failure to surface")
	}
	if _, err := NewTreeWithOptions(failing, WithRFC6962()); err == nil {
		t.Error("error: expected a CalculateHash failure to surface in RFC 6962 mode")
	}
	if _, err := NewTreeWithOptions([]Content{propContent{x: "a"}, nil}, WithRFC6962()); !errors.Is(err, ErrNilContent) {
		t.Errorf("error: expected ErrNilContent in RFC 6962 mode, got %v", err)
	}
	if _, err := NewTreeWithOptions(nil, WithRFC6962()); !errors.Is(err, ErrNoContent) {
		t.Errorf("error: expected ErrNoContent in RFC 6962 mode, got %v", err)
	}
}

// TestPropertyConstructionSurvivesSerialization checks that the construction a tree
// was built with is recorded in its payload. If it were not, a decoded tree would be
// hashed a different way and would silently fail to match the root it was written
// with. The registry free path is used so the test touches no package level state.
func TestPropertyConstructionSurvivesSerialization(t *testing.T) {
	encode := func(c Content) ([]byte, error) { return []byte(c.(propContent).x), nil }
	decode := func(b []byte) (Content, error) { return propContent{x: string(b)}, nil }

	for _, mode := range propModes {
		for _, n := range []int{1, 3, 5, 8} {
			name := fmt.Sprintf("%s/n=%d", mode.name, n)
			t.Run(name, func(t *testing.T) {
				contents := propSeries(n)
				tree, err := mode.build(contents, sha256.New)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}

				payload, err := tree.MarshalWith(encode)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}

				decoded, err := UnmarshalWith(payload, decode)
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}

				if !bytes.Equal(tree.MerkleRoot(), decoded.MerkleRoot()) {
					t.Error("error: the decoded tree has a different merkle root")
				}
				if decoded.Sorted() != mode.sorted {
					t.Errorf("error: expected Sorted to be %v, got %v", mode.sorted, decoded.Sorted())
				}
				if decoded.RFC6962() != mode.rfc6962 {
					t.Errorf("error: expected RFC6962 to be %v, got %v", mode.rfc6962, decoded.RFC6962())
				}
				if len(decoded.Leafs) != len(tree.Leafs) {
					t.Errorf("error: expected %d leaves, got %d", len(tree.Leafs), len(decoded.Leafs))
				}

				ok, err := decoded.VerifyTree()
				if err != nil {
					t.Fatalf("error: unexpected error: %v", err)
				}
				if !ok {
					t.Error("error: expected the decoded tree to verify")
				}
			})
		}
	}
}

// TestDocumentedSecondPreimage pins the absence of domain separation between leaf and
// interior hashing in the default construction. Both are computed the same way, so the
// tree cannot distinguish a genuine leaf digest from an interior node digest: a two leaf
// tree whose leaves are the two subtree hashes of a four leaf tree reproduces the
// original root.
//
// This is a property of the Bitcoin-style construction, kept because roots must stay
// compatible with it. Build with WithRFC6962 to avoid it; see
// TestPropertyRFC6962ResistsSecondPreimage for the same forgery failing there.
func TestDocumentedSecondPreimage(t *testing.T) {
	original, err := NewTree(propList("A", "B", "C", "D"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	forged, err := NewTree([]Content{
		staticContent{name: "left", hash: original.Root.Left.Hash},
		staticContent{name: "right", hash: original.Root.Right.Hash},
	})
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	if !bytes.Equal(original.MerkleRoot(), forged.MerkleRoot()) {
		t.Error("error: expected the forged two leaf tree to reproduce the original root")
	}

	// The forged tree is internally consistent, which is the point: nothing about
	// the root alone reveals how many leaves went into it.
	ok, err := forged.VerifyTree()
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if !ok {
		t.Error("error: expected the forged tree to verify against itself")
	}
}

// TestPropertyGetMerklePathAbsentContent checks that content the tree does not hold
// is reported as ErrContentNotFound rather than as an empty but successful result.
func TestPropertyGetMerklePathAbsentContent(t *testing.T) {
	tree, err := NewTree(propList("A", "B", "C", "D"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	path, index, err := tree.GetMerklePath(propContent{x: "absent"})
	if !errors.Is(err, ErrContentNotFound) {
		t.Errorf("error: expected ErrContentNotFound for absent content, got %v", err)
	}
	if path != nil {
		t.Errorf("error: expected a nil path for absent content, got %v", path)
	}
	if index != nil {
		t.Errorf("error: expected a nil index for absent content, got %v", index)
	}

	// A leaf that is present must not report the sentinel.
	if _, _, err := tree.GetMerklePath(propContent{x: "A"}); err != nil {
		t.Errorf("error: unexpected error for present content: %v", err)
	}
}

// TestPropertyNilContentIsRejected checks that a nil entry in the content list is
// reported as an error rather than panicking on the CalculateHash call.
func TestPropertyNilContentIsRejected(t *testing.T) {
	lists := map[string][]Content{
		"only entry":  {nil},
		"first entry": {nil, propContent{x: "B"}},
		"last entry":  {propContent{x: "A"}, nil},
		"middle":      {propContent{x: "A"}, nil, propContent{x: "C"}},
	}

	for name, cs := range lists {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("error: expected an error, got panic: %v", r)
				}
			}()

			if _, err := NewTree(cs); !errors.Is(err, ErrNilContent) {
				t.Errorf("error: expected ErrNilContent from NewTree, got %v", err)
			}

			tree, err := NewTree(propList("A", "B"))
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}
			before := append([]byte(nil), tree.MerkleRoot()...)

			if err := tree.RebuildTreeWith(cs); !errors.Is(err, ErrNilContent) {
				t.Errorf("error: expected ErrNilContent from RebuildTreeWith, got %v", err)
			}
			if !bytes.Equal(before, tree.MerkleRoot()) {
				t.Error("error: a rejected rebuild changed the merkle root")
			}
		})
	}
}

// TestPropertySortedAccessor checks that Sorted reports the construction actually
// used, including across a rebuild.
func TestPropertySortedAccessor(t *testing.T) {
	plain, err := NewTree(propList("A", "B", "C"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if plain.Sorted() {
		t.Error("error: expected NewTree to produce an unsorted tree")
	}

	strategy, err := NewTreeWithHashStrategy(propList("A", "B", "C"), sha256.New)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if strategy.Sorted() {
		t.Error("error: expected NewTreeWithHashStrategy to produce an unsorted tree")
	}

	for _, sorted := range []bool{false, true} {
		tree, err := NewTreeWithHashStrategySorted(propList("A", "B", "C"), sha256.New, sorted)
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if tree.Sorted() != sorted {
			t.Errorf("error: expected Sorted to report %v, got %v", sorted, tree.Sorted())
		}
		if err := tree.RebuildTree(); err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		if tree.Sorted() != sorted {
			t.Errorf("error: expected Sorted to survive a rebuild, got %v", tree.Sorted())
		}
	}
}

// FuzzTreeInvariants builds a tree from fuzzer supplied leaves and asserts the
// invariants that must hold regardless of input: the tree verifies, every leaf
// verifies and every proof replays to the root.
func FuzzTreeInvariants(f *testing.F) {
	f.Add("A|B|C|D", false, false)
	f.Add("A", true, false)
	f.Add("A|A|A", false, false)
	f.Add("|", true, false)
	f.Add("A|B|C|D|E|F|G", true, false)
	f.Add("A|B|C|D|E", false, true)
	f.Add("A", false, true)
	f.Add("A|A|A|A|A|A|A|A|A", false, true)

	f.Fuzz(func(t *testing.T, joined string, sorted, rfc6962 bool) {
		parts := splitOn(joined, '|')
		if len(parts) == 0 || len(parts) > 128 {
			t.Skip()
		}

		contents := make([]Content, 0, len(parts))
		for _, p := range parts {
			contents = append(contents, propContent{x: p})
		}

		mode := propMode{sorted: sorted, rfc6962: rfc6962}
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			// Empty input and the sorted/RFC 6962 combination are documented errors,
			// not failures.
			t.Skip()
		}

		ok, err := tree.VerifyTree()
		if err != nil {
			t.Fatalf("VerifyTree returned an error: %v", err)
		}
		if !ok {
			t.Fatal("a freshly built tree failed to verify")
		}

		for i, c := range contents {
			ok, err := tree.VerifyContent(c)
			if err != nil {
				t.Fatalf("[content:%d] VerifyContent returned an error: %v", i, err)
			}
			if !ok {
				t.Fatalf("[content:%d] content in the tree failed to verify", i)
			}

			path, index, err := tree.GetMerklePath(c)
			if err != nil {
				t.Fatalf("[content:%d] GetMerklePath returned an error: %v", i, err)
			}
			leafHash, err := c.CalculateHash()
			if err != nil {
				t.Fatalf("[content:%d] CalculateHash returned an error: %v", i, err)
			}
			replayed, err := replayProof(leafHash, path, index, sha256.New, mode)
			if err != nil {
				t.Fatalf("[content:%d] %v", i, err)
			}
			if !bytes.Equal(replayed, tree.MerkleRoot()) {
				t.Fatalf("[content:%d] proof did not replay to the root", i)
			}
		}

		// RFC 6962 pads nothing, so the leaf count is exactly what went in.
		if rfc6962 && len(tree.Leafs) != len(contents) {
			t.Fatalf("expected %d leaves, got %d", len(contents), len(tree.Leafs))
		}

		// Rebuilding must be a no-op for the root.
		root := append([]byte(nil), tree.MerkleRoot()...)
		if err := tree.RebuildTree(); err != nil {
			t.Fatalf("RebuildTree returned an error: %v", err)
		}
		if !bytes.Equal(root, tree.MerkleRoot()) {
			t.Fatal("RebuildTree changed the merkle root")
		}
	})
}

func splitOn(s string, sep rune) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == sep {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}

	return append(out, cur)
}
