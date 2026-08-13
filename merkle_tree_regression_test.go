// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// splitContent deliberately breaks the correspondence between Equals and
// CalculateHash: equality is decided by id, the hash is derived from data. Two
// items can therefore be distinct yet hash identically, which is the only way to
// reach the left/right ambiguity that GetMerklePath used to resolve by hash.
type splitContent struct {
	id   string
	data string
}

func (t splitContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.data)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (t splitContent) Equals(other Content) (bool, error) {
	return t.id == other.(splitContent).id, nil
}

// expectedPath walks from leaf to root using node identity, which is the
// structurally correct answer GetMerklePath should agree with.
func expectedPath(leaf *Node) ([][]byte, []int64) {
	var path [][]byte
	var index []int64
	current := leaf
	for parent := current.Parent; parent != nil; parent = parent.Parent {
		if parent.Left == current {
			path = append(path, parent.Right.Hash)
			index = append(index, 1)
		} else {
			path = append(path, parent.Left.Hash)
			index = append(index, 0)
		}
		current = parent
	}

	return path, index
}

// TestGetMerklePathIndexMatchesStructure guards against a regression in which
// GetMerklePath decided whether a node was a left or right child by comparing
// sibling hashes rather than node identity. Sibling hashes are equal exactly when
// the returned path bytes are unaffected, so proofs still verified, but the
// reported index could describe a right-hand node as a left-hand one.
func TestGetMerklePathIndexMatchesStructure(t *testing.T) {
	// Leaves 0 and 1 hash identically but are distinct according to Equals.
	contents := []Content{
		splitContent{id: "one", data: "collide"},
		splitContent{id: "two", data: "collide"},
		splitContent{id: "three", data: "c"},
		splitContent{id: "four", data: "d"},
	}

	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	for i, c := range contents {
		path, index, err := tree.GetMerklePath(c)
		if err != nil {
			t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
		}

		// GetMerklePath resolves content to the first matching leaf.
		var leaf *Node
		for _, l := range tree.Leafs {
			ok, err := l.C.Equals(c)
			if err != nil {
				t.Fatalf("[content:%d] error: unexpected error: %v", i, err)
			}
			if ok {
				leaf = l
				break
			}
		}
		if leaf == nil {
			t.Fatalf("[content:%d] error: content not found in tree", i)
		}

		wantPath, wantIndex := expectedPath(leaf)
		if len(index) != len(wantIndex) {
			t.Fatalf("[content:%d] error: expected %d index entries, got %d", i, len(wantIndex), len(index))
		}
		for k := range wantIndex {
			if index[k] != wantIndex[k] {
				t.Errorf("[content:%d] error: index[%d] describes the wrong side: got %d want %d",
					i, k, index[k], wantIndex[k])
			}
		}
		for k := range wantPath {
			if !bytes.Equal(path[k], wantPath[k]) {
				t.Errorf("[content:%d] error: path[%d] expected %v got %v", i, k, wantPath[k], path[k])
			}
		}
	}
}

// TestVerifyContentChecksMerkleRoot guards against a regression in which
// VerifyContent walked the path from a leaf up to the root, comparing each
// recomputed hash against the hash already stored on the node, but never
// compared the root node against the tree's recorded merkle root. A tree whose
// merkleRoot field had been tampered with therefore still reported its content
// as valid, contradicting the method's documented contract.
func TestVerifyContentChecksMerkleRoot(t *testing.T) {
	for i := 0; i < len(table); i++ {
		if len(table[i].contents) == 0 {
			continue
		}

		var tree *MerkleTree
		var err error
		switch {
		case table[i].defaultHashStrategy:
			tree, err = NewTree(table[i].contents)
		case table[i].sort:
			tree, err = NewTreeWithHashStrategySorted(table[i].contents, table[i].hashStrategy, true)
		default:
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}

		// Sanity check: the untampered tree vouches for its own content.
		v, err := tree.VerifyContent(table[i].contents[0])
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if !v {
			t.Fatalf("[case:%d] error: expected valid content", table[i].testCaseId)
		}

		// Tamper with the recorded merkle root only, leaving every Node.Hash in
		// the tree internally consistent. VerifyContent must still reject.
		tree.merkleRoot = []byte{1}

		v, err = tree.VerifyContent(table[i].contents[0])
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if v {
			t.Errorf("[case:%d] error: expected content to be invalid when merkleRoot is tampered", table[i].testCaseId)
		}

		// VerifyTree already covered this case and must continue to.
		vt, err := tree.VerifyTree()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if vt {
			t.Errorf("[case:%d] error: expected tree to be invalid when merkleRoot is tampered", table[i].testCaseId)
		}
	}
}

// TestRebuildTreeDoesNotPromotePadding guards against a regression in which
// RebuildTree rebuilt from every entry of Leafs, including the padding copy that
// buildWithContent appends when the content count is odd. That copy was thereby
// promoted to real content: a tree built from three items reported four leaves
// with no dup marker, so callers reading Leafs saw a phantom entry and String()
// output changed after a rebuild. The merkle root was stable before and after
// this fix; only the bookkeeping was wrong.
func TestRebuildTreeDoesNotPromotePadding(t *testing.T) {
	cases := [][]Content{
		{TestSHA256Content{x: "A"}},
		{TestSHA256Content{x: "A"}, TestSHA256Content{x: "B"}},
		{TestSHA256Content{x: "A"}, TestSHA256Content{x: "B"}, TestSHA256Content{x: "C"}},
		// A user-supplied duplicate must survive; only padding is skipped.
		{TestSHA256Content{x: "A"}, TestSHA256Content{x: "B"}, TestSHA256Content{x: "C"}, TestSHA256Content{x: "C"}},
		{TestSHA256Content{x: "A"}, TestSHA256Content{x: "A"}, TestSHA256Content{x: "B"}},
		{TestSHA256Content{x: "A"}, TestSHA256Content{x: "B"}, TestSHA256Content{x: "C"},
			TestSHA256Content{x: "D"}, TestSHA256Content{x: "E"}},
	}

	for i, contents := range cases {
		tree, err := NewTree(contents)
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", i, err)
		}

		wantRoot := append([]byte(nil), tree.MerkleRoot()...)
		wantLeafs := len(tree.Leafs)
		wantString := tree.String()
		wantDups := 0
		for _, l := range tree.Leafs {
			if l.dup {
				wantDups++
			}
		}

		// Repeated rebuilds must be idempotent in every observable respect.
		for n := 1; n <= 3; n++ {
			if err := tree.RebuildTree(); err != nil {
				t.Fatalf("[case:%d] rebuild %d: unexpected error: %v", i, n, err)
			}
			if !bytes.Equal(tree.MerkleRoot(), wantRoot) {
				t.Errorf("[case:%d] rebuild %d: root changed: got %v want %v", i, n, tree.MerkleRoot(), wantRoot)
			}
			if len(tree.Leafs) != wantLeafs {
				t.Errorf("[case:%d] rebuild %d: leaf count changed: got %d want %d", i, n, len(tree.Leafs), wantLeafs)
			}
			gotDups := 0
			for _, l := range tree.Leafs {
				if l.dup {
					gotDups++
				}
			}
			if gotDups != wantDups {
				t.Errorf("[case:%d] rebuild %d: dup marker lost: got %d want %d", i, n, gotDups, wantDups)
			}
			if tree.String() != wantString {
				t.Errorf("[case:%d] rebuild %d: String() output changed", i, n)
			}
			if ok, err := tree.VerifyTree(); err != nil || !ok {
				t.Errorf("[case:%d] rebuild %d: VerifyTree=%v err=%v", i, n, ok, err)
			}
		}

		// Every originally supplied item must still verify.
		for j, c := range contents {
			ok, err := tree.VerifyContent(c)
			if err != nil || !ok {
				t.Errorf("[case:%d] content %d: VerifyContent=%v err=%v", i, j, ok, err)
			}
		}
	}
}

// TestOddNodeCountDuplicatesLastNode pins the Bitcoin-style handling of levels
// holding an odd number of nodes: the last node is duplicated and paired with
// itself. This is intentional, and it means a tree built from an odd number of
// leaves produces the same root as a tree that includes the duplicate explicitly.
// The property is inherent to the Bitcoin construction (CVE-2012-2459) and is
// documented in the README. This test exists so that changing it has to be a
// deliberate decision rather than an accident, since doing so would alter every
// root this library has ever produced.
func TestOddNodeCountDuplicatesLastNode(t *testing.T) {
	equivalent := []struct {
		implicit []string
		explicit []string
	}{
		{[]string{"A"}, []string{"A", "A"}},
		{[]string{"A", "B", "C"}, []string{"A", "B", "C", "C"}},
		{[]string{"A", "B", "C", "D", "E"}, []string{"A", "B", "C", "D", "E", "E"}},
		// Duplication at an interior level, not just among the leaves.
		{[]string{"A", "B", "C", "D", "E", "F"}, []string{"A", "B", "C", "D", "E", "F", "E", "F"}},
	}

	for i, pair := range equivalent {
		implicit, err := NewTree(sha256Contents(pair.implicit))
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", i, err)
		}
		explicit, err := NewTree(sha256Contents(pair.explicit))
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", i, err)
		}

		if !bytes.Equal(implicit.MerkleRoot(), explicit.MerkleRoot()) {
			t.Errorf("[case:%d] error: expected %v and %v to share a root, got %v and %v",
				i, pair.implicit, pair.explicit, implicit.MerkleRoot(), explicit.MerkleRoot())
		}

		// When the duplication happens among the leaves, the padded tree ends up
		// with the same leaf count as the explicit one. When it happens at an
		// interior level the leaf counts differ by design, so only check the
		// leaf-level case.
		if len(pair.explicit) == len(pair.implicit)+1 {
			if len(implicit.Leafs) != len(explicit.Leafs) {
				t.Errorf("[case:%d] error: expected equal leaf counts, got %d and %d",
					i, len(implicit.Leafs), len(explicit.Leafs))
			}
		}

		// The padding copy is present in Leafs and flagged, so callers that need
		// to tell the two apart still can.
		if len(pair.implicit)%2 == 1 {
			dups := 0
			for _, l := range implicit.Leafs {
				if l.dup {
					dups++
				}
			}
			if dups != 1 {
				t.Errorf("[case:%d] error: expected exactly one leaf flagged as padding, got %d", i, dups)
			}
		}
	}
}

func sha256Contents(xs []string) []Content {
	var cs []Content
	for _, x := range xs {
		cs = append(cs, TestSHA256Content{x: x})
	}

	return cs
}

// TestSortAppendDoesNotAliasInput ensures sortAppend returns a fresh slice
// rather than appending into the spare capacity of its arguments. Content
// implementations may legally return a hash slice with cap > len from
// CalculateHash, and that buffer stays owned by the caller.
func TestSortAppendDoesNotAliasInput(t *testing.T) {
	for _, sort := range []bool{false, true} {
		a := make([]byte, 4, 64)
		b := make([]byte, 4, 64)
		copy(a, []byte{1, 2, 3, 4})
		copy(b, []byte{5, 6, 7, 8})

		aBefore := string(a[:cap(a)])
		bBefore := string(b[:cap(b)])

		out := sortAppend(sort, a, b)

		if got := string(a[:cap(a)]); got != aBefore {
			t.Errorf("sort=%v: sortAppend wrote into the backing array of a", sort)
		}
		if got := string(b[:cap(b)]); got != bBefore {
			t.Errorf("sort=%v: sortAppend wrote into the backing array of b", sort)
		}
		if len(out) != len(a)+len(b) {
			t.Errorf("sort=%v: expected %d bytes, got %d", sort, len(a)+len(b), len(out))
		}

		// Mutating the result must not be observable through a or b.
		out[0] = 0xff
		if a[0] == 0xff || b[0] == 0xff {
			t.Errorf("sort=%v: result aliases an input slice", sort)
		}
	}
}
