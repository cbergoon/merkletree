// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Node exposes Tree, Parent, Left, Right, and Hash, and MerkleTree exposes Root and
// Leafs, so a caller can hand the verification methods a node graph no constructor
// would have produced - a zero value tree, a tree decoded and then edited, or one
// assembled by hand. None of that is supported usage, but a library whose response to
// unsupported usage is a nil dereference cannot be called from a server that verifies
// trees it did not build. The tests below pin the error-rather-than-fault behavior.

// TestZeroValueTreeIsInert checks that every method is safe to call on a MerkleTree
// that was never built. VerifyTree used to fault here.
func TestZeroValueTreeIsInert(t *testing.T) {
	t.Run("VerifyTree", func(t *testing.T) {
		var m MerkleTree
		ok, err := m.VerifyTree()
		if ok {
			t.Error("error: a tree that was never built reported as verified")
		}
		if !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree, got %v", err)
		}
	})

	t.Run("VerifyContent", func(t *testing.T) {
		var m MerkleTree
		ok, err := m.VerifyContent(TestSHA256Content{x: "Hello"})
		if ok || err != nil {
			t.Errorf("error: expected (false, nil) for content absent from an empty tree, got (%v, %v)", ok, err)
		}
	})

	t.Run("GetMerklePath", func(t *testing.T) {
		var m MerkleTree
		path, index, err := m.GetMerklePath(TestSHA256Content{x: "Hello"})
		if !errors.Is(err, ErrContentNotFound) {
			t.Errorf("error: expected ErrContentNotFound, got %v", err)
		}
		if path != nil || index != nil {
			t.Errorf("error: expected no path, got %v %v", path, index)
		}
	})

	t.Run("RebuildTree", func(t *testing.T) {
		var m MerkleTree
		if err := m.RebuildTree(); !errors.Is(err, ErrNoContent) {
			t.Errorf("error: expected ErrNoContent, got %v", err)
		}
	})

	t.Run("accessors", func(t *testing.T) {
		var m MerkleTree
		if m.MerkleRoot() != nil {
			t.Error("error: expected a nil root hash")
		}
		if m.Sorted() || m.RFC6962() {
			t.Error("error: expected both mode flags to be false")
		}
		if s := m.String(); s != "" {
			t.Errorf("error: expected an empty string, got %q", s)
		}
	})

	t.Run("MarshalBinary", func(t *testing.T) {
		var m MerkleTree
		if _, err := m.MarshalBinary(); err == nil {
			t.Error("error: expected marshaling an empty tree to fail")
		}
	})
}

// TestMalformedNodeGraphIsReported covers the graphs that are reachable only by
// editing exported fields. Each must produce an error rather than a fault.
func TestMalformedNodeGraphIsReported(t *testing.T) {
	build := func(t *testing.T) *MerkleTree {
		t.Helper()
		tree, err := NewTree([]Content{
			TestSHA256Content{x: "A"},
			TestSHA256Content{x: "B"},
			TestSHA256Content{x: "C"},
			TestSHA256Content{x: "D"},
		})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}
		return tree
	}

	t.Run("root with no children", func(t *testing.T) {
		tree := build(t)
		tree.Root.Left, tree.Root.Right = nil, nil

		ok, err := tree.VerifyTree()
		if ok {
			t.Error("error: a rootless graph reported as verified")
		}
		if !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree, got %v", err)
		}
	})

	t.Run("interior node missing its right child", func(t *testing.T) {
		tree := build(t)
		tree.Root.Left.Right = nil

		if _, err := tree.VerifyTree(); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree from VerifyTree, got %v", err)
		}
		// VerifyContent walks up from a leaf, so it reaches the damage from below.
		if _, err := tree.VerifyContent(TestSHA256Content{x: "A"}); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree from VerifyContent, got %v", err)
		}
	})

	t.Run("node detached from its tree", func(t *testing.T) {
		tree := build(t)
		tree.Leafs[0].Tree = nil

		if _, err := tree.VerifyTree(); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree from VerifyTree, got %v", err)
		}
		if _, err := tree.VerifyContent(TestSHA256Content{x: "A"}); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree from VerifyContent, got %v", err)
		}
	})

	t.Run("root replaced with a detached node", func(t *testing.T) {
		tree := build(t)
		tree.Root = &Node{Hash: bytes.Clone(tree.Root.Hash)}

		if _, err := tree.VerifyTree(); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree, got %v", err)
		}
	})
}

// TestNonCanonicalVarintRejected pins the decoder half of the format's determinism
// guarantee. binary.ReadUvarint accepts padded encodings, so before the decoder
// enforced minimality a payload could be rewritten - here the one byte version 0x02
// becomes the two byte 0x82 0x00 - into different bytes that decoded to exactly the
// same tree. Any digest taken over the payload would then fail to identify it.
func TestNonCanonicalVarintRejected(t *testing.T) {
	tree, err := NewTree([]Content{TestSHA256Content{x: "A"}, TestSHA256Content{x: "B"}})
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	// The version varint sits directly after the magic and is a single byte here.
	if data[len(serializationMagic)] != serializationVersion {
		t.Fatalf("error: expected the version at offset %d, got %#x", len(serializationMagic), data[len(serializationMagic)])
	}
	padded := make([]byte, 0, len(data)+1)
	padded = append(padded, data[:len(serializationMagic)]...)
	padded = append(padded, 0x80|serializationVersion, 0x00)
	padded = append(padded, data[len(serializationMagic)+1:]...)

	var got MerkleTree
	err = got.UnmarshalBinary(padded)
	if err == nil {
		t.Fatal("error: a non-minimally encoded varint was accepted, so the format is malleable")
	}
	if !errors.Is(err, ErrCorruptData) {
		t.Errorf("error: expected ErrCorruptData, got %v", err)
	}
}

// TestCanonicalVarintBoundaries checks the minimality rule accepts every legitimate
// encoding. A rule that also rejected valid payloads would be worse than no rule.
func TestCanonicalVarintBoundaries(t *testing.T) {
	for _, v := range []uint64{0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 1 << 35, 1<<64 - 1} {
		var buf bytes.Buffer
		writeUvarint(&buf, v)
		r := &binaryReader{data: buf.Bytes()}

		got, err := r.uvarint()
		if err != nil {
			t.Errorf("error: %d encoded as %x was rejected: %v", v, buf.Bytes(), err)
			continue
		}
		if got != v {
			t.Errorf("error: %d round tripped to %d", v, got)
		}
		if r.remaining() != 0 {
			t.Errorf("error: %d left %d bytes unread", v, r.remaining())
		}
	}
}

// TestMalformedVarintsRejected covers the shapes the minimality and overflow rules
// exist to catch.
func TestMalformedVarintsRejected(t *testing.T) {
	cases := []struct {
		name string
		hex  string
	}{
		{"padded zero", "8000"},
		{"padded one", "8100"},
		{"doubly padded", "80808000"},
		{"padded 0x7f", "ff0000"},
		{"truncated continuation", "80"},
		{"overflow", "ffffffffffffffffff7f"},
		{"ten byte overflow", "ffffffffffffffffff02"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatalf("error: bad test input: %v", err)
			}
			r := &binaryReader{data: raw}
			if got, err := r.uvarint(); err == nil {
				t.Errorf("error: %s (%s) was accepted as %d", tc.name, tc.hex, got)
			}
		})
	}
}

// TestDecodeIsCanonicalAcrossTheTable is the table driven counterpart to the fuzz
// target's canonicality assertion: for every tree the suite builds, the payload the
// encoder produces is the only one the decoder accepts for it.
func TestDecodeIsCanonicalAcrossTheTable(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)
		data, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}

		var decoded MerkleTree
		if err := decoded.UnmarshalBinary(data); err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		again, err := decoded.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if !bytes.Equal(data, again) {
			t.Errorf("[case:%d] error: decoding and re-encoding changed the payload", table[i].testCaseId)
		}
	}
}
