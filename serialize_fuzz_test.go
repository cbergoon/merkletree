// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// The decoders are the only part of this package that consumes bytes it did not
// produce. Everything else operates on Content the caller already holds, so a
// serialized tree arriving over a network or off disk is the whole untrusted input
// surface. The hand written malformed payload tests cover the cases someone thought
// of; these targets cover the ones nobody did.
//
// Three properties are asserted of anything the binary decoder accepts:
//
//   - It does not fault. A verifier that can be crashed by a payload is a denial of
//     service, and every length in the format is attacker chosen.
//   - The tree it produces is internally consistent and every leaf has a working
//     audit path, so a payload cannot yield a tree that looks decoded but proves
//     nothing.
//   - The payload is the canonical encoding of that tree. Two different byte strings
//     must never decode to the same tree, or a payload could be rewritten in transit
//     while still matching whatever digest was taken of it.

// fuzzSeedPayloads returns valid payloads for the fuzzer to mutate. Starting from
// well formed input is what lets the fuzzer reach the code past the header; from
// random bytes it would almost never get past the magic.
func fuzzSeedPayloads(tb testing.TB) [][]byte {
	tb.Helper()

	seeds := make([][]byte, 0, len(goldenPayloads)+len(table))
	for _, g := range goldenPayloads {
		data, err := hex.DecodeString(g.hex)
		if err != nil {
			tb.Fatalf("error: bad golden payload %s: %v", g.name, err)
		}
		seeds = append(seeds, data)
	}

	// The shared table covers the other hash strategies, content types, and the
	// odd leaf counts that pad.
	for i := range table {
		var (
			tree *MerkleTree
			err  error
		)
		switch {
		case table[i].defaultHashStrategy:
			tree, err = NewTree(table[i].contents)
		case table[i].sort:
			tree, err = NewTreeWithHashStrategySorted(table[i].contents, table[i].hashStrategy, true)
		default:
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			continue
		}
		data, err := tree.MarshalBinary()
		if err != nil {
			continue
		}
		seeds = append(seeds, data)
	}

	return seeds
}

// checkDecodedTree asserts everything that must hold of a tree the decoder accepted.
func checkDecodedTree(t *testing.T, tree *MerkleTree) {
	t.Helper()

	if tree.Root == nil || len(tree.Leafs) == 0 {
		t.Fatal("error: decoder returned a tree with no root or no leaves")
	}

	ok, err := tree.VerifyTree()
	if err != nil {
		t.Fatalf("error: VerifyTree on a decoded tree: %v", err)
	}
	if !ok {
		t.Fatal("error: the decoder accepted a payload whose tree does not verify")
	}

	// Proof generation and replay is the operation the tree exists for, so a decoded
	// tree that cannot produce a usable proof is as broken as one that fails to
	// verify. Large trees are skipped to keep each fuzz iteration cheap.
	if len(tree.Leafs) > 64 {
		return
	}
	mode := propMode{sorted: tree.Sorted(), rfc6962: tree.RFC6962()}
	for i, l := range tree.Leafs {
		if l.dup {
			continue
		}
		path, index, err := tree.GetMerklePath(l.C)
		if err != nil {
			t.Fatalf("[leaf:%d] error: GetMerklePath on a decoded tree: %v", i, err)
		}
		leafHash, err := l.C.CalculateHash()
		if err != nil {
			t.Fatalf("[leaf:%d] error: CalculateHash: %v", i, err)
		}
		replayed, err := replayProof(leafHash, path, index, tree.hashStrategy, mode)
		if err != nil {
			t.Fatalf("[leaf:%d] error: %v", i, err)
		}
		// GetMerklePath resolves content to the first matching leaf, so a tree
		// holding the same content twice can answer with an earlier leaf's path.
		// That path still has to replay to the root.
		if !bytes.Equal(replayed, tree.MerkleRoot()) {
			t.Fatalf("[leaf:%d] error: proof replayed to %x, want %x", i, replayed, tree.MerkleRoot())
		}
	}
}

// FuzzUnmarshalBinary drives the binary decoder with arbitrary bytes.
func FuzzUnmarshalBinary(f *testing.F) {
	for _, seed := range fuzzSeedPayloads(f) {
		f.Add(seed)
	}
	// Shapes worth reaching directly rather than waiting for the mutator.
	f.Add([]byte(nil))
	f.Add([]byte("MTREE"))
	f.Add([]byte("MTREE\x02"))
	f.Add([]byte("NOTMT\x02"))
	f.Add([]byte("MTREE\x82\x00"))                                       // non-minimal version varint
	f.Add([]byte("MTREE\x02\x06sha256\x00\x00\x20\xff\xff\xff\xff"))     // truncated root
	f.Add([]byte("MTREE\x02\x06sha256\x02\x00\x00\x00"))                 // out of range sort flag
	f.Add([]byte("MTREE\x02\x06sha256\x00\x00\x00\xff\xff\xff\xff\x7f")) // huge content count

	f.Fuzz(func(t *testing.T, data []byte) {
		var tree MerkleTree
		if err := tree.UnmarshalBinary(data); err != nil {
			// Rejecting a payload is always an acceptable outcome. The receiver
			// must be untouched when that happens.
			if tree.Root != nil || tree.Leafs != nil || tree.merkleRoot != nil {
				t.Fatalf("error: a failed decode modified the receiver: %v", err)
			}
			return
		}

		checkDecodedTree(t, &tree)

		// The format is canonical in both directions: the only byte string that
		// decodes to this tree is the one the encoder would produce for it.
		again, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("error: re-encoding a decoded tree failed: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("error: payload is not canonical; a second byte string decodes to the same tree:\n accepted %x\n re-encoded %x", data, again)
		}
	})
}

// FuzzUnmarshalJSON drives the JSON decoder. The JSON form is not canonical -
// encoding/json accepts whitespace, escapes, and reordered fields - so only the
// structural properties are asserted here.
func FuzzUnmarshalJSON(f *testing.F) {
	for _, seed := range fuzzSeedPayloads(f) {
		var tree MerkleTree
		if err := tree.UnmarshalBinary(seed); err != nil {
			continue
		}
		encoded, err := json.Marshal(tree)
		if err != nil {
			continue
		}
		f.Add(encoded)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`{"version":2,"hashStrategy":"sha256","sort":true,"rfc6962":true,"contents":[]}`))
	f.Add([]byte(`{"version":2,"hashStrategy":"nope","merkleRoot":"AA==","contents":[{"payload":"AA=="}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var tree MerkleTree
		if err := tree.UnmarshalJSON(data); err != nil {
			if tree.Root != nil || tree.Leafs != nil || tree.merkleRoot != nil {
				t.Fatalf("error: a failed decode modified the receiver: %v", err)
			}
			return
		}

		checkDecodedTree(t, &tree)

		// Whatever JSON was accepted, re-encoding and decoding again must land on
		// the same tree.
		encoded, err := json.Marshal(tree)
		if err != nil {
			t.Fatalf("error: re-encoding a decoded tree failed: %v", err)
		}
		var again MerkleTree
		if err := again.UnmarshalJSON(encoded); err != nil {
			t.Fatalf("error: a tree this package encoded did not decode: %v", err)
		}
		if !bytes.Equal(again.MerkleRoot(), tree.MerkleRoot()) {
			t.Fatalf("error: JSON round trip changed the root: %x then %x", tree.MerkleRoot(), again.MerkleRoot())
		}
	})
}

// FuzzPayloadCorruption checks the property the recorded root exists to provide: a
// payload that has been altered on its way to the decoder cannot be turned into a
// tree with a different root. Either the decode fails, or what comes back commits to
// exactly what was encoded.
//
// Note that a decode is allowed to succeed on altered bytes. Flipping the sort flag
// of a tree whose sibling pairs are already in ascending order, for instance, yields
// a payload that rebuilds to the very same root - the root is a commitment to the
// hashing that happened, not to the settings that produced it. What must never happen
// is a successful decode to some other root.
func FuzzPayloadCorruption(f *testing.F) {
	f.Add("A|B|C|D", false, false, 0, byte(1))
	f.Add("A|B|C", false, false, 7, byte(0xff))
	f.Add("A|B|C|D|E", true, false, 20, byte(0x80))
	f.Add("A|B|C|D|E|F|G", false, true, 40, byte(0x01))
	f.Add("A", false, false, 5, byte(0x02))

	f.Fuzz(func(t *testing.T, joined string, sorted, rfc6962 bool, offset int, mask byte) {
		parts := splitOn(joined, '|')
		if len(parts) == 0 || len(parts) > 64 {
			t.Skip()
		}
		contents := make([]Content, 0, len(parts))
		for _, p := range parts {
			contents = append(contents, TestSHA256Content{x: p})
		}

		tree, err := propMode{sorted: sorted, rfc6962: rfc6962}.build(contents, sha256.New)
		if err != nil {
			// The sorted and RFC 6962 combination is a documented error.
			t.Skip()
		}
		data, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("error: unexpected error marshaling: %v", err)
		}

		if mask == 0 || len(data) == 0 {
			t.Skip()
		}
		// offset is fuzzer chosen and may be anything an int can hold.
		i := offset % len(data)
		if i < 0 {
			i += len(data)
		}
		corrupted := bytes.Clone(data)
		corrupted[i] ^= mask
		if bytes.Equal(corrupted, data) {
			t.Skip()
		}

		var got MerkleTree
		if err := got.UnmarshalBinary(corrupted); err != nil {
			return // rejected, which is the expected outcome
		}
		if !bytes.Equal(got.MerkleRoot(), tree.MerkleRoot()) {
			t.Fatalf("error: a corrupted payload decoded to a different root:\n got %x\nwant %x\n byte %d xor %#x",
				got.MerkleRoot(), tree.MerkleRoot(), i, mask)
		}
		checkDecodedTree(t, &got)
	})
}
