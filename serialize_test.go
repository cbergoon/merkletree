// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc64"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// The content types the rest of the suite builds trees from carry a single string, so
// their binary encoding is that string. UnmarshalBinary takes a pointer receiver, which
// is what lets a value type be registered and still be reconstructed.

func (t TestSHA256Content) MarshalBinary() ([]byte, error) { return []byte(t.x), nil }

func (t *TestSHA256Content) UnmarshalBinary(data []byte) error {
	t.x = string(data)
	return nil
}

func (t TestMD5Content) MarshalBinary() ([]byte, error) { return []byte(t.x), nil }

func (t *TestMD5Content) UnmarshalBinary(data []byte) error {
	t.x = string(data)
	return nil
}

// sha256d160 stands in for a hash strategy from outside the standard library, of the
// sort RegisterHashStrategy exists to support: keccak256, blake2b, or anything else a
// caller brings along. It hashes twice and truncates, so both its digest size and its
// output differ from every built-in strategy.
type sha256d160 struct {
	inner hash.Hash
}

func newSHA256d160() hash.Hash { return &sha256d160{inner: sha256.New()} }

func (h *sha256d160) Write(p []byte) (int, error) { return h.inner.Write(p) }
func (h *sha256d160) Reset()                      { h.inner.Reset() }
func (h *sha256d160) Size() int                   { return 20 }
func (h *sha256d160) BlockSize() int              { return h.inner.BlockSize() }

func (h *sha256d160) Sum(b []byte) []byte {
	second := sha256.Sum256(h.inner.Sum(nil))
	return append(b, second[:20]...)
}

// TestCustomContent hashes with the custom strategy above.
type TestCustomContent struct {
	x string
}

func (t TestCustomContent) CalculateHash() ([]byte, error) {
	h := newSHA256d160()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (t TestCustomContent) Equals(other Content) (bool, error) {
	o, ok := other.(TestCustomContent)
	if !ok {
		return false, nil
	}
	return t.x == o.x, nil
}

func (t TestCustomContent) MarshalBinary() ([]byte, error) { return []byte(t.x), nil }

func (t *TestCustomContent) UnmarshalBinary(data []byte) error {
	t.x = string(data)
	return nil
}

var crc64Table = crc64.MakeTable(crc64.ECMA)

func newCRC64() hash.Hash { return crc64.New(crc64Table) }

// TestCRC64Content produces eight byte digests, which exercises a hash width nothing
// else in the suite uses.
type TestCRC64Content struct {
	x string
}

func (t TestCRC64Content) CalculateHash() ([]byte, error) {
	h := newCRC64()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (t TestCRC64Content) Equals(other Content) (bool, error) {
	o, ok := other.(TestCRC64Content)
	if !ok {
		return false, nil
	}
	return t.x == o.x, nil
}

func (t TestCRC64Content) MarshalBinary() ([]byte, error) { return []byte(t.x), nil }

func (t *TestCRC64Content) UnmarshalBinary(data []byte) error {
	t.x = string(data)
	return nil
}

// TestPointerContent is registered as a pointer, to prove pointer content survives a
// round trip as a pointer rather than being flattened to a value.
type TestPointerContent struct {
	x string
}

func (t *TestPointerContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (t *TestPointerContent) Equals(other Content) (bool, error) {
	o, ok := other.(*TestPointerContent)
	if !ok {
		return false, nil
	}
	return t.x == o.x, nil
}

func (t *TestPointerContent) MarshalBinary() ([]byte, error) { return []byte(t.x), nil }

func (t *TestPointerContent) UnmarshalBinary(data []byte) error {
	t.x = string(data)
	return nil
}

// TestRetainingContent keeps the exact slice handed to UnmarshalBinary, which the
// encoding.BinaryUnmarshaler contract permits, so that the decoder can be caught
// aliasing the caller's buffer.
type TestRetainingContent struct {
	raw []byte
}

func (t TestRetainingContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(t.raw); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (t TestRetainingContent) Equals(other Content) (bool, error) {
	o, ok := other.(TestRetainingContent)
	if !ok {
		return false, nil
	}
	return bytes.Equal(t.raw, o.raw), nil
}

func (t TestRetainingContent) MarshalBinary() ([]byte, error) { return t.raw, nil }

func (t *TestRetainingContent) UnmarshalBinary(data []byte) error {
	t.raw = data
	return nil
}

// unserializableContent implements Content but not encoding.BinaryMarshaler.
type unserializableContent struct {
	x string
}

func (t unserializableContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (t unserializableContent) Equals(other Content) (bool, error) {
	o, ok := other.(unserializableContent)
	if !ok {
		return false, nil
	}
	return t.x == o.x, nil
}

func init() {
	RegisterContent(TestSHA256Content{})
	RegisterContent(TestMD5Content{})
	RegisterContent(TestCustomContent{})
	RegisterContent(TestCRC64Content{})
	RegisterContent(TestRetainingContent{})
	RegisterContent(&TestPointerContent{})

	RegisterHashStrategy("sha256d160", newSHA256d160)
	RegisterHashStrategy("crc64", newCRC64)
}

// buildTableTree constructs the tree described by row i of the shared test table.
func buildTableTree(t *testing.T, i int) *MerkleTree {
	t.Helper()

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
		t.Fatalf("[case:%d] error: unexpected error building tree: %v", table[i].testCaseId, err)
	}
	return tree
}

// assertEquivalent checks that a decoded tree is indistinguishable from the original:
// same root, internally consistent, same leaves in the same order, and answering
// membership and path queries identically.
func assertEquivalent(t *testing.T, label string, want, got *MerkleTree, contents []Content, notIn Content) {
	t.Helper()

	if !bytes.Equal(want.MerkleRoot(), got.MerkleRoot()) {
		t.Fatalf("%s: expected Merkle root %x, got %x", label, want.MerkleRoot(), got.MerkleRoot())
	}
	if want.sort != got.sort {
		t.Errorf("%s: expected sort flag %t, got %t", label, want.sort, got.sort)
	}
	if len(want.Leafs) != len(got.Leafs) {
		t.Fatalf("%s: expected %d leaves, got %d", label, len(want.Leafs), len(got.Leafs))
	}
	if want.String() != got.String() {
		t.Errorf("%s: expected tree\n%s\ngot\n%s", label, want.String(), got.String())
	}

	ok, err := got.VerifyTree()
	if err != nil {
		t.Fatalf("%s: unexpected error verifying decoded tree: %v", label, err)
	}
	if !ok {
		t.Errorf("%s: expected decoded tree to verify", label)
	}

	for _, c := range contents {
		ok, err := got.VerifyContent(c)
		if err != nil {
			t.Fatalf("%s: unexpected error verifying content: %v", label, err)
		}
		if !ok {
			t.Errorf("%s: expected decoded tree to contain %v", label, c)
		}

		wantPath, wantIndex, err := want.GetMerklePath(c)
		if err != nil {
			t.Fatalf("%s: unexpected error reading original path: %v", label, err)
		}
		gotPath, gotIndex, err := got.GetMerklePath(c)
		if err != nil {
			t.Fatalf("%s: unexpected error reading decoded path: %v", label, err)
		}
		if len(wantPath) != len(gotPath) {
			t.Fatalf("%s: expected path of length %d for %v, got %d", label, len(wantPath), c, len(gotPath))
		}
		for i := range wantPath {
			if !bytes.Equal(wantPath[i], gotPath[i]) {
				t.Errorf("%s: expected path element %d of %v to be %x, got %x", label, i, c, wantPath[i], gotPath[i])
			}
			if wantIndex[i] != gotIndex[i] {
				t.Errorf("%s: expected path index %d of %v to be %d, got %d", label, i, c, wantIndex[i], gotIndex[i])
			}
		}
	}

	if notIn != nil {
		ok, err := got.VerifyContent(notIn)
		if err != nil {
			t.Fatalf("%s: unexpected error verifying absent content: %v", label, err)
		}
		if ok {
			t.Errorf("%s: expected decoded tree not to contain %v", label, notIn)
		}
	}
}

func TestMarshalBinaryRoundTrip(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)

		data, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error marshaling: %v", table[i].testCaseId, err)
		}

		var got MerkleTree
		if err := got.UnmarshalBinary(data); err != nil {
			t.Fatalf("[case:%d] error: unexpected error unmarshaling: %v", table[i].testCaseId, err)
		}

		if !bytes.Equal(got.MerkleRoot(), table[i].expectedHash) {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, got.MerkleRoot())
		}
		assertEquivalent(t, fmt.Sprintf("[case:%d]", table[i].testCaseId), tree, &got, table[i].contents, table[i].notInContents)
	}
}

func TestMarshalJSONRoundTrip(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)

		data, err := json.Marshal(tree)
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error marshaling: %v", table[i].testCaseId, err)
		}

		var got MerkleTree
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("[case:%d] error: unexpected error unmarshaling: %v", table[i].testCaseId, err)
		}

		if !bytes.Equal(got.MerkleRoot(), table[i].expectedHash) {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, got.MerkleRoot())
		}
		assertEquivalent(t, fmt.Sprintf("[case:%d]", table[i].testCaseId), tree, &got, table[i].contents, table[i].notInContents)
	}
}

// TestGobRoundTrip is the case from issue #13: encoding/gob applied to a tree directly.
// Before the marshalers existed this did not return an error, it crashed the process
// with a stack overflow as gob chased the Node to Tree to Node cycle.
func TestGobRoundTrip(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)

		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(tree); err != nil {
			t.Fatalf("[case:%d] error: unexpected error encoding: %v", table[i].testCaseId, err)
		}

		var got MerkleTree
		if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
			t.Fatalf("[case:%d] error: unexpected error decoding: %v", table[i].testCaseId, err)
		}

		if !bytes.Equal(got.MerkleRoot(), table[i].expectedHash) {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, got.MerkleRoot())
		}
		assertEquivalent(t, fmt.Sprintf("[case:%d]", table[i].testCaseId), tree, &got, table[i].contents, table[i].notInContents)
	}
}

// TestMarshalWithRoundTrip exercises the callback layer, which touches neither registry.
func TestMarshalWithRoundTrip(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)

		md5Case := table[i].hashStrategyName == "md5"
		encode := func(c Content) ([]byte, error) {
			if md5Case {
				return []byte(c.(TestMD5Content).x), nil
			}
			return []byte(c.(TestSHA256Content).x), nil
		}
		decode := func(b []byte) (Content, error) {
			if md5Case {
				return TestMD5Content{x: string(b)}, nil
			}
			return TestSHA256Content{x: string(b)}, nil
		}

		data, err := tree.MarshalWith(encode)
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error marshaling: %v", table[i].testCaseId, err)
		}

		got, err := UnmarshalWith(data, decode)
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error unmarshaling: %v", table[i].testCaseId, err)
		}

		if !bytes.Equal(got.MerkleRoot(), table[i].expectedHash) {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, got.MerkleRoot())
		}
		assertEquivalent(t, fmt.Sprintf("[case:%d]", table[i].testCaseId), tree, got, table[i].contents, table[i].notInContents)
	}
}

// TestBuiltinHashStrategiesRoundTrip covers every strategy the package registers for
// the caller, including the two whose digests are not 32 bytes wide.
func TestBuiltinHashStrategiesRoundTrip(t *testing.T) {
	strategies := map[string]func() hash.Hash{
		"sha256":     sha256.New,
		"sha224":     sha256.New224,
		"sha512":     sha512.New,
		"sha384":     sha512.New384,
		"sha512_224": sha512.New512_224,
		"sha512_256": sha512.New512_256,
		"sha1":       sha1.New,
		"md5":        md5.New,
	}

	registered := HashStrategyNames()
	for name := range strategies {
		found := false
		for _, r := range registered {
			if r == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("error: expected %q to be registered by default, have %v", name, registered)
		}
	}

	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
		TestSHA256Content{x: "Hola"},
		TestSHA256Content{x: "Bonjour"},
	}

	for name, strategy := range strategies {
		for _, sorted := range []bool{false, true} {
			tree, err := NewTreeWithHashStrategySorted(contents, strategy, sorted)
			if err != nil {
				t.Fatalf("[%s sorted:%t] error: unexpected error building tree: %v", name, sorted, err)
			}

			data, err := tree.MarshalBinary()
			if err != nil {
				t.Fatalf("[%s sorted:%t] error: unexpected error marshaling: %v", name, sorted, err)
			}

			td, err := unmarshalTreeData(data)
			if err != nil {
				t.Fatalf("[%s sorted:%t] error: unexpected error parsing payload: %v", name, sorted, err)
			}
			if td.HashStrategy != name {
				t.Errorf("[%s sorted:%t] error: expected recorded strategy %q, got %q", name, sorted, name, td.HashStrategy)
			}
			if td.Sort != sorted {
				t.Errorf("[%s sorted:%t] error: expected recorded sort flag %t, got %t", name, sorted, sorted, td.Sort)
			}

			var got MerkleTree
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("[%s sorted:%t] error: unexpected error unmarshaling: %v", name, sorted, err)
			}
			assertEquivalent(t, fmt.Sprintf("[%s sorted:%t]", name, sorted), tree, &got, contents, TestSHA256Content{x: "NotInTestTable"})
		}
	}
}

// TestCustomHashStrategyRoundTrip covers strategies that are not from the standard
// library at all, which is the case RegisterHashStrategy exists for. A caller supplying
// keccak256 or blake2b registers it exactly the way these two are registered.
func TestCustomHashStrategyRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		strategy   func() hash.Hash
		digestSize int
		contents   []Content
		notIn      Content
	}{
		{
			name:       "sha256d160",
			strategy:   newSHA256d160,
			digestSize: 20,
			contents: []Content{
				TestCustomContent{x: "Hello"},
				TestCustomContent{x: "Hi"},
				TestCustomContent{x: "Hey"},
			},
			notIn: TestCustomContent{x: "NotInTestTable"},
		},
		{
			name:       "crc64",
			strategy:   newCRC64,
			digestSize: 8,
			contents: []Content{
				TestCRC64Content{x: "Hello"},
				TestCRC64Content{x: "Hi"},
				TestCRC64Content{x: "Hey"},
				TestCRC64Content{x: "Hola"},
			},
			notIn: TestCRC64Content{x: "NotInTestTable"},
		},
	}

	for _, tc := range cases {
		for _, sorted := range []bool{false, true} {
			label := fmt.Sprintf("[%s sorted:%t]", tc.name, sorted)

			tree, err := NewTreeWithHashStrategySorted(tc.contents, tc.strategy, sorted)
			if err != nil {
				t.Fatalf("%s error: unexpected error building tree: %v", label, err)
			}
			if len(tree.MerkleRoot()) != tc.digestSize {
				t.Errorf("%s error: expected a %d byte root, got %d", label, tc.digestSize, len(tree.MerkleRoot()))
			}

			data, err := tree.MarshalBinary()
			if err != nil {
				t.Fatalf("%s error: unexpected error marshaling: %v", label, err)
			}

			var got MerkleTree
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("%s error: unexpected error unmarshaling: %v", label, err)
			}
			assertEquivalent(t, label, tree, &got, tc.contents, tc.notIn)

			// The strategy has to survive the trip as well: the decoded tree must be
			// able to rebuild and re-verify itself, which only works if it is hashing
			// with the same function the payload was written with.
			if err := got.RebuildTree(); err != nil {
				t.Fatalf("%s error: unexpected error rebuilding: %v", label, err)
			}
			if !bytes.Equal(got.MerkleRoot(), tree.MerkleRoot()) {
				t.Errorf("%s error: expected root %x after rebuild, got %x", label, tree.MerkleRoot(), got.MerkleRoot())
			}
		}
	}
}

// unregisterHashStrategy removes a strategy from the package registry. Registration is
// process wide and deliberately permanent, so a test that registers a throwaway strategy
// has to undo it or the test will not survive a second run under -count.
func unregisterHashStrategy(t *testing.T, name string) {
	t.Helper()

	hashStrategyRegistry.Lock()
	defer hashStrategyRegistry.Unlock()

	strategy, ok := hashStrategyRegistry.byName[name]
	if !ok {
		return
	}
	delete(hashStrategyRegistry.byName, name)
	if ptr := reflect.ValueOf(strategy).Pointer(); hashStrategyRegistry.byFunc[ptr] == name {
		delete(hashStrategyRegistry.byFunc, ptr)
	}
}

// TestHashStrategyNameResolvedLazily proves a strategy can be registered after the tree
// that uses it has already been built.
func TestHashStrategyNameResolvedLazily(t *testing.T) {
	unregisterHashStrategy(t, "test_late_strategy")
	t.Cleanup(func() { unregisterHashStrategy(t, "test_late_strategy") })

	lateStrategy := func() hash.Hash { return sha512.New512_256() }

	contents := []Content{TestSHA256Content{x: "Hello"}, TestSHA256Content{x: "Hi"}}
	tree, err := NewTreeWithHashStrategy(contents, lateStrategy)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	if _, err := tree.MarshalBinary(); !errors.Is(err, ErrNoHashStrategy) {
		t.Fatalf("error: expected ErrNoHashStrategy for an unregistered strategy, got %v", err)
	}

	RegisterHashStrategy("test_late_strategy", lateStrategy)

	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling after registration: %v", err)
	}
	var got MerkleTree
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}
	assertEquivalent(t, "late registration", tree, &got, contents, TestSHA256Content{x: "NotInTestTable"})
}

// TestRegistryFreeRoundTrip uses the option overrides on both sides, so neither the
// hash strategy nor the content type is ever named in a package-level registry.
func TestRegistryFreeRoundTrip(t *testing.T) {
	strategy := func() hash.Hash { return sha512.New384() }

	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
	}
	tree, err := NewTreeWithHashStrategy(contents, strategy)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	encode := func(c Content) ([]byte, error) { return []byte(c.(TestSHA256Content).x), nil }
	decode := func(b []byte) (Content, error) { return TestSHA256Content{x: string(b)}, nil }

	data, err := tree.MarshalWith(encode, WithHashStrategyName("private/strategy"))
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	if _, err := UnmarshalWith(data, decode); !errors.Is(err, ErrNoHashStrategy) {
		t.Fatalf("error: expected ErrNoHashStrategy without an override, got %v", err)
	}

	got, err := UnmarshalWith(data, decode, WithHashStrategy(strategy))
	if err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}
	assertEquivalent(t, "registry free", tree, got, contents, TestSHA256Content{x: "NotInTestTable"})

	// The name from the payload is retained, so re-encoding reproduces it rather than
	// falling back to whatever the override strategy happens to be registered as.
	again, err := got.MarshalWith(encode)
	if err != nil {
		t.Fatalf("error: unexpected error re-marshaling: %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Errorf("error: expected re-encoding to reproduce the original payload")
	}
}

func TestUnknownHashStrategyOnUnmarshal(t *testing.T) {
	td := &treeData{
		Version:      serializationVersion,
		HashStrategy: "not_a_registered_strategy",
		MerkleRoot:   []byte{1, 2, 3},
		Contents:     []contentRecord{{Type: contentTypeName2(TestSHA256Content{}), Payload: []byte("Hello")}},
	}

	var got MerkleTree
	err := got.UnmarshalBinary(td.marshalBinary())
	if !errors.Is(err, ErrNoHashStrategy) {
		t.Fatalf("error: expected ErrNoHashStrategy, got %v", err)
	}
	if !strings.Contains(err.Error(), "not_a_registered_strategy") {
		t.Errorf("error: expected the strategy name in %q", err.Error())
	}
}

func TestUnregisteredContentOnMarshal(t *testing.T) {
	contents := []Content{
		unserializableContent{x: "Hello"},
		unserializableContent{x: "Hi"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	_, err = tree.MarshalBinary()
	if !errors.Is(err, ErrNoContentType) {
		t.Fatalf("error: expected ErrNoContentType, got %v", err)
	}
	if !strings.Contains(err.Error(), "RegisterContent") {
		t.Errorf("error: expected the error to point at RegisterContent, got %q", err.Error())
	}

	// The callback layer has no such requirement.
	encode := func(c Content) ([]byte, error) { return []byte(c.(unserializableContent).x), nil }
	decode := func(b []byte) (Content, error) { return unserializableContent{x: string(b)}, nil }

	data, err := tree.MarshalWith(encode)
	if err != nil {
		t.Fatalf("error: unexpected error marshaling with a callback: %v", err)
	}
	got, err := UnmarshalWith(data, decode)
	if err != nil {
		t.Fatalf("error: unexpected error unmarshaling with a callback: %v", err)
	}
	assertEquivalent(t, "unregistered content via callback", tree, got, contents, unserializableContent{x: "NotInTestTable"})
}

func TestUnregisteredContentOnUnmarshal(t *testing.T) {
	tree, err := NewTree([]Content{TestSHA256Content{x: "Hello"}, TestSHA256Content{x: "Hi"}})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	td, err := unmarshalTreeData(data)
	if err != nil {
		t.Fatalf("error: unexpected error parsing payload: %v", err)
	}
	for i := range td.Contents {
		td.Contents[i].Type = "example.com/other.Content"
	}

	var got MerkleTree
	err = got.UnmarshalBinary(td.marshalBinary())
	if !errors.Is(err, ErrNoContentType) {
		t.Fatalf("error: expected ErrNoContentType, got %v", err)
	}
	if !strings.Contains(err.Error(), "example.com/other.Content") {
		t.Errorf("error: expected the type name in %q", err.Error())
	}
}

// TestCallbackPayloadRejectedByRegistry checks that mixing the layers fails with an
// error that names the fix rather than something opaque.
func TestCallbackPayloadRejectedByRegistry(t *testing.T) {
	tree, err := NewTree([]Content{TestSHA256Content{x: "Hello"}, TestSHA256Content{x: "Hi"}})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	data, err := tree.MarshalWith(func(c Content) ([]byte, error) {
		return []byte(c.(TestSHA256Content).x), nil
	})
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	var got MerkleTree
	err = got.UnmarshalBinary(data)
	if !errors.Is(err, ErrNoContentType) {
		t.Fatalf("error: expected ErrNoContentType, got %v", err)
	}
	if !strings.Contains(err.Error(), "UnmarshalWith") {
		t.Errorf("error: expected the error to point at UnmarshalWith, got %q", err.Error())
	}
}

// TestTamperedContentRejected is the payoff for recording the root: content that is
// altered in transit cannot produce a tree that verifies.
func TestTamperedContentRejected(t *testing.T) {
	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	td, err := unmarshalTreeData(data)
	if err != nil {
		t.Fatalf("error: unexpected error parsing payload: %v", err)
	}
	td.Contents[1].Payload = []byte("Tampered")

	var got MerkleTree
	err = got.UnmarshalBinary(td.marshalBinary())
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("error: expected ErrRootMismatch, got %v", err)
	}
	if got.Root != nil {
		t.Errorf("error: expected the receiver to be untouched after a failed decode")
	}
}

func TestTamperedRootRejected(t *testing.T) {
	tree, err := NewTree([]Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
	})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	td, err := unmarshalTreeData(data)
	if err != nil {
		t.Fatalf("error: unexpected error parsing payload: %v", err)
	}
	td.MerkleRoot[0] ^= 0xff

	var got MerkleTree
	if err := got.UnmarshalBinary(td.marshalBinary()); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("error: expected ErrRootMismatch, got %v", err)
	}
}

// TestMismatchedHashStrategyRejected covers a payload decoded with the wrong strategy,
// which the recorded root catches even though every other field is well formed.
func TestMismatchedHashStrategyRejected(t *testing.T) {
	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	decode := func(b []byte) (Content, error) { return TestSHA256Content{x: string(b)}, nil }
	if _, err := UnmarshalWith(data, decode, WithHashStrategy(md5.New)); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("error: expected ErrRootMismatch, got %v", err)
	}
}

// TestTruncatedPayloadRejected feeds every prefix of a valid payload to the decoder.
// None may succeed and none may panic.
func TestTruncatedPayloadRejected(t *testing.T) {
	tree, err := NewTree([]Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
	})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	for n := 0; n < len(data); n++ {
		var got MerkleTree
		if err := got.UnmarshalBinary(data[:n]); err == nil {
			t.Errorf("error: expected an error decoding the first %d of %d bytes", n, len(data))
		}
		if got.Root != nil {
			t.Errorf("error: expected the receiver to be untouched after decoding %d bytes", n)
		}
	}
}

// TestCorruptedPayloadRejected flips a bit at every position and requires an error
// rather than a panic or a silently wrong tree.
func TestCorruptedPayloadRejected(t *testing.T) {
	tree, err := NewTree([]Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
	})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	for i := range data {
		corrupt := bytes.Clone(data)
		corrupt[i] ^= 0xff

		var got MerkleTree
		if err := got.UnmarshalBinary(corrupt); err == nil {
			t.Errorf("error: expected an error decoding a payload with byte %d flipped", i)
		}
	}
}

func TestMalformedPayloadsRejected(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrCorruptData},
		{name: "short", data: []byte("MT"), want: ErrCorruptData},
		{name: "wrong magic", data: []byte("NOTMTREEpayload"), want: ErrCorruptData},
		{name: "magic only", data: []byte(serializationMagic), want: ErrCorruptData},
	}

	for _, tc := range cases {
		var got MerkleTree
		if err := got.UnmarshalBinary(tc.data); !errors.Is(err, tc.want) {
			t.Errorf("[%s] error: expected %v, got %v", tc.name, tc.want, err)
		}
	}
}

func TestUnsupportedVersionRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(serializationMagic)
	writeUvarint(&buf, serializationVersion+1)
	writeBytes(&buf, []byte("sha256"))
	buf.WriteByte(0)
	writeBytes(&buf, []byte{1, 2, 3})
	writeUvarint(&buf, 0)

	var got MerkleTree
	err := got.UnmarshalBinary(buf.Bytes())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("error: expected ErrUnsupportedVersion, got %v", err)
	}

	// The JSON form carries the same version field and must reject it too.
	err = (&MerkleTree{}).UnmarshalJSON([]byte(`{"version":99,"hashStrategy":"sha256","contents":[]}`))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("error: expected ErrUnsupportedVersion from JSON, got %v", err)
	}
}

func TestTrailingBytesRejected(t *testing.T) {
	tree, err := NewTree([]Content{TestSHA256Content{x: "Hello"}, TestSHA256Content{x: "Hi"}})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	var got MerkleTree
	if err := got.UnmarshalBinary(append(bytes.Clone(data), 0x00)); !errors.Is(err, ErrCorruptData) {
		t.Fatalf("error: expected ErrCorruptData for trailing bytes, got %v", err)
	}
}

// TestEncodingIsDeterministic matters because payloads are often hashed, compared, or
// content addressed by the caller.
func TestEncodingIsDeterministic(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)

		first, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error marshaling: %v", table[i].testCaseId, err)
		}
		second, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error marshaling: %v", table[i].testCaseId, err)
		}
		if !bytes.Equal(first, second) {
			t.Errorf("[case:%d] error: expected identical bytes from repeated encoding", table[i].testCaseId)
		}

		// A decoded tree must encode back to exactly what it was decoded from.
		var got MerkleTree
		if err := got.UnmarshalBinary(first); err != nil {
			t.Fatalf("[case:%d] error: unexpected error unmarshaling: %v", table[i].testCaseId, err)
		}
		third, err := got.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error re-marshaling: %v", table[i].testCaseId, err)
		}
		if !bytes.Equal(first, third) {
			t.Errorf("[case:%d] error: expected a decoded tree to re-encode identically", table[i].testCaseId)
		}
	}
}

// TestPaddingIsNotSerialized checks that the duplicate leaf appended for an odd content
// count is left out of the payload and regenerated on decode. Encoding it would promote
// it to real content and the tree would grow by one item on every round trip.
func TestPaddingIsNotSerialized(t *testing.T) {
	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	if len(tree.Leafs) != 4 {
		t.Fatalf("error: expected 4 leaves for 3 contents, got %d", len(tree.Leafs))
	}

	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}
	td, err := unmarshalTreeData(data)
	if err != nil {
		t.Fatalf("error: unexpected error parsing payload: %v", err)
	}
	if len(td.Contents) != 3 {
		t.Errorf("error: expected 3 encoded contents, got %d", len(td.Contents))
	}

	// Round trip repeatedly; the leaf count and the root must both stay put.
	current := tree
	for i := 0; i < 3; i++ {
		data, err := current.MarshalBinary()
		if err != nil {
			t.Fatalf("error: unexpected error marshaling on pass %d: %v", i, err)
		}
		var next MerkleTree
		if err := next.UnmarshalBinary(data); err != nil {
			t.Fatalf("error: unexpected error unmarshaling on pass %d: %v", i, err)
		}
		if len(next.Leafs) != 4 {
			t.Fatalf("error: expected 4 leaves on pass %d, got %d", i, len(next.Leafs))
		}
		if !next.Leafs[3].dup {
			t.Errorf("error: expected the fourth leaf to be marked as padding on pass %d", i)
		}
		if !bytes.Equal(next.MerkleRoot(), tree.MerkleRoot()) {
			t.Errorf("error: expected root %x on pass %d, got %x", tree.MerkleRoot(), i, next.MerkleRoot())
		}
		current = &next
	}
}

// TestSingleContentRoundTrip is the smallest tree there is: one item plus its padding copy.
func TestSingleContentRoundTrip(t *testing.T) {
	contents := []Content{TestSHA256Content{x: "Hello"}}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}
	var got MerkleTree
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}
	assertEquivalent(t, "single content", tree, &got, contents, TestSHA256Content{x: "NotInTestTable"})
}

// TestDecodedTreeOwnsItsNodes checks that every node points back at the tree it now
// belongs to, not at the scratch tree the decoder built into.
func TestDecodedTreeOwnsItsNodes(t *testing.T) {
	for i := range table {
		tree := buildTableTree(t, i)
		data, err := tree.MarshalBinary()
		if err != nil {
			t.Fatalf("[case:%d] error: unexpected error marshaling: %v", table[i].testCaseId, err)
		}

		got := &MerkleTree{}
		if err := got.UnmarshalBinary(data); err != nil {
			t.Fatalf("[case:%d] error: unexpected error unmarshaling: %v", table[i].testCaseId, err)
		}

		var walk func(n *Node)
		seen := map[*Node]bool{}
		walk = func(n *Node) {
			if n == nil || seen[n] {
				return
			}
			seen[n] = true
			if n.Tree != got {
				t.Fatalf("[case:%d] error: node %v points at a different tree", table[i].testCaseId, n.Hash)
			}
			walk(n.Left)
			walk(n.Right)
		}
		walk(got.Root)

		for _, l := range got.Leafs {
			if !seen[l] {
				t.Errorf("[case:%d] error: leaf %v is not reachable from the root", table[i].testCaseId, l.Hash)
			}
		}

		// Rebuilding uses the tree's own strategy and sort flag, so a tree that
		// decoded correctly rebuilds to the same root.
		if err := got.RebuildTree(); err != nil {
			t.Fatalf("[case:%d] error: unexpected error rebuilding: %v", table[i].testCaseId, err)
		}
		if !bytes.Equal(got.MerkleRoot(), tree.MerkleRoot()) {
			t.Errorf("[case:%d] error: expected root %x after rebuild, got %x", table[i].testCaseId, tree.MerkleRoot(), got.MerkleRoot())
		}
	}
}

// TestFailedDecodeLeavesReceiverIntact checks that a tree already holding data is not
// damaged by a failed decode into it.
func TestFailedDecodeLeavesReceiverIntact(t *testing.T) {
	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}

	got := &MerkleTree{}
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}
	before := bytes.Clone(got.MerkleRoot())

	if err := got.UnmarshalBinary([]byte("not a merkletree payload")); err == nil {
		t.Fatal("error: expected an error decoding garbage")
	}
	if !bytes.Equal(got.MerkleRoot(), before) {
		t.Errorf("error: expected root %x to survive a failed decode, got %x", before, got.MerkleRoot())
	}
	ok, err := got.VerifyTree()
	if err != nil {
		t.Fatalf("error: unexpected error verifying: %v", err)
	}
	if !ok {
		t.Error("error: expected the tree to still verify after a failed decode")
	}
}

func TestMarshalEmptyTree(t *testing.T) {
	var empty MerkleTree

	if _, err := empty.MarshalBinary(); err == nil {
		t.Error("error: expected an error marshaling an empty tree")
	}
	if _, err := json.Marshal(&empty); err == nil {
		t.Error("error: expected an error marshaling an empty tree to JSON")
	}
	if _, err := empty.MarshalWith(func(Content) ([]byte, error) { return nil, nil }); err == nil {
		t.Error("error: expected an error marshaling an empty tree with a callback")
	}
}

// TestTreeHeldByValueMarshals covers a tree reached as a struct field rather than through
// a pointer. The marshalers take value receivers precisely so this case still encodes: a
// pointer receiver is unreachable on an unaddressable value, and encoding/json and
// encoding/gob would fall back to walking the node graph and recurse until the process
// died.
func TestTreeHeldByValueMarshals(t *testing.T) {
	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	type wrapper struct {
		Tree MerkleTree
	}

	data, err := json.Marshal(wrapper{Tree: *tree})
	if err != nil {
		t.Fatalf("error: unexpected error marshaling to JSON: %v", err)
	}
	var fromJSON wrapper
	if err := json.Unmarshal(data, &fromJSON); err != nil {
		t.Fatalf("error: unexpected error unmarshaling from JSON: %v", err)
	}
	assertEquivalent(t, "value tree via JSON", tree, &fromJSON.Tree, contents, TestSHA256Content{x: "NotInTestTable"})

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(wrapper{Tree: *tree}); err != nil {
		t.Fatalf("error: unexpected error encoding with gob: %v", err)
	}
	var fromGob wrapper
	if err := gob.NewDecoder(&buf).Decode(&fromGob); err != nil {
		t.Fatalf("error: unexpected error decoding with gob: %v", err)
	}
	assertEquivalent(t, "value tree via gob", tree, &fromGob.Tree, contents, TestSHA256Content{x: "NotInTestTable"})
}

func TestMarshalWithRequiresCallbacks(t *testing.T) {
	tree, err := NewTree([]Content{TestSHA256Content{x: "Hello"}, TestSHA256Content{x: "Hi"}})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	if _, err := tree.MarshalWith(nil); err == nil {
		t.Error("error: expected an error from MarshalWith with a nil encoder")
	}
	if _, err := UnmarshalWith([]byte(serializationMagic), nil); err == nil {
		t.Error("error: expected an error from UnmarshalWith with a nil decoder")
	}
}

func TestContentMarshalErrorsPropagate(t *testing.T) {
	tree, err := NewTree([]Content{TestSHA256Content{x: "Hello"}, TestSHA256Content{x: "Hi"}})
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	sentinel := errors.New("content encoder failed")
	if _, err := tree.MarshalWith(func(Content) ([]byte, error) { return nil, sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("error: expected the encoder error to propagate, got %v", err)
	}

	data, err := tree.MarshalWith(func(c Content) ([]byte, error) {
		return []byte(c.(TestSHA256Content).x), nil
	})
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}
	if _, err := UnmarshalWith(data, func([]byte) (Content, error) { return nil, sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("error: expected the decoder error to propagate, got %v", err)
	}
	if _, err := UnmarshalWith(data, func([]byte) (Content, error) { return nil, nil }); err == nil {
		t.Error("error: expected an error when the decoder returns nil content")
	}
}

// TestPointerContentRoundTrip checks that a type registered as a pointer comes back as a
// pointer. Its Equals asserts on *TestPointerContent, so a value would fail to match.
func TestPointerContentRoundTrip(t *testing.T) {
	contents := []Content{
		&TestPointerContent{x: "Hello"},
		&TestPointerContent{x: "Hi"},
		&TestPointerContent{x: "Hey"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}
	var got MerkleTree
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}

	for i, l := range got.Leafs {
		if _, ok := l.C.(*TestPointerContent); !ok {
			t.Fatalf("error: expected leaf %d to hold *TestPointerContent, got %T", i, l.C)
		}
	}
	assertEquivalent(t, "pointer content", tree, &got, contents, &TestPointerContent{x: "NotInTestTable"})
}

// TestDecoderDoesNotAliasPayload checks that content which retains the slice it is given
// does not end up pointing into the caller's buffer.
func TestDecoderDoesNotAliasPayload(t *testing.T) {
	contents := []Content{
		TestRetainingContent{raw: []byte("Hello")},
		TestRetainingContent{raw: []byte("Hi")},
		TestRetainingContent{raw: []byte("Hey")},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}

	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}
	var got MerkleTree
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}

	// Scribble over the source buffer. A decoded tree that aliased it now hashes to
	// something else entirely.
	for i := range data {
		data[i] = 0xff
	}

	ok, err := got.VerifyTree()
	if err != nil {
		t.Fatalf("error: unexpected error verifying: %v", err)
	}
	if !ok {
		t.Error("error: expected the decoded tree to survive its source buffer being overwritten")
	}
	if !bytes.Equal(got.MerkleRoot(), tree.MerkleRoot()) {
		t.Errorf("error: expected root %x, got %x", tree.MerkleRoot(), got.MerkleRoot())
	}
}

func TestRegisterHashStrategyPanics(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
	}{
		{"empty name", func() { RegisterHashStrategy("", sha256.New) }},
		{"nil strategy", func() { RegisterHashStrategy("test_nil_strategy", nil) }},
		{"conflicting name", func() { RegisterHashStrategy("sha256", md5.New) }},
	}

	for _, tc := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("[%s] error: expected a panic", tc.name)
				}
			}()
			tc.fn()
		}()
	}

	// Re-registering the same pairing is a no-op rather than a panic, so that two
	// packages registering the same well known strategy do not fight.
	RegisterHashStrategy("sha256", sha256.New)
}

func TestRegisterContentPanics(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
	}{
		{"nil content", func() { RegisterContent(nil) }},
		{"empty name", func() { RegisterContentName("", TestSHA256Content{}) }},
		{"not a BinaryMarshaler", func() { RegisterContent(unserializableContent{}) }},
		{"conflicting name", func() { RegisterContentName(contentTypeName2(TestSHA256Content{}), TestMD5Content{}) }},
	}

	for _, tc := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("[%s] error: expected a panic", tc.name)
				}
			}()
			tc.fn()
		}()
	}

	// Registering the same type again is a no-op.
	RegisterContent(TestSHA256Content{})
}

// contentTypeName2 exposes the name a content value would be registered under.
func contentTypeName2(c Content) string {
	name, _, err := marshalRegisteredContent(c, &contentTypeCache{})
	if err != nil {
		panic(err)
	}
	return name
}

// TestConcurrentUse exercises the registries and the marshalers together under the race
// detector.
func TestConcurrentUse(t *testing.T) {
	contents := []Content{
		TestSHA256Content{x: "Hello"},
		TestSHA256Content{x: "Hi"},
		TestSHA256Content{x: "Hey"},
		TestSHA256Content{x: "Hola"},
	}
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error building tree: %v", err)
	}
	want := bytes.Clone(tree.MerkleRoot())

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			data, err := tree.MarshalBinary()
			if err != nil {
				t.Errorf("error: unexpected error marshaling: %v", err)
				return
			}
			var got MerkleTree
			if err := got.UnmarshalBinary(data); err != nil {
				t.Errorf("error: unexpected error unmarshaling: %v", err)
				return
			}
			if !bytes.Equal(got.MerkleRoot(), want) {
				t.Errorf("error: expected root %x, got %x", want, got.MerkleRoot())
			}
			RegisterHashStrategy("sha256", sha256.New)
			_ = HashStrategyNames()
		}(i)
	}
	wg.Wait()
}
