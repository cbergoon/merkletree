// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"hash"
	"reflect"
	"strings"
	"testing"
)

// Error paths are where a library is least exercised and most likely to be wrong,
// because nothing in normal use reaches them. The failures injected here are the ones
// that can actually happen to a caller: a hash strategy that stops accepting bytes
// partway through a build, and a content type whose own encoding fails or whose
// decoded value cannot be hashed.

// newAfterNFailHash returns a hash strategy that accepts the first n writes made
// through it and refuses every write after that, counting across every hasher it
// hands out. Failing at a chosen point in the build is what reaches the error
// branches that a hasher failing from the very first write cannot: those branches
// are only entered once earlier hashing has already succeeded.
//
// It is not safe for concurrent use, which is fine - the tests below are sequential.
func newAfterNFailHash(n int) func() hash.Hash {
	count := 0

	return func() hash.Hash {
		return &afterNFailHash{inner: sha256.New(), n: n, count: &count}
	}
}

type afterNFailHash struct {
	inner hash.Hash
	n     int
	count *int
}

var errHashRefused = errors.New("hash refused the write")

func (h *afterNFailHash) Write(p []byte) (int, error) {
	*h.count++
	if *h.count > h.n {
		return 0, errHashRefused
	}

	return h.inner.Write(p)
}

func (h *afterNFailHash) Sum(b []byte) []byte { return h.inner.Sum(b) }
func (h *afterNFailHash) Reset()              { h.inner.Reset() }
func (h *afterNFailHash) Size() int           { return h.inner.Size() }
func (h *afterNFailHash) BlockSize() int      { return h.inner.BlockSize() }

// TestRFC6962InteriorHashFailuresPropagate walks the failure point through the three
// writes hashInterior makes under RFC 6962 - the 0x01 prefix, the left hash, the
// right hash. A hasher that fails from its first write never reaches any of them,
// because leaf hashing fails first and construction stops there.
//
// Four leaves cost two writes each, so the interior prefix is the ninth write.
func TestRFC6962InteriorHashFailuresPropagate(t *testing.T) {
	contents := propSeries(4)

	for _, tc := range []struct {
		name  string
		after int
	}{
		{"interior prefix", 8},
		{"left hash", 9},
		{"right hash", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTreeWithOptions(contents, WithHasher(newAfterNFailHash(tc.after)), WithRFC6962())
			if !errors.Is(err, errHashRefused) {
				t.Errorf("error: expected the hash failure to surface, got %v", err)
			}
		})
	}
}

// TestRFC6962RightSubtreeFailurePropagates reaches the error return for the right
// hand recursive call, which needs the left subtree to have been built successfully
// first. Six leaves cost twelve writes, the left subtree of four costs nine more, and
// the right subtree's first write is the twenty second.
func TestRFC6962RightSubtreeFailurePropagates(t *testing.T) {
	_, err := NewTreeWithOptions(propSeries(6), WithHasher(newAfterNFailHash(21)), WithRFC6962())
	if !errors.Is(err, errHashRefused) {
		t.Errorf("error: expected the hash failure from the right subtree, got %v", err)
	}
}

// TestVerifyContentReportsAMissingRoot covers the check that VerifyContent makes once
// it has recomputed the whole path: the node it climbed to must be the tree's root.
// Clearing Root leaves the leaf-to-ancestor chain intact, so the walk succeeds and
// the check is what catches it.
func TestVerifyContentReportsAMissingRoot(t *testing.T) {
	contents := propSeries(4)
	tree, err := NewTree(contents)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	tree.Root = nil

	ok, err := tree.VerifyContent(contents[0])
	if ok {
		t.Error("error: content verified against a tree with no root")
	}
	if !errors.Is(err, ErrMalformedTree) {
		t.Errorf("error: expected ErrMalformedTree, got %v", err)
	}
}

// TestCalculateNodeHashRejectsMalformedNodes covers the guards directly, since the
// callers check for the same conditions before they get here.
func TestCalculateNodeHashRejectsMalformedNodes(t *testing.T) {
	tree, err := NewTree(propList("A", "B"))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	t.Run("detached node", func(t *testing.T) {
		n := &Node{Hash: []byte{1}}
		if _, err := n.calculateNodeHash(false); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree, got %v", err)
		}
	})

	t.Run("interior node with no children", func(t *testing.T) {
		n := &Node{Tree: tree, Hash: []byte{1}}
		if _, err := n.calculateNodeHash(false); !errors.Is(err, ErrMalformedTree) {
			t.Errorf("error: expected ErrMalformedTree, got %v", err)
		}
	})
}

// codecFailContent fails in both directions. Failing to unmarshal as well as to
// marshal is deliberate: it means no payload naming this type can ever decode, so
// registering it cannot make a well formed tree unencodable.
type codecFailContent struct {
	x string
}

var errContentCodec = errors.New("content codec refused")

func (c codecFailContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(c.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (c codecFailContent) Equals(other Content) (bool, error) {
	o, ok := other.(codecFailContent)

	return ok && c.x == o.x, nil
}

func (c codecFailContent) MarshalBinary() ([]byte, error) { return nil, errContentCodec }
func (c *codecFailContent) UnmarshalBinary([]byte) error  { return errContentCodec }

// hashFailContent decodes cleanly but cannot be hashed, which is what it takes to
// reach the rebuild failure inside the decoder rather than at the content layer.
type hashFailContent struct {
	x string
}

var errContentHash = errors.New("content cannot be hashed")

func (c hashFailContent) CalculateHash() ([]byte, error) { return nil, errContentHash }

func (c hashFailContent) Equals(other Content) (bool, error) {
	o, ok := other.(hashFailContent)

	return ok && c.x == o.x, nil
}

func (c hashFailContent) MarshalBinary() ([]byte, error) { return []byte(c.x), nil }

func (c *hashFailContent) UnmarshalBinary(data []byte) error {
	c.x = string(data)

	return nil
}

func init() {
	RegisterContent(codecFailContent{})
	RegisterContent(hashFailContent{})
}

func TestRegisteredContentMarshalErrorPropagates(t *testing.T) {
	tree, err := NewTree([]Content{codecFailContent{x: "A"}, codecFailContent{x: "B"}})
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}

	if _, err := tree.MarshalBinary(); !errors.Is(err, errContentCodec) {
		t.Errorf("error: expected the content marshal failure to surface, got %v", err)
	}
	if _, err := json.Marshal(tree); err == nil || !strings.Contains(err.Error(), errContentCodec.Error()) {
		t.Errorf("error: expected the content marshal failure to surface from MarshalJSON, got %v", err)
	}
}

// craftPayload builds a payload by hand, which is the only way to produce one holding
// content that the encoder would refuse to write.
func craftPayload(t *testing.T, td *treeData) []byte {
	t.Helper()

	return td.marshalBinary()
}

func TestRegisteredContentUnmarshalErrorPropagates(t *testing.T) {
	name := contentTypeName(reflect.TypeOf(codecFailContent{}))
	data := craftPayload(t, &treeData{
		Version:      serializationVersion,
		HashStrategy: "sha256",
		MerkleRoot:   []byte{0x00},
		Contents: []contentRecord{
			{Type: name, Payload: []byte("A")},
			{Type: name, Payload: []byte("B")},
		},
	})

	var tree MerkleTree
	if err := tree.UnmarshalBinary(data); !errors.Is(err, errContentCodec) {
		t.Errorf("error: expected the content unmarshal failure to surface, got %v", err)
	}
}

// TestDecodedContentThatCannotBeHashedIsRejected covers the rebuild failing inside
// the decoder: the content comes back fine, and only hashing it fails.
func TestDecodedContentThatCannotBeHashedIsRejected(t *testing.T) {
	name := contentTypeName(reflect.TypeOf(hashFailContent{}))
	data := craftPayload(t, &treeData{
		Version:      serializationVersion,
		HashStrategy: "sha256",
		MerkleRoot:   []byte{0x00},
		Contents: []contentRecord{
			{Type: name, Payload: []byte("A")},
			{Type: name, Payload: []byte("B")},
		},
	})

	var tree MerkleTree
	if err := tree.UnmarshalBinary(data); !errors.Is(err, errContentHash) {
		t.Errorf("error: expected the content hash failure to surface, got %v", err)
	}
	if tree.Root != nil {
		t.Error("error: a failed decode left the receiver populated")
	}
}

// TestPayloadWithBothModeFlagsRejected covers a payload claiming a configuration no
// constructor will produce. NewTreeWithOptions rejects the combination up front, so
// only a hand written or tampered payload can carry it, and the decoder has to make
// the same judgement rather than building whichever mode happens to win.
func TestPayloadWithBothModeFlagsRejected(t *testing.T) {
	name := contentTypeName(reflect.TypeOf(TestSHA256Content{}))
	record := contentRecord{Type: name, Payload: []byte("A")}

	t.Run("binary", func(t *testing.T) {
		data := craftPayload(t, &treeData{
			Version:      serializationVersion,
			HashStrategy: "sha256",
			Sort:         true,
			RFC6962:      true,
			MerkleRoot:   []byte{0x00},
			Contents:     []contentRecord{record, record},
		})

		var tree MerkleTree
		err := tree.UnmarshalBinary(data)
		if !errors.Is(err, ErrCorruptData) {
			t.Errorf("error: expected ErrCorruptData, got %v", err)
		}
	})

	t.Run("json", func(t *testing.T) {
		encoded, err := json.Marshal(&treeData{
			Version:      serializationVersion,
			HashStrategy: "sha256",
			Sort:         true,
			RFC6962:      true,
			MerkleRoot:   []byte{0x00},
			Contents:     []contentRecord{record, record},
		})
		if err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}

		var tree MerkleTree
		if err := tree.UnmarshalJSON(encoded); !errors.Is(err, ErrCorruptData) {
			t.Errorf("error: expected ErrCorruptData, got %v", err)
		}
	})
}

func TestMalformedJSONRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"truncated object", `{"version":2`},
		{"not an object", `[]`},
		{"wrong field type", `{"version":"two"}`},
		{"garbage", `not json at all`},
		{"empty", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tree MerkleTree
			err := tree.UnmarshalJSON([]byte(tc.data))
			if err == nil {
				t.Fatal("error: expected malformed JSON to be rejected")
			}
			if !errors.Is(err, ErrCorruptData) {
				t.Errorf("error: expected ErrCorruptData, got %v", err)
			}
			if tree.Root != nil {
				t.Error("error: a failed decode left the receiver populated")
			}
		})
	}
}

// The branches listed below are the only statements in the package that no test
// reaches, and each is unreachable by construction rather than merely untested. They
// are kept because they guard invariants established elsewhere in the file, and
// deleting them would make those invariants implicit. Recorded here so that a
// coverage report can be read without re-deriving the argument each time.
//
//   - RegisterContent's unnamed type check. Go does not allow methods on unnamed
//     types, so a value reaching it cannot implement Content in the first place.
//   - The three type assertions in marshalRegisteredContent and
//     unmarshalRegisteredContent. RegisterContentName panics unless the type
//     implements BinaryMarshaler, its pointer implements BinaryUnmarshaler, and the
//     value satisfies Content, so nothing in either registry can fail them.
//   - snapshot's empty content check. The padding leaf is only ever appended next to
//     real content, so the leaves cannot all be padding.
//   - The io.ReadFull error in binaryReader.bytes. The length was already compared
//     against the bytes remaining in the reader on the line above, so the read
//     cannot come up short.

// marshalOnlyContent can write itself but cannot read itself back, the one shape of
// broken content type that RegisterContent's second check exists to catch. It is
// never registered, so it cannot affect any other test.
type marshalOnlyContent struct {
	x string
}

func (c marshalOnlyContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(c.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (c marshalOnlyContent) Equals(other Content) (bool, error) {
	o, ok := other.(marshalOnlyContent)

	return ok && c.x == o.x, nil
}

func (c marshalOnlyContent) MarshalBinary() ([]byte, error) { return []byte(c.x), nil }

// TestRegisterContentRejectsUnreadableTypes covers the registration guards that the
// existing panic table does not reach. Both are ways a caller can register a type
// that would fail only later, at decode time, in someone else's process.
func TestRegisterContentRejectsUnreadableTypes(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
	}{
		{"nil content by name", func() { RegisterContentName("test_nil_by_name", nil) }},
		{"pointer is not a BinaryUnmarshaler", func() { RegisterContent(marshalOnlyContent{}) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("error: expected a panic")
				}
			}()
			tc.fn()
		})
	}
}

// TestContentTypeNameEdgeCases pins the naming rules, which are wire format: the name
// a type is registered under is what every payload written for it carries. A builtin
// type is named without a package path, and a type with no name at all cannot be
// named, which is what RegisterContent turns into a panic.
func TestContentTypeNameEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		typ  reflect.Type
		want string
	}{
		{"builtin", reflect.TypeOf(0), "int"},
		{"pointer to builtin", reflect.TypeOf(new(int)), "*int"},
		{"unnamed struct", reflect.TypeOf(struct{ A int }{}), ""},
		{"pointer to unnamed struct", reflect.TypeOf(&struct{ A int }{}), ""},
		{"package type", reflect.TypeOf(TestSHA256Content{}), "github.com/cbergoon/merkletree.TestSHA256Content"},
		{"pointer to package type", reflect.TypeOf(&TestPointerContent{}), "*github.com/cbergoon/merkletree.TestPointerContent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentTypeName(tc.typ); got != tc.want {
				t.Errorf("error: contentTypeName(%s) = %q, want %q", tc.typ, got, tc.want)
			}
		})
	}
}

// TestRegistryLookupsHandleNil covers the guards the registry helpers apply before
// touching reflect, which a hand assembled MerkleTree can reach.
func TestRegistryLookupsHandleNil(t *testing.T) {
	if name, ok := lookupHashStrategyName(nil); ok || name != "" {
		t.Errorf("error: expected a nil strategy to resolve to no name, got %q %v", name, ok)
	}

	if _, _, err := marshalRegisteredContent(nil, &contentTypeCache{}); !errors.Is(err, ErrNoContentType) {
		t.Errorf("error: expected ErrNoContentType for nil content, got %v", err)
	}
}

// TestUnmarshalWithRejectsCorruptPayloads checks that the registry free decoder
// applies the same framing checks as the registry backed one; the caller's content
// decoder must never be handed bytes from a payload that failed to parse.
func TestUnmarshalWithRejectsCorruptPayloads(t *testing.T) {
	called := false
	dec := func(b []byte) (Content, error) {
		called = true

		return TestSHA256Content{x: string(b)}, nil
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"bad magic", []byte("XXXXX\x02")},
		{"truncated", []byte("MTREE")},
		{"non-minimal varint", []byte("MTREE\x82\x00\x06sha256\x00\x00\x00\x00")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			if _, err := UnmarshalWith(tc.data, dec); err == nil {
				t.Fatal("error: expected a corrupt payload to be rejected")
			}
			if called {
				t.Error("error: the content decoder was handed bytes from a payload that did not parse")
			}
		})
	}
}
