// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"reflect"
	"slices"
	"sync"
)

// A serialized tree records only what is needed to regenerate it: the ordered leaf
// content, the name of the hash strategy, the sibling sort flag, and the Merkle root
// the encoder observed. Every other part of the tree - the intermediate nodes, the
// parent and tree back-pointers, the leaf and padding markers - is derived from those
// inputs by buildWithContent, so storing it would be redundant.
//
// Persisting the derived structure is not merely wasteful, it is impossible with the
// standard codecs: Node points at its Tree and its Parent while the tree points back
// down at its Root and Leafs, and those cycles send encoding/gob and encoding/json
// into unbounded recursion rather than an error. Recording the seed sidesteps the
// cycle instead of working around it, and the recorded root turns decoding into an
// integrity check for free - a corrupted payload, a mismatched hash strategy, or a
// non-deterministic content encoder all surface as a root mismatch.
const (
	// serializationMagic prefixes every binary blob so a truncated or foreign
	// payload is rejected before any length is trusted.
	serializationMagic = "MTREE"
	// serializationVersion is the wire format version written by this package.
	// Version 2 added the RFC 6962 flag after the sort flag.
	serializationVersion = 2
)

var (
	// ErrUnsupportedVersion is returned when decoding a tree written by a newer
	// format version than this build understands.
	ErrUnsupportedVersion = errors.New("merkletree: unsupported serialization version")
	// ErrCorruptData is returned when a serialized tree is malformed, truncated,
	// or not a merkletree payload at all.
	ErrCorruptData = errors.New("merkletree: corrupt serialized tree")
	// ErrRootMismatch is returned when the tree rebuilt from a payload does not
	// hash to the Merkle root recorded in that payload.
	ErrRootMismatch = errors.New("merkletree: rebuilt Merkle root does not match the encoded root")
	// ErrNoHashStrategy is returned when a hash strategy cannot be named at encode
	// time or resolved at decode time.
	ErrNoHashStrategy = errors.New("merkletree: unknown hash strategy")
	// ErrNoContentType is returned when a content type cannot be named at encode
	// time or resolved at decode time.
	ErrNoContentType = errors.New("merkletree: unregistered content type")
)

// hashStrategyRegistry maps names to hash strategies and back. A function value
// cannot be serialized, so a tree records the name of its strategy and the decoder
// looks the name up here. The reverse index is keyed by the strategy's code pointer,
// which is stable for both plain functions and closure literals.
var hashStrategyRegistry = struct {
	sync.RWMutex
	byName map[string]func() hash.Hash
	byFunc map[uintptr]string
}{
	byName: map[string]func() hash.Hash{},
	byFunc: map[uintptr]string{},
}

func init() {
	RegisterHashStrategy("sha256", sha256.New)
	RegisterHashStrategy("sha224", sha256.New224)
	RegisterHashStrategy("sha512", sha512.New)
	RegisterHashStrategy("sha384", sha512.New384)
	RegisterHashStrategy("sha512_224", sha512.New512_224)
	RegisterHashStrategy("sha512_256", sha512.New512_256)
	RegisterHashStrategy("sha1", sha1.New)
	RegisterHashStrategy("md5", md5.New)
}

// RegisterHashStrategy makes a hash strategy serializable under the given name. The
// hash strategies in the standard library are registered automatically; anything else
// - keccak256, blake2b, or a strategy of your own - must be registered before a tree
// using it can be marshaled or unmarshaled.
//
//	merkletree.RegisterHashStrategy("keccak256", sha3.NewLegacyKeccak256)
//	t, err := merkletree.NewTreeWithHashStrategy(list, sha3.NewLegacyKeccak256)
//
// Registration is idempotent: registering the same name and strategy again is a no-op.
// Registering a different strategy under a name already in use panics, because doing
// so would silently change the meaning of previously written payloads. Registering a
// second name for an already registered strategy is allowed, but the first name wins
// when encoding.
//
// RegisterHashStrategy is safe for concurrent use, though the natural place to call
// it is package initialization.
func RegisterHashStrategy(name string, strategy func() hash.Hash) {
	if name == "" {
		panic("merkletree: cannot register a hash strategy under an empty name")
	}
	if strategy == nil {
		panic("merkletree: cannot register a nil hash strategy")
	}

	ptr := reflect.ValueOf(strategy).Pointer()

	hashStrategyRegistry.Lock()
	defer hashStrategyRegistry.Unlock()

	if existing, ok := hashStrategyRegistry.byName[name]; ok {
		if reflect.ValueOf(existing).Pointer() == ptr {
			return
		}
		panic(fmt.Sprintf("merkletree: hash strategy %q is already registered to a different function", name))
	}
	hashStrategyRegistry.byName[name] = strategy
	if _, ok := hashStrategyRegistry.byFunc[ptr]; !ok {
		hashStrategyRegistry.byFunc[ptr] = name
	}
}

// HashStrategyNames returns the sorted names of every registered hash strategy.
func HashStrategyNames() []string {
	hashStrategyRegistry.RLock()
	defer hashStrategyRegistry.RUnlock()

	names := make([]string, 0, len(hashStrategyRegistry.byName))
	for name := range hashStrategyRegistry.byName {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// lookupHashStrategy resolves a registered name to its strategy.
func lookupHashStrategy(name string) (func() hash.Hash, bool) {
	hashStrategyRegistry.RLock()
	defer hashStrategyRegistry.RUnlock()

	strategy, ok := hashStrategyRegistry.byName[name]
	return strategy, ok
}

// lookupHashStrategyName resolves a strategy back to the name it was registered under.
func lookupHashStrategyName(strategy func() hash.Hash) (string, bool) {
	if strategy == nil {
		return "", false
	}

	hashStrategyRegistry.RLock()
	defer hashStrategyRegistry.RUnlock()

	name, ok := hashStrategyRegistry.byFunc[reflect.ValueOf(strategy).Pointer()]
	return name, ok
}

// contentRegistry maps names to content types and back, mirroring the role gob.Register
// plays for interface values. Content is defined by the application, so the tree cannot
// know how to rebuild a concrete type from bytes without being told.
var contentRegistry = struct {
	sync.RWMutex
	byName map[string]reflect.Type
	byType map[reflect.Type]string
}{
	byName: map[string]reflect.Type{},
	byType: map[reflect.Type]string{},
}

// RegisterContent makes a Content type serializable by the registry-backed marshalers
// (MarshalBinary, MarshalJSON, and anything built on them such as encoding/gob), under
// a name derived from its package path and type name.
//
// The value passed is a template, not data: pass a zero value of the type exactly as it
// is stored in the tree. Registering TestContent{} round-trips leaves back to
// TestContent values; registering &TestContent{} round-trips them back to pointers.
//
// The type must marshal itself. c must implement encoding.BinaryMarshaler and a pointer
// to it must implement encoding.BinaryUnmarshaler, which is the usual pairing of a value
// receiver for MarshalBinary and a pointer receiver for UnmarshalBinary. RegisterContent
// panics if either is missing, or if the type is unnamed.
//
// Callers who would rather not use a package-level registry can skip registration
// entirely and use MarshalWith and UnmarshalWith instead.
func RegisterContent(c Content) {
	rt := reflect.TypeOf(c)
	if rt == nil {
		panic("merkletree: cannot register nil content")
	}
	name := contentTypeName(rt)
	if name == "" {
		panic(fmt.Sprintf("merkletree: cannot register unnamed content type %s", rt))
	}
	RegisterContentName(name, c)
}

// RegisterContentName is RegisterContent with an explicit name. Use it to pin a stable
// name into the wire format so that renaming or moving the Go type does not invalidate
// payloads already written.
func RegisterContentName(name string, c Content) {
	if name == "" {
		panic("merkletree: cannot register content under an empty name")
	}
	rt := reflect.TypeOf(c)
	if rt == nil {
		panic("merkletree: cannot register nil content")
	}
	if _, ok := c.(encoding.BinaryMarshaler); !ok {
		panic(fmt.Sprintf("merkletree: content type %s does not implement encoding.BinaryMarshaler", rt))
	}
	// A pointer to the underlying type must be able to load itself from bytes. When a
	// pointer type is registered that is rt itself; when a value type is registered it
	// is the address of a fresh value, which is what the decoder will unmarshal into.
	ptrType := rt
	if ptrType.Kind() != reflect.Pointer {
		ptrType = reflect.PointerTo(rt)
	}
	if !ptrType.Implements(reflect.TypeOf((*encoding.BinaryUnmarshaler)(nil)).Elem()) {
		panic(fmt.Sprintf("merkletree: %s does not implement encoding.BinaryUnmarshaler", ptrType))
	}

	contentRegistry.Lock()
	defer contentRegistry.Unlock()

	if existing, ok := contentRegistry.byName[name]; ok {
		if existing == rt {
			return
		}
		panic(fmt.Sprintf("merkletree: content name %q is already registered to %s", name, existing))
	}
	contentRegistry.byName[name] = rt
	if _, ok := contentRegistry.byType[rt]; !ok {
		contentRegistry.byType[rt] = name
	}
}

// contentTypeName derives a stable, unambiguous name for a content type. Pointer depth
// is preserved so that T and *T round-trip back to what was registered.
func contentTypeName(rt reflect.Type) string {
	prefix := ""
	for rt.Kind() == reflect.Pointer {
		prefix += "*"
		rt = rt.Elem()
	}
	if rt.Name() == "" {
		return ""
	}
	if rt.PkgPath() == "" {
		return prefix + rt.Name()
	}
	return prefix + rt.PkgPath() + "." + rt.Name()
}

// marshalRegisteredContent encodes a single content item along with the name needed to
// rebuild its concrete type.
func marshalRegisteredContent(c Content) (string, []byte, error) {
	rt := reflect.TypeOf(c)
	if rt == nil {
		return "", nil, fmt.Errorf("%w: tree contains nil content", ErrNoContentType)
	}

	contentRegistry.RLock()
	name, ok := contentRegistry.byType[rt]
	contentRegistry.RUnlock()

	if !ok {
		return "", nil, fmt.Errorf("%w: %s; call merkletree.RegisterContent to make it serializable, or use MarshalWith", ErrNoContentType, rt)
	}

	bm, ok := c.(encoding.BinaryMarshaler)
	if !ok {
		return "", nil, fmt.Errorf("%w: %s does not implement encoding.BinaryMarshaler", ErrNoContentType, rt)
	}
	payload, err := bm.MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("merkletree: marshaling content of type %s: %w", rt, err)
	}
	return name, payload, nil
}

// unmarshalRegisteredContent rebuilds a concrete content value from its recorded name
// and payload.
func unmarshalRegisteredContent(name string, payload []byte) (Content, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: payload carries no content type names, which means it was written by MarshalWith; decode it with UnmarshalWith", ErrNoContentType)
	}

	contentRegistry.RLock()
	rt, ok := contentRegistry.byName[name]
	contentRegistry.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %q; call merkletree.RegisterContent for that type before unmarshaling", ErrNoContentType, name)
	}

	isPointer := rt.Kind() == reflect.Pointer
	elem := rt
	if isPointer {
		elem = rt.Elem()
	}

	pv := reflect.New(elem)
	bu, ok := pv.Interface().(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, fmt.Errorf("%w: %s does not implement encoding.BinaryUnmarshaler", ErrNoContentType, pv.Type())
	}
	// UnmarshalBinary implementations are permitted to retain the slice they are
	// handed, and payload points into the caller's buffer, so hand over a copy.
	if err := bu.UnmarshalBinary(bytes.Clone(payload)); err != nil {
		return nil, fmt.Errorf("merkletree: unmarshaling content of type %q: %w", name, err)
	}

	var v any = pv.Elem().Interface()
	if isPointer {
		v = pv.Interface()
	}
	c, ok := v.(Content)
	if !ok {
		return nil, fmt.Errorf("%w: %q does not implement merkletree.Content", ErrNoContentType, name)
	}
	return c, nil
}

// ContentMarshalFunc encodes a single content item to bytes. It must be deterministic:
// two content items that are Equals must encode identically, or a decoded tree will not
// reproduce the root it was encoded with.
type ContentMarshalFunc func(Content) ([]byte, error)

// ContentUnmarshalFunc decodes a single content item produced by a ContentMarshalFunc.
type ContentUnmarshalFunc func([]byte) (Content, error)

// MarshalOption adjusts how a tree is encoded.
type MarshalOption func(*marshalConfig)

type marshalConfig struct {
	hashStrategyName string
}

// WithHashStrategyName records the given name for the tree's hash strategy instead of
// looking the strategy up in the package registry. Pair it with WithHashStrategy at
// decode time to serialize trees without touching global state at all.
func WithHashStrategyName(name string) MarshalOption {
	return func(c *marshalConfig) { c.hashStrategyName = name }
}

// UnmarshalOption adjusts how a tree is decoded.
type UnmarshalOption func(*unmarshalConfig)

type unmarshalConfig struct {
	hashStrategy func() hash.Hash
}

// WithHashStrategy rebuilds the tree with the given hash strategy instead of resolving
// the name recorded in the payload through the package registry. The recorded name is
// still preserved, so re-encoding the decoded tree reproduces the original name.
func WithHashStrategy(strategy func() hash.Hash) UnmarshalOption {
	return func(c *unmarshalConfig) { c.hashStrategy = strategy }
}

// treeData is the on-the-wire form of a tree: the seed it can be rebuilt from.
type treeData struct {
	Version      int             `json:"version"`
	HashStrategy string          `json:"hashStrategy"`
	Sort         bool            `json:"sort"`
	RFC6962      bool            `json:"rfc6962,omitempty"`
	MerkleRoot   []byte          `json:"merkleRoot"`
	Contents     []contentRecord `json:"contents"`
}

// contentRecord is one leaf's content. Type is empty for payloads written by
// MarshalWith, where the caller's own decoder supplies the concrete type.
type contentRecord struct {
	Type    string `json:"type,omitempty"`
	Payload []byte `json:"payload"`
}

// snapshot captures the tree as the seed it can be rebuilt from. enc may be nil, in
// which case content is encoded through the package registry.
//
// The marshalers all take a value receiver, following the example of time.Time. A
// pointer receiver would leave a tree that is held by value rather than by pointer -
// a struct field, say - falling back to reflection inside encoding/json and
// encoding/gob, which is precisely the unbounded recursion these methods exist to
// prevent. Marshaling only reads, so the copy costs nothing that matters.
func (m MerkleTree) snapshot(enc ContentMarshalFunc, opts ...MarshalOption) (*treeData, error) {
	if m.Root == nil || len(m.Leafs) == 0 {
		return nil, errors.New("merkletree: cannot marshal an empty tree")
	}

	var cfg marshalConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	name := cfg.hashStrategyName
	if name == "" {
		name = m.hashStrategyName
	}
	if name == "" {
		var ok bool
		if name, ok = lookupHashStrategyName(m.hashStrategy); !ok {
			return nil, fmt.Errorf("%w: the tree's hash strategy has no registered name; call merkletree.RegisterHashStrategy for it, or pass merkletree.WithHashStrategyName", ErrNoHashStrategy)
		}
	}

	td := &treeData{
		Version:      serializationVersion,
		HashStrategy: name,
		Sort:         m.sort,
		RFC6962:      m.rfc6962,
		MerkleRoot:   bytes.Clone(m.merkleRoot),
	}

	for _, l := range m.Leafs {
		// Skip the padding copy buildWithContent appends for an odd content count.
		// It is regenerated on rebuild; encoding it would promote it to real content
		// and the decoded tree would report one more item than was put in.
		if l.dup {
			continue
		}
		if enc != nil {
			payload, err := enc(l.C)
			if err != nil {
				return nil, fmt.Errorf("merkletree: marshaling content: %w", err)
			}
			td.Contents = append(td.Contents, contentRecord{Payload: payload})
			continue
		}
		typeName, payload, err := marshalRegisteredContent(l.C)
		if err != nil {
			return nil, err
		}
		td.Contents = append(td.Contents, contentRecord{Type: typeName, Payload: payload})
	}

	if len(td.Contents) == 0 {
		return nil, errors.New("merkletree: cannot marshal a tree with no content")
	}
	return td, nil
}

// tree rebuilds a tree from its seed and verifies that it hashes back to the recorded
// root. dec may be nil, in which case content is decoded through the package registry.
func (td *treeData) tree(dec ContentUnmarshalFunc, opts ...UnmarshalOption) (*MerkleTree, error) {
	if td.Version != serializationVersion {
		return nil, fmt.Errorf("%w: got %d, this build writes and reads %d", ErrUnsupportedVersion, td.Version, serializationVersion)
	}

	var cfg unmarshalConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	strategy := cfg.hashStrategy
	if strategy == nil {
		var ok bool
		if strategy, ok = lookupHashStrategy(td.HashStrategy); !ok {
			return nil, fmt.Errorf("%w: %q; call merkletree.RegisterHashStrategy for it before unmarshaling, or pass merkletree.WithHashStrategy", ErrNoHashStrategy, td.HashStrategy)
		}
	}

	if len(td.Contents) == 0 {
		return nil, errors.New("merkletree: serialized tree contains no content")
	}

	cs := make([]Content, 0, len(td.Contents))
	for i, record := range td.Contents {
		var (
			c   Content
			err error
		)
		if dec != nil {
			if c, err = dec(record.Payload); err != nil {
				return nil, fmt.Errorf("merkletree: unmarshaling content at index %d: %w", i, err)
			}
		} else if c, err = unmarshalRegisteredContent(record.Type, record.Payload); err != nil {
			return nil, err
		}
		if c == nil {
			return nil, fmt.Errorf("merkletree: content at index %d decoded to nil", i)
		}
		cs = append(cs, c)
	}

	if td.Sort && td.RFC6962 {
		return nil, fmt.Errorf("%w: both the sort and RFC 6962 flags are set, which no tree can be built with", ErrCorruptData)
	}

	t := &MerkleTree{
		hashStrategy:     strategy,
		hashStrategyName: td.HashStrategy,
		sort:             td.Sort,
		rfc6962:          td.RFC6962,
	}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	// The recorded root makes decoding self-checking. Content that decoded to
	// something other than what was encoded, a hash strategy that does not match the
	// one the payload was written with, and bit rot anywhere in the payload all land
	// here rather than producing a tree that looks fine and verifies against nothing.
	if !bytes.Equal(root.Hash, td.MerkleRoot) {
		return nil, fmt.Errorf("%w: rebuilt %x, encoded %x", ErrRootMismatch, root.Hash, td.MerkleRoot)
	}

	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

// MarshalWith encodes the tree, using enc to encode each content item. It requires no
// package-level registration, which makes it the right choice for libraries and for
// content types that already have an encoding of their own.
//
// Only the leaf content, the hash strategy name, the sibling sort flag, and the Merkle
// root are written; the tree structure is rebuilt on decode. Pair this with
// UnmarshalWith and a decoder that is the exact inverse of enc.
func (m MerkleTree) MarshalWith(enc ContentMarshalFunc, opts ...MarshalOption) ([]byte, error) {
	if enc == nil {
		return nil, errors.New("merkletree: MarshalWith requires a content marshal function")
	}
	td, err := m.snapshot(enc, opts...)
	if err != nil {
		return nil, err
	}
	return td.marshalBinary(), nil
}

// UnmarshalWith decodes a tree written by MarshalWith, using dec to decode each content
// item. The rebuilt tree is verified against the Merkle root recorded in data, so a
// successful return means the tree hashes exactly as it did when it was encoded.
func UnmarshalWith(data []byte, dec ContentUnmarshalFunc, opts ...UnmarshalOption) (*MerkleTree, error) {
	if dec == nil {
		return nil, errors.New("merkletree: UnmarshalWith requires a content unmarshal function")
	}
	td, err := unmarshalTreeData(data)
	if err != nil {
		return nil, err
	}
	return td.tree(dec, opts...)
}

// MarshalBinary encodes the tree using the package content registry, implementing
// encoding.BinaryMarshaler. This is what makes a tree work with encoding/gob and any
// other codec that honors BinaryMarshaler:
//
//	merkletree.RegisterContent(MyContent{})
//	err := gob.NewEncoder(&buf).Encode(tree)
//
// Every content type in the tree must have been registered with RegisterContent, and
// the tree's hash strategy must have been registered with RegisterHashStrategy. Use
// MarshalWith to avoid the registries.
func (m MerkleTree) MarshalBinary() ([]byte, error) {
	td, err := m.snapshot(nil)
	if err != nil {
		return nil, err
	}
	return td.marshalBinary(), nil
}

// UnmarshalBinary rebuilds the tree from a payload written by MarshalBinary,
// implementing encoding.BinaryUnmarshaler. The receiver is left untouched if decoding
// fails for any reason, including the rebuilt root failing to match the recorded one.
func (m *MerkleTree) UnmarshalBinary(data []byte) error {
	td, err := unmarshalTreeData(data)
	if err != nil {
		return err
	}
	t, err := td.tree(nil)
	if err != nil {
		return err
	}
	*m = *t
	m.adoptNodes()
	return nil
}

// MarshalJSON encodes the tree using the package content registry, implementing
// json.Marshaler. Byte fields are base64 encoded by encoding/json as usual.
//
// Without this method json.Marshal would recurse forever on the tree's parent and tree
// back-pointers. Content is encoded through encoding.BinaryMarshaler, the same as
// MarshalBinary, so the JSON form carries opaque content payloads rather than the
// content's own JSON shape. Use MarshalWith when you need control over that.
func (m MerkleTree) MarshalJSON() ([]byte, error) {
	td, err := m.snapshot(nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(td)
}

// UnmarshalJSON rebuilds the tree from a payload written by MarshalJSON, implementing
// json.Unmarshaler. As with UnmarshalBinary the receiver is left untouched on failure.
func (m *MerkleTree) UnmarshalJSON(data []byte) error {
	var td treeData
	if err := json.Unmarshal(data, &td); err != nil {
		return fmt.Errorf("%w: %w", ErrCorruptData, err)
	}
	t, err := td.tree(nil)
	if err != nil {
		return err
	}
	*m = *t
	m.adoptNodes()
	return nil
}

// adoptNodes re-points every node's Tree back-pointer at m. The unmarshalers build into
// a scratch tree so that a failure leaves the receiver alone, which leaves the nodes
// referring to that scratch tree once its fields are copied over.
//
// Walking up from the leaves reaches every node, and stopping as soon as an ancestor
// has already been adopted keeps the whole pass linear.
func (m *MerkleTree) adoptNodes() {
	for _, l := range m.Leafs {
		for n := l; n != nil && n.Tree != m; n = n.Parent {
			n.Tree = m
		}
	}
}

// marshalBinary writes the seed in a compact, deterministic, self-describing format:
//
//	magic       "MTREE"
//	version     uvarint
//	strategy    uvarint length + bytes
//	sort        one byte, 0 or 1
//	rfc6962     one byte, 0 or 1
//	merkleRoot  uvarint length + bytes
//	count       uvarint
//	  type      uvarint length + bytes   (repeated count times)
//	  payload   uvarint length + bytes
//
// Encoding the same tree twice always produces identical bytes, so payloads can be
// compared or content-addressed directly.
func (td *treeData) marshalBinary() []byte {
	var buf bytes.Buffer
	buf.WriteString(serializationMagic)
	writeUvarint(&buf, uint64(td.Version))
	writeBytes(&buf, []byte(td.HashStrategy))
	if td.Sort {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	if td.RFC6962 {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	writeBytes(&buf, td.MerkleRoot)
	writeUvarint(&buf, uint64(len(td.Contents)))
	for _, record := range td.Contents {
		writeBytes(&buf, []byte(record.Type))
		writeBytes(&buf, record.Payload)
	}
	return buf.Bytes()
}

// unmarshalTreeData parses the format written by marshalBinary. Every length is checked
// against the bytes actually remaining before it is used to allocate, so a corrupt or
// hostile payload fails rather than exhausting memory.
func unmarshalTreeData(data []byte) (*treeData, error) {
	if len(data) < len(serializationMagic) || string(data[:len(serializationMagic)]) != serializationMagic {
		return nil, fmt.Errorf("%w: missing %q header", ErrCorruptData, serializationMagic)
	}
	r := &binaryReader{r: bytes.NewReader(data[len(serializationMagic):])}

	version, err := r.uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: reading version: %w", ErrCorruptData, err)
	}
	if version != serializationVersion {
		return nil, fmt.Errorf("%w: got %d, this build writes and reads %d", ErrUnsupportedVersion, version, serializationVersion)
	}

	td := &treeData{Version: int(version)}

	strategy, err := r.bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: reading hash strategy: %w", ErrCorruptData, err)
	}
	td.HashStrategy = string(strategy)

	sortFlag, err := r.r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("%w: reading sort flag: %w", ErrCorruptData, err)
	}
	if sortFlag > 1 {
		return nil, fmt.Errorf("%w: sort flag is %d, expected 0 or 1", ErrCorruptData, sortFlag)
	}
	td.Sort = sortFlag == 1

	rfcFlag, err := r.r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("%w: reading RFC 6962 flag: %w", ErrCorruptData, err)
	}
	if rfcFlag > 1 {
		return nil, fmt.Errorf("%w: RFC 6962 flag is %d, expected 0 or 1", ErrCorruptData, rfcFlag)
	}
	td.RFC6962 = rfcFlag == 1

	if td.MerkleRoot, err = r.bytes(); err != nil {
		return nil, fmt.Errorf("%w: reading Merkle root: %w", ErrCorruptData, err)
	}

	count, err := r.uvarint()
	if err != nil {
		return nil, fmt.Errorf("%w: reading content count: %w", ErrCorruptData, err)
	}
	// Each record costs at least two length bytes, so a count larger than the bytes
	// remaining cannot be honest. This bounds the allocation below.
	if count > uint64(r.r.Len()) {
		return nil, fmt.Errorf("%w: content count %d exceeds the %d bytes remaining", ErrCorruptData, count, r.r.Len())
	}

	td.Contents = make([]contentRecord, 0, count)
	for i := uint64(0); i < count; i++ {
		typeName, err := r.bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: reading content type at index %d: %w", ErrCorruptData, i, err)
		}
		payload, err := r.bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: reading content payload at index %d: %w", ErrCorruptData, i, err)
		}
		td.Contents = append(td.Contents, contentRecord{Type: string(typeName), Payload: payload})
	}

	if r.r.Len() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after the last content record", ErrCorruptData, r.r.Len())
	}
	return td, nil
}

// binaryReader reads the length-prefixed pieces of the wire format.
type binaryReader struct {
	r *bytes.Reader
}

func (br *binaryReader) uvarint() (uint64, error) {
	return binary.ReadUvarint(br.r)
}

func (br *binaryReader) bytes() ([]byte, error) {
	n, err := binary.ReadUvarint(br.r)
	if err != nil {
		return nil, err
	}
	if n > uint64(br.r.Len()) {
		return nil, fmt.Errorf("length %d exceeds the %d bytes remaining", n, br.r.Len())
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(br.r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeUvarint(buf *bytes.Buffer, v uint64) {
	var scratch [binary.MaxVarintLen64]byte
	buf.Write(scratch[:binary.PutUvarint(scratch[:], v)])
}

func writeBytes(buf *bytes.Buffer, b []byte) {
	writeUvarint(buf, uint64(len(b)))
	buf.Write(b)
}
