// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"runtime"
	"strings"
	"sync"
)

var (
	// ErrNoContent is returned when a tree is built from an empty list of content.
	ErrNoContent = errors.New("error: cannot construct tree with no content")

	// ErrNilContent is returned when a list of content holds a nil entry.
	ErrNilContent = errors.New("error: cannot construct tree with nil content")

	// ErrContentNotFound is returned by GetMerklePath when the requested content is
	// not held by any leaf of the tree. Test for it with errors.Is.
	ErrContentNotFound = errors.New("error: content not found in tree")

	// ErrMalformedTree is returned by the verification methods when the tree they
	// are asked to walk is not one a constructor could have produced: a zero value
	// MerkleTree, or a node graph whose interior nodes are missing a child or a tree
	// back-pointer. Node exposes its fields, so a caller can assemble such a graph by
	// hand or by editing a decoded tree; verification reports it rather than faulting.
	ErrMalformedTree = errors.New("error: tree is empty or malformed")
)

// Content represents the data that is stored and verified by the tree. A type that
// implements this interface can be used as an item in the tree.
//
// Implementations are expected to keep Equals and CalculateHash consistent: two
// items that report equal should hash equal, and two items that hash equal should
// report equal. Lookups by content return the first matching leaf, so a type that
// breaks this correspondence can be located by one method and hashed by the other.
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

// MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
// a list of pointers to the leaf nodes, and the merkle root.
//
// Note that Node points back at its Tree and at its Parent, so the tree contains
// reference cycles and cannot be handed directly to a reflection-based codec. Use the
// marshalers in serialize.go, which encode the content the tree is rebuilt from rather
// than the node graph itself.
type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	Leafs      []*Node
	// hashStrategyName is the name hashStrategy is registered under, when it is
	// known. It is only ever set by the unmarshalers, to preserve the name a payload
	// was written with even when the strategy was supplied via WithHashStrategy
	// rather than resolved through the registry. When it is empty the name is looked
	// up from hashStrategy at marshal time, so registering a strategy after building
	// a tree with it still works.
	hashStrategyName string
	hashStrategy     func() hash.Hash
	sort             bool
	rfc6962          bool
	// parallelism is the goroutine budget for building this tree, or zero to build
	// serially. Unlike sort and rfc6962 it does not affect the root, so it is a
	// property of how a tree is built rather than of the tree itself, and it is
	// deliberately absent from the serialized form.
	parallelism int
	// wantLeafIndex records that WithLeafIndex was asked for, so that a rebuild
	// regenerates the index rather than silently dropping it. Like parallelism it
	// does not affect the root and is absent from the serialized form.
	wantLeafIndex bool
	// leafIndex maps a leaf hash to the lowest index in Leafs holding it, or is nil
	// when the tree was built without WithLeafIndex. It is written only while a tree
	// is being built or rebuilt and is read only afterwards, so proof serving needs
	// no synchronization.
	leafIndex map[string]int
	// scratchPool recycles the hasher and replay buffer one proof verification
	// needs, or is nil, in which case they are created per call. Only
	// defaultProofConfig carries one: its strategy is fixed forever, so a recycled
	// hasher can never be of the wrong kind. Trees deliberately have none, because
	// hashStrategy is a mutable field within this package and a pool filled before
	// a swap would keep hashing with the old strategy. Held by pointer so that
	// copying a MerkleTree, as the value-receiver marshalers do, copies a reference
	// rather than the pool's internals.
	scratchPool *sync.Pool
}

// Prefixes that separate the two kinds of hash an RFC 6962 tree computes, so that no
// interior digest can ever be mistaken for a leaf digest.
const (
	rfc6962LeafPrefix     = 0x00
	rfc6962InteriorPrefix = 0x01
)

// The prefixes as slices, so writing one does not allocate on every node.
var (
	rfc6962LeafPrefixBytes     = []byte{rfc6962LeafPrefix}
	rfc6962InteriorPrefixBytes = []byte{rfc6962InteriorPrefix}
)

// hashLeaf produces the hash recorded on the leaf holding c.
//
// In the default construction this is whatever Content.CalculateHash returned. Under
// RFC 6962 that digest is hashed again behind a leaf prefix, which is what stops an
// interior digest being presented as a leaf.
func (m *MerkleTree) hashLeaf(c Content) ([]byte, error) {
	digest, err := c.CalculateHash()
	if err != nil {
		return nil, err
	}
	if !m.rfc6962 {
		return digest, nil
	}

	return m.appendLeafDigest(m.hashStrategy(), nil, digest)
}

// appendLeafDigest appends the RFC 6962 leaf hash of digest to dst, reusing h.
//
// The hasher must not be shared across goroutines. Construction keeps its hasher local
// to the call, and VerifyTree creates one for the walk it then runs to completion on a
// single goroutine, so concurrent reads of a built tree remain safe.
func (m *MerkleTree) appendLeafDigest(h hash.Hash, dst, digest []byte) ([]byte, error) {
	h.Reset()
	if _, err := h.Write(rfc6962LeafPrefixBytes); err != nil {
		return nil, err
	}
	if _, err := h.Write(digest); err != nil {
		return nil, err
	}

	return h.Sum(dst), nil
}

// hashInterior produces the hash recorded on the interior node above left and right.
func (m *MerkleTree) hashInterior(left, right []byte) ([]byte, error) {
	return m.appendInteriorHash(m.hashStrategy(), nil, left, right)
}

// appendInteriorHash appends the interior hash of left and right to dst, reusing h.
//
// The pair is written to the hasher in two calls rather than being concatenated into a
// scratch slice first. The bytes fed to the hash are identical either way, so roots are
// unaffected, but the concatenation is one allocation per interior node.
func (m *MerkleTree) appendInteriorHash(h hash.Hash, dst, left, right []byte) ([]byte, error) {
	h.Reset()
	if m.rfc6962 {
		if _, err := h.Write(rfc6962InteriorPrefixBytes); err != nil {
			return nil, err
		}
	} else {
		left, right = sortPair(m.sort, left, right)
	}
	if _, err := h.Write(left); err != nil {
		return nil, err
	}
	if _, err := h.Write(right); err != nil {
		return nil, err
	}

	return h.Sum(dst), nil
}

// Node represents a node, root, or leaf in the tree. It stores pointers to its immediate
// relationships, a hash, the content stored if it is a leaf, and other metadata.
type Node struct {
	Tree   *MerkleTree
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	dup    bool
	Hash   []byte
	C      Content
}

// sortAppend concatenates a and b, optionally ordering the pair by big-endian
// integer value first so the result matches the OpenZeppelin MerkleProof convention.
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol
//
// The result is always a freshly allocated slice. Appending directly onto a or b
// would write into their spare capacity, and Content.CalculateHash may legally
// return a slice with cap > len that the caller still owns. The concatenated bytes
// are identical either way, so Merkle roots are unaffected.
func sortAppend(sort bool, a, b []byte) []byte {
	a, b = sortPair(sort, a, b)

	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// sortPair returns a and b in the order they should be hashed: unchanged by default,
// or ordered by big-endian integer value when sort is set. It is the ordering half of
// sortAppend, split out so the hashing path can order a pair without concatenating it.
func sortPair(sort bool, a, b []byte) ([]byte, []byte) {
	if sort && compareBigEndian(a, b) != -1 {
		return b, a
	}

	return a, b
}

// compareBigEndian compares a and b as big-endian unsigned integers, returning -1, 0
// or 1 the way big.Int.Cmp does.
//
// This reproduces big.Int comparison exactly rather than approximating it with
// bytes.Compare. The two agree only for equal-length inputs: read as integers,
// {0x01, 0x00} is larger than {0xff}, while lexicographically it is smaller. Digests
// from a single hash strategy are all the same width, but Content.CalculateHash is
// free to return any width, and the ordering chosen here decides the Merkle root.
//
// Going through big.Int would cost two heap allocations per interior node, which on a
// sorted tree is the largest single source of allocation during construction.
func compareBigEndian(a, b []byte) int {
	// Leading zero bytes do not change the value, so {0x00, 0x01} and {0x01} are
	// equal here just as they are to big.Int.
	for len(a) > 0 && a[0] == 0 {
		a = a[1:]
	}
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}

		return 1
	}

	return bytes.Compare(a, b)
}

// verifyNode walks down the tree until hitting a leaf, recalculating the hash at each
// level from the content beneath it. It appends the recalculated hash of Node n to dst
// and returns the extended buffer along with whether n and everything below it matched
// the hash each node has recorded. The recalculated hash is the tail of the returned
// buffer, from the length dst had on entry.
//
// Recalculating alone only proves the content still hashes to the root; it says nothing
// about the hashes cached on the nodes in between. Reporting both lets VerifyTree catch
// a tree whose interior hashes have been edited as well as one whose content has.
//
// The hasher and the buffer are threaded through the whole walk rather than being
// created per node. A fresh hasher and a fresh digest for every node made allocation,
// not hashing, the dominant cost of verifying: the node count is linear in the leaves,
// so a tree of any size paid two allocations per node. Both are owned by the caller for
// the duration of the walk, which is single goroutine, so nothing here is shared.
func (n *Node) verifyNode(h hash.Hash, dst []byte) ([]byte, bool, error) {
	// Hashing anything at all needs the tree's strategy, and an interior node needs
	// both children. Neither can be missing in a tree a constructor built, but the
	// fields are exported, so check rather than fault on a graph assembled by hand.
	if n.Tree == nil {
		return nil, false, fmt.Errorf("%w: node is not attached to a tree", ErrMalformedTree)
	}
	if n.leaf {
		off := len(dst)
		digest, err := n.C.CalculateHash()
		if err != nil {
			return nil, false, err
		}
		// Only RFC 6962 hashes the leaf digest again; the default construction
		// records what CalculateHash returned. This mirrors hashLeaf, but appends
		// into the shared buffer rather than allocating.
		if n.Tree.rfc6962 {
			if dst, err = n.Tree.appendLeafDigest(h, dst, digest); err != nil {
				return nil, false, err
			}
		} else {
			dst = append(dst, digest...)
		}

		return dst, bytes.Equal(dst[off:], n.Hash), nil
	}
	if n.Left == nil || n.Right == nil {
		return nil, false, fmt.Errorf("%w: interior node is missing a child", ErrMalformedTree)
	}

	off := len(dst)
	dst, rightMatched, err := n.Right.verifyNode(h, dst)
	if err != nil {
		return nil, false, err
	}
	mid := len(dst)

	dst, leftMatched, err := n.Left.verifyNode(h, dst)
	if err != nil {
		return nil, false, err
	}
	end := len(dst)

	// The children's digests are read into the hasher before Sum appends, so a growth
	// of dst here cannot invalidate them.
	dst, err = n.Tree.appendInteriorHash(h, dst, dst[mid:end], dst[off:mid])
	if err != nil {
		return nil, false, err
	}

	// The children's digests are dead once this node's is computed, so slide it down
	// over them. The buffer then holds only the path currently being walked, which
	// keeps it at the depth of the tree rather than the size of it.
	dst = dst[:off+copy(dst[off:], dst[end:])]

	return dst, leftMatched && rightMatched && bytes.Equal(dst[off:], n.Hash), nil
}

// calculateNodeHash is a helper function that calculates the hash of the node.
//
// The argument is retained so existing callers keep compiling. The tree's own sort
// setting is what gets applied, and every call site has always passed exactly that.
func (n *Node) calculateNodeHash(_ bool) ([]byte, error) {
	if n.Tree == nil {
		return nil, fmt.Errorf("%w: node is not attached to a tree", ErrMalformedTree)
	}

	return n.appendCalculatedHash(n.Tree.hashStrategy(), nil)
}

// appendCalculatedHash appends the hash calculateNodeHash would return to dst,
// reusing h instead of creating a hasher and a digest per node. It is what lets
// VerifyContent walk a whole path with one hasher and one buffer, the same way
// verifyNode does; a fresh pair per node made allocation the dominant cost of both.
func (n *Node) appendCalculatedHash(h hash.Hash, dst []byte) ([]byte, error) {
	if n.Tree == nil {
		return nil, fmt.Errorf("%w: node is not attached to a tree", ErrMalformedTree)
	}
	if n.leaf {
		digest, err := n.C.CalculateHash()
		if err != nil {
			return nil, err
		}
		if n.Tree.rfc6962 {
			return n.Tree.appendLeafDigest(h, dst, digest)
		}

		return append(dst, digest...), nil
	}
	if n.Left == nil || n.Right == nil {
		return nil, fmt.Errorf("%w: interior node is missing a child", ErrMalformedTree)
	}

	return n.Tree.appendInteriorHash(h, dst, n.Left.Hash, n.Right.Hash)
}

// NewTree creates a new Merkle Tree using the content cs.
func NewTree(cs []Content) (*MerkleTree, error) {
	var defaultHashStrategy = sha256.New
	t := &MerkleTree{
		hashStrategy: defaultHashStrategy,
		sort:         false,
	}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

// NewTreeWithHashStrategy creates a new Merkle Tree using the content cs using the provided hash
// strategy. Note that the hash type used in the type that implements the Content interface must
// match the hash type provided to the tree.
func NewTreeWithHashStrategy(cs []Content, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	t := &MerkleTree{
		hashStrategy: hashStrategy,
		sort:         false,
	}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

// NewTreeWithHashStrategySorted just like NewTreeWithHashStrategy
// but sorts the siblings before hashing, mostly to follow the OpenZepplin Merkle implementation
// https://github.com/OpenZeppelin/openzeppelin-contracts-ethereum-package/blob/master/contracts/cryptography/MerkleProof.sol
func NewTreeWithHashStrategySorted(cs []Content, hashStrategy func() hash.Hash, sort bool) (*MerkleTree, error) {
	t := &MerkleTree{
		hashStrategy: hashStrategy,
		sort:         sort,
	}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

// TreeOption configures a tree built by NewTreeWithOptions.
type TreeOption func(*MerkleTree)

// WithHasher sets the hash strategy used for interior nodes, and for the leaf prefix
// under WithRFC6962. It defaults to sha256.New.
//
// The hash a Content implementation returns from CalculateHash must be produced by a
// compatible algorithm; the tree does not and cannot check this.
func WithHasher(strategy func() hash.Hash) TreeOption {
	return func(m *MerkleTree) {
		m.hashStrategy = strategy
	}
}

// WithSortedSiblings orders each pair of siblings by their big-endian integer value
// before hashing them, matching the OpenZeppelin MerkleProof convention. It is the
// option form of NewTreeWithHashStrategySorted.
//
// Sorting makes the root independent of the order content was supplied in; see
// MerkleTree.Sorted. It cannot be combined with WithRFC6962, which specifies its own
// unsorted ordering.
func WithSortedSiblings() TreeOption {
	return func(m *MerkleTree) {
		m.sort = true
	}
}

// WithRFC6962 builds the tree the way RFC 6962 section 2.1 specifies, which closes two
// weaknesses in the default Bitcoin-style construction:
//
// Leaf and interior hashes are computed behind distinct one byte prefixes, 0x00 and
// 0x01. Without them an interior digest can be handed back as a leaf: a two leaf tree
// whose leaves are the two subtree hashes of a four leaf tree reproduces the original
// root exactly, and the forged tree verifies. With them a forgery would need a genuine
// collision between two differently prefixed inputs.
//
// Odd node counts are split rather than duplicated. The default construction pairs the
// last node with itself, so [A B C] and [A B C C] hash alike, which is CVE-2012-2459.
// RFC 6962 splits each node list at the largest power of two below its length instead,
// so every distinct leaf sequence has a distinct root.
//
// Note that RFC 6962 hashes raw leaf data, whereas this tree hashes whatever
// Content.CalculateHash returns. Roots therefore match a Certificate Transparency log
// only if CalculateHash returns the leaf bytes themselves rather than a digest of
// them. The structural guarantees above hold either way.
//
// Trees built this way do not share roots with trees built any other way, so this is a
// choice to make when a tree is created rather than one to change later.
func WithRFC6962() TreeOption {
	return func(m *MerkleTree) {
		m.rfc6962 = true
	}
}

// WithParallelism builds the tree using up to n goroutines, or GOMAXPROCS of them when
// n is less than one. It is off by default.
//
// Content.CalculateHash is called concurrently from several goroutines when this is
// set, and implementations must be safe for that. Nothing else in this package calls
// it concurrently and the tree cannot check whether yours is safe, so this requirement
// is the whole cost of the option and the reason it is not the default.
//
// The root is unaffected. Every hash is written to a slot fixed by its position, so the
// order the goroutines finish in cannot change the result: a tree built with this option
// is byte for byte the tree built without it.
//
// How much it buys depends almost entirely on what CalculateHash costs. Hashing the
// interior of the tree parallelizes too, but that work is small and fixed, so it is left
// serial below a threshold where the coordination would cost more than it saves. Content
// hashing is neither small nor knowable in advance, so it is always spread across the
// goroutine budget when this option is set, whatever the leaf count.
//
// That last point cuts both ways, and it is worth measuring rather than assuming. Where
// content is expensive to hash this option is worth several times the serial build, and
// the advantage grows with the cost. Where content is cheap the leaves finish so quickly
// that handing them out costs more than it saves on a small tree: a few thousand leaves
// of a short string is roughly the break-even, and below it a parallel build can be
// slower than a serial one.
//
// Parallelism is not recorded when a tree is serialized, because it has no bearing on
// the root. A tree read back with UnmarshalBinary or UnmarshalJSON rebuilds serially
// unless it is built again with this option.
func WithParallelism(n int) TreeOption {
	return func(m *MerkleTree) {
		if n < 1 {
			n = runtime.GOMAXPROCS(0)
		}
		m.parallelism = n
	}
}

// WithLeafIndex builds a lookup table from leaf hash to leaf position, so that
// GetMerklePath and VerifyContent find their content by hashing it once instead of
// scanning every leaf. It is off by default.
//
// Without it, locating content is a linear scan calling Content.Equals on each leaf,
// which makes a single proof O(n) and a full set of proofs O(n²). At a hundred thousand
// leaves that is around 98µs per proof and roughly ten seconds for the whole set. With
// it, a lookup is one hash and one map probe whatever the leaf count.
//
// The index costs memory proportional to the leaf count, on the order of the digest
// width plus map overhead per leaf, which is why it is opt in rather than automatic. It
// costs no extra hashing to build: every leaf hash it records was already computed and
// stored during construction.
//
// It changes how content is located, which is the reason to think before reaching for
// it. Without the index a leaf is found by Content.Equals; with it a leaf is found by
// comparing the hash of the query against the recorded leaf hashes. The Content
// interface already requires the two to agree - items that are equal must hash equal,
// and items that hash equal must be equal - so for any implementation that honors that
// contract both routes return the same leaf, including the rule that the earliest
// matching leaf wins. For an implementation that does not, the two disagree, and only
// the scan reflects Equals.
//
// One consequence is worth stating plainly, because it shows up in error handling: an
// indexed lookup hashes the content it is given and never calls Equals, where a scan
// calls Equals on each leaf and never hashes what it was given. A query whose
// CalculateHash returns an error therefore fails only on the indexed path, and content
// whose Equals returns an error surfaces that only on the scanning path.
//
// The root is unaffected, and neither is anything a proof is checked against. Like
// WithParallelism the index is absent from the serialized form, so a tree read back
// with UnmarshalBinary or UnmarshalJSON has no index unless it is asked for again;
// RebuildTree and RebuildTreeWith do regenerate it.
func WithLeafIndex() TreeOption {
	return func(m *MerkleTree) {
		m.wantLeafIndex = true
	}
}

// NewTreeWithOptions creates a new Merkle Tree using the content cs, configured by the
// given options. With no options it is equivalent to NewTree.
func NewTreeWithOptions(cs []Content, opts ...TreeOption) (*MerkleTree, error) {
	// Resolved through the same function the proof verifier uses, so that a tree and a
	// proof checked against it cannot disagree about what an option meant.
	t, err := configFromOptions(opts)
	if err != nil {
		return nil, err
	}

	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	t.buildLeafIndex()

	return t, nil
}

// buildLeafIndex regenerates leafIndex from the current leaves, or clears it when the
// tree was not asked for one. It is called after every build, so a rebuilt tree neither
// keeps a stale index nor silently loses the one it was asked for.
//
// The padding leaf that an odd content count produces carries the same hash as the leaf
// it copies. Keeping the lowest index for a hash means the copy never displaces the
// original, which is the same "earliest leaf wins" rule the scan follows.
func (m *MerkleTree) buildLeafIndex() {
	if !m.wantLeafIndex {
		m.leafIndex = nil

		return
	}

	// The keys are substrings of one backing string holding every leaf hash, rather
	// than a string(l.Hash) conversion per leaf. The conversion copies, so building
	// the index that way cost one allocation per leaf - the single largest source of
	// allocation in an indexed build. Every key is retained by the map anyway, so
	// sharing one backing keeps the same bytes alive in one object instead of n.
	total := 0
	for _, l := range m.Leafs {
		total += len(l.Hash)
	}
	var b strings.Builder
	b.Grow(total)
	for _, l := range m.Leafs {
		b.Write(l.Hash)
	}
	keys := b.String()

	idx := make(map[string]int, len(m.Leafs))
	off := 0
	for i, l := range m.Leafs {
		k := keys[off : off+len(l.Hash)]
		off += len(l.Hash)
		if _, seen := idx[k]; !seen {
			idx[k] = i
		}
	}
	m.leafIndex = idx
}

// findLeaf returns the position in Leafs of the first leaf holding content, or -1 if no
// leaf holds it. It goes through the index when the tree has one and falls back to the
// scan over Content.Equals when it does not.
func (m *MerkleTree) findLeaf(content Content) (int, error) {
	if m.leafIndex != nil {
		// The recorded leaf hashes are what hashLeaf produces, prefix and all under
		// RFC 6962, so the query has to go through the same function to be comparable.
		digest, err := m.hashLeaf(content)
		if err != nil {
			return -1, err
		}
		// Indexing a map with string(byteSlice) does not allocate the string.
		if i, ok := m.leafIndex[string(digest)]; ok {
			return i, nil
		}

		return -1, nil
	}

	for i, l := range m.Leafs {
		ok, err := l.C.Equals(content)
		if err != nil {
			return -1, err
		}
		if ok {
			return i, nil
		}
	}

	return -1, nil
}

// pathFromLeaf walks from a leaf up to the root, collecting the sibling hash at each
// level and which side it sits on.
func (m *MerkleTree) pathFromLeaf(current *Node) ([][]byte, []int64) {
	// The walk takes one step per level, so the depth of the tree is how many entries
	// the two slices end up holding. bits.Len of the highest leaf position is that
	// depth exactly, for a power-of-two count as much as a padded or split one, so
	// the slices come out exact-fit; this is the hottest allocation site in the
	// package, and a spare entry per proof is measurable at proof-serving rates.
	depth := bits.Len(uint(len(m.Leafs) - 1))

	return m.appendPathFromLeaf(make([][]byte, 0, depth), make([]int64, 0, depth), current)
}

// appendPathFromLeaf is pathFromLeaf appending into caller supplied slices. It is the
// walk both the slice-returning and the appending proof methods share.
func (m *MerkleTree) appendPathFromLeaf(merklePath [][]byte, index []int64, current *Node) ([][]byte, []int64) {
	for currentParent := current.Parent; currentParent != nil; currentParent = current.Parent {
		// Whether current sits on the left or the right is a structural question, so
		// compare node identity rather than hashes. Comparing hashes gives the same
		// answer only while Content.Equals agrees with Content.CalculateHash: an
		// implementation where two distinct items hash alike would see a right-hand
		// node reported as a left-hand one, producing a correct path with a wrong
		// index.
		if currentParent.Left == current {
			merklePath = append(merklePath, currentParent.Right.Hash)
			index = append(index, 1) // right leaf
		} else {
			merklePath = append(merklePath, currentParent.Left.Hash)
			index = append(index, 0) // left leaf
		}
		current = currentParent
	}

	return merklePath, index
}

// GetMerklePath returns the sibling hashes on the path from the leaf holding content
// up to the root, together with an index describing which side each sibling sits on:
// 1 when the sibling is the right hand node, 0 when it is the left hand node.
//
// Content is located by Content.Equals and the first matching leaf wins, so a value
// stored in more than one leaf yields the proof for the earliest of them. If no leaf
// holds the content, the returned error wraps ErrContentNotFound.
//
// Locating the content is a scan over every leaf, which makes this O(n) in the leaf
// count while the walk it performs afterwards is only O(log n). Build the tree with
// WithLeafIndex to replace the scan with a single hash and map probe, or use
// GetMerklePathByIndex when the position is already known. AppendMerklePath produces
// the same proof into caller supplied slices, for callers generating proofs at a rate
// where the two returned slices are a cost worth removing.
func (m *MerkleTree) GetMerklePath(content Content) ([][]byte, []int64, error) {
	i, err := m.findLeaf(content)
	if err != nil {
		return nil, nil, err
	}
	if i < 0 {
		return nil, nil, ErrContentNotFound
	}

	merklePath, index := m.pathFromLeaf(m.Leafs[i])

	return merklePath, index, nil
}

// GetMerklePathByIndex returns the same audit path as GetMerklePath for the leaf at
// position i in Leafs, without locating it by content first. It costs one step per
// level of the tree whatever the leaf count, where GetMerklePath has to find the leaf
// before it can walk.
//
// The index is a position in Leafs, which is the order the content was supplied in.
// Note that a tree built from an odd number of items holds one more leaf than it was
// given, the last being a copy of the one before it; that copy is addressable here and
// yields a valid path, though its content is not distinct.
//
// Returns ErrContentNotFound if i is outside the range of Leafs.
func (m *MerkleTree) GetMerklePathByIndex(i int) ([][]byte, []int64, error) {
	if i < 0 || i >= len(m.Leafs) {
		return nil, nil, fmt.Errorf("%w: no leaf at index %d, the tree has %d", ErrContentNotFound, i, len(m.Leafs))
	}

	merklePath, index := m.pathFromLeaf(m.Leafs[i])

	return merklePath, index, nil
}

// AppendMerklePath appends the audit path for the leaf holding content to path, and
// the side each sibling sits on to index, returning the extended slices. It is
// GetMerklePath in the style of strconv.AppendInt: the proof produced is identical,
// but where the slices land is the caller's decision. Passing slices with capacity to
// spare - most simply the previous proof's, resliced to length zero - makes proof
// generation allocate nothing, which is worth having where proofs are served at rate:
// the per-proof slice allocations are otherwise the ceiling on concurrent throughput,
// with the garbage collector as the shared resource every goroutine queues on.
//
//	var path [][]byte
//	var index []int64
//	for _, c := range contents {
//		path, index, err = tree.AppendMerklePath(path[:0], index[:0], c)
//		...
//	}
//
// The appended hashes are the tree's own, not copies; treat them as read only, and
// note that reusing the path buffer overwrites the positions of the previous proof,
// so a proof that must outlive the next call has to be copied out.
//
// Content is located exactly as GetMerklePath locates it, including the leaf index
// when the tree has one and the first-match rule. If no leaf holds the content, the
// returned error wraps ErrContentNotFound and the slices are returned unchanged.
func (m *MerkleTree) AppendMerklePath(path [][]byte, index []int64, content Content) ([][]byte, []int64, error) {
	i, err := m.findLeaf(content)
	if err != nil {
		return path, index, err
	}
	if i < 0 {
		return path, index, ErrContentNotFound
	}

	path, index = m.appendPathFromLeaf(path, index, m.Leafs[i])

	return path, index, nil
}

// AppendMerklePathByIndex appends the audit path for the leaf at position i in Leafs
// to path, and the side each sibling sits on to index, returning the extended slices.
// It is to GetMerklePathByIndex what AppendMerklePath is to GetMerklePath, and the
// notes there - identical proofs, reused buffers making generation allocation free,
// appended hashes being the tree's own - apply unchanged.
//
// Returns ErrContentNotFound and the slices unchanged if i is outside the range of
// Leafs.
func (m *MerkleTree) AppendMerklePathByIndex(path [][]byte, index []int64, i int) ([][]byte, []int64, error) {
	if i < 0 || i >= len(m.Leafs) {
		return path, index, fmt.Errorf("%w: no leaf at index %d, the tree has %d", ErrContentNotFound, i, len(m.Leafs))
	}

	path, index = m.appendPathFromLeaf(path, index, m.Leafs[i])

	return path, index, nil
}

// buildWithContent is a helper function that for a given set of Contents, generates a
// corresponding tree and returns the root node, a list of leaf nodes, and a possible error.
// Returns ErrNoContent if cs is empty and ErrNilContent if any entry is nil.
// Chunking limits for a parallel build. Content hashing costs whatever the caller's
// CalculateHash costs, which is unknowable here, so it is spread as thinly as the
// goroutine budget allows. Interior hashing is a fixed, small amount of work per node,
// so a level is only worth splitting up once it is large enough that coordinating the
// split costs less than doing the work in one goroutine.
const (
	minLeafChunk             = 1
	minInteriorChunk         = 64
	parallelInteriorMinNodes = 1024
)

// buildWorkers is the goroutine budget for a build, where one means build serially.
func (m *MerkleTree) buildWorkers() int {
	if m.parallelism > 1 {
		return m.parallelism
	}

	return 1
}

// newHashers creates n hashers up front, on the calling goroutine. A parallel build
// hands one to each worker rather than calling hashStrategy from the workers, so a
// caller supplied strategy is never invoked concurrently even though the build is.
func (m *MerkleTree) newHashers(n int) []hash.Hash {
	hashers := make([]hash.Hash, n)
	for i := range hashers {
		hashers[i] = m.hashStrategy()
	}

	return hashers
}

// runParallel splits [0, n) into contiguous chunks across at most workers goroutines and
// calls fn for every index. fn receives the index of the worker running it, so it can
// reach for per-worker state such as that worker's hasher.
//
// The error returned is the one from the lowest failing index rather than from whichever
// goroutine happened to report first, so the same input always fails the same way.
func runParallel(n, workers, minChunk int, fn func(worker, i int) error) error {
	chunk := (n + workers - 1) / workers
	if chunk < minChunk {
		chunk = minChunk
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		errIndex = -1
		panicked any
	)

	worker := 0
	for start := 0; start < n; start += chunk {
		end := start + chunk
		if end > n {
			end = n
		}

		wg.Add(1)
		go func(w, s, e int) {
			defer wg.Done()
			// A panic out of Content.CalculateHash would kill the process from here,
			// where a serial build would have delivered it to the caller. Carry it
			// back and re-raise it on the calling goroutine instead.
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					if panicked == nil {
						panicked = r
					}
					mu.Unlock()
				}
			}()

			for i := s; i < e; i++ {
				if err := fn(w, i); err != nil {
					mu.Lock()
					if errIndex == -1 || i < errIndex {
						firstErr, errIndex = err, i
					}
					mu.Unlock()

					return
				}
			}
		}(worker, start, end)
		worker++
	}
	wg.Wait()

	if panicked != nil {
		panic(panicked)
	}

	return firstErr
}

// Building allocates the nodes of each level as a single slab rather than one at a
// time, and appends the digests of a level into a single buffer rather than calling
// Sum(nil) per node. The tree that comes out is the same one either way - the same
// Node values, the same Parent, Left, Right and Tree pointers, the same content held
// on the leaves - but the node count is linear in the leaves, so allocating per node
// makes allocation, not hashing, the dominant cost of construction.
//
// Nodes are handed out as pointers into a slab that is sized exactly and never
// appended to, so no reallocation can invalidate a pointer already taken from it.
func buildWithContent(cs []Content, t *MerkleTree) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, ErrNoContent
	}

	// One hasher serves the whole build. It never leaves this call tree, so a tree
	// under construction shares no hash state with anything verifying concurrently.
	h := t.hashStrategy()

	// A default-construction tree pads an odd leaf count with a duplicate; an
	// RFC 6962 tree splits instead and so holds exactly what the caller supplied.
	leafCount := len(cs)
	if !t.rfc6962 && leafCount%2 == 1 {
		leafCount++
	}
	slab := make([]Node, leafCount)
	leafs := make([]*Node, 0, leafCount)

	// Only RFC 6962 hashes the leaf digest again, so only it needs somewhere to put
	// the result. The default construction records what CalculateHash returned.
	var (
		leafBuf  []byte
		leafSize int
	)
	if t.rfc6962 {
		leafSize = h.Size()
		leafBuf = make([]byte, len(cs)*leafSize)
	}

	// hashLeafAt fills in leaf i using the given hasher. Every leaf writes only to its
	// own slab entry and its own region of leafBuf, so running this across goroutines
	// needs no coordination and cannot depend on the order they run in.
	hashLeafAt := func(lh hash.Hash, i int) error {
		c := cs[i]
		// A nil entry would panic on the call below, so reject it as an error the
		// caller can handle rather than a fault.
		if c == nil {
			return fmt.Errorf("%w: index %d", ErrNilContent, i)
		}
		hash, err := c.CalculateHash()
		if err != nil {
			return err
		}
		if t.rfc6962 {
			off := i * leafSize
			if hash, err = t.appendLeafDigest(lh, leafBuf[off:off:off+leafSize], hash); err != nil {
				return err
			}
		}

		n := &slab[i]
		n.Hash = hash
		n.C = c
		n.leaf = true
		n.Tree = t

		return nil
	}

	workers := t.buildWorkers()
	if workers > 1 {
		// Content hashing is spread across the budget whatever the leaf count, since
		// how expensive it is belongs to the caller and cannot be guessed here.
		var hashers []hash.Hash
		if t.rfc6962 {
			hashers = t.newHashers(workers)
		} else {
			hashers = make([]hash.Hash, workers)
		}
		if err := runParallel(len(cs), workers, minLeafChunk, func(w, i int) error {
			return hashLeafAt(hashers[w], i)
		}); err != nil {
			return nil, nil, err
		}
	} else {
		for i := range cs {
			if err := hashLeafAt(h, i); err != nil {
				return nil, nil, err
			}
		}
	}

	for i := range cs {
		leafs = append(leafs, &slab[i])
	}
	if t.rfc6962 {
		// RFC 6962 splits the leaves rather than padding them, so there is no
		// duplicate to append and Leafs holds exactly what the caller supplied.
		root, err := buildRFC6962(leafs, t, h)
		if err != nil {
			return nil, nil, err
		}

		return root, leafs, nil
	}
	if len(cs)%2 == 1 {
		last := leafs[len(leafs)-1]
		n := &slab[len(cs)]
		n.Hash = last.Hash
		n.C = last.C
		n.leaf = true
		n.dup = true
		n.Tree = t
		leafs = append(leafs, n)
	}
	root, err := buildIntermediate(leafs, t, h)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

// buildRFC6962 assembles the tree described by RFC 6962 section 2.1. The node list is
// split at the largest power of two below its length, so a count that is not a power
// of two yields an unbalanced tree instead of a duplicated node. A single node is its
// own root, which is why a one item RFC 6962 tree has a root equal to its only leaf
// hash and an empty audit path.
//
// https://datatracker.ietf.org/doc/html/rfc6962#section-2.1
func buildRFC6962(nl []*Node, t *MerkleTree, h hash.Hash) (*Node, error) {
	// Splitting rather than padding means the interior nodes of a tree over n leaves
	// number exactly n-1, whatever shape the splits produce, so one slab covers the
	// whole recursion. More than that: the subtree over any k consecutive leaves
	// owns exactly k-1 of them, so every subtree's slab and digest region is known
	// before anything is built - which is what lets the recursion fork.
	b := &rfc6962Builder{
		t:    t,
		size: h.Size(),
		slab: make([]Node, len(nl)-1),
		buf:  make([]byte, (len(nl)-1)*h.Size()),
	}

	// The same policy buildIntermediate applies: interior work is small and fixed
	// per node, so the tree only earns the goroutines once it has enough of them.
	if workers := t.buildWorkers(); workers > 1 && len(nl) >= parallelInteriorMinNodes {
		return b.buildParallel(nl, 0, t.newHashers(workers))
	}

	return b.build(nl, 0, h)
}

// rfc6962Builder carries the slab and the digest buffer down the recursion, so that
// assembling the tree costs two allocations rather than one per node.
//
// Regions are addressed by position rather than handed out from a cursor: the subtree
// over nl owns slab entries and digest slots [base, base+len(nl)-1), its left child
// the first k-1 of them, its right child the next len(nl)-k-1, and the node joining
// them the last one. Sibling regions are disjoint by construction, which is what lets
// buildParallel assemble them on separate goroutines with no coordination at all.
type rfc6962Builder struct {
	t    *MerkleTree
	size int
	slab []Node
	buf  []byte
}

// build assembles the subtree over nl into region [base, base+len(nl)-1) of the slab
// and digest buffer, reusing h, and returns the subtree's root.
func (b *rfc6962Builder) build(nl []*Node, base int, h hash.Hash) (*Node, error) {
	if len(nl) == 1 {
		return nl[0], nil
	}

	k := largestPowerOfTwoBelow(len(nl))
	left, err := b.build(nl[:k], base, h)
	if err != nil {
		return nil, err
	}
	right, err := b.build(nl[k:], base+k-1, h)
	if err != nil {
		return nil, err
	}

	return b.join(left, right, base+len(nl)-2, h)
}

// join builds the node above left and right in slab slot i.
func (b *rfc6962Builder) join(left, right *Node, i int, h hash.Hash) (*Node, error) {
	off := i * b.size
	// Cap the slice at its own digest so that appending to a node's Hash cannot
	// reach into the digest stored after it.
	nodeHash, err := b.t.appendInteriorHash(h, b.buf[off:off:off+b.size], left.Hash, right.Hash)
	if err != nil {
		return nil, err
	}

	n := &b.slab[i]
	n.Left = left
	n.Right = right
	n.Hash = nodeHash
	n.Tree = b.t
	left.Parent = n
	right.Parent = n

	return n, nil
}

// buildParallel is build forking across goroutines. hashers is the goroutine budget:
// each fork splits it between the two subtrees in proportion to their size, and a
// subtree whose share is down to one hasher, or which is too small to be worth the
// coordination, is built serially with the first hasher of its share. The shares stay
// disjoint the way the slab regions do, and the whole budget is created up front on
// the calling goroutine, so a caller supplied strategy is never invoked concurrently
// even though the build is.
func (b *rfc6962Builder) buildParallel(nl []*Node, base int, hashers []hash.Hash) (*Node, error) {
	if len(hashers) == 1 || len(nl) < parallelInteriorMinNodes {
		return b.build(nl, base, hashers[0])
	}

	k := largestPowerOfTwoBelow(len(nl))
	share := len(hashers) * k / len(nl)
	if share < 1 {
		share = 1
	}
	if share > len(hashers)-1 {
		share = len(hashers) - 1
	}

	var (
		wg       sync.WaitGroup
		right    *Node
		rightErr error
		panicked any
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// A panic out of a caller supplied hasher would kill the process from here,
		// where a serial build would have delivered it to the caller. Carry it back
		// and re-raise it on the calling goroutine instead.
		defer func() {
			if r := recover(); r != nil {
				panicked = r
			}
		}()
		right, rightErr = b.buildParallel(nl[k:], base+k-1, hashers[share:])
	}()

	left, leftErr := b.buildParallel(nl[:k], base, hashers[:share])
	wg.Wait()

	if panicked != nil {
		panic(panicked)
	}
	// The serial build reaches the left subtree's error first; deliver errors in
	// the same order however the goroutines happened to finish, so the same input
	// always fails the same way.
	if leftErr != nil {
		return nil, leftErr
	}
	if rightErr != nil {
		return nil, rightErr
	}

	return b.join(left, right, base+len(nl)-2, hashers[0])
}

// largestPowerOfTwoBelow returns the largest power of two strictly less than n, which
// is the split point RFC 6962 uses. n is always greater than one here.
func largestPowerOfTwoBelow(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// buildIntermediate is a helper function that for a given list of leaf nodes, constructs
// the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node, t *MerkleTree, h hash.Hash) (*Node, error) {
	workers := t.buildWorkers()

	// The worker hashers are created once and reused for every level large enough to
	// build in parallel, rather than a fresh set per level. Created lazily, so a
	// serial build or a small tree never pays for them.
	var hashers []hash.Hash

	for len(nl) > 1 {
		// Each pass consumes a level and produces the one above it, so the node
		// count is known before any of them are built.
		count := (len(nl) + 1) / 2
		size := h.Size()
		slab := make([]Node, count)
		next := make([]*Node, count)
		buf := make([]byte, count*size)

		// buildNode assembles the node above pair p. Pair p reads only nodes 2p and
		// 2p+1 and writes only its own slab entry, digest region and next slot, so
		// pairs are independent of each other and of the order they are built in.
		buildNode := func(nh hash.Hash, p int) error {
			left, right := p*2, p*2+1
			if right == len(nl) {
				right = left
			}

			off := p * size
			// Cap the slice at its own digest so that appending to a node's Hash
			// cannot reach into the digest stored after it.
			nodeHash, err := t.appendInteriorHash(nh, buf[off:off:off+size], nl[left].Hash, nl[right].Hash)
			if err != nil {
				return err
			}

			n := &slab[p]
			n.Left = nl[left]
			n.Right = nl[right]
			n.Hash = nodeHash
			n.Tree = t
			nl[left].Parent = n
			nl[right].Parent = n
			next[p] = n

			return nil
		}

		// Interior work is small and fixed per node, so a level only earns the
		// coordination once there are enough nodes in it.
		if workers > 1 && count >= parallelInteriorMinNodes {
			if hashers == nil {
				hashers = t.newHashers(workers)
			}
			if err := runParallel(count, workers, minInteriorChunk, func(w, p int) error {
				return buildNode(hashers[w], p)
			}); err != nil {
				return nil, err
			}
		} else {
			for p := 0; p < count; p++ {
				if err := buildNode(h, p); err != nil {
					return nil, err
				}
			}
		}
		nl = next
	}

	return nl[0], nil
}

// MerkleRoot returns the unverified Merkle Root (hash of the root node) of the tree.
//
// The returned slice is the tree's own, not a copy; treat it as read only.
func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

// Sorted reports whether the tree orders each pair of siblings before hashing them,
// as chosen by NewTreeWithHashStrategySorted.
//
// Sorting siblings makes the root independent of the order the content was supplied
// in: [A B C D] and [B A C D] and [D C B A] all produce the same root, because each
// pair is ordered before it is hashed and the pairing itself is all that survives.
// Only regrouping which items are paired together changes the root. Callers that
// depend on the root committing to leaf order should check this is false.
func (m *MerkleTree) Sorted() bool {
	return m.sort
}

// RFC6962 reports whether the tree was built with WithRFC6962, meaning leaf and
// interior hashes carry distinct prefixes and odd node counts are split rather than
// duplicated.
func (m *MerkleTree) RFC6962() bool {
	return m.rfc6962
}

// RebuildTree is a helper function that will rebuild the tree reusing only the content that
// it holds in the leaves.
func (m *MerkleTree) RebuildTree() error {
	// Sized to the leaf count up front; at most one entry, the padding copy, goes
	// unused.
	cs := make([]Content, 0, len(m.Leafs))
	for _, c := range m.Leafs {
		// Leafs holds the padding copy that buildWithContent appends when the
		// content count is odd. Feeding it back in would promote that copy to
		// real content, so the tree would lose track of which leaf is padding
		// and report one more item than the caller supplied. The root is
		// unaffected either way; skipping it keeps Leafs and the dup marker
		// accurate across repeated rebuilds.
		if c.dup {
			continue
		}
		cs = append(cs, c.C)
	}
	root, leafs, err := buildWithContent(cs, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	m.buildLeafIndex()
	return nil
}

// RebuildTreeWith replaces the content of the tree and does a complete rebuild; while the root of
// the tree will be replaced the MerkleTree completely survives this operation. Returns an error if the
// list of content cs contains no entries.
func (m *MerkleTree) RebuildTreeWith(cs []Content) error {
	root, leafs, err := buildWithContent(cs, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	m.buildLeafIndex()
	return nil
}

// VerifyTree verify tree validates the hashes at each level of the tree and returns true if the
// resulting hash at the root of the tree matches the resulting root hash; returns false otherwise.
func (m *MerkleTree) VerifyTree() (bool, error) {
	// A zero value MerkleTree has no root to walk. Report it rather than faulting,
	// so that a caller handed a tree from elsewhere can tell "never built" apart
	// from "built and does not verify".
	if m.Root == nil {
		return false, fmt.Errorf("%w: tree has no root", ErrMalformedTree)
	}
	// One hasher and one buffer serve the whole walk. The buffer holds only the path
	// being walked, so the depth of the tree is enough for it; append covers the case
	// of a Content.CalculateHash that returns a digest wider than the tree's own.
	h := m.hashStrategy()
	scratch := make([]byte, 0, (bits.Len(uint(len(m.Leafs)))+2)*h.Size())

	calculatedMerkleRoot, matched, err := m.Root.verifyNode(h, scratch)
	if err != nil {
		return false, err
	}
	if !matched {
		return false, nil
	}

	return bytes.Equal(m.merkleRoot, calculatedMerkleRoot), nil
}

// VerifyContent indicates whether a given content is in the tree and the hashes are valid for that content.
// Returns true if the expected Merkle Root is equivalent to the Merkle root calculated on the critical path
// for a given content. Returns true if valid and false otherwise.
func (m *MerkleTree) VerifyContent(content Content) (bool, error) {
	// Locating the content carries the same O(n) scan as GetMerklePath unless the
	// tree was built with WithLeafIndex.
	i, err := m.findLeaf(content)
	if err != nil {
		return false, err
	}
	if i < 0 {
		return false, nil
	}

	// One hasher and one buffer serve the whole climb, the way verifyNode threads
	// them through its walk. Recomputing a level takes three digests - each child
	// from what sits beneath it, then the parent from the pair - and creating a
	// hasher and a digest for each made allocation, not hashing, the dominant cost
	// here. The buffer never holds more than one level, so three digests is its
	// whole working set; append covers a Content.CalculateHash wider than the
	// tree's own digest.
	h := m.hashStrategy()
	scratch := make([]byte, 0, 4*h.Size())

	for currentParent := m.Leafs[i].Parent; currentParent != nil; currentParent = currentParent.Parent {
		if currentParent.Left == nil || currentParent.Right == nil {
			return false, fmt.Errorf("%w: interior node is missing a child", ErrMalformedTree)
		}
		scratch = scratch[:0]
		scratch, err = currentParent.Right.appendCalculatedHash(h, scratch)
		if err != nil {
			return false, err
		}
		mid := len(scratch)

		scratch, err = currentParent.Left.appendCalculatedHash(h, scratch)
		if err != nil {
			return false, err
		}
		end := len(scratch)

		// The children's digests are read into the hasher before Sum appends, so a
		// growth of scratch here cannot invalidate them.
		scratch, err = m.appendInteriorHash(h, scratch, scratch[mid:end], scratch[:mid])
		if err != nil {
			return false, err
		}
		if !bytes.Equal(scratch[end:], currentParent.Hash) {
			return false, nil
		}
	}
	// The walk above recomputes and checks every hash on the path from the leaf up to
	// and including the root node. Confirm that node really is the root this tree
	// advertises, otherwise a tampered merkleRoot would go unnoticed.
	if m.Root == nil {
		return false, fmt.Errorf("%w: tree has no root", ErrMalformedTree)
	}

	return bytes.Equal(m.Root.Hash, m.merkleRoot), nil
}

// String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%t %t %v %s", n.leaf, n.dup, n.Hash, n.C)
}

// String returns a string representation of the tree. Only leaf nodes are included
// in the output.
func (m *MerkleTree) String() string {
	// One builder rather than repeated string concatenation, which re-copies the
	// whole prefix on every leaf and turns printing a large tree quadratic.
	var sb strings.Builder
	for _, l := range m.Leafs {
		fmt.Fprintln(&sb, l)
	}
	return sb.String()
}
