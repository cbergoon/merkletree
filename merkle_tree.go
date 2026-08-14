// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

var (
	// ErrNoContent is returned when a tree is built from an empty list of content.
	ErrNoContent = errors.New("error: cannot construct tree with no content")

	// ErrNilContent is returned when a list of content holds a nil entry.
	ErrNilContent = errors.New("error: cannot construct tree with nil content")

	// ErrContentNotFound is returned by GetMerklePath when the requested content is
	// not held by any leaf of the tree. Test for it with errors.Is.
	ErrContentNotFound = errors.New("error: content not found in tree")
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
}

// Prefixes that separate the two kinds of hash an RFC 6962 tree computes, so that no
// interior digest can ever be mistaken for a leaf digest.
const (
	rfc6962LeafPrefix     = 0x00
	rfc6962InteriorPrefix = 0x01
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

	h := m.hashStrategy()
	if _, err := h.Write([]byte{rfc6962LeafPrefix}); err != nil {
		return nil, err
	}
	if _, err := h.Write(digest); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// hashInterior produces the hash recorded on the interior node above left and right.
func (m *MerkleTree) hashInterior(left, right []byte) ([]byte, error) {
	h := m.hashStrategy()
	if m.rfc6962 {
		if _, err := h.Write([]byte{rfc6962InteriorPrefix}); err != nil {
			return nil, err
		}
		if _, err := h.Write(left); err != nil {
			return nil, err
		}
		if _, err := h.Write(right); err != nil {
			return nil, err
		}

		return h.Sum(nil), nil
	}

	if _, err := h.Write(sortAppend(m.sort, left, right)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
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
	if sort {
		var aBig, bBig big.Int
		aBig.SetBytes(a)
		bBig.SetBytes(b)
		if aBig.Cmp(&bBig) != -1 {
			a, b = b, a
		}
	}
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// verifyNode walks down the tree until hitting a leaf, recalculating the hash at each
// level from the content beneath it. It returns the recalculated hash of Node n and
// whether n and everything below it matched the hash each node has recorded.
//
// Recalculating alone only proves the content still hashes to the root; it says nothing
// about the hashes cached on the nodes in between. Reporting both lets VerifyTree catch
// a tree whose interior hashes have been edited as well as one whose content has.
func (n *Node) verifyNode(sort bool) ([]byte, bool, error) {
	if n.leaf {
		leafHash, err := n.Tree.hashLeaf(n.C)
		if err != nil {
			return nil, false, err
		}

		return leafHash, bytes.Equal(leafHash, n.Hash), nil
	}
	rightBytes, rightMatched, err := n.Right.verifyNode(sort)
	if err != nil {
		return nil, false, err
	}

	leftBytes, leftMatched, err := n.Left.verifyNode(sort)
	if err != nil {
		return nil, false, err
	}

	nodeHash, err := n.Tree.hashInterior(leftBytes, rightBytes)
	if err != nil {
		return nil, false, err
	}

	return nodeHash, leftMatched && rightMatched && bytes.Equal(nodeHash, n.Hash), nil
}

// calculateNodeHash is a helper function that calculates the hash of the node.
//
// The argument is retained so existing callers keep compiling. The tree's own sort
// setting is what gets applied, and every call site has always passed exactly that.
func (n *Node) calculateNodeHash(_ bool) ([]byte, error) {
	if n.leaf {
		return n.Tree.hashLeaf(n.C)
	}

	return n.Tree.hashInterior(n.Left.Hash, n.Right.Hash)
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

// NewTreeWithOptions creates a new Merkle Tree using the content cs, configured by the
// given options. With no options it is equivalent to NewTree.
func NewTreeWithOptions(cs []Content, opts ...TreeOption) (*MerkleTree, error) {
	t := &MerkleTree{
		hashStrategy: sha256.New,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(t)
	}
	if t.hashStrategy == nil {
		return nil, errors.New("error: hash strategy cannot be nil")
	}
	if t.rfc6962 && t.sort {
		return nil, errors.New("error: WithRFC6962 and WithSortedSiblings cannot be combined; RFC 6962 specifies its own sibling ordering")
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

// GetMerklePath returns the sibling hashes on the path from the leaf holding content
// up to the root, together with an index describing which side each sibling sits on:
// 1 when the sibling is the right hand node, 0 when it is the left hand node.
//
// Content is located by Content.Equals and the first matching leaf wins, so a value
// stored in more than one leaf yields the proof for the earliest of them. If no leaf
// holds the content, the returned error wraps ErrContentNotFound.
func (m *MerkleTree) GetMerklePath(content Content) ([][]byte, []int64, error) {
	for _, current := range m.Leafs {
		ok, err := current.C.Equals(content)
		if err != nil {
			return nil, nil, err
		}

		if ok {
			currentParent := current.Parent
			var merklePath [][]byte
			var index []int64
			for currentParent != nil {
				// Whether current sits on the left or the right is a structural
				// question, so compare node identity rather than hashes. Comparing
				// hashes gives the same answer only while Content.Equals agrees with
				// Content.CalculateHash: an implementation where two distinct items
				// hash alike would see a right-hand node reported as a left-hand one,
				// producing a correct path with a wrong index.
				if currentParent.Left == current {
					merklePath = append(merklePath, currentParent.Right.Hash)
					index = append(index, 1) // right leaf
				} else {
					merklePath = append(merklePath, currentParent.Left.Hash)
					index = append(index, 0) // left leaf
				}
				current = currentParent
				currentParent = currentParent.Parent
			}
			return merklePath, index, nil
		}
	}
	return nil, nil, ErrContentNotFound
}

// buildWithContent is a helper function that for a given set of Contents, generates a
// corresponding tree and returns the root node, a list of leaf nodes, and a possible error.
// Returns ErrNoContent if cs is empty and ErrNilContent if any entry is nil.
func buildWithContent(cs []Content, t *MerkleTree) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, ErrNoContent
	}
	var leafs []*Node
	for i, c := range cs {
		// A nil entry would panic on the call below, so reject it as an error the
		// caller can handle rather than a fault.
		if c == nil {
			return nil, nil, fmt.Errorf("%w: index %d", ErrNilContent, i)
		}
		hash, err := t.hashLeaf(c)
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hash,
			C:    c,
			leaf: true,
			Tree: t,
		})
	}
	if t.rfc6962 {
		// RFC 6962 splits the leaves rather than padding them, so there is no
		// duplicate to append and Leafs holds exactly what the caller supplied.
		root, err := buildRFC6962(leafs, t)
		if err != nil {
			return nil, nil, err
		}

		return root, leafs, nil
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash: leafs[len(leafs)-1].Hash,
			C:    leafs[len(leafs)-1].C,
			leaf: true,
			dup:  true,
			Tree: t,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildIntermediate(leafs, t)
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
func buildRFC6962(nl []*Node, t *MerkleTree) (*Node, error) {
	if len(nl) == 1 {
		return nl[0], nil
	}

	k := largestPowerOfTwoBelow(len(nl))
	left, err := buildRFC6962(nl[:k], t)
	if err != nil {
		return nil, err
	}
	right, err := buildRFC6962(nl[k:], t)
	if err != nil {
		return nil, err
	}

	hash, err := t.hashInterior(left.Hash, right.Hash)
	if err != nil {
		return nil, err
	}

	n := &Node{
		Left:  left,
		Right: right,
		Hash:  hash,
		Tree:  t,
	}
	left.Parent = n
	right.Parent = n

	return n, nil
}

// largestPowerOfTwoBelow returns the largest power of two strictly less than n, which
// is the split point RFC 6962 uses. n is always greater than one here.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}

	return k
}

// buildIntermediate is a helper function that for a given list of leaf nodes, constructs
// the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node, t *MerkleTree) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		var left, right int = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash, err := t.hashInterior(nl[left].Hash, nl[right].Hash)
		if err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  chash,
			Tree:  t,
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes, t)
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
	var cs []Content
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
	return nil
}

// VerifyTree verify tree validates the hashes at each level of the tree and returns true if the
// resulting hash at the root of the tree matches the resulting root hash; returns false otherwise.
func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, matched, err := m.Root.verifyNode(m.sort)
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
	for _, l := range m.Leafs {
		ok, err := l.C.Equals(content)
		if err != nil {
			return false, err
		}

		if ok {
			currentParent := l.Parent
			for currentParent != nil {
				rightBytes, err := currentParent.Right.calculateNodeHash(m.sort)
				if err != nil {
					return false, err
				}

				leftBytes, err := currentParent.Left.calculateNodeHash(m.sort)
				if err != nil {
					return false, err
				}

				parentHash, err := m.hashInterior(leftBytes, rightBytes)
				if err != nil {
					return false, err
				}
				if !bytes.Equal(parentHash, currentParent.Hash) {
					return false, nil
				}
				currentParent = currentParent.Parent
			}
			// The walk above recomputes and checks every hash on the path from the
			// leaf up to and including the root node. Confirm that node really is
			// the root this tree advertises, otherwise a tampered merkleRoot would
			// go unnoticed.
			return bytes.Equal(m.Root.Hash, m.merkleRoot), nil
		}
	}
	return false, nil
}

// String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%t %t %v %s", n.leaf, n.dup, n.Hash, n.C)
}

// String returns a string representation of the tree. Only leaf nodes are included
// in the output.
func (m *MerkleTree) String() string {
	s := ""
	for _, l := range m.Leafs {
		s += fmt.Sprint(l)
		s += "\n"
	}
	return s
}
