// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

/*
Package merkletree implements a Merkle Tree capable of storing arbitrary content.

A Merkle Tree is a hash tree that provides an efficient way to verify the contents
of a set data are present and untampered with. At its core, a Merkle Tree is
a list of items representing the data that should be verified. Each of these items
is inserted into a leaf node and a tree of hashes is constructed bottom up using a
hash of the nodes left and right children's hashes. This means that the root node
will effictively be a hash of all other nodes (hashes) in the tree. This property
allows the tree to be reproduced and thus verified by on the hash of the root node
of the tree. The benefit of the tree structure is verifying any single content
entry in the tree will require only nlog2(n) steps in the worst case.

Creating a new merkletree requires that the type that the tree will be constructed
from implements the Content interface.

	type Content interface {
		CalculateHash() ([]byte, error)
		Equals(other Content) (bool, error)
	}

A slice of the Content items should be created and then passed to the NewTree method.

	t, err := merkletree.NewTree(list)

t represents the Merkle Tree and can be verified and manipulated with the API methods
described below.

# Constructions

By default the tree is built the way Bitcoin builds one: sibling hashes are concatenated
in the order given, and a level holding an odd number of nodes duplicates its last node
so it can be paired. NewTreeWithHashStrategySorted additionally orders each pair of
siblings before hashing, matching the OpenZeppelin MerkleProof convention.

Both of those constructions inherit two well known properties. The last node duplication
means [A B C] and [A B C C] hash to the same root, which is CVE-2012-2459. And because
leaf and interior hashes are computed the same way, an interior digest can be presented
as a leaf: a two leaf tree whose leaves are the two subtree hashes of a four leaf tree
reproduces the original root, and verifies.

NewTreeWithOptions with WithRFC6962 builds the tree specified by RFC 6962 section 2.1
instead, which avoids both. Leaf and interior hashes carry distinct one byte prefixes,
and node lists are split at the largest power of two below their length rather than
padded, so every distinct leaf sequence has a distinct root.

	t, err := merkletree.NewTreeWithOptions(list, merkletree.WithRFC6962())

The constructions produce different roots and are not interchangeable, so pick one when
the tree is created. See WithRFC6962 for the details, including how it relates to
Certificate Transparency.

# Parallel construction

WithParallelism builds a tree across several goroutines. It is off by default, because
it calls Content.CalculateHash concurrently and only the caller knows whether their
implementation is safe for that.

	t, err := merkletree.NewTreeWithOptions(list, merkletree.WithParallelism(0))

The root is unaffected: results are written to slots fixed by position, so a tree built
in parallel is byte for byte the tree built serially. What it is worth depends on what
CalculateHash costs, and is large when content is expensive to hash and negative on a
small tree of cheap content. See WithParallelism.

# Proof lookup

GetMerklePath and VerifyContent locate their content by scanning every leaf, which makes
a single proof cost O(n) in the leaf count even though the walk it performs afterwards is
only O(log n), and a full set of proofs O(n²). Two options avoid the scan.

WithLeafIndex records a lookup table from leaf hash to leaf position at construction, so
a lookup becomes one hash and one map probe whatever the leaf count:

	t, err := merkletree.NewTreeWithOptions(list, merkletree.WithLeafIndex())

It costs memory proportional to the leaf count and changes how content is located, from
Content.Equals to a comparison of hashes. The Content interface already requires the two
to agree, so any implementation honoring that contract gets the same leaf either way. See
WithLeafIndex.

GetMerklePathByIndex takes the position in Leafs directly, needs no option and no extra
memory, and is the better choice when the caller already tracks which item is which.

AppendMerklePath and AppendMerklePathByIndex produce the same proofs into caller
supplied slices, so a proof server reusing its buffers generates proofs without
allocating at all:

	path, index, err = t.AppendMerklePathByIndex(path[:0], index[:0], i)

# Verifying a proof without the tree

VerifyProof checks an audit path against a root and needs no tree, which is what a
verifier does when it holds a root from a source it trusts and a proof from one it does
not:

	ok, err := merkletree.VerifyProof(content, path, index, root, merkletree.WithRFC6962())

The options must describe the construction the proof was produced under. A verifier that
has no Content implementation can use VerifyProofWithDigest instead, and one that does
hold the tree can call the MerkleTree.VerifyProof method and skip restating the options.

This is a different question from MerkleTree.VerifyContent, which walks a tree it already
has and recomputes every hash on the path from its own stored nodes. VerifyContent is the
stronger check when you have the tree; VerifyProof is what you use when you do not. See
VerifyProof for what a verified proof does and does not establish, and why WithRFC6962
matters more for proofs from untrusted sources.

# Serialization

A tree holds reference cycles - a Node points back at its Tree and at its Parent - so it
cannot be handed to a reflection-based codec directly. Use the marshalers instead, which
write the content the tree is rebuilt from rather than the node graph: the ordered leaf
content, the name of the hash strategy, the construction the tree was built with, and the
Merkle root. The recorded root is checked against the rebuilt tree on decode, so a payload
that has been tampered with, truncated, or decoded with the wrong hash strategy is
rejected.

Register the content type and encoding/gob, encoding/json, and anything else built on
encoding.BinaryMarshaler or json.Marshaler will work:

	merkletree.RegisterContent(MyContent{})
	err := gob.NewEncoder(&buf).Encode(t)

Content types registered this way must implement encoding.BinaryMarshaler, and a pointer
to them must implement encoding.BinaryUnmarshaler.

To serialize without touching a package-level registry, supply the content codec directly
with MarshalWith and UnmarshalWith.

Hash strategies are recorded by name, because a function value cannot be serialized. The
standard library strategies are registered automatically; register anything else, such as
keccak256 or blake2b, with RegisterHashStrategy before marshaling a tree that uses it.
*/
package merkletree
