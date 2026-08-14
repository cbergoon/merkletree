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
instead, which closes both. Leaf and interior hashes carry distinct one byte prefixes,
and node lists are split at the largest power of two below their length rather than
padded, so every distinct leaf sequence has a distinct root.

	t, err := merkletree.NewTreeWithOptions(list, merkletree.WithRFC6962())

The constructions produce different roots and are not interchangeable, so pick one when
the tree is created. See WithRFC6962 for the details, including how it relates to
Certificate Transparency.

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
