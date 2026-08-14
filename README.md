<h1 align="center">Merkle Tree in Golang</h1>
<p align="center">
<a href="https://github.com/cbergoon/merkletree/actions/workflows/ci.yml"><img src="https://github.com/cbergoon/merkletree/actions/workflows/ci.yml/badge.svg" alt="Build"></a>
<a href="https://pkg.go.dev/github.com/cbergoon/merkletree"><img src="https://pkg.go.dev/badge/github.com/cbergoon/merkletree.svg" alt="Docs"></a>
<a href="#"><img src="https://img.shields.io/badge/version-0.4.0-brightgreen.svg" alt="Version"></a>
</p>

An implementation of a Merkle Tree written in Go. A Merkle Tree is a hash tree that provides an efficient way to verify
the contents of a set data are present and untampered with.

At its core, a Merkle Tree is a list of items representing the data that should be verified. Each of these items
is inserted into a leaf node and a tree of hashes is constructed bottom up using a hash of the nodes left and
right children's hashes. This means that the root node will effictively be a hash of all other nodes (hashes) in
the tree. This property allows the tree to be reproduced and thus verified by on the hash of the root node
of the tree. The benefit of the tree structure is verifying any single content entry in the tree will require only
nlog2(n) steps in the worst case.

#### Documentation 

See the docs [here](https://pkg.go.dev/github.com/cbergoon/merkletree).

#### Constructions

The tree can be built three ways. All of them are supported; they produce different roots
and are not interchangeable, so pick one when the tree is created.

| Construction | Built with | Notes |
| --- | --- | --- |
| Bitcoin-style (default) | `NewTree`, `NewTreeWithHashStrategy` | Pairs siblings in order, duplicates the last node on an odd count |
| Sorted siblings | `NewTreeWithHashStrategySorted`, `WithSortedSiblings()` | Orders each pair before hashing, matching OpenZeppelin `MerkleProof` |
| RFC 6962 | `WithRFC6962()` | Prefixed leaf and interior hashes, splits instead of padding |

The default follows Bitcoin deliberately, so the roots line up with Bitcoin-style trees.
That construction carries two well-known properties:

**Duplicated odd nodes.** A level holding an odd number of nodes duplicates its last node
so it can be paired, which means a tree built from an odd number of leaves has the same
root as a tree that spells the duplicate out — this is CVE-2012-2459:

```
[A, B, C]  and  [A, B, C, C]  ->  same root
[A]        and  [A, A]        ->  same root
```

**No separation between leaf and interior hashes.** Both are computed the same way, so an
interior digest can be handed back as a leaf. A two-leaf tree whose leaves are the two
subtree hashes of a four-leaf tree reproduces the original root exactly, and the forged
tree verifies against itself.

Sorted mode shares both, and additionally discards leaf order: `[A B C D]`, `[B A C D]`
and `[D C B A]` all produce the same root, because each pair is ordered before it is
hashed. Only regrouping which leaves are paired changes the root. Check
`tree.Sorted()` if you depend on the root committing to order.

##### RFC 6962

`WithRFC6962()` builds the tree specified by
[RFC 6962 section 2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1), which
closes both of the above:

```go
tree, err := merkletree.NewTreeWithOptions(list, merkletree.WithRFC6962())
```

Leaf hashes are computed as `H(0x00 ‖ digest)` and interior hashes as `H(0x01 ‖ left ‖ right)`,
so a forged leaf would need a genuine collision between two differently prefixed inputs
rather than a rearrangement. Odd node counts are split at the largest power of two below
their length instead of being padded, so every distinct leaf sequence gets a distinct
root and `[A, B, C]` no longer collides with `[A, B, C, C]`.

Two things to know. RFC 6962 hashes raw leaf data, whereas this tree hashes whatever
`CalculateHash` returns — roots match a Certificate Transparency log only if your
`CalculateHash` returns the leaf bytes themselves rather than a digest of them. The
structural guarantees hold either way. And a single-leaf tree is its own root, so its
audit path is legitimately empty.

`WithRFC6962()` cannot be combined with `WithSortedSiblings()`; RFC 6962 specifies its own
sibling ordering, and asking for both returns an error.

#### Serialization

A tree can be written out and read back. What gets written is not the node graph but the
content the tree is rebuilt from: the ordered leaf content, the name of the hash strategy,
the sibling sort flag, and the Merkle root. Everything else is derived, and the recorded
root makes decoding self-checking — a payload that has been altered, or that is decoded
with the wrong hash strategy, fails rather than producing a tree that quietly verifies
against nothing.

Register your content type and the standard codecs work directly:

```go
merkletree.RegisterContent(TestContent{}) // needs MarshalBinary/UnmarshalBinary

err := gob.NewEncoder(&buf).Encode(tree)

var decoded merkletree.MerkleTree
err = gob.NewDecoder(&buf).Decode(&decoded)
```

`MarshalBinary`, `UnmarshalBinary`, `MarshalJSON`, and `UnmarshalJSON` are all available,
so anything built on `encoding.BinaryMarshaler` or `json.Marshaler` works too.

To avoid the package-level registry entirely — in a library, or for content that already
has an encoding of its own — supply the content codec directly:

```go
data, err := tree.MarshalWith(func(c merkletree.Content) ([]byte, error) {
  return []byte(c.(TestContent).x), nil
})

decoded, err := merkletree.UnmarshalWith(data, func(b []byte) (merkletree.Content, error) {
  return TestContent{x: string(b)}, nil
})
```

Hash strategies are recorded by name, since a function cannot be serialized. Everything in
the standard library is registered for you; anything else is one call:

```go
merkletree.RegisterHashStrategy("keccak256", sha3.NewLegacyKeccak256)
tree, err := merkletree.NewTreeWithHashStrategy(list, sha3.NewLegacyKeccak256)
```

Note that a tree with reference cycles cannot be handed to a reflection-based codec
directly — `Node` points back at its `Tree` and its `Parent`. Before these marshalers
existed, `gob.Encode(tree)` did not return an error, it crashed the process with a stack
overflow. The marshalers above are the supported path.

#### Install
```
go get github.com/cbergoon/merkletree
```

#### Example Usage
Below is an example that makes use of the entire API - its quite small.
```go
package main

import (
  "crypto/sha256"
  "errors"
  "log"

  "github.com/cbergoon/merkletree"
)

//TestContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestContent struct {
  x string
}

//CalculateHash hashes the values of a TestContent
func (t TestContent) CalculateHash() ([]byte, error) {
  h := sha256.New()
  if _, err := h.Write([]byte(t.x)); err != nil {
    return nil, err
  }

  return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestContent) Equals(other merkletree.Content) (bool, error) {
  otherTC, ok := other.(TestContent)
  if !ok {
    return false, errors.New("value is not of type TestContent")
  }
  return t.x == otherTC.x, nil
}

func main() {
  //Build list of Content to build tree
  var list []merkletree.Content
  list = append(list, TestContent{x: "Hello"})
  list = append(list, TestContent{x: "Hi"})
  list = append(list, TestContent{x: "Hey"})
  list = append(list, TestContent{x: "Hola"})

  //Create a new Merkle Tree from the list of Content
  t, err := merkletree.NewTree(list)
  if err != nil {
    log.Fatal(err)
  }

  //Get the Merkle Root of the tree
  mr := t.MerkleRoot()
  log.Println(mr)

  //Verify the entire tree (hashes for each node) is valid
  vt, err := t.VerifyTree()
  if err != nil {
    log.Fatal(err)
  }
  log.Println("Verify Tree: ", vt)

  //Verify a specific content in in the tree
  vc, err := t.VerifyContent(list[0])
  if err != nil {
    log.Fatal(err)
  }

  log.Println("Verify Content: ", vc)

  //String representation
  log.Println(t)
}

```
#### Sample
![merkletree](merkle_tree.png)


#### License
This project is licensed under the MIT License.
