package merkletree

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

//Content represents the data that is stored and verified by the tree. A type that
//implements this interface can be used as an item in the tree.
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

//MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
//a list of pointers to the leaf nodes, and the merkle root.
type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	Leafs      []*Node
}

//Node represents a node, root, or leaf in the tree. It stores pointers to its immediate
//relationships, a hash, the content stored if it is a leaf, and other metadata.
type Node struct {
	Tree   *MerkleTree
	Parent *Node
	Left   *Node
	Right  *Node
	Hash   []byte
	C      Content
}

//NewTree creates a new Merkle Tree using the content cs.
func NewTree(cs []Content) (*MerkleTree, error) {
	t := &MerkleTree{}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

// GetMerklePath: Get Merkle path and indexes(left leaf or right leaf)
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
				if bytes.Equal(currentParent.Left.Hash, current.Hash) {
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
	return nil, nil, nil
}

//buildWithContent is a helper function that for a given set of Contents, generates a
//corresponding tree and returns the root node, a list of leaf nodes, and a possible error.
//Returns an error if cs contains no Contents.
func buildWithContent(cs []Content, t *MerkleTree) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, c := range cs {
		hash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hash,
			C:    c,
			Tree: t,
		})
	}

	root, err := buildIntermediate(leafs, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

//buildIntermediate is a helper function that for a given list of leaf nodes, constructs
//the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node, t *MerkleTree) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		var left, right int = i, i + 1

		if i+1 == len(nl) {
			n := &Node{
				Left:  nl[left],
				Right: nil,
				Hash:  nl[left].Hash,
				Tree:  t,
			}

			nodes = append(nodes, n)
			nl[left].Parent = n
		} else {
			leftHex := hex.EncodeToString(nl[left].Hash)
			rightHex := hex.EncodeToString(nl[right].Hash)
			hashes := []string{leftHex, rightHex}
			sort.Strings(hashes)

			if hashes[0] == rightHex {
				nl[left], nl[right] = nl[right], nl[left]
			}

			chash := append(nl[left].Hash, nl[right].Hash...)
			keccak := crypto.Keccak256(chash)

			n := &Node{
				Left:  nl[left],
				Right: nl[right],
				Hash:  keccak,
				Tree:  t,
			}

			nodes = append(nodes, n)
			nl[left].Parent = n
			nl[right].Parent = n

			if len(nl) == 2 {
				return n, nil
			}
		}
	}
	return buildIntermediate(nodes, t)
}
