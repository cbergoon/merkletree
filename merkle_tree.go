package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

type Content interface {
	CalculateHash() []byte
	Equals(other Content) bool
}

type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	Leafs      []*Node
}

type Node struct {
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	dup    bool
	Hash   []byte
	C      Content
}

func NewTree(cs []Content) (*MerkleTree, error) {
	root, leafs, err := buildWithContent(cs)
	if err != nil {
		return nil, err
	}
	t := &MerkleTree{
		Root:       root,
		merkleRoot: root.Hash,
		Leafs:      leafs,
	}
	return t, nil
}

func buildWithContent(cs []Content) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("Error: cannot construct tree with no content.")
	}
	var leafs []*Node
	for _, c := range cs {
		leafs = append(leafs, &Node{
			Hash: c.CalculateHash(),
			C:    c,
			leaf: true,
		})
	}
	if len(leafs)%2 == 1 {
		leafs = append(leafs, leafs[len(leafs)-1])
		leafs[len(leafs)-1].dup = true
	}
	root := buildIntermediate(leafs)
	return root, leafs, nil
}

func buildIntermediate(nl []*Node) *Node {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := sha256.New()
		chash := append(nl[i].Hash, nl[i+1].Hash...)
		h.Write(chash)
		n := &Node{
			Left:  nl[i],
			Right: nl[i+1],
			Hash:  h.Sum(nil),
		}
		nodes = append(nodes, n)
		nl[i].Parent = n
		nl[i+1].Parent = n
		if len(nl) == 2 {
			return n
		}
	}
	return buildIntermediate(nodes)
}

func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

func (m *MerkleTree) RebuildTree() error {
	var cs []Content
	for _, c := range m.Leafs {
		cs = append(cs, c.C)
	}
	root, leafs, err := buildWithContent(cs)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) RebuildTreeWith(cs []Content) error {
	root, leafs, err := buildWithContent(cs)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) VerifyTree() bool {
	calculatedMerkleRoot := m.Root.verifyNode()
	if bytes.Compare(m.merkleRoot, calculatedMerkleRoot) == 0 {
		return true
	}
	return false
}

func (n *Node) verifyNode() []byte {
	if n.leaf {
		return n.C.CalculateHash()
	} else {
		h := sha256.New()
		h.Write(append(n.Left.verifyNode(), n.Right.verifyNode()...))
		return h.Sum(nil)
	}
}

func (n *Node) calculateNodeHash() []byte {
	if n.leaf {
		return n.C.CalculateHash()
	} else {
		h := sha256.New()
		h.Write(append(n.Left.Hash, n.Right.Hash...))
		return h.Sum(nil)
	}
}

func (m *MerkleTree) VerifyContent(expectedMerkleRoot []byte, content Content) bool {
	for _, l := range m.Leafs {
		if l.C.Equals(content) {
			currentParent := l.Parent
			for currentParent != nil {
				h := sha256.New()
				if currentParent.Left.leaf && currentParent.Right.leaf {
					h.Write(append(currentParent.Left.calculateNodeHash(), currentParent.Right.calculateNodeHash()...))
					if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
						return false
					}
					currentParent = currentParent.Parent
				} else {
					h.Write(append(currentParent.Left.calculateNodeHash(), currentParent.Right.calculateNodeHash()...))
					if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
						return false
					}
					currentParent = currentParent.Parent
				}
			}
			return true
		}
	}
	return false
}

func (m *MerkleTree) String() string {
	s := ""
	for _, l := range m.Leafs {
		s += fmt.Sprint(l)
		s += "\n"
	}
	return s
}
