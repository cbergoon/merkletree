// Copyright (c) 2015, Emir Pasic. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package btree implements a B tree.
//
// According to Knuth's definition, a B-tree of order m is a tree which satisfies the following properties:
// - Every node has at most m children.
// - Every non-leaf node (except root) has at least ⌈m/2⌉ children.
// - The root has at least two children if it is not a leaf node.
// - A non-leaf node with k children contains k−1 keys.
// - All leaves appear in the same level
//
// Structure is not thread safe.
//
// References: https://en.wikipedia.org/wiki/B-tree
package merklebtree

import (
	"crypto/sha256"
	"encoding/hex"
)

// Tree holds elements of the B-tree
type Tree struct {
	Root *Node // Root node
	size int   // Total number of keys in the tree
	m    int   // order (maximum number of children)
}

// Node is a single element within the tree
type Node struct {
	Parent   *Node
	Hash     []byte
	Contents []*Content // Contained keys in node
	Children []*Node    // Children nodes
}

func (node *Node) Put(item Content) {
	node.Contents = append(node.Contents, &item)
}

// CalculateHash update the merkle hash of node,include children and content.
func (tree *Tree) CalculateHash(node *Node) ([]byte, error) {
	h := sha256.New()
	var bytes []byte

	for _, content := range node.Contents {
		hash, err := (*content).CalculateHash()
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, hash...)
	}

	for _, children := range node.Children {
		bytes = append(bytes, children.Hash...)
	}

	if _, err := h.Write(bytes); err != nil {
		return nil, err
	}

	node.Hash = h.Sum(nil)

	return node.Hash, nil
}

//ReCalculateMerkleRoot update Merkleroot from node to root node.
func (tree *Tree) ReCalculateMerkleRoot(node *Node) ([]byte, error) {
	if node == tree.Root {
		return tree.CalculateHash(node)
	} else {
		_, err := tree.CalculateHash(node)
		if err != nil {
			return nil, err
		}
		return tree.ReCalculateMerkleRoot(node.Parent)
	}
}

type Content interface {
	// CalculateHash calculate the hash of content
	CalculateHash() ([]byte, error)

	// If a.Comparator(b) return
	// negative , if a < b
	// zero     , if a == b
	// positive , if a > b
	Comparator(than Content) int
}

// NewWith instantiates a B-tree with the order (maximum number of children) and a custom key comparator.
func NewWith(order int) *Tree {
	if order < 3 {
		panic("Invalid order, should be at least 3")
	}
	return &Tree{m: order}
}

// Put inserts key-value pair node into the tree.
// If key already exists, then its value is updated with the new value.
// Key should adhere to the comparator's type assertion, otherwise method panics.
func (tree *Tree) Put(item Content) {
	content := &item

	if tree.Root == nil {
		tree.Root = &Node{Contents: []*Content{content}, Children: []*Node{}}
		tree.size++

		//calculate merkle root hash
		_, err := tree.ReCalculateMerkleRoot(tree.Root)
		if err != nil {
			panic(err)
		}

		return
	}

	if tree.insert(tree.Root, content) {
		tree.size++
	}
}

// Get searches the node in the tree by key and returns its value or nil if key is not found in tree.
// Second return parameter is true if key was found, otherwise false.
// Key should adhere to the comparator's type assertion, otherwise method panics.
func (tree *Tree) Get(item Content) (result Content, found bool) {
	node, index, found := tree.searchRecursively(tree.Root, item)
	if found {
		return *node.Contents[index], true
	}
	return item, false
}

// Remove remove the node from the tree by key.
// Key should adhere to the comparator's type assertion, otherwise method panics.
func (tree *Tree) Remove(item Content) {
	node, index, found := tree.searchRecursively(tree.Root, item)
	if found {
		tree.delete(node, index)
		tree.size--
	}
}

// Empty returns true if tree does not contain any nodes
func (tree *Tree) Empty() bool {
	return tree.size == 0
}

// Size returns number of nodes in the tree.
func (tree *Tree) Size() int {
	return tree.size
}

// Keys returns all keys in-order
func (tree *Tree) Contents() []Content {
	contents := make([]Content, tree.size)
	it := tree.Iterator()
	for i := 0; it.Next(); i++ {
		contents[i] = it.Item()
	}
	return contents
}

// Clear removes all nodes from the tree.
func (tree *Tree) Clear() {
	tree.Root = nil
	tree.size = 0
}

func (tree *Tree) MerkleBTreeRoot() string {
	if tree.Root == nil {
		return ""
	} else {
		return hex.EncodeToString(tree.Root.Hash)
	}
}

// Height returns the height of the tree.
func (tree *Tree) Height() int {
	return tree.Root.height()
}

// Left returns the left-most (min) node or nil if tree is empty.
func (tree *Tree) Left() *Node {
	return tree.left(tree.Root)
}

// LeftKey returns the left-most (min) key or nil if tree is empty.
func (tree *Tree) LeftItem() Content {
	if left := tree.Left(); left != nil {
		return *left.Contents[0]
	}
	return nil
}

// Right returns the right-most (max) node or nil if tree is empty.
func (tree *Tree) Right() *Node {
	return tree.right(tree.Root)
}

// RightKey returns the right-most (max) key or nil if tree is empty.
func (tree *Tree) RightItem() Content {
	if right := tree.Right(); right != nil {
		return *right.Contents[len(right.Contents)-1]
	}
	return nil
}

func (node *Node) height() int {
	height := 0
	for ; node != nil; node = node.Children[0] {
		height++
		if len(node.Children) == 0 {
			break
		}
	}
	return height
}

func (tree *Tree) isLeaf(node *Node) bool {
	return len(node.Children) == 0
}

func (tree *Tree) isFull(node *Node) bool {
	return len(node.Contents) == tree.maxContents()
}

func (tree *Tree) shouldSplit(node *Node) bool {
	return len(node.Contents) > tree.maxContents()
}

func (tree *Tree) maxChildren() int {
	return tree.m
}

func (tree *Tree) minChildren() int {
	return (tree.m + 1) / 2 // ceil(m/2)
}

func (tree *Tree) maxContents() int {
	return tree.maxChildren() - 1
}

func (tree *Tree) minContents() int {
	return tree.minChildren() - 1
}

func (tree *Tree) middle() int {
	return (tree.m - 1) / 2 // "-1" to favor right nodes to have more keys when splitting
}

// search searches only within the single node among its contents
func (tree *Tree) search(node *Node, item Content) (index int, found bool) {
	low, high := 0, len(node.Contents)-1
	var mid int
	for low <= high {
		mid = (high + low) / 2
		compare := item.Comparator(*node.Contents[mid])
		switch {
		case compare > 0:
			low = mid + 1
		case compare < 0:
			high = mid - 1
		case compare == 0:
			return mid, true
		}
	}
	return low, false
}

// deep search the tree and return the node
func (tree *Tree) deepSearch() [][]*Node {
	var nodes [][]*Node
	if tree.Root == nil {
		return nodes
	}
	var startnodes, nextnodes []*Node
	startnodes = append(startnodes, tree.Root)
	nodes = append(nodes, startnodes)

	for true {
		for _, node := range startnodes {
			nextnodes = append(nextnodes, node.Children...)
		}
		nodes = append(nodes, nextnodes)
		startnodes = nextnodes
		nextnodes = nil
		if len(startnodes) == 0 {
			break
		}
		if tree.isLeaf(startnodes[0]) {
			break
		}
	}

	return nodes
}

// calculateMerkleRoot by iterator the tree
func (tree *Tree) calculateMerkleRoot() string {
	if tree.Root == nil {
		return ""
	}
	nodes := tree.deepSearch()
	for i := len(nodes) - 1; i > 0; i-- {
		for j := 0; j < len(nodes[i]); j++ {
			//reset nodes[i][j] Hash
			nodes[i][j].Hash = nil
			tree.CalculateHash(nodes[i][j])
		}
	}
	return hex.EncodeToString(nodes[0][0].Hash)
}

// searchRecursively searches recursively down the tree starting at the startNode
func (tree *Tree) searchRecursively(startNode *Node, item Content) (node *Node, index int, found bool) {
	if tree.Empty() {
		return nil, -1, false
	}
	node = startNode
	for {
		index, found = tree.search(node, item)
		if found {
			return node, index, true
		}
		if tree.isLeaf(node) {
			return nil, -1, false
		}
		node = node.Children[index]
	}
}

func (tree *Tree) insert(node *Node, content *Content) (inserted bool) {
	if tree.isLeaf(node) {
		return tree.insertIntoLeaf(node, content)
	}
	return tree.insertIntoInternal(node, content)
}

func (tree *Tree) insertIntoLeaf(node *Node, content *Content) (inserted bool) {
	insertPosition, found := tree.search(node, *content)
	if found {
		node.Contents[insertPosition] = content
		tree.ReCalculateMerkleRoot(node)
		return false
	}
	// Insert content's key in the middle of the node
	node.Contents = append(node.Contents, nil)
	copy(node.Contents[insertPosition+1:], node.Contents[insertPosition:])
	node.Contents[insertPosition] = content
	tree.split(node)
	return true
}

func (tree *Tree) insertIntoInternal(node *Node, content *Content) (inserted bool) {
	insertPosition, found := tree.search(node, *content)
	if found {
		node.Contents[insertPosition] = content
		tree.ReCalculateMerkleRoot(node)
		return false
	}
	return tree.insert(node.Children[insertPosition], content)
}

func (tree *Tree) split(node *Node) {
	if !tree.shouldSplit(node) {
		tree.ReCalculateMerkleRoot(node)
		return
	}

	if node == tree.Root {
		tree.splitRoot()
		return
	}

	tree.splitNonRoot(node)
}

func (tree *Tree) splitNonRoot(node *Node) {
	middle := tree.middle()
	parent := node.Parent

	left := &Node{Contents: append([]*Content(nil), node.Contents[:middle]...), Parent: parent}
	right := &Node{Contents: append([]*Content(nil), node.Contents[middle+1:]...), Parent: parent}

	// Move children from the node to be split into left and right nodes
	if !tree.isLeaf(node) {
		left.Children = append([]*Node(nil), node.Children[:middle+1]...)
		right.Children = append([]*Node(nil), node.Children[middle+1:]...)
		setParent(left.Children, left)
		setParent(right.Children, right)
	}

	insertPosition, _ := tree.search(parent, *node.Contents[middle])

	// Insert middle key into parent
	parent.Contents = append(parent.Contents, nil)
	copy(parent.Contents[insertPosition+1:], parent.Contents[insertPosition:])
	parent.Contents[insertPosition] = node.Contents[middle]

	// Set child left of inserted key in parent to the created left node
	parent.Children[insertPosition] = left

	// Set child right of inserted key in parent to the created right node
	parent.Children = append(parent.Children, nil)
	copy(parent.Children[insertPosition+2:], parent.Children[insertPosition+1:])
	parent.Children[insertPosition+1] = right

	tree.CalculateHash(left)
	tree.CalculateHash(right)
	tree.CalculateHash(parent)

	tree.split(parent)
}

func (tree *Tree) splitRoot() {
	middle := tree.middle()

	left := &Node{Contents: append([]*Content(nil), tree.Root.Contents[:middle]...)}
	right := &Node{Contents: append([]*Content(nil), tree.Root.Contents[middle+1:]...)}

	// Move children from the node to be split into left and right nodes
	if !tree.isLeaf(tree.Root) {
		left.Children = append([]*Node(nil), tree.Root.Children[:middle+1]...)
		right.Children = append([]*Node(nil), tree.Root.Children[middle+1:]...)
		setParent(left.Children, left)
		setParent(right.Children, right)
	}
	tree.CalculateHash(left)
	tree.CalculateHash(right)

	// Root is a node with one content and two children (left and right)
	newRoot := &Node{
		Contents: []*Content{tree.Root.Contents[middle]},
		Children: []*Node{left, right},
	}

	left.Parent = newRoot
	right.Parent = newRoot
	tree.Root = newRoot
	tree.CalculateHash(newRoot)
}

func setParent(nodes []*Node, parent *Node) {
	for _, node := range nodes {
		node.Parent = parent
	}
}

func (tree *Tree) left(node *Node) *Node {
	if tree.Empty() {
		return nil
	}
	current := node
	for {
		if tree.isLeaf(current) {
			return current
		}
		current = current.Children[0]
	}
}

func (tree *Tree) right(node *Node) *Node {
	if tree.Empty() {
		return nil
	}
	current := node
	for {
		if tree.isLeaf(current) {
			return current
		}
		current = current.Children[len(current.Children)-1]
	}
}

// leftSibling returns the node's left sibling and child index (in parent) if it exists, otherwise (nil,-1)
// key is any of keys in node (could even be deleted).
func (tree *Tree) leftSibling(node *Node, item Content) (*Node, int) {
	if node.Parent != nil {
		index, _ := tree.search(node.Parent, item)
		index--
		if index >= 0 && index < len(node.Parent.Children) {
			return node.Parent.Children[index], index
		}
	}
	return nil, -1
}

// rightSibling returns the node's right sibling and child index (in parent) if it exists, otherwise (nil,-1)
// key is any of keys in node (could even be deleted).
func (tree *Tree) rightSibling(node *Node, item Content) (*Node, int) {
	if node.Parent != nil {
		index, _ := tree.search(node.Parent, item)
		index++
		if index < len(node.Parent.Children) {
			return node.Parent.Children[index], index
		}
	}
	return nil, -1
}

// delete deletes an content in node at contents' index
// ref.: https://en.wikipedia.org/wiki/B-tree#Deletion
func (tree *Tree) delete(node *Node, index int) {
	// deleting from a leaf node
	if tree.isLeaf(node) {
		deletedKey := node.Contents[index]
		tree.deleteContent(node, index)
		tree.rebalance(node, *deletedKey)
		if len(tree.Root.Contents) == 0 {
			tree.Root = nil
		}
		return
	}

	// deleting from an internal node
	leftLargestNode := tree.right(node.Children[index]) // largest node in the left sub-tree (assumed to exist)
	leftLargestContentIndex := len(leftLargestNode.Contents) - 1
	node.Contents[index] = leftLargestNode.Contents[leftLargestContentIndex]
	deletedKey := leftLargestNode.Contents[leftLargestContentIndex]
	tree.deleteContent(leftLargestNode, leftLargestContentIndex)
	tree.rebalance(leftLargestNode, *deletedKey)
}

// rebalance rebalances the tree after deletion if necessary and returns true, otherwise false.
// Note that we first delete the content and then call rebalance, thus the passed deleted key as reference.
func (tree *Tree) rebalance(node *Node, deletedItem Content) {
	// check if rebalancing is needed
	if node == nil || len(node.Contents) >= tree.minContents() {
		//recalculate merkle root from leaf node
		if node != nil {
			//root is not nil
			tree.ReCalculateMerkleRoot(node)
		}
		return
	}

	// try to borrow from left sibling
	leftSibling, leftSiblingIndex := tree.leftSibling(node, deletedItem)
	if leftSibling != nil && len(leftSibling.Contents) > tree.minContents() {
		// rotate right
		node.Contents = append([]*Content{node.Parent.Contents[leftSiblingIndex]}, node.Contents...) // prepend parent's separator content to node's contents
		node.Parent.Contents[leftSiblingIndex] = leftSibling.Contents[len(leftSibling.Contents)-1]
		tree.deleteContent(leftSibling, len(leftSibling.Contents)-1)
		if !tree.isLeaf(leftSibling) {
			leftSiblingRightMostChild := leftSibling.Children[len(leftSibling.Children)-1]
			leftSiblingRightMostChild.Parent = node
			node.Children = append([]*Node{leftSiblingRightMostChild}, node.Children...)
			tree.deleteChild(leftSibling, len(leftSibling.Children)-1)
		}
		tree.CalculateHash(node)
		tree.CalculateHash(leftSibling)
		return
	}

	// try to borrow from right sibling
	rightSibling, rightSiblingIndex := tree.rightSibling(node, deletedItem)
	if rightSibling != nil && len(rightSibling.Contents) > tree.minContents() {
		// rotate left
		node.Contents = append(node.Contents, node.Parent.Contents[rightSiblingIndex-1]) // append parent's separator content to node's contents
		node.Parent.Contents[rightSiblingIndex-1] = rightSibling.Contents[0]
		tree.deleteContent(rightSibling, 0)
		if !tree.isLeaf(rightSibling) {
			rightSiblingLeftMostChild := rightSibling.Children[0]
			rightSiblingLeftMostChild.Parent = node
			node.Children = append(node.Children, rightSiblingLeftMostChild)
			tree.deleteChild(rightSibling, 0)
		}
		tree.CalculateHash(node)
		tree.CalculateHash(rightSibling)
		return
	}

	// merge with siblings
	if rightSibling != nil {
		// merge with right sibling
		node.Contents = append(node.Contents, node.Parent.Contents[rightSiblingIndex-1])
		node.Contents = append(node.Contents, rightSibling.Contents...)
		deletedItem = *node.Parent.Contents[rightSiblingIndex-1]
		tree.deleteContent(node.Parent, rightSiblingIndex-1)
		tree.appendChildren(node.Parent.Children[rightSiblingIndex], node)
		tree.deleteChild(node.Parent, rightSiblingIndex)
		tree.CalculateHash(node)
	} else if leftSibling != nil {
		// merge with left sibling
		contents := append([]*Content(nil), leftSibling.Contents...)
		contents = append(contents, node.Parent.Contents[leftSiblingIndex])
		node.Contents = append(contents, node.Contents...)
		deletedItem = *node.Parent.Contents[leftSiblingIndex]
		tree.deleteContent(node.Parent, leftSiblingIndex)
		tree.prependChildren(node.Parent.Children[leftSiblingIndex], node)
		tree.deleteChild(node.Parent, leftSiblingIndex)
		tree.CalculateHash(node)
	}

	// make the merged node the root if its parent was the root and the root is empty
	if node.Parent == tree.Root && len(tree.Root.Contents) == 0 {
		tree.Root = node
		node.Parent = nil
		tree.CalculateHash(tree.Root)
		return
	}

	// parent might underflow, so try to rebalance if necessary
	tree.rebalance(node.Parent, deletedItem)
}

func (tree *Tree) prependChildren(fromNode *Node, toNode *Node) {
	children := append([]*Node(nil), fromNode.Children...)
	toNode.Children = append(children, toNode.Children...)
	setParent(fromNode.Children, toNode)
}

func (tree *Tree) appendChildren(fromNode *Node, toNode *Node) {
	toNode.Children = append(toNode.Children, fromNode.Children...)
	setParent(fromNode.Children, toNode)
}

func (tree *Tree) deleteContent(node *Node, index int) {
	copy(node.Contents[index:], node.Contents[index+1:])
	node.Contents[len(node.Contents)-1] = nil
	node.Contents = node.Contents[:len(node.Contents)-1]
}

func (tree *Tree) deleteChild(node *Node, index int) {
	if index >= len(node.Children) {
		return
	}
	copy(node.Children[index:], node.Children[index+1:])
	node.Children[len(node.Children)-1] = nil
	node.Children = node.Children[:len(node.Children)-1]
}
