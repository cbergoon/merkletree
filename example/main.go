package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/cbergoon/merkletree"
)

// StringContent implements the Content interface for simple strings.
type StringContent struct {
	x string
}

// CalculateHash hashes the values of a StringContent
func (t StringContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (t StringContent) Equals(other merkletree.Content) (bool, error) {
	return t.x == other.(StringContent).x, nil
}

// String returns the string value
func (t StringContent) String() string {
	return t.x
}

// syncTrees checks if two trees have the same root. If not, it recursively
// finds the inconsistent leaf in t2, updates it to match t1, and rebuilds t2.
func syncTrees(t1, t2 *merkletree.MerkleTree) error {
	if bytes.Equal(t1.MerkleRoot(), t2.MerkleRoot()) {
		fmt.Println("Trees are already synchronized.")
		return nil
	}

	fmt.Println("Inconsistency detected! Roots do not match.")
	fixed, err := fixInconsistentNode(t1.Root, t2.Root)
	if err != nil {
		return err
	}

	if fixed {
		fmt.Println("Rebuilding Tree 2 after fixing consistency...")
		return t2.RebuildTree()
	}

	fmt.Println("No specific leaf inconsistency found to fix (trees may have different structures).")
	return nil
}

// fixInconsistentNode recursively finds the diverging node.
// Returns true if a leaf was fixed.
func fixInconsistentNode(n1, n2 *merkletree.Node) (bool, error) {
	if n1 == nil || n2 == nil {
		return false, nil
	}
	
	// If the hashes match, this subtree is consistent
	if bytes.Equal(n1.Hash, n2.Hash) {
		return false, nil
	}

	// If we reached leaves and hashes don't match, we found the inconsistency
	// (Assumes both trees have the same depth/structure for this logic)
	// merkle_tree doesn't expose `leaf` boolean natively outside the package if it's lowercase `leaf`.
	// Let's check if Left and Right are nil to identify leaves.
	isLeaf1 := n1.Left == nil && n1.Right == nil
	isLeaf2 := n2.Left == nil && n2.Right == nil

	if isLeaf1 && isLeaf2 {
		fmt.Printf("Inconsistent leaf found! Tree 1 has '%v', Tree 2 has '%v'\n", n1.C, n2.C)
		fmt.Printf("Updating Tree 2 leaf to match Tree 1: '%v'\n", n1.C)
		n2.C = n1.C
		return true, nil
	}

	// Not leaves. Check Left child.
	if n1.Left != nil && n2.Left != nil && !bytes.Equal(n1.Left.Hash, n2.Left.Hash) {
		return fixInconsistentNode(n1.Left, n2.Left)
	}

	// If left children match or don't exist, check right child.
	if n1.Right != nil && n2.Right != nil && !bytes.Equal(n1.Right.Hash, n2.Right.Hash) {
		return fixInconsistentNode(n1.Right, n2.Right)
	}

	return false, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <tree1_elements> <tree2_elements>")
		fmt.Println("Example: go run main.go \"A,B,C,D\" \"A,B,X,D\"")
		return
	}

	list1 := strings.Split(os.Args[1], ",")
	list2 := strings.Split(os.Args[2], ",")

	if len(list1) != len(list2) {
		fmt.Println("Error: Please provide two lists of the same length to test inconsistency logic.")
		return
	}

	var content1 []merkletree.Content
	for _, val := range list1 {
		content1 = append(content1, StringContent{x: strings.TrimSpace(val)})
	}

	var content2 []merkletree.Content
	for _, val := range list2 {
		content2 = append(content2, StringContent{x: strings.TrimSpace(val)})
	}

	fmt.Println("Building Tree 1 with:", content1)
	tree1, err := merkletree.NewTree(content1)
	if err != nil {
		fmt.Println("Error building Tree 1:", err)
		return
	}

	fmt.Println("Building Tree 2 with:", content2)
	tree2, err := merkletree.NewTree(content2)
	if err != nil {
		fmt.Println("Error building Tree 2:", err)
		return
	}

	fmt.Printf("\nInitial Roots:\n")
	fmt.Printf("Tree 1 Root: %x\n", tree1.MerkleRoot())
	fmt.Printf("Tree 2 Root: %x\n\n", tree2.MerkleRoot())

	err = syncTrees(tree1, tree2)
	if err != nil {
		fmt.Println("Error syncing trees:", err)
		return
	}

	fmt.Printf("\nFinal Roots:\n")
	fmt.Printf("Tree 1 Root: %x\n", tree1.MerkleRoot())
	fmt.Printf("Tree 2 Root: %x\n", tree2.MerkleRoot())

	if bytes.Equal(tree1.MerkleRoot(), tree2.MerkleRoot()) {
		fmt.Println("Success! Trees are fully synchronized.")
	} else {
		fmt.Println("Failed to synchronize trees.")
	}
}
