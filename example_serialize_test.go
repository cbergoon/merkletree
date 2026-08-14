// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"

	"github.com/cbergoon/merkletree"
)

// Record is the content stored in the trees below. Alongside the Content interface it
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler, which is what
// makes it serializable through the package registry.
type Record struct {
	Name string
}

func (r Record) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(r.Name)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (r Record) Equals(other merkletree.Content) (bool, error) {
	o, ok := other.(Record)
	if !ok {
		return false, nil
	}
	return r.Name == o.Name, nil
}

func (r Record) MarshalBinary() ([]byte, error) { return []byte(r.Name), nil }

func (r *Record) UnmarshalBinary(data []byte) error {
	r.Name = string(data)
	return nil
}

// Example_serialization stores a tree with encoding/gob and reads it back. Registering
// the content type is what lets the decoder rebuild concrete Record values from an
// interface field.
func Example_serialization() {
	merkletree.RegisterContent(Record{})

	list := []merkletree.Content{Record{Name: "Alice"}, Record{Name: "Bob"}, Record{Name: "Carol"}}
	tree, err := merkletree.NewTree(list)
	if err != nil {
		fmt.Println(err)
		return
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(tree); err != nil {
		fmt.Println(err)
		return
	}

	var decoded merkletree.MerkleTree
	if err := gob.NewDecoder(&buf).Decode(&decoded); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("same root:", bytes.Equal(tree.MerkleRoot(), decoded.MerkleRoot()))

	found, err := decoded.VerifyContent(Record{Name: "Bob"})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("contains Bob:", found)

	// Output:
	// same root: true
	// contains Bob: true
}

// ExampleMerkleTree_MarshalWith serializes a tree without registering anything, by
// supplying the content codec directly.
func ExampleMerkleTree_MarshalWith() {
	list := []merkletree.Content{Record{Name: "Alice"}, Record{Name: "Bob"}}
	tree, err := merkletree.NewTree(list)
	if err != nil {
		fmt.Println(err)
		return
	}

	data, err := tree.MarshalWith(func(c merkletree.Content) ([]byte, error) {
		return []byte(c.(Record).Name), nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	decoded, err := merkletree.UnmarshalWith(data, func(b []byte) (merkletree.Content, error) {
		return Record{Name: string(b)}, nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// UnmarshalWith rebuilds the tree and checks it against the root recorded in the
	// payload, so reaching this point already proves the tree is intact.
	fmt.Println("same root:", bytes.Equal(tree.MerkleRoot(), decoded.MerkleRoot()))

	// Output:
	// same root: true
}
