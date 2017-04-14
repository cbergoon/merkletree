// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

//TestContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestContent struct {
	x string
}

//CalculateHash hashes the values of a TestContent
func (t TestContent) CalculateHash() []byte {
	h := sha256.New()
	h.Write([]byte(t.x))
	return h.Sum(nil)
}

//Equals tests for equality of two Contents
func (t TestContent) Equals(other Content) bool {
	return t.x == other.(TestContent).x
}

var table = []struct {
	contents     []Content
	expectedHash []byte
}{
	{
		contents: []Content{
			TestContent{
				x: "Hello",
			},
			TestContent{
				x: "Hi",
			},
			TestContent{
				x: "Hey",
			},
			TestContent{
				x: "Hola",
			},
		},
		expectedHash: []byte{95, 48, 204, 128, 19, 59, 147, 148, 21, 110, 36, 178, 51, 240, 196, 190, 50, 178, 78, 68, 187, 51, 129, 240, 44, 123, 165, 38, 25, 208, 254, 188},
	},
	{
		contents: []Content{
			TestContent{
				x: "Hello",
			},
			TestContent{
				x: "Hi",
			},
			TestContent{
				x: "Hey",
			},
		},
		expectedHash: []byte{189, 214, 55, 197, 35, 237, 92, 14, 171, 121, 43, 152, 109, 177, 136, 80, 194, 57, 162, 226, 56, 2, 179, 106, 255, 38, 187, 104, 251, 63, 224, 8},
	},
	{
		contents: []Content{
			TestContent{
				x: "123",
			},
			TestContent{
				x: "234",
			},
			TestContent{
				x: "345",
			},
			TestContent{
				x: "456",
			},
			TestContent{
				x: "1123",
			},
			TestContent{
				x: "2234",
			},
			TestContent{
				x: "3345",
			},
			TestContent{
				x: "4456",
			},
		},
		expectedHash: []byte{30, 76, 61, 40, 106, 173, 169, 183, 149, 2, 157, 246, 162, 218, 4, 70, 153, 148, 62, 162, 90, 24, 173, 250, 41, 149, 173, 121, 141, 187, 146, 43},
	},
}

func TestNewTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("error: expected hash equal to %v got %v", table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_MerkleRoot(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("error: expected hash equal to %v got %v", table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_RebuildTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		err = tree.RebuildTree()
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("error: expected hash equal to %v got %v", table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_RebuildTreeWith(t *testing.T) {
	for i := 0; i < len(table)-1; i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		err = tree.RebuildTreeWith(table[i+1].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i+1].expectedHash) != 0 {
			t.Errorf("error: expected hash equal to %v got %v", table[i+1].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_VerifyTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		v1 := tree.VerifyTree()
		if v1 != true {
			t.Error("error: expected tree to be valid")
		}
		tree.Root.Hash = []byte{1}
		tree.merkleRoot = []byte{1}
		v2 := tree.VerifyTree()
		if v2 != false {
			t.Error("error: expected tree to be invalid")
		}
	}
}

func TestMerkleTree_VerifyContent(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		if len(table[i].contents) > 0 {
			v := tree.VerifyContent(tree.MerkleRoot(), table[i].contents[0])
			if !v {
				t.Error("error: expected valid content")
			}
		}
		if len(table[i].contents) > 1 {
			v := tree.VerifyContent(tree.MerkleRoot(), table[i].contents[1])
			if !v {
				t.Error("error: expected valid content")
			}
		}
		if len(table[i].contents) > 2 {
			v := tree.VerifyContent(tree.MerkleRoot(), table[i].contents[2])
			if !v {
				t.Error("error: expected valid content")
			}
		}
		if len(table[i].contents) > 0 {
			tree.Root.Hash = []byte{1}
			tree.merkleRoot = []byte{1}
			v := tree.VerifyContent(tree.MerkleRoot(), table[i].contents[0])
			if v {
				t.Error("error: expected invalid content")
			}
			tree.RebuildTree()
		}
		v := tree.VerifyContent(tree.MerkleRoot(), TestContent{x: "NotInTestTable"})
		if v {
			t.Error("error: expected invalid content")
		}
	}
}

func TestMerkleTree_String(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Error("error: unexpected error:  ", err)
		}
		if tree.String() == "" {
			t.Error("error: expected not empty string")
		}
	}
}
