// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/md5"
	"hash"
	"testing"

	"golang.org/x/crypto/sha3"
)

//TestSHAContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestSHAContent struct {
	x string
}

const defaultHashStrategyName string = "sha3-256"

var defaultHashStrategy (func() hash.Hash) = sha3.New256

//Generator default generator
func Generator() hash.Hash {
	return defaultHashStrategy()
}

//CalculateHash hashes the values of a TestSHA256Content
func (t TestSHAContent) CalculateHash() ([]byte, error) {
	h := Generator()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestSHAContent) Equals(other Content) (bool, error) {
	return t.x == other.(TestSHAContent).x, nil
}

//TestContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestMD5Content struct {
	x string
}

//CalculateHash hashes the values of a TestContent
func (t TestMD5Content) CalculateHash() ([]byte, error) {
	h := md5.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestMD5Content) Equals(other Content) (bool, error) {
	return t.x == other.(TestMD5Content).x, nil
}

func calHash(hash []byte, hashStrategy func() hash.Hash) ([]byte, error) {
	h := hashStrategy()
	if _, err := h.Write(hash); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

var table = []struct {
	testCaseId          int
	hashStrategy        func() hash.Hash
	hashStrategyName    string
	defaultHashStrategy bool
	contents            []Content
	expectedHash        []byte
	notInContents       Content
}{
	{
		testCaseId:          0,
		hashStrategy:        defaultHashStrategy,
		hashStrategyName:    defaultHashStrategyName,
		defaultHashStrategy: true,
		contents: []Content{
			TestSHAContent{
				x: "Hello",
			},
			TestSHAContent{
				x: "Hi",
			},
			TestSHAContent{
				x: "Hey",
			},
			TestSHAContent{
				x: "Hola",
			},
		},
		notInContents: TestSHAContent{x: "NotInTestTable"},
		expectedHash:  []byte{32, 188, 172, 153, 245, 171, 51, 156, 161, 201, 80, 58, 155, 97, 1, 79, 86, 175, 244, 91, 137, 105, 238, 155, 233, 126, 112, 151, 195, 101, 37, 220},
	},
	{
		testCaseId:          1,
		hashStrategy:        defaultHashStrategy,
		hashStrategyName:    defaultHashStrategyName,
		defaultHashStrategy: true,
		contents: []Content{
			TestSHAContent{
				x: "Hello",
			},
			TestSHAContent{
				x: "Hi",
			},
			TestSHAContent{
				x: "Hey",
			},
		},
		notInContents: TestSHAContent{x: "NotInTestTable"},
		expectedHash:  []byte{246, 99, 11, 12, 67, 200, 116, 99, 203, 3, 108, 4, 0, 233, 95, 255, 15, 246, 248, 96, 75, 108, 103, 113, 133, 191, 75, 34, 210, 198, 105, 142},
	},
	{
		testCaseId:          2,
		hashStrategy:        defaultHashStrategy,
		hashStrategyName:    defaultHashStrategyName,
		defaultHashStrategy: true,
		contents: []Content{
			TestSHAContent{
				x: "Hello",
			},
			TestSHAContent{
				x: "Hi",
			},
			TestSHAContent{
				x: "Hey",
			},
			TestSHAContent{
				x: "Greetings",
			},
			TestSHAContent{
				x: "Hola",
			},
		},
		notInContents: TestSHAContent{x: "NotInTestTable"},
		expectedHash:  []byte{136, 215, 127, 182, 176, 143, 79, 68, 202, 214, 24, 78, 62, 145, 30, 204, 179, 170, 168, 186, 229, 63, 48, 193, 209, 165, 91, 208, 45, 255, 197, 224},
	},
	{
		testCaseId:          3,
		hashStrategy:        defaultHashStrategy,
		hashStrategyName:    defaultHashStrategyName,
		defaultHashStrategy: true,
		contents: []Content{
			TestSHAContent{
				x: "123",
			},
			TestSHAContent{
				x: "234",
			},
			TestSHAContent{
				x: "345",
			},
			TestSHAContent{
				x: "456",
			},
			TestSHAContent{
				x: "1123",
			},
			TestSHAContent{
				x: "2234",
			},
			TestSHAContent{
				x: "3345",
			},
			TestSHAContent{
				x: "4456",
			},
		},
		notInContents: TestSHAContent{x: "NotInTestTable"},
		expectedHash:  []byte{34, 206, 114, 216, 133, 246, 9, 62, 39, 249, 11, 159, 238, 217, 98, 5, 48, 221, 167, 237, 59, 192, 140, 138, 196, 128, 147, 66, 116, 197, 192, 137},
	},
	{
		testCaseId:          4,
		hashStrategy:        defaultHashStrategy,
		hashStrategyName:    defaultHashStrategyName,
		defaultHashStrategy: true,
		contents: []Content{
			TestSHAContent{
				x: "123",
			},
			TestSHAContent{
				x: "234",
			},
			TestSHAContent{
				x: "345",
			},
			TestSHAContent{
				x: "456",
			},
			TestSHAContent{
				x: "1123",
			},
			TestSHAContent{
				x: "2234",
			},
			TestSHAContent{
				x: "3345",
			},
			TestSHAContent{
				x: "4456",
			},
			TestSHAContent{
				x: "5567",
			},
		},
		notInContents: TestSHAContent{x: "NotInTestTable"},
		expectedHash:  []byte{131, 208, 129, 139, 57, 219, 227, 204, 170, 132, 60, 169, 110, 79, 215, 25, 28, 199, 4, 70, 205, 134, 183, 26, 185, 129, 117, 26, 155, 193, 111, 12},
	},
	{
		testCaseId:          5,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "Hello",
			},
			TestMD5Content{
				x: "Hi",
			},
			TestMD5Content{
				x: "Hey",
			},
			TestMD5Content{
				x: "Hola",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{217, 158, 206, 52, 191, 78, 253, 233, 25, 55, 69, 142, 254, 45, 127, 144},
	},
	{
		testCaseId:          6,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "Hello",
			},
			TestMD5Content{
				x: "Hi",
			},
			TestMD5Content{
				x: "Hey",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{145, 228, 171, 107, 94, 219, 221, 171, 7, 195, 206, 128, 148, 98, 59, 76},
	},
	{
		testCaseId:          7,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "Hello",
			},
			TestMD5Content{
				x: "Hi",
			},
			TestMD5Content{
				x: "Hey",
			},
			TestMD5Content{
				x: "Greetings",
			},
			TestMD5Content{
				x: "Hola",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{167, 200, 229, 62, 194, 247, 117, 12, 206, 194, 90, 235, 70, 14, 100, 100},
	},
	{
		testCaseId:          8,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "123",
			},
			TestMD5Content{
				x: "234",
			},
			TestMD5Content{
				x: "345",
			},
			TestMD5Content{
				x: "456",
			},
			TestMD5Content{
				x: "1123",
			},
			TestMD5Content{
				x: "2234",
			},
			TestMD5Content{
				x: "3345",
			},
			TestMD5Content{
				x: "4456",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{8, 36, 33, 50, 204, 197, 82, 81, 207, 74, 6, 60, 162, 209, 168, 21},
	},
	{
		testCaseId:          9,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "123",
			},
			TestMD5Content{
				x: "234",
			},
			TestMD5Content{
				x: "345",
			},
			TestMD5Content{
				x: "456",
			},
			TestMD5Content{
				x: "1123",
			},
			TestMD5Content{
				x: "2234",
			},
			TestMD5Content{
				x: "3345",
			},
			TestMD5Content{
				x: "4456",
			},
			TestMD5Content{
				x: "5567",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{158, 85, 181, 191, 25, 250, 251, 71, 215, 22, 68, 68, 11, 198, 244, 148},
	},
}

func TestNewTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		if !table[i].defaultHashStrategy {
			continue
		}
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestNewTreeWithHashingStrategy(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_MerkleRoot(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_RebuildTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		err = tree.RebuildTree()
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error:  %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_RebuildTreeWith(t *testing.T) {
	for i := 0; i < len(table)-1; i++ {
		if table[i].hashStrategyName != table[i+1].hashStrategyName {
			continue
		}
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		err = tree.RebuildTreeWith(table[i+1].contents)
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i+1].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i+1].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_VerifyTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		v1, err := tree.VerifyTree()
		if err != nil {
			t.Fatal(err)
		}
		if v1 != true {
			t.Errorf("[case:%d] error: expected tree to be valid", table[i].testCaseId)
		}
		tree.Root.Hash = []byte{1}
		tree.merkleRoot = []byte{1}
		v2, err := tree.VerifyTree()
		if err != nil {
			t.Fatal(err)
		}
		if v2 != false {
			t.Errorf("[case:%d] error: expected tree to be invalid", table[i].testCaseId)
		}
	}
}

func TestMerkleTree_VerifyContent(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if len(table[i].contents) > 0 {
			v, err := tree.VerifyContent(table[i].contents[0])
			if err != nil {
				t.Fatal(err)
			}
			if !v {
				t.Errorf("[case:%d] error: expected valid content", table[i].testCaseId)
			}
		}
		if len(table[i].contents) > 1 {
			v, err := tree.VerifyContent(table[i].contents[1])
			if err != nil {
				t.Fatal(err)
			}
			if !v {
				t.Errorf("[case:%d] error: expected valid content", table[i].testCaseId)
			}
		}
		if len(table[i].contents) > 2 {
			v, err := tree.VerifyContent(table[i].contents[2])
			if err != nil {
				t.Fatal(err)
			}
			if !v {
				t.Errorf("[case:%d] error: expected valid content", table[i].testCaseId)
			}
		}
		if len(table[i].contents) > 0 {
			tree.Root.Hash = []byte{1}
			tree.merkleRoot = []byte{1}
			v, err := tree.VerifyContent(table[i].contents[0])
			if err != nil {
				t.Fatal(err)
			}
			if v {
				t.Errorf("[case:%d] error: expected invalid content", table[i].testCaseId)
			}
			if err := tree.RebuildTree(); err != nil {
				t.Fatal(err)
			}
		}
		v, err := tree.VerifyContent(table[i].notInContents)
		if err != nil {
			t.Fatal(err)
		}
		if v {
			t.Errorf("[case:%d] error: expected invalid content", table[i].testCaseId)
		}
	}
}

func TestMerkleTree_String(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if tree.String() == "" {
			t.Errorf("[case:%d] error: expected not empty string", table[i].testCaseId)
		}
	}
}

func TestMerkleTree_MerklePath(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		for j := 0; j < len(table[i].contents); j++ {
			merklePath, index, _ := tree.GetMerklePath(table[i].contents[j])

			hash, err := tree.Leafs[j].calculateNodeHash()
			if err != nil {
				t.Errorf("[case:%d] error: calculateNodeHash error: %v", table[i].testCaseId, err)
			}
			h := Generator()
			for k := 0; k < len(merklePath); k++ {
				if index[k] == 1 {
					hash = append(hash, merklePath[k]...)
				} else {
					hash = append(merklePath[k], hash...)
				}
				if _, err := h.Write(hash); err != nil {
					t.Errorf("[case:%d] error: Write error: %v", table[i].testCaseId, err)
				}
				hash, err = calHash(hash, table[i].hashStrategy)
				if err != nil {
					t.Errorf("[case:%d] error: calHash error: %v", table[i].testCaseId, err)
				}
			}
			if bytes.Compare(tree.MerkleRoot(), hash) != 0 {
				t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, hash, tree.MerkleRoot())
			}
		}
	}
}
