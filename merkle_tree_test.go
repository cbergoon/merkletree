// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"hash"
	"testing"
)

//TestSHA256Content implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestSHA256Content struct {
	x string
}

//CalculateHash hashes the values of a TestSHA256Content
func (t TestSHA256Content) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestSHA256Content) Equals(other Content) (bool, error) {
	return t.x == other.(TestSHA256Content).x, nil
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
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "Hello",
			},
			TestSHA256Content{
				x: "Hi",
			},
			TestSHA256Content{
				x: "Hey",
			},
			TestSHA256Content{
				x: "Hola",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{95, 48, 204, 128, 19, 59, 147, 148, 21, 110, 36, 178, 51, 240, 196, 190, 50, 178, 78, 68, 187, 51, 129, 240, 44, 123, 165, 38, 25, 208, 254, 188},
	},
	{
		testCaseId:          1,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "Hello",
			},
			TestSHA256Content{
				x: "Hi",
			},
			TestSHA256Content{
				x: "Hey",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{189, 214, 55, 197, 35, 237, 92, 14, 171, 121, 43, 152, 109, 177, 136, 80, 194, 57, 162, 226, 56, 2, 179, 106, 255, 38, 187, 104, 251, 63, 224, 8},
	},
	{
		testCaseId:          2,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "Hello",
			},
			TestSHA256Content{
				x: "Hi",
			},
			TestSHA256Content{
				x: "Hey",
			},
			TestSHA256Content{
				x: "Greetings",
			},
			TestSHA256Content{
				x: "Hola",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{46, 216, 115, 174, 13, 210, 55, 39, 119, 197, 122, 104, 93, 144, 112, 131, 202, 151, 41, 14, 80, 143, 21, 71, 140, 169, 139, 173, 50, 37, 235, 188},
	},
	{
		testCaseId:          3,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "123",
			},
			TestSHA256Content{
				x: "234",
			},
			TestSHA256Content{
				x: "345",
			},
			TestSHA256Content{
				x: "456",
			},
			TestSHA256Content{
				x: "1123",
			},
			TestSHA256Content{
				x: "2234",
			},
			TestSHA256Content{
				x: "3345",
			},
			TestSHA256Content{
				x: "4456",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{30, 76, 61, 40, 106, 173, 169, 183, 149, 2, 157, 246, 162, 218, 4, 70, 153, 148, 62, 162, 90, 24, 173, 250, 41, 149, 173, 121, 141, 187, 146, 43},
	},
	{
		testCaseId:          4,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "123",
			},
			TestSHA256Content{
				x: "234",
			},
			TestSHA256Content{
				x: "345",
			},
			TestSHA256Content{
				x: "456",
			},
			TestSHA256Content{
				x: "1123",
			},
			TestSHA256Content{
				x: "2234",
			},
			TestSHA256Content{
				x: "3345",
			},
			TestSHA256Content{
				x: "4456",
			},
			TestSHA256Content{
				x: "5567",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{143, 37, 161, 192, 69, 241, 248, 56, 169, 87, 79, 145, 37, 155, 51, 159, 209, 129, 164, 140, 130, 167, 16, 182, 133, 205, 126, 55, 237, 188, 89, 236},
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
			h := sha256.New()
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
