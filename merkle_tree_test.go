package merkletree

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/zeebo/errs"
)

//TestKeccak256Content implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestKeccak256Content struct {
	x string
}

//CalculateHash hashes the values of a TestKeccak256Content
func (t TestKeccak256Content) CalculateHash() ([]byte, error) {
	walletAddress := strings.ToLower(t.x[2:])

	if !common.IsHexAddress(walletAddress) {
		return nil, errs.New("%v - is not address", t.x)
	}

	bytes, err := hex.DecodeString(walletAddress)
	if err != nil {
		return nil, err
	}

	return crypto.Keccak256(bytes), nil
}

//Equals tests for equality of two Contents
func (t TestKeccak256Content) Equals(other Content) (bool, error) {
	return t.x == other.(TestKeccak256Content).x, nil
}

var table = []struct {
	contents     []Content
	expectedHash string
	proofs       []string
}{
	{
		contents: []Content{
			TestKeccak256Content{
				x: "0x5EE3e1B1484d415B194974ea2Be6A632D02Ce15D",
			},
			TestKeccak256Content{
				x: "0x8894bC144F9C6EDd3ac938a38A437E4af4868934",
			},
			TestKeccak256Content{
				x: "0xfaBcb77c3B2429076a59BA1Ea7f0ad0Df3Aa736C",
			},
			TestKeccak256Content{
				x: "0x5b8a63F0C21bC4B3c9a5A422f05325809E04b890",
			},
		},
		expectedHash: "66f61f0c29aec6db7edec8deb827feec5a5d12f414e485c02bc754e0c4d72a49",
		proofs: []string{
			"6b6b244df3a1069765b46c12cf07b6fcd277987d36de896b64c8073becec9906",
			"644c20bfb2e9937f761d46fe9740867d4e7fc7afa8d5efd4fe41e4574dab8d84",
		},
	},
}

func TestNewTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Errorf("error: unexpected error: %v", err)
		}

		mr := tree.merkleRoot
		hexMr := hex.EncodeToString(mr)

		if hexMr != table[i].expectedHash {
			t.Errorf("error: expected hash equal to %v got %v", table[i].expectedHash, tree.merkleRoot)
		}
	}
}

func TestMerkleTree_MerkleRoot(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Errorf("error: unexpected error: %v", err)
		}

		mr := tree.merkleRoot
		hexMr := hex.EncodeToString(mr)

		if hexMr != table[i].expectedHash {
			t.Errorf("error: expected hash equal to %v got %v", table[i].expectedHash, tree.merkleRoot)
		}
	}
}

func TestMerkleTree_MerklePath(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Errorf("error: unexpected error: %v", err)
		}

		merklePath, _, err := tree.GetMerklePath(table[i].contents[3])
		if err != nil {
			t.Errorf("error: calculateNodeHash error: %v", err)
		}
		for k, v := range merklePath {
			hexMr := hex.EncodeToString(v)

			if hexMr != table[i].proofs[k] {
				t.Errorf("error: expected hash equal to %v got %v", hexMr, table[i].proofs[k])
			}
		}
	}
}
