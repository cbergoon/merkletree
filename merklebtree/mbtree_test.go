package merklebtree

import (
	"strings"
	"testing"
)

func TestMBTreePut1(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item2{Key: 1, Value: 0})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	tree.Put(Item2{Key: 2, Value: 1})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	//replace root node
	tree.Put(Item2{Key: 1, Value: 3})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	//split root node
	tree.Put(Item2{Key: 3, Value: 6})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	//replace leaf node
	tree.Put(Item2{Key: 2, Value: 5})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	tree.Put(Item2{Key: 4, Value: 2})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	tree.Put(Item2{Key: 5, Value: 2})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	tree.Put(Item2{Key: 6, Value: 2})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

	tree.Put(Item2{Key: 7, Value: 2})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())
}

func TestMBTreePut2(t *testing.T) {
	const max = 1000
	orders := []int{3, 4, 5, 6, 7, 8, 9, 10, 20, 100, 500}
	for _, order := range orders {
		tree := NewWith(order)
		{
			for i := 1; i <= max; i++ {
				tree.Put(Item2{Key: i, Value: i})
				assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())
			}

		}
		{
			for i := max; i > 0; i-- {
				tree.Remove(Item2{Key: i})
				assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())
			}
		}
	}
}

func TestMBTreeRemove1(t *testing.T){
	tree := NewWith(3)
	tree.Put(Item2{Key: 1, Value: 0})
	tree.Put(Item2{Key: 2, Value: 1})
	tree.Put(Item2{Key: 1, Value: 3})
	tree.Put(Item2{Key: 3, Value: 6})
	tree.Put(Item2{Key: 2, Value: 5})
	tree.Put(Item2{Key: 4, Value: 2})
	tree.Put(Item2{Key: 5, Value: 2})
	tree.Put(Item2{Key: 6, Value: 2})
	assertValidMerkleRoot(t, tree.MerkleBTreeRoot(), tree.calculateMerkleRoot())

}

func assertValidMerkleRoot(t *testing.T, str1 string, str2 string) {
	if strings.Compare(str1, str2) != 0 {
		t.Errorf("Got %v expected %v for MerkleRoot", str1, str2)
	}
}