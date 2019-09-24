// Copyright (c) 2015, Emir Pasic. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package merklebtree

import (
	"fmt"
	"testing"
)

// Int implements the Item interface for integers.
type Item struct {
	key   int
	value string
}

type Item2 struct {
	key   int
	value int
}

type Item3 struct {
	key   int
	value interface{}
}

type TestData struct {
	Item
	result bool
}

// IntComparator provides a basic comparison on int
func (a Item) Comparator(b Content) int {
	bAsserted := b.(Item)
	switch {
	case a.key > bAsserted.key:
		return 1
	case a.key < bAsserted.key:
		return -1
	default:
		return 0
	}
}

// IntComparator provides a basic comparison on int
func (a Item2) Comparator(b Content) int {
	bAsserted := b.(Item2)
	switch {
	case a.key > bAsserted.key:
		return 1
	case a.key < bAsserted.key:
		return -1
	default:
		return 0
	}
}

// IntComparator provides a basic comparison on int
func (a Item3) Comparator(b Content) int {
	bAsserted := b.(Item3)
	switch {
	case a.key > bAsserted.key:
		return 1
	case a.key < bAsserted.key:
		return -1
	default:
		return 0
	}
}

func TestBTreeGet1(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 4, value: "d"})
	tree.Put(Item{key: 5, value: "e"})
	tree.Put(Item{key: 6, value: "f"})
	tree.Put(Item{key: 7, value: "g"})

	tests := [][]interface{}{
		{0, "", false},
		{1, "a", true},
		{2, "b", true},
		{3, "c", true},
		{4, "d", true},
		{5, "e", true},
		{6, "f", true},
		{7, "g", true},
		{8, "", false},
	}
	//
	for _, test := range tests {
		item, found := tree.Get(Item{key: test[0].(int), value: test[1].(string)})
		if item.(Item).value != test[1] || found != test[2] {
			t.Errorf("Got %v,%v expected %v,%v", item.(Item).value, found, test[1], test[2])
		}
	}
}

//
func TestBTreeGet2(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 7, value: "g"})
	tree.Put(Item{key: 9, value: "i"})
	tree.Put(Item{key: 10, value: "j"})
	tree.Put(Item{key: 6, value: "f"})
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 4, value: "d"})
	tree.Put(Item{key: 5, value: "e"})
	tree.Put(Item{key: 8, value: "h"})
	tree.Put(Item{key: 2, value: "b"})
	tree.Put(Item{key: 1, value: "a"})

	tests := [][]interface{}{
		{0, "", false},
		{1, "a", true},
		{2, "b", true},
		{3, "c", true},
		{4, "d", true},
		{5, "e", true},
		{6, "f", true},
		{7, "g", true},
		{8, "h", true},
		{9, "i", true},
		{10, "j", true},
		{11, "", false},
	}

	for _, test := range tests {
		if value, found := tree.Get(Item{key: test[0].(int), value: test[1].(string)}); value.(Item).value != test[1] || found != test[2] {
			t.Errorf("Got %v,%v expected %v,%v", value, found, test[1], test[2])
		}
	}
}

//
func TestBTreePut1(t *testing.T) {
	// https://upload.wikimedia.org/wikipedia/commons/3/33/B_tree_insertion_example.png
	tree := NewWith(3)
	assertValidTree(t, tree, 0)

	tree.Put(Item2{key: 1, value: 0})
	assertValidTree(t, tree, 1)
	assertValidTreeNode(t, tree.Root, 1, 0, []int{1}, false)

	tree.Put(Item2{key: 2, value: 1})
	assertValidTree(t, tree, 2)
	assertValidTreeNode(t, tree.Root, 2, 0, []int{1, 2}, false)

	tree.Put(Item2{key: 3, value: 2})
	assertValidTree(t, tree, 3)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{2}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{1}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{3}, true)

	tree.Put(Item2{key: 4, value: 2})
	assertValidTree(t, tree, 4)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{2}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{1}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 2, 0, []int{3, 4}, true)
	//
	tree.Put(Item2{key: 5, value: 2})
	assertValidTree(t, tree, 5)
	assertValidTreeNode(t, tree.Root, 2, 3, []int{2, 4}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{1}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{3}, true)
	assertValidTreeNode(t, tree.Root.Children[2], 1, 0, []int{5}, true)

	tree.Put(Item2{key: 6, value: 2})
	assertValidTree(t, tree, 6)
	assertValidTreeNode(t, tree.Root, 2, 3, []int{2, 4}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{1}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{3}, true)
	assertValidTreeNode(t, tree.Root.Children[2], 2, 0, []int{5, 6}, true)

	tree.Put(Item2{key: 7, value: 2})
	assertValidTree(t, tree, 7)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{4}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{2}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{6}, true)
	assertValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{1}, true)
	assertValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{3}, true)
	assertValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{5}, true)
	assertValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{7}, true)
}

func TestBTreePut2(t *testing.T) {
	tree := NewWith(4)
	assertValidTree(t, tree, 0)

	tree.Put(Item2{key: 0, value: 0})
	assertValidTree(t, tree, 1)
	assertValidTreeNode(t, tree.Root, 1, 0, []int{0}, false)

	tree.Put(Item2{key: 2, value: 2})
	assertValidTree(t, tree, 2)
	assertValidTreeNode(t, tree.Root, 2, 0, []int{0, 2}, false)

	tree.Put(Item2{key: 1, value: 1})
	assertValidTree(t, tree, 3)
	assertValidTreeNode(t, tree.Root, 3, 0, []int{0, 1, 2}, false)

	tree.Put(Item2{key: 1, value: 1})
	assertValidTree(t, tree, 3)
	assertValidTreeNode(t, tree.Root, 3, 0, []int{0, 1, 2}, false)

	tree.Put(Item2{key: 3, value: 3})
	assertValidTree(t, tree, 4)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{1}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{0}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 2, 0, []int{2, 3}, true)

	tree.Put(Item2{key: 4, value: 4})
	assertValidTree(t, tree, 5)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{1}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{0}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 3, 0, []int{2, 3, 4}, true)

	tree.Put(Item2{key: 5, value: 5})
	assertValidTree(t, tree, 6)
	assertValidTreeNode(t, tree.Root, 2, 3, []int{1, 3}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{0}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{2}, true)
	assertValidTreeNode(t, tree.Root.Children[2], 2, 0, []int{4, 5}, true)
}

//
func TestBTreePut3(t *testing.T) {
	// http://www.geeksforgeeks.org/b-tree-set-1-insert-2/
	tree := NewWith(6)
	assertValidTree(t, tree, 0)

	tree.Put(Item2{key: 10, value: 0})
	assertValidTree(t, tree, 1)
	assertValidTreeNode(t, tree.Root, 1, 0, []int{10}, false)

	tree.Put(Item2{key: 20, value: 1})
	assertValidTree(t, tree, 2)
	assertValidTreeNode(t, tree.Root, 2, 0, []int{10, 20}, false)

	tree.Put(Item2{key: 30, value: 2})
	assertValidTree(t, tree, 3)
	assertValidTreeNode(t, tree.Root, 3, 0, []int{10, 20, 30}, false)

	tree.Put(Item2{key: 40, value: 3})
	assertValidTree(t, tree, 4)
	assertValidTreeNode(t, tree.Root, 4, 0, []int{10, 20, 30, 40}, false)

	tree.Put(Item2{key: 50, value: 4})
	assertValidTree(t, tree, 5)
	assertValidTreeNode(t, tree.Root, 5, 0, []int{10, 20, 30, 40, 50}, false)

	tree.Put(Item2{key: 60, value: 5})
	assertValidTree(t, tree, 6)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{30}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{10, 20}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 3, 0, []int{40, 50, 60}, true)

	tree.Put(Item2{key: 70, value: 6})
	assertValidTree(t, tree, 7)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{30}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{10, 20}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 4, 0, []int{40, 50, 60, 70}, true)

	tree.Put(Item2{key: 80, value: 7})
	assertValidTree(t, tree, 8)
	assertValidTreeNode(t, tree.Root, 1, 2, []int{30}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{10, 20}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 5, 0, []int{40, 50, 60, 70, 80}, true)

	tree.Put(Item2{key: 90, value: 8})
	assertValidTree(t, tree, 9)
	assertValidTreeNode(t, tree.Root, 2, 3, []int{30, 60}, false)
	assertValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{10, 20}, true)
	assertValidTreeNode(t, tree.Root.Children[1], 2, 0, []int{40, 50}, true)
	assertValidTreeNode(t, tree.Root.Children[2], 3, 0, []int{70, 80, 90}, true)
}

//
func TestBTreePut4(t *testing.T) {
	tree := NewWith(3)
	assertValidTree(t, tree, 0)

	tree.Put(Item3{key: 6, value: nil})
	assertValidTree(t, tree, 1)
	assertItem3ValidTreeNode(t, tree.Root, 1, 0, []int{6}, false)

	tree.Put(Item3{key: 5, value: nil})
	assertValidTree(t, tree, 2)
	assertItem3ValidTreeNode(t, tree.Root, 2, 0, []int{5, 6}, false)
	//
	tree.Put(Item3{key: 4, value: nil})
	assertValidTree(t, tree, 3)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{5}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{6}, true)
	//
	tree.Put(Item3{key: 3, value: nil})
	assertValidTree(t, tree, 4)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{5}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{3, 4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{6}, true)
	//
	tree.Put(Item3{key: 2, value: nil})
	assertValidTree(t, tree, 5)
	assertItem3ValidTreeNode(t, tree.Root, 2, 3, []int{3, 5}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2], 1, 0, []int{6}, true)

	tree.Put(Item3{key: 1, value: nil})
	assertValidTree(t, tree, 6)
	assertItem3ValidTreeNode(t, tree.Root, 2, 3, []int{3, 5}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{1, 2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2], 1, 0, []int{6}, true)

	tree.Put(Item3{key: 0, value: nil})
	assertValidTree(t, tree, 7)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{3}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{0}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{6}, true)

	tree.Put(Item3{key: -1, value: nil})
	assertValidTree(t, tree, 8)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{3}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 2, 0, []int{-1, 0}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{6}, true)

	tree.Put(Item3{key: -2, value: nil})
	assertValidTree(t, tree, 9)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{3}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 3, []int{-1, 1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{-2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{0}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[2], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{6}, true)

	tree.Put(Item3{key: -3, value: nil})
	assertValidTree(t, tree, 10)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{3}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 3, []int{-1, 1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 2, 0, []int{-3, -2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{0}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[2], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{6}, true)

	tree.Put(Item3{key: -4, value: nil})
	assertValidTree(t, tree, 11)
	assertItem3ValidTreeNode(t, tree.Root, 2, 3, []int{-1, 3}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{-3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2], 1, 2, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{-4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{-2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{0}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2].Children[0], 1, 0, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2].Children[1], 1, 0, []int{6}, true)
}

//
func TestBTreeRemove1(t *testing.T) {
	// empty
	tree := NewWith(3)
	tree.Remove(Item{key: 1})
	assertValidTree(t, tree, 0)
}

func TestBTreeRemove2(t *testing.T) {
	// leaf node (no underflow)
	tree := NewWith(3)
	tree.Put(Item3{key: 1, value: nil})
	tree.Put(Item3{key: 2, value: nil})

	tree.Remove(Item3{key: 1})
	assertValidTree(t, tree, 1)
	assertItem3ValidTreeNode(t, tree.Root, 1, 0, []int{2}, false)

	tree.Remove(Item3{key: 2})
	assertValidTree(t, tree, 0)
}

func TestBTreeRemove3(t *testing.T) {
	// merge with right (underflow)
	{
		tree := NewWith(3)
		tree.Put(Item3{key: 1, value: nil})
		tree.Put(Item3{key: 2, value: nil})
		tree.Put(Item3{key: 3, value: nil})

		tree.Remove(Item3{key: 1})
		assertValidTree(t, tree, 2)
		assertItem3ValidTreeNode(t, tree.Root, 2, 0, []int{2, 3}, false)
	}
	// merge with left (underflow)
	{
		tree := NewWith(3)
		tree.Put(Item3{key: 1, value: nil})
		tree.Put(Item3{key: 2, value: nil})
		tree.Put(Item3{key: 3, value: nil})

		tree.Remove(Item3{key: 3})
		assertValidTree(t, tree, 2)
		assertItem3ValidTreeNode(t, tree.Root, 2, 0, []int{1, 2}, false)
	}
}

func TestBTreeRemove4(t *testing.T) {
	// rotate left (underflow)
	tree := NewWith(3)
	tree.Put(Item3{key: 1, value: nil})
	tree.Put(Item3{key: 2, value: nil})
	tree.Put(Item3{key: 3, value: nil})
	tree.Put(Item3{key: 4, value: nil})

	assertValidTree(t, tree, 4)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{2}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 2, 0, []int{3, 4}, true)

	tree.Remove(Item3{key: 1})
	assertValidTree(t, tree, 3)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{3}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{4}, true)
}

func TestBTreeRemove5(t *testing.T) {
	// rotate right (underflow)
	tree := NewWith(3)
	tree.Put(Item3{key: 1, value: nil})
	tree.Put(Item3{key: 2, value: nil})
	tree.Put(Item3{key: 3, value: nil})
	tree.Put(Item3{key: 0, value: nil})

	assertValidTree(t, tree, 4)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{2}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{0, 1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{3}, true)

	tree.Remove(Item3{key: 3})
	assertValidTree(t, tree, 3)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{1}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{0}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{2}, true)
}

func TestBTreeRemove6(t *testing.T) {
	// root height reduction after a series of underflows on right side
	// use simulator: https://www.cs.usfca.edu/~galles/visualization/BTree.html
	tree := NewWith(3)
	tree.Put(Item3{key: 1, value: nil})
	tree.Put(Item3{key: 2, value: nil})
	tree.Put(Item3{key: 3, value: nil})
	tree.Put(Item3{key: 4, value: nil})
	tree.Put(Item3{key: 5, value: nil})
	tree.Put(Item3{key: 6, value: nil})
	tree.Put(Item3{key: 7, value: nil})

	assertValidTree(t, tree, 7)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{4}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{6}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{7}, true)

	tree.Remove(Item3{key: 7})
	assertValidTree(t, tree, 6)
	assertItem3ValidTreeNode(t, tree.Root, 2, 3, []int{2, 4}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2], 2, 0, []int{5, 6}, true)
}

//
func TestBTreeRemove7(t *testing.T) {
	// root height reduction after a series of underflows on left side
	// use simulator: https://www.cs.usfca.edu/~galles/visualization/BTree.html
	tree := NewWith(3)
	tree.Put(Item3{key: 1, value: nil})
	tree.Put(Item3{key: 2, value: nil})
	tree.Put(Item3{key: 3, value: nil})
	tree.Put(Item3{key: 4, value: nil})
	tree.Put(Item3{key: 5, value: nil})
	tree.Put(Item3{key: 6, value: nil})
	tree.Put(Item3{key: 7, value: nil})

	assertValidTree(t, tree, 7)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{4}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{6}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{7}, true)

	tree.Remove(Item3{key: 1}) // series of underflows
	assertValidTree(t, tree, 6)
	assertItem3ValidTreeNode(t, tree.Root, 2, 3, []int{4, 6}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{2, 3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2], 1, 0, []int{7}, true)

	// clear all remaining
	tree.Remove(Item3{key: 2})
	assertValidTree(t, tree, 5)
	assertItem3ValidTreeNode(t, tree.Root, 2, 3, []int{4, 6}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[2], 1, 0, []int{7}, true)

	tree.Remove(Item3{key: 3})
	assertValidTree(t, tree, 4)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{6}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 2, 0, []int{4, 5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{7}, true)

	tree.Remove(Item3{key: 4})
	assertValidTree(t, tree, 3)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{6}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 0, []int{7}, true)

	tree.Remove(Item3{key: 5})
	assertValidTree(t, tree, 2)
	assertItem3ValidTreeNode(t, tree.Root, 2, 0, []int{6, 7}, false)

	tree.Remove(Item3{key: 6})
	assertValidTree(t, tree, 1)
	assertItem3ValidTreeNode(t, tree.Root, 1, 0, []int{7}, false)

	tree.Remove(Item3{key: 7})
	assertValidTree(t, tree, 0)
}

//
func TestBTreeRemove8(t *testing.T) {
	// use simulator: https://www.cs.usfca.edu/~galles/visualization/BTree.html
	tree := NewWith(3)
	tree.Put(Item3{key: 1, value: nil})
	tree.Put(Item3{key: 2, value: nil})
	tree.Put(Item3{key: 3, value: nil})
	tree.Put(Item3{key: 4, value: nil})
	tree.Put(Item3{key: 5, value: nil})
	tree.Put(Item3{key: 6, value: nil})
	tree.Put(Item3{key: 7, value: nil})
	tree.Put(Item3{key: 8, value: nil})
	tree.Put(Item3{key: 9, value: nil})

	assertValidTree(t, tree, 9)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{4}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{2}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 2, 3, []int{6, 8}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 1, 0, []int{1}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{7}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[2], 1, 0, []int{9}, true)

	tree.Remove(Item3{key: 1})
	assertValidTree(t, tree, 8)
	assertItem3ValidTreeNode(t, tree.Root, 1, 2, []int{6}, false)
	assertItem3ValidTreeNode(t, tree.Root.Children[0], 1, 2, []int{4}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1], 1, 2, []int{8}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[0], 2, 0, []int{2, 3}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[0].Children[1], 1, 0, []int{5}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[0], 1, 0, []int{7}, true)
	assertItem3ValidTreeNode(t, tree.Root.Children[1].Children[1], 1, 0, []int{9}, true)
}

func TestBTreeRemove9(t *testing.T) {
	const max = 1000
	orders := []int{3, 4, 5, 6, 7, 8, 9, 10, 20, 100, 500, 1000, 5000, 10000}
	for _, order := range orders {

		tree := NewWith(order)

		{
			for i := 1; i <= max; i++ {
				tree.Put(Item2{key: i, value: i})
			}
			assertValidTree(t, tree, max)

			for i := 1; i <= max; i++ {
				if _, found := tree.Get(Item2{key: i}); !found {
					t.Errorf("Not found %v", i)
				}
			}

			for i := 1; i <= max; i++ {
				tree.Remove(Item2{key: i})
			}
			assertValidTree(t, tree, 0)
		}

		{
			for i := max; i > 0; i-- {
				tree.Put(Item2{key: i, value: i})
			}
			assertValidTree(t, tree, max)

			for i := max; i > 0; i-- {
				if _, found := tree.Get(Item2{key: i}); !found {
					t.Errorf("Not found %v", i)
				}
			}

			for i := max; i > 0; i-- {
				tree.Remove(Item2{key: i})
			}
			assertValidTree(t, tree, 0)
		}
	}
}

func TestBTreeHeight(t *testing.T) {
	tree := NewWith(3)
	if actualValue, expectedValue := tree.Height(), 0; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 1, value: 0})
	if actualValue, expectedValue := tree.Height(), 1; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 2, value: 1})
	if actualValue, expectedValue := tree.Height(), 1; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 3, value: 2})
	if actualValue, expectedValue := tree.Height(), 2; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 4, value: 2})
	if actualValue, expectedValue := tree.Height(), 2; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 5, value: 2})
	if actualValue, expectedValue := tree.Height(), 2; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 6, value: 2})
	if actualValue, expectedValue := tree.Height(), 2; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Put(Item2{key: 7, value: 2})
	if actualValue, expectedValue := tree.Height(), 3; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	tree.Remove(Item2{key: 1})
	tree.Remove(Item2{key: 2})
	tree.Remove(Item2{key: 3})
	tree.Remove(Item2{key: 4})
	tree.Remove(Item2{key: 5})
	tree.Remove(Item2{key: 6})
	tree.Remove(Item2{key: 7})
	if actualValue, expectedValue := tree.Height(), 0; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeLeftAndRight(t *testing.T) {
	tree := NewWith(3)

	if actualValue := tree.Left(); actualValue != nil {
		t.Errorf("Got %v expected %v", actualValue, nil)
	}
	if actualValue := tree.Right(); actualValue != nil {
		t.Errorf("Got %v expected %v", actualValue, nil)
	}

	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 5, value: "e"})
	tree.Put(Item{key: 6, value: "f"})
	tree.Put(Item{key: 7, value: "g"})
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 4, value: "d"})
	tree.Put(Item{key: 1, value: "x"}) // overwrite
	tree.Put(Item{key: 2, value: "b"})

	if actualValue, expectedValue := tree.LeftItem(), 1; actualValue.(Item).key != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
	if actualValue, expectedValue := tree.LeftItem(), "x"; actualValue.(Item).value != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}

	if actualValue, expectedValue := tree.RightItem(), 7; actualValue.(Item).key != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
	if actualValue, expectedValue := tree.RightItem(), "g"; actualValue.(Item).value != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIteratorValuesAndKeys(t *testing.T) {
	tree := NewWith(4)
	tree.Put(Item{key: 4, value: "d"})
	tree.Put(Item{key: 5, value: "e"})
	tree.Put(Item{key: 6, value: "f"})
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 7, value: "g"})
	tree.Put(Item{key: 2, value: "b"})
	tree.Put(Item{key: 1, value: "x"}) // override

	contents := tree.Contents()
	var keys []interface{}
	var values []interface{}
	for _, content := range contents {
		keys = append(keys, content.(Item).key)
		values = append(values, content.(Item).value)
	}

	if actualValue, expectedValue := fmt.Sprintf("%d%d%d%d%d%d%d", keys...), "1234567"; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
	if actualValue, expectedValue := fmt.Sprintf("%s%s%s%s%s%s%s", values...), "xbcdefg"; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
	if actualValue := tree.Size(); actualValue != 7 {
		t.Errorf("Got %v expected %v", actualValue, 7)
	}
}

func TestBTreeIteratorNextOnEmpty(t *testing.T) {
	tree := NewWith(3)
	it := tree.Iterator()
	for it.Next() {
		t.Errorf("Shouldn't iterate on empty tree")
	}
}

//
func TestBTreeIteratorPrevOnEmpty(t *testing.T) {
	tree := NewWith(3)
	it := tree.Iterator()
	for it.Prev() {
		t.Errorf("Shouldn't iterate on empty tree")
	}
}

func TestBTreeIterator1Next(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 5, value: "e"})
	tree.Put(Item{key: 6, value: "f"})
	tree.Put(Item{key: 7, value: "g"})
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 4, value: "d"})
	tree.Put(Item{key: 1, value: "x"})
	tree.Put(Item{key: 2, value: "b"})
	tree.Put(Item{key: 1, value: "a"}) //overwrite
	it := tree.Iterator()
	count := 0
	for it.Next() {
		count++
		key := it.Item().(Item).key
		switch key {
		case count:
			if actualValue, expectedValue := key, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := key, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
	}
	if actualValue, expectedValue := count, tree.Size(); actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

//
func TestBTreeIterator1Prev(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 5, value: "e"})
	tree.Put(Item{key: 6, value: "f"})
	tree.Put(Item{key: 7, value: "g"})
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 4, value: "d"})
	tree.Put(Item{key: 1, value: "x"})
	tree.Put(Item{key: 2, value: "b"})
	tree.Put(Item{key: 1, value: "a"}) //overwrite
	it := tree.Iterator()
	for it.Next() {
	}
	countDown := tree.size
	for it.Prev() {
		key := it.Item().(Item).key
		switch key {
		case countDown:
			if actualValue, expectedValue := key, countDown; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := key, countDown; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
		countDown--
	}
	if actualValue, expectedValue := countDown, 0; actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIterator2Next(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	it := tree.Iterator()
	count := 0
	for it.Next() {
		count++
		key := it.Item().(Item).key
		switch key {
		case count:
			if actualValue, expectedValue := key, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := key, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
	}
	if actualValue, expectedValue := count, tree.Size(); actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

//
func TestBTreeIterator2Prev(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	it := tree.Iterator()
	for it.Next() {
	}
	countDown := tree.size
	for it.Prev() {
		key := it.Item().(Item).key
		switch key {
		case countDown:
			if actualValue, expectedValue := key, countDown; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := key, countDown; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
		countDown--
	}
	if actualValue, expectedValue := countDown, 0; actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIterator3Next(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 1, value: "a"})
	it := tree.Iterator()
	count := 0
	for it.Next() {
		count++
		key := it.Item().(Item).key
		switch key {
		case count:
			if actualValue, expectedValue := key, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := key, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
	}
	if actualValue, expectedValue := count, tree.Size(); actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIterator3Prev(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 1, value: "a"})
	it := tree.Iterator()
	for it.Next() {
	}
	countDown := tree.size
	for it.Prev() {
		key := it.Item().(Item).key
		switch key {
		case countDown:
			if actualValue, expectedValue := key, countDown; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := key, countDown; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
		countDown--
	}
	if actualValue, expectedValue := countDown, 0; actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIterator4Next(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item2{key: 13, value: 5})
	tree.Put(Item2{key: 8, value: 3})
	tree.Put(Item2{key: 17, value: 7})
	tree.Put(Item2{key: 1, value: 1})
	tree.Put(Item2{key: 11, value: 4})
	tree.Put(Item2{key: 15, value: 6})
	tree.Put(Item2{key: 25, value: 9})
	tree.Put(Item2{key: 6, value: 2})
	tree.Put(Item2{key: 22, value: 8})
	tree.Put(Item2{key: 27, value: 10})
	it := tree.Iterator()
	count := 0
	for it.Next() {
		count++
		value := it.Item().(Item2).value
		switch value {
		case count:
			if actualValue, expectedValue := value, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := value, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
	}
	if actualValue, expectedValue := count, tree.Size(); actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIterator4Prev(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item2{key: 13, value: 5})
	tree.Put(Item2{key: 8, value: 3})
	tree.Put(Item2{key: 17, value: 7})
	tree.Put(Item2{key: 1, value: 1})
	tree.Put(Item2{key: 11, value: 4})
	tree.Put(Item2{key: 15, value: 6})
	tree.Put(Item2{key: 25, value: 9})
	tree.Put(Item2{key: 6, value: 2})
	tree.Put(Item2{key: 22, value: 8})
	tree.Put(Item2{key: 27, value: 10})
	it := tree.Iterator()
	count := tree.Size()
	for it.Next() {
	}
	for it.Prev() {
		value := it.Item().(Item2).value
		switch value {
		case count:
			if actualValue, expectedValue := value, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		default:
			if actualValue, expectedValue := value, count; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
		count--
	}
	if actualValue, expectedValue := count, 0; actualValue != expectedValue {
		t.Errorf("Size different. Got %v expected %v", actualValue, expectedValue)
	}
}

func TestBTreeIteratorBegin(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	it := tree.Iterator()

	if it.node != nil {
		t.Errorf("Got %v expected %v", it.node, nil)
	}

	it.Begin()

	if it.node != nil {
		t.Errorf("Got %v expected %v", it.node, nil)
	}

	for it.Next() {
	}

	it.Begin()

	if it.node != nil {
		t.Errorf("Got %v expected %v", it.node, nil)
	}

	it.Next()
	if key, value := it.Item().(Item).key, it.Item().(Item).value; key != 1 || value != "a" {
		t.Errorf("Got %v,%v expected %v,%v", key, value, 1, "a")
	}
}

func TestBTreeIteratorEnd(t *testing.T) {
	tree := NewWith(3)
	it := tree.Iterator()

	if it.node != nil {
		t.Errorf("Got %v expected %v", it.node, nil)
	}

	it.End()
	if it.node != nil {
		t.Errorf("Got %v expected %v", it.node, nil)
	}

	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	it.End()
	if it.node != nil {
		t.Errorf("Got %v expected %v", it.node, nil)
	}

	it.Prev()
	if key, value := it.Item().(Item).key, it.Item().(Item).value; key != 3 || value != "c" {
		t.Errorf("Got %v,%v expected %v,%v", key, value, 3, "c")
	}
}

//
func TestBTreeIteratorFirst(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	it := tree.Iterator()
	if actualValue, expectedValue := it.First(), true; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
	if key, value := it.Item().(Item).key, it.Item().(Item).value; key != 1 || value != "a" {
		t.Errorf("Got %v,%v expected %v,%v", key, value, 1, "a")
	}
}

func TestBTreeIteratorLast(t *testing.T) {
	tree := NewWith(3)
	tree.Put(Item{key: 3, value: "c"})
	tree.Put(Item{key: 1, value: "a"})
	tree.Put(Item{key: 2, value: "b"})
	it := tree.Iterator()
	if actualValue, expectedValue := it.Last(), true; actualValue != expectedValue {
		t.Errorf("Got %v expected %v", actualValue, expectedValue)
	}
	if key, value := it.Item().(Item).key, it.Item().(Item).value; key != 3 || value != "c" {
		t.Errorf("Got %v,%v expected %v,%v", key, value, 3, "c")
	}
}

//
func TestBTree_search(t *testing.T) {
	{
		tree := NewWith(3)
		tree.Root = &Node{Contents: []*Content{}, Children: make([]*Node, 0)}
		tests := [][]interface{}{
			{0, 0, false},
		}
		for _, test := range tests {
			index, found := tree.search(tree.Root, Item3{key: test[0].(int)})
			if actualValue, expectedValue := index, test[1]; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
			if actualValue, expectedValue := found, test[2]; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
	}
	{
		tree := NewWith(3)
		var node Node
		node.Put(Item2{key: 2, value: 0})
		node.Put(Item2{key: 4, value: 1})
		node.Put(Item2{key: 6, value: 2})
		node.Children = []*Node{}
		tree.Root = &node
		tests := [][]interface{}{
			{0, 0, false},
			{1, 0, false},
			{2, 0, true},
			{3, 1, false},
			{4, 1, true},
			{5, 2, false},
			{6, 2, true},
			{7, 3, false},
		}
		for _, test := range tests {
			index, found := tree.search(tree.Root, Item2{key: test[0].(int)})
			if actualValue, expectedValue := index, test[1].(int); actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
			if actualValue, expectedValue := found, test[2]; actualValue != expectedValue {
				t.Errorf("Got %v expected %v", actualValue, expectedValue)
			}
		}
	}
}

func assertValidTree(t *testing.T, tree *Tree, expectedSize int) {
	if actualValue, expectedValue := tree.size, expectedSize; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for tree size", actualValue, expectedValue)
	}
}

//
func assertValidTreeNode(t *testing.T, node *Node, expectedContents int, expectedChildren int, keys []int, hasParent bool) {
	if actualValue, expectedValue := node.Parent != nil, hasParent; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for hasParent", actualValue, expectedValue)
	}
	if actualValue, expectedValue := len(node.Contents), expectedContents; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for contents size", actualValue, expectedValue)
	}
	if actualValue, expectedValue := len(node.Children), expectedChildren; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for children size", actualValue, expectedValue)
	}
	for i, key := range keys {
		if actualValue, expectedValue := (*node.Contents[i]).(Item2).key, key; actualValue != expectedValue {
			t.Errorf("Got %v expected %v for key", actualValue, expectedValue)
		}
	}
}

func assertItem3ValidTreeNode(t *testing.T, node *Node, expectedContents int, expectedChildren int, keys []int, hasParent bool) {
	if actualValue, expectedValue := node.Parent != nil, hasParent; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for hasParent", actualValue, expectedValue)
	}
	if actualValue, expectedValue := len(node.Contents), expectedContents; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for contents size", actualValue, expectedValue)
	}
	if actualValue, expectedValue := len(node.Children), expectedChildren; actualValue != expectedValue {
		t.Errorf("Got %v expected %v for children size", actualValue, expectedValue)
	}
	for i, key := range keys {
		if actualValue, expectedValue := (*node.Contents[i]).(Item3).key, key; actualValue != expectedValue {
			t.Errorf("Got %v expected %v for key", actualValue, expectedValue)
		}
	}
}

func benchmarkGet(b *testing.B, tree *Tree, size int) {
	for i := 0; i < b.N; i++ {
		for n := 0; n < size; n++ {
			tree.Get(Item3{key: n})
		}
	}
}

func benchmarkPut(b *testing.B, tree *Tree, size int) {
	for i := 0; i < b.N; i++ {
		for n := 0; n < size; n++ {
			tree.Put(Item3{key: n, value: struct{}{}})
		}
	}
}

//
func benchmarkRemove(b *testing.B, tree *Tree, size int) {
	for i := 0; i < b.N; i++ {
		for n := 0; n < size; n++ {
			tree.Remove(Item3{key: n})
		}
	}
}

func BenchmarkBTreeGet100(b *testing.B) {
	b.StopTimer()
	size := 100
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkGet(b, tree, size)
}

func BenchmarkBTreeGet1000(b *testing.B) {
	b.StopTimer()
	size := 1000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkGet(b, tree, size)
}

func BenchmarkBTreeGet10000(b *testing.B) {
	b.StopTimer()
	size := 10000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkGet(b, tree, size)
}

//
func BenchmarkBTreeGet100000(b *testing.B) {
	b.StopTimer()
	size := 100000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkGet(b, tree, size)
}

func BenchmarkBTreePut100(b *testing.B) {
	b.StopTimer()
	size := 100
	tree := NewWith(128)
	b.StartTimer()
	benchmarkPut(b, tree, size)
}

func BenchmarkBTreePut1000(b *testing.B) {
	b.StopTimer()
	size := 1000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkPut(b, tree, size)
}

//
func BenchmarkBTreePut10000(b *testing.B) {
	b.StopTimer()
	size := 10000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkPut(b, tree, size)
}

//
func BenchmarkBTreePut100000(b *testing.B) {
	b.StopTimer()
	size := 100000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkPut(b, tree, size)
}

func BenchmarkBTreeRemove100(b *testing.B) {
	b.StopTimer()
	size := 100
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkRemove(b, tree, size)
}

//
func BenchmarkBTreeRemove1000(b *testing.B) {
	b.StopTimer()
	size := 1000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkRemove(b, tree, size)
}

//
func BenchmarkBTreeRemove10000(b *testing.B) {
	b.StopTimer()
	size := 10000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkRemove(b, tree, size)
}

func BenchmarkBTreeRemove100000(b *testing.B) {
	b.StopTimer()
	size := 100000
	tree := NewWith(128)
	for n := 0; n < size; n++ {
		tree.Put(Item3{key: n, value: struct{}{}})
	}
	b.StartTimer()
	benchmarkRemove(b, tree, size)
}
