<h1 align="center">Merkle Tree in Golang</h1>
<p align="center">
<a href="https://travis-ci.org/cbergoon/merkletree"><img src="https://travis-ci.org/cbergoon/merkletree.svg?branch=master" alt="Build"></a>
<a href="https://goreportcard.com/report/github.com/cbergoon/merkletree"><img src="https://goreportcard.com/badge/github.com/cbergoon/merkletree?1=1" alt="Report"></a>
<a href="https://godoc.org/github.com/cbergoon/merkletree"><img src="https://img.shields.io/badge/godoc-reference-brightgreen.svg" alt="Docs"></a>
<a href="#"><img src="https://img.shields.io/badge/version-0.1.0-brightgreen.svg" alt="Version"></a>
</p>

An implementation of a Merkle Tree written in Go. A Merkle Tree is a hash tree that provides an efficient way to verify
the contents of a set data are present and untampered with.

At its core, a Merkle Tree is a list of items representing the data that should be verified. Each of these items
is inserted into a leaf node and a tree of hashes is constructed bottom up using a hash of the nodes left and
right children's hashes. This means that the root node will effictively be a hash of all other nodes (hashes) in
the tree. This property allows the tree to be reproduced and thus verified by on the hash of the root node
of the tree. The benefit of the tree structure is verifying any single content entry in the tree will require only
nlog2(n) steps in the worst case.

#### Documentation 

See the docs [here](https://godoc.org/github.com/cbergoon/merkletree).

#### Install
```
go get github.com/cbergoon/merkletree
```

#### Example Usage
Below is an example that makes use of the entire API - its quite small.
```go
package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/cbergoon/merkletree"
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
func (t TestContent) Equals(other merkletree.Content) bool {
	return t.x == other.(TestContent).x
}

func main() {

	//Build list of Content to build tree
	var list []merkletree.Content
	list = append(list, TestContent{x: "Hello"})
	list = append(list, TestContent{x: "Hi"})
	list = append(list, TestContent{x: "Hey"})
	list = append(list, TestContent{x: "Hola"})

	//Create a new Merkle Tree from the list of Content
	t, _ := merkletree.NewTree(list)

	//Get the Merkle Root of the tree
	mr := t.MerkleRoot()
	fmt.Println(mr)

	//Verify the entire tree (hashes for each node) is valid
	vt := t.VerifyTree()
	fmt.Println("Verify Tree: ", vt)

	//Verify a specific content in in the tree
	vc := t.VerifyContent(t.MerkleRoot(), list[0])
	fmt.Println("Verify Content: ", vc)

	//String representation
	fmt.Println(t)

}

```

#### License
This project is licensed under the MIT License.
