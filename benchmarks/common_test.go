// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

// Package benchmarks compares merkletree against the other Merkle tree libraries in the
// Go ecosystem, on construction, proof generation and verification.
//
// See ANALYSIS.md in this directory for what the libraries actually do differently and
// for what the numbers mean. The short version, because it governs how everything here
// is written: these libraries do not all compute the same function, so a benchmark that
// simply calls each one's constructor would be comparing different work and reporting it
// as a speed difference.
//
// What is held constant here:
//
//   - The hash. Every tree below uses SHA-256, supplied explicitly wherever the library
//     allows it. jvsteiner/merkle hardcodes SHA-256, which is the only reason it can be
//     included on equal terms.
//   - The leaf data. Every library is handed the same byte slices.
//   - Where the leaf hash comes from. Every library hashes the leaf data itself, so
//     merkletree's Content.CalculateHash returns SHA-256 of the data rather than the
//     data itself, which is what makes its leaf hashes the same as everyone else's.
//
// What cannot be held constant, and is therefore reported rather than hidden, is the
// shape of the tree over a leaf count that is not a power of two. See ANALYSIS.md and
// TestRootAgreement in crosscheck_test.go, which pins down exactly who agrees with whom.
package benchmarks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"

	cb "github.com/cbergoon/merkletree"
	jvs "github.com/jvsteiner/merkle"
	onrik "github.com/onrik/gomerkle"
	txaty "github.com/txaty/go-merkletree"
	weald "github.com/wealdtech/go-merkletree"
	xsl "github.com/xsleonard/go-merkle"
)

// benchSizes spans the range where the differences show. The small end is where
// per-call overhead dominates, and the large end is where anything quadratic separates
// from anything that is not.
//
// Note that txaty/go-merkletree rejects a single data block, so no size here is 1.
var benchSizes = []int{16, 256, 4096, 65536}

// leafData returns n distinct leaves, identical for every library under test.
func leafData(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, []byte(fmt.Sprintf("leaf-%d", i)))
	}

	return out
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)

	return s[:]
}

// ---------------------------------------------------------------------------
// Adapters. Each library wants its leaves in a different shape.
// ---------------------------------------------------------------------------

// cbContent adapts a leaf for merkletree. CalculateHash returns SHA-256 of the data
// because every other library here hashes its leaf data, and merkletree records
// whatever CalculateHash returns as the leaf hash. Returning the data unchanged would
// build a tree over unhashed leaves and would not be the same tree.
type cbContent struct {
	data []byte
}

func (c cbContent) CalculateHash() ([]byte, error) {
	return sha256Of(c.data), nil
}

func (c cbContent) Equals(other cb.Content) (bool, error) {
	o, ok := other.(cbContent)
	if !ok {
		return false, nil
	}

	return bytes.Equal(c.data, o.data), nil
}

func cbContents(d [][]byte) []cb.Content {
	cs := make([]cb.Content, 0, len(d))
	for _, x := range d {
		cs = append(cs, cbContent{data: x})
	}

	return cs
}

// txatyBlock adapts a leaf for txaty/go-merkletree, whose DataBlock interface hands the
// library the bytes to hash.
type txatyBlock struct {
	data []byte
}

func (b txatyBlock) Serialize() ([]byte, error) {
	return b.data, nil
}

func txatyBlocks(d [][]byte) []txaty.DataBlock {
	bs := make([]txaty.DataBlock, 0, len(d))
	for _, x := range d {
		bs = append(bs, txatyBlock{data: x})
	}

	return bs
}

// txatySHA256 is the hash function in the signature txaty expects.
func txatySHA256(b []byte) ([]byte, error) {
	return sha256Of(b), nil
}

// wealdSHA256 supplies SHA-256 to wealdtech/go-merkletree, which ships BLAKE2b and
// Keccak256 but takes any implementation of its one method HashType interface. Pinning
// it to SHA-256 is what makes the comparison a comparison of tree code rather than of
// hash function choice.
type wealdSHA256 struct{}

func (wealdSHA256) Hash(d []byte) []byte {
	return sha256Of(d)
}

// newHasher is the stateful hash the two older libraries want, rather than a
// constructor or a function.
func newHasher() hash.Hash {
	return sha256.New()
}

// ---------------------------------------------------------------------------
// Constructors, one per library, so the benchmarks read as a list rather than a
// switch and so the cross-check and the benchmarks build trees the same way.
// ---------------------------------------------------------------------------

func buildCB(d [][]byte, opts ...cb.TreeOption) (*cb.MerkleTree, error) {
	return cb.NewTreeWithOptions(cbContents(d), opts...)
}

func buildTxaty(d [][]byte, mode txaty.TypeConfigMode, parallel bool) (*txaty.MerkleTree, error) {
	return txaty.New(&txaty.Config{
		HashFunc:      txatySHA256,
		Mode:          mode,
		RunInParallel: parallel,
	}, txatyBlocks(d))
}

func buildWeald(d [][]byte) (*weald.MerkleTree, error) {
	return weald.NewUsing(d, wealdSHA256{}, nil)
}

func buildOnrik(d [][]byte) (onrik.Tree, error) {
	t := onrik.NewTree(newHasher())
	t.AddData(d...)

	return t, t.Generate()
}

// buildXsleonard uses DoubleOddNodes, which is the option that makes it build the same
// tree as merkletree's default construction rather than a different one. Its own default
// promotes a lone node instead. See ANALYSIS.md.
func buildXsleonard(d [][]byte, doubleOdd bool) (xsl.Tree, error) {
	t := xsl.NewTreeWithOpts(xsl.TreeOptions{DoubleOddNodes: doubleOdd})

	return t, t.Generate(d, newHasher())
}

func buildJvsteiner(d [][]byte) *jvs.Tree {
	t := jvs.NewTreeFromData(d)
	t.Build()

	return t
}
