// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sync"
)

// ErrMalformedProof is returned when a proof cannot be walked at all: a path and an
// index of different lengths, or a side marker that is neither 0 nor 1. It reports a
// proof that is the wrong shape rather than one that is the right shape and does not
// verify, which is an ordinary false. Test for it with errors.Is.
var ErrMalformedProof = errors.New("error: proof is malformed")

// proofScratch is the working state one proof verification needs: a hasher and the
// buffer the replay slides its digests through. Pooled as a pair, so the option-less
// verification path allocates nothing of its own.
type proofScratch struct {
	h   hash.Hash
	buf []byte
}

// defaultProofConfig is the configuration an option-less VerifyProof runs under: the
// same value configFromOptions produces for an empty option list, allocated once
// rather than per verification. It is shared across goroutines and must never be
// mutated; the verification path only ever reads it.
//
// Being private and immutable is also what makes it the one place a scratch pool is
// safe; see the field's comment on MerkleTree.
var defaultProofConfig = &MerkleTree{
	hashStrategy: sha256.New,
	scratchPool: &sync.Pool{New: func() any {
		return &proofScratch{h: sha256.New(), buf: make([]byte, 0, 2*sha256.Size)}
	}},
}

// VerifyProof reports whether content, the audit path and the side index returned by
// GetMerklePath together reproduce root.
//
// This is the operation a verifier performs when it holds a root obtained from somewhere
// it trusts, and a proof obtained from somewhere it does not. It needs no tree: the
// whole point is that the party checking the proof does not have to hold, rebuild, or
// have ever seen the tree the proof came from. MerkleTree.VerifyContent answers a
// different question, on a tree it already has.
//
// The options configure the construction the proof was produced under, and they must
// match the tree that produced it or verification fails. Only the options that affect
// hashing are meaningful here: WithHasher, WithSortedSiblings and WithRFC6962. The
// others describe how a tree is built rather than how its hashes are computed, and are
// accepted and ignored so that the same option list can be shared with the constructor.
// A tree's own settings are readable through MerkleTree.Sorted and MerkleTree.RFC6962.
//
// Returns false when the proof simply does not reproduce root, and an error when the
// proof is malformed or hashing the content fails.
//
// # What a verified proof does and does not establish
//
// It establishes that content sits in some tree whose root is root. It says nothing
// about whether root is the root a verifier should be trusting; that has to arrive
// through a channel the verifier already trusts, and this function cannot check it.
//
// Under the default construction it establishes less than it appears to. Leaf and
// interior hashes are computed the same way, so nothing distinguishes a leaf digest from
// an interior one, and a path can be presented that treats an interior node as though it
// were a leaf. Building the tree with WithRFC6962 closes this: the two kinds of hash
// carry distinct prefixes, so a forgery of that shape would need a genuine collision.
// The distinction matters far more here than it does for VerifyContent, which walks a
// real tree and so can only be shown nodes that are really in it. Prefer WithRFC6962 for
// proofs that arrive from somewhere untrusted.
func VerifyProof(content Content, path [][]byte, index []int64, root []byte, opts ...TreeOption) (bool, error) {
	if content == nil {
		return false, ErrNilContent
	}
	digest, err := content.CalculateHash()
	if err != nil {
		return false, err
	}

	return VerifyProofWithDigest(digest, path, index, root, opts...)
}

// VerifyProofWithDigest is VerifyProof for a verifier that holds the leaf digest rather
// than the content itself, and so has no reason to implement Content.
//
// The digest is the value Content.CalculateHash returns for the leaf, which is the leaf
// hash the tree records under the default construction. Under WithRFC6962 the tree
// records the prefixed hash of that digest instead, and this function applies the prefix
// itself, so the argument is the same value either way: what CalculateHash returned, not
// what the tree stored.
func VerifyProofWithDigest(digest []byte, path [][]byte, index []int64, root []byte, opts ...TreeOption) (bool, error) {
	if len(path) != len(index) {
		return false, fmt.Errorf("%w: path has %d entries and the index has %d", ErrMalformedProof, len(path), len(index))
	}

	// With no options there is nothing to resolve, so the shared default carries the
	// configuration instead of a fresh one allocated per call. rootFromProof only
	// reads it, which is what makes sharing it across goroutines safe.
	cfg := defaultProofConfig
	if len(opts) > 0 {
		var err error
		if cfg, err = configFromOptions(opts); err != nil {
			return false, err
		}
	}

	return cfg.proofReproducesRoot(digest, path, index, root)
}

// proofReproducesRoot replays a proof from the leaf upwards and reports whether it
// arrives at root.
//
// The hashing goes through the same appendLeafDigest and appendInteriorHash the
// constructor uses, so a proof is checked with the code that built the tree rather than
// with a second implementation of the same rules that could drift from it. What keeps
// that from being circular is the oracle module, which checks the construction itself
// against the RFC 6962 reference implementation.
//
// Merkle roots are public values, so the ordinary comparison at the end is
// appropriate; there is no secret here whose length or content a timing difference
// could leak.
func (m *MerkleTree) proofReproducesRoot(digest []byte, path [][]byte, index []int64, root []byte) (bool, error) {
	// One hasher and one buffer serve the whole replay, recycled through the pool
	// when the configuration carries one. Each level appends its hash and then
	// slides it down over the previous one, so the buffer stays the width of a
	// single digest however tall the tree is. Doing the comparison here rather than
	// returning the computed root is what lets the buffer go back to the pool.
	var (
		scratch *proofScratch
		h       hash.Hash
		buf     []byte
	)
	if m.scratchPool != nil {
		scratch = m.scratchPool.Get().(*proofScratch)
		h, buf = scratch.h, scratch.buf[:0]
	} else {
		h = m.hashStrategy()
		buf = make([]byte, 0, 2*h.Size())
	}
	defer func() {
		if scratch != nil {
			scratch.buf = buf
			m.scratchPool.Put(scratch)
		}
	}()

	var err error
	if m.rfc6962 {
		if buf, err = m.appendLeafDigest(h, buf, digest); err != nil {
			return false, err
		}
	} else {
		buf = append(buf, digest...)
	}

	for k := range path {
		// GetMerklePath records 1 when the sibling is the right hand node, which is
		// to say when the node being carried up is the left hand one.
		var left, right []byte
		switch index[k] {
		case 1:
			left, right = buf, path[k]
		case 0:
			left, right = path[k], buf
		default:
			return false, fmt.Errorf("%w: index entry %d is %d, expected 0 or 1", ErrMalformedProof, k, index[k])
		}

		off := len(buf)
		if buf, err = m.appendInteriorHash(h, buf, left, right); err != nil {
			return false, err
		}
		buf = buf[:copy(buf, buf[off:])]
	}

	return bytes.Equal(buf, root), nil
}

// configFromOptions applies opts to a MerkleTree that carries configuration and nothing
// else, and reports the same conflicts the constructor does.
//
// The verification path and the construction path resolve options through this one
// function, so a tree and a proof checked against it can never disagree about what an
// option meant.
func configFromOptions(opts []TreeOption) (*MerkleTree, error) {
	m := &MerkleTree{
		hashStrategy: sha256.New,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(m)
	}
	if m.hashStrategy == nil {
		return nil, errors.New("error: hash strategy cannot be nil")
	}
	if m.rfc6962 && m.sort {
		return nil, errors.New("error: WithRFC6962 and WithSortedSiblings cannot be combined; RFC 6962 specifies its own sibling ordering")
	}

	return m, nil
}

// VerifyProof reports whether the given proof reproduces this tree's root, using this
// tree's construction settings.
//
// It is the convenience form of the package level VerifyProof for a caller that does
// hold the tree, and saves restating the tree's options. It still verifies the proof it
// is given rather than looking anything up, so it will reject a proof for content this
// tree holds if that proof was generated somewhere else under different settings.
func (m *MerkleTree) VerifyProof(content Content, path [][]byte, index []int64) (bool, error) {
	if content == nil {
		return false, ErrNilContent
	}
	if len(path) != len(index) {
		return false, fmt.Errorf("%w: path has %d entries and the index has %d", ErrMalformedProof, len(path), len(index))
	}
	digest, err := content.CalculateHash()
	if err != nil {
		return false, err
	}

	return m.proofReproducesRoot(digest, path, index, m.merkleRoot)
}
