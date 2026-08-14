// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package benchmarks

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	cb "github.com/cbergoon/merkletree"
	txaty "github.com/txaty/go-merkletree"
)

// This file is a correctness check rather than a benchmark, and it exists because the
// benchmarks next door would otherwise be measuring six programs doing six different
// things. Knowing exactly where the implementations agree is what makes the timings
// comparable, and where they disagree it says why.
//
// It also does something the oracle module cannot. That module validates the RFC 6962
// construction against the specification's published values. Nothing external validates
// the default Bitcoin style construction, because it has no specification to be checked
// against - so the next best thing is agreement with other independent implementations
// of the same folklore, which is what TestRootAgreement pins down.

// rootsFor computes the root every library produces over the same n leaves.
func rootsFor(t *testing.T, n int) map[string]string {
	t.Helper()

	d := leafData(n)
	roots := make(map[string]string)

	tree, err := buildCB(d)
	if err != nil {
		t.Fatalf("error: cbergoon: %v", err)
	}
	roots["cbergoon"] = hex.EncodeToString(tree.MerkleRoot())

	tt, err := buildTxaty(d, txaty.ModeTreeBuild, false)
	if err != nil {
		t.Fatalf("error: txaty: %v", err)
	}
	roots["txaty"] = hex.EncodeToString(tt.Root)

	wt, err := buildWeald(d)
	if err != nil {
		t.Fatalf("error: wealdtech: %v", err)
	}
	roots["wealdtech"] = hex.EncodeToString(wt.Root())

	ot, err := buildOnrik(d)
	if err != nil {
		t.Fatalf("error: onrik: %v", err)
	}
	roots["onrik"] = hex.EncodeToString(ot.Root())

	xt, err := buildXsleonard(d, false)
	if err != nil {
		t.Fatalf("error: xsleonard: %v", err)
	}
	roots["xsleonard"] = hex.EncodeToString(xt.Root().Hash)

	xtd, err := buildXsleonard(d, true)
	if err != nil {
		t.Fatalf("error: xsleonard(DoubleOddNodes): %v", err)
	}
	roots["xsleonard+doubleodd"] = hex.EncodeToString(xtd.Root().Hash)

	roots["jvsteiner"] = hex.EncodeToString(buildJvsteiner(d).Root())

	return roots
}

// TestRootAgreementOnPowersOfTwo pins the one case where the whole field agrees. With a
// power of two leaf count there is no odd node to make a decision about, so every
// library reduces to the same pairwise hashing and produces the same root.
//
// This is worth asserting rather than assuming, because it is what establishes that the
// libraries are configured equivalently here: same hash, same leaf hashing, same
// pairing. Any disagreement at these sizes would mean the comparison is misconfigured,
// not that the implementations differ.
func TestRootAgreementOnPowersOfTwo(t *testing.T) {
	for _, n := range []int{2, 4, 8, 16, 64, 256} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			roots := rootsFor(t, n)

			want := roots["cbergoon"]
			for _, name := range sortedKeys(roots) {
				if roots[name] != want {
					t.Errorf("error: %s produced %s, want %s; with a power of two leaf count "+
						"every implementation should agree", name, roots[name], want)
				}
			}
		})
	}
}

// TestRootAgreementOnOddCounts records who agrees with merkletree once there is a lone
// node to place, which is the only structural decision these libraries make differently.
//
// merkletree's default duplicates the odd node, and the assertion is that the two
// libraries which document the same policy reach the same root. That is a real
// cross-implementation check on the default construction, which has no specification to
// be validated against otherwise.
//
// The libraries that take a different policy are expected to differ, and the test says
// so explicitly rather than leaving it to be discovered. Note what this means in
// practice: a proof produced by one of them will not verify against a root produced by
// another, so the choice of library is not an implementation detail for anyone whose
// roots are published or stored.
func TestRootAgreementOnOddCounts(t *testing.T) {
	// Duplicating the trailing node is the policy merkletree's default uses.
	sameAsUs := []string{"txaty", "xsleonard+doubleodd"}
	// A different policy for the lone node, so a different root by construction.
	differsFromUs := []string{"wealdtech", "onrik", "xsleonard", "jvsteiner"}

	for _, n := range []int{3, 5, 7, 9, 13, 21, 100, 1000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			roots := rootsFor(t, n)
			ours := roots["cbergoon"]

			for _, name := range sameAsUs {
				if roots[name] != ours {
					t.Errorf("error: %s produced %s, want %s; it duplicates the odd node "+
						"as merkletree does and should agree", name, roots[name], ours)
				}
			}
			for _, name := range differsFromUs {
				if roots[name] == ours {
					t.Errorf("error: %s produced the same root as merkletree at n=%d, but it "+
						"uses a different policy for the odd node; this test's premise is stale", name, n)
				}
			}
		})
	}
}

// TestOddNodePolicyGrouping is the same data viewed as a partition, and it is here so
// that a change in any library's behaviour shows up as a change in the grouping rather
// than as a wall of individual failures. The count is what is asserted; ANALYSIS.md
// carries the explanation.
func TestOddNodePolicyGrouping(t *testing.T) {
	roots := rootsFor(t, 5)

	groups := make(map[string][]string)
	for _, name := range sortedKeys(roots) {
		groups[roots[name]] = append(groups[roots[name]], name)
	}

	// Three distinct roots: duplicate the odd node, promote it, or pad the leaf count
	// out to a power of two.
	if len(groups) != 3 {
		t.Errorf("error: %d distinct roots at n=5, want 3", len(groups))
	}
	for root, names := range groups {
		t.Logf("%s: %v", root[:16], names)
	}
}

// TestSortedSiblingsMatchesTxaty checks merkletree's OpenZeppelin compatible mode against
// the other library that implements it, so that the sorted construction is covered by
// something outside this repository too.
func TestSortedSiblingsMatchesTxaty(t *testing.T) {
	for _, n := range []int{2, 4, 5, 8, 16, 33, 100} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			d := leafData(n)

			ours, err := buildCB(d, cb.WithSortedSiblings())
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			theirs, err := txaty.New(&txaty.Config{
				HashFunc:         txatySHA256,
				Mode:             txaty.ModeTreeBuild,
				SortSiblingPairs: true,
			}, txatyBlocks(d))
			if err != nil {
				t.Fatalf("error: unexpected error: %v", err)
			}

			if !bytes.Equal(ours.MerkleRoot(), theirs.Root) {
				t.Errorf("error: sorted root %x, want %x", ours.MerkleRoot(), theirs.Root)
			}
		})
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)

	return out
}
