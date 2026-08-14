// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"fmt"
	"testing"
)

// Locating content is the part of proof generation that scales with the tree rather
// than with its depth, so these benchmarks vary the leaf count over a range wide enough
// for the difference between a scan and a lookup to show as a change in shape and not
// just a constant factor. The ns/proof metric is what to read: for the scan it climbs
// with n, and for the other two it does not.
var lookupSizes = []int{1000, 4000, 16000, 64000}

// BenchmarkAllProofs generates the full set of proofs, which is the operation the scan
// makes quadratic.
func BenchmarkAllProofs(b *testing.B) {
	for _, tc := range []struct {
		name     string
		indexed  bool
		byIndex  bool
		appendTo bool
	}{
		{name: "scan"},
		{name: "leafindex", indexed: true},
		{name: "byindex", byIndex: true},
		{name: "append", appendTo: true},
	} {
		for _, n := range lookupSizes {
			b.Run(fmt.Sprintf("%s/n=%d", tc.name, n), func(b *testing.B) {
				contents := benchContents(n)
				var (
					tree *MerkleTree
					err  error
				)
				if tc.indexed {
					tree, err = NewTreeWithOptions(contents, WithLeafIndex())
				} else {
					tree, err = NewTree(contents)
				}
				if err != nil {
					b.Fatal(err)
				}

				var (
					path  [][]byte
					index []int64
				)

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if tc.appendTo {
						for j := range contents {
							if path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], j); err != nil {
								b.Fatal(err)
							}
						}
						continue
					}
					if tc.byIndex {
						for j := range contents {
							if _, _, err := tree.GetMerklePathByIndex(j); err != nil {
								b.Fatal(err)
							}
						}
						continue
					}
					for _, c := range contents {
						if _, _, err := tree.GetMerklePath(c); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/proof")
			})
		}
	}
}

// BenchmarkSingleProof isolates one lookup at the worst case position for the scan, the
// last leaf, which is where the O(n) shows up most directly.
func BenchmarkSingleProof(b *testing.B) {
	for _, indexed := range []bool{false, true} {
		name := "scan"
		if indexed {
			name = "leafindex"
		}
		for _, n := range lookupSizes {
			b.Run(fmt.Sprintf("%s/n=%d", name, n), func(b *testing.B) {
				contents := benchContents(n)
				var (
					tree *MerkleTree
					err  error
				)
				if indexed {
					tree, err = NewTreeWithOptions(contents, WithLeafIndex())
				} else {
					tree, err = NewTree(contents)
				}
				if err != nil {
					b.Fatal(err)
				}
				target := contents[len(contents)-1]

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, _, err := tree.GetMerklePath(target); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
