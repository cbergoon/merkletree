// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

// Benchmarks exist here mainly so that a change made for correctness can be checked
// for what it cost. Construction and verification are both linear in the leaf count
// and proof generation is linear in it too, because GetMerklePath scans Leafs to find
// the content before walking up; benchmarking across sizes is what would show any of
// those turning superlinear.

var benchSizes = []int{16, 256, 4096}

func benchContents(n int) []Content {
	cs := make([]Content, 0, n)
	for i := 0; i < n; i++ {
		cs = append(cs, TestSHA256Content{x: fmt.Sprintf("item-%d", i)})
	}

	return cs
}

func eachBenchMode(b *testing.B, fn func(b *testing.B, mode propMode, contents []Content)) {
	b.Helper()
	for _, mode := range propModes {
		for _, n := range benchSizes {
			contents := benchContents(n)
			b.Run(fmt.Sprintf("%s/n=%d", mode.name, n), func(b *testing.B) {
				fn(b, mode, contents)
			})
		}
	}
}

func BenchmarkNewTree(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := mode.build(contents, sha256.New); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkNewTreeParallel builds with the full goroutine budget across every
// construction, so both parallel interior paths - the level-splitting default and the
// RFC 6962 fork-join - stay measured. The sizes sit above the interior threshold,
// where the option is documented to pay.
func BenchmarkNewTreeParallel(b *testing.B) {
	for _, mode := range propModes {
		for _, n := range []int{4096, 65536} {
			contents := benchContents(n)
			opts := []TreeOption{WithParallelism(0)}
			if mode.sorted {
				opts = append(opts, WithSortedSiblings())
			}
			if mode.rfc6962 {
				opts = append(opts, WithRFC6962())
			}
			b.Run(fmt.Sprintf("%s/n=%d", mode.name, n), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := NewTreeWithOptions(contents, opts...); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkNewTreeIndexed builds with WithLeafIndex, so the cost of the index - one
// shared backing string and the map over it - stays measured against the plain build.
func BenchmarkNewTreeIndexed(b *testing.B) {
	for _, n := range benchSizes {
		contents := benchContents(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := NewTreeWithOptions(contents, WithLeafIndex()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyTree(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ok, err := tree.VerifyTree()
			if err != nil || !ok {
				b.Fatalf("verify failed: %v %v", ok, err)
			}
		}
	})
}

func BenchmarkGetMerklePath(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		// The last item is the worst case for the linear scan over Leafs.
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

func BenchmarkVerifyContent(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		target := contents[len(contents)-1]
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ok, err := tree.VerifyContent(target)
			if err != nil || !ok {
				b.Fatalf("verify failed: %v %v", ok, err)
			}
		}
	})
}

func BenchmarkMarshalBinary(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := tree.MarshalBinary(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// RebuildTree is the operation a caller reaches for after mutating content in place,
// and RebuildTreeWith after replacing it wholesale. Both discard and regenerate every
// node, so they cost a full construction plus, for RebuildTree, a pass over the leaves
// to recover the content.
func BenchmarkRebuildTree(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := tree.RebuildTree(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRebuildTreeWith(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := tree.RebuildTreeWith(contents); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// The JSON codec is a separate path from the binary one: it shares the snapshot and
// rebuild steps but frames them through encoding/json, which base64s every hash and
// every content payload. Benchmarking it separately is what shows that cost.
func BenchmarkMarshalJSON(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := json.Marshal(tree); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		data, err := json.Marshal(tree)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var got MerkleTree
			if err := json.Unmarshal(data, &got); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchEncode and benchDecode are the registry free codec pair, exercising MarshalWith
// and UnmarshalWith. Comparing these against the MarshalBinary benchmarks isolates what
// the content registry's reflection and map lookups cost per leaf.
func benchEncode(c Content) ([]byte, error) {
	return []byte(c.(TestSHA256Content).x), nil
}

func benchDecode(b []byte) (Content, error) {
	return TestSHA256Content{x: string(b)}, nil
}

func BenchmarkMarshalWith(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := tree.MarshalWith(benchEncode); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnmarshalWith(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		data, err := tree.MarshalWith(benchEncode)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := UnmarshalWith(data, benchDecode); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSortAppend isolates the sorted mode's inner loop. Ordering a sibling pair
// means parsing both hashes into big.Int values, which allocates twice per interior
// node - the reason sorted trees cost more to build than unsorted ones. This is the
// benchmark to watch if that comparison is ever reworked.
func BenchmarkSortAppend(b *testing.B) {
	left := sha256.Sum256([]byte("left"))
	right := sha256.Sum256([]byte("right"))

	for _, tc := range []struct {
		name string
		sort bool
	}{
		{"unsorted", false},
		{"sorted", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = sortAppend(tc.sort, left[:], right[:])
			}
		})
	}
}

// BenchmarkHashStrategies shows what the choice of hash strategy costs at a fixed
// size and construction, which is otherwise hidden inside the per-mode numbers.
func BenchmarkHashStrategies(b *testing.B) {
	contents := benchContents(256)

	for _, s := range propStrategies {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := NewTreeWithHashStrategy(contents, s.fn); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// A built tree is read only, so the expected deployment is one tree shared by many
// goroutines answering proof and verification requests. These measure that shape.
// VerifyContent touches only the tree, while the marshalers also take a read lock on
// each of the package registries, so the two can scale differently.
func BenchmarkVerifyContentParallel(b *testing.B) {
	contents := benchContents(1024)
	tree, err := NewTree(contents)
	if err != nil {
		b.Fatal(err)
	}
	target := contents[len(contents)-1]

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ok, err := tree.VerifyContent(target)
			if err != nil || !ok {
				b.Fatalf("verify failed: %v %v", ok, err)
			}
		}
	})
}

func BenchmarkMarshalBinaryParallel(b *testing.B) {
	tree, err := NewTree(benchContents(256))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := tree.MarshalBinary(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkUnmarshalBinary(b *testing.B) {
	eachBenchMode(b, func(b *testing.B, mode propMode, contents []Content) {
		tree, err := mode.build(contents, sha256.New)
		if err != nil {
			b.Fatal(err)
		}
		data, err := tree.MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var got MerkleTree
			if err := got.UnmarshalBinary(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}
