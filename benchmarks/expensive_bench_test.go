// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package benchmarks

import (
	"fmt"
	"testing"

	cb "github.com/cbergoon/merkletree"
	txaty "github.com/txaty/go-merkletree"
)

// Every other benchmark in this directory uses leaves of about seven bytes, which makes
// the cost of hashing a leaf almost nothing and the cost of the surrounding tree
// machinery almost everything. Real content is often not like that, and the ratio is not
// a detail: it decides whether the tree code or the hash function is the thing being
// measured, and it moves the point where parallel construction starts paying.
//
// These benchmarks vary the leaf size and hold everything else fixed, so the same
// libraries can be read at both ends of that ratio.

// leafSizes spans from "the hash function is free" to "the hash function is everything".
// 32 bytes is a digest, 1 KiB a small record, 16 KiB a document or a block.
var leafSizes = []int{32, 1024, 16384}

// leafDataSized returns n distinct leaves of the given size. The index is written into
// the front of each leaf so that no two are equal, and the rest is filled with a
// position dependent pattern rather than zeros, so the data is not trivially
// compressible and every leaf hashes to something different.
func leafDataSized(n, size int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, size)
		copy(b, fmt.Sprintf("leaf-%d-", i))
		for j := len(fmt.Sprintf("leaf-%d-", i)); j < size; j++ {
			b[j] = byte(i*31 + j)
		}
		out = append(out, b)
	}

	return out
}

// BenchmarkConstructionByLeafSize is the cross-library comparison at each leaf size. As
// the leaves grow, every library converges on the cost of SHA-256 over the same bytes,
// and the differences between them shrink to nothing - except where a library can spread
// that hashing across cores.
func BenchmarkConstructionByLeafSize(b *testing.B) {
	const n = 4096

	for _, size := range leafSizes {
		d := leafDataSized(n, size)

		run := func(name string, fn func() error) {
			b.Run(fmt.Sprintf("%s/leaf=%dB", name, size), func(b *testing.B) {
				b.SetBytes(int64(n * size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := fn(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}

		run("cbergoon", func() error { _, err := buildCB(d); return err })
		run("cbergoon-parallel", func() error { _, err := buildCB(d, cb.WithParallelism(0)); return err })
		run("txaty", func() error { _, err := buildTxaty(d, txaty.ModeTreeBuild, false); return err })
		run("txaty-parallel", func() error { _, err := buildTxaty(d, txaty.ModeTreeBuild, true); return err })
		run("wealdtech", func() error { _, err := buildWeald(d); return err })
		run("onrik", func() error { _, err := buildOnrik(d); return err })
		run("xsleonard", func() error { _, err := buildXsleonard(d, true); return err })
		run("jvsteiner", func() error { buildJvsteiner(d); return nil })
	}
}

// BenchmarkParallelBreakEven locates the leaf count at which parallel construction
// overtakes serial, at each leaf size.
//
// WithParallelism documents the break-even for cheap content as a few thousand leaves,
// and warns that below it a parallel build is slower than a serial one. That figure is a
// property of how expensive Content.CalculateHash is, not of the leaf count alone, so it
// is measured here across both.
func BenchmarkParallelBreakEven(b *testing.B) {
	for _, size := range leafSizes {
		for _, n := range []int{64, 256, 1024, 4096} {
			d := leafDataSized(n, size)

			b.Run(fmt.Sprintf("serial/leaf=%dB/n=%d", size, n), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := buildCB(d); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run(fmt.Sprintf("parallel/leaf=%dB/n=%d", size, n), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := buildCB(d, cb.WithParallelism(0)); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkLookupByLeafSize measures what content size does to finding a leaf, which is
// a different question from what it does to building the tree.
//
// Locating content by value means hashing the query, so a lookup carries the cost of one
// CalculateHash however the library indexes its leaves. Addressing a leaf by position
// does not. At seven byte leaves that distinction is invisible; it should not stay that
// way as the leaves grow.
func BenchmarkLookupByLeafSize(b *testing.B) {
	const n = 4096

	for _, size := range leafSizes {
		d := leafDataSized(n, size)
		last := d[n-1]

		b.Run(fmt.Sprintf("cbergoon-leafindex/leaf=%dB", size), func(b *testing.B) {
			tree, err := buildCB(d, cb.WithLeafIndex())
			if err != nil {
				b.Fatal(err)
			}
			target := cbContent{data: last}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := tree.GetMerklePath(target); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("cbergoon-byindex/leaf=%dB", size), func(b *testing.B) {
			tree, err := buildCB(d)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := tree.GetMerklePathByIndex(n - 1); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("txaty/leaf=%dB", size), func(b *testing.B) {
			tree, err := buildTxaty(d, txaty.ModeTreeBuild, false)
			if err != nil {
				b.Fatal(err)
			}
			target := txatyBlock{data: last}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := tree.Proof(target); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("onrik-byindex/leaf=%dB", size), func(b *testing.B) {
			tree, err := buildOnrik(d)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = tree.GetProof(n - 1)
			}
		})
	}
}

// BenchmarkVerifyByLeafSize does the same for verification, which also has to hash the
// content it is checking.
func BenchmarkVerifyByLeafSize(b *testing.B) {
	const n = 4096

	for _, size := range leafSizes {
		d := leafDataSized(n, size)
		last := d[n-1]

		b.Run(fmt.Sprintf("cbergoon-verifyproof/leaf=%dB", size), func(b *testing.B) {
			tree, err := buildCB(d)
			if err != nil {
				b.Fatal(err)
			}
			target := cbContent{data: last}
			path, index, err := tree.GetMerklePath(target)
			if err != nil {
				b.Fatal(err)
			}
			root := tree.MerkleRoot()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, err := cb.VerifyProof(target, path, index, root)
				if err != nil || !ok {
					b.Fatalf("verify failed: %v %v", ok, err)
				}
			}
		})

		b.Run(fmt.Sprintf("txaty/leaf=%dB", size), func(b *testing.B) {
			tree, err := buildTxaty(d, txaty.ModeTreeBuild, false)
			if err != nil {
				b.Fatal(err)
			}
			target := txatyBlock{data: last}
			proof, err := tree.Proof(target)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, err := tree.Verify(target, proof)
				if err != nil || !ok {
					b.Fatalf("verify failed: %v %v", ok, err)
				}
			}
		})
	}
}
