// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package benchmarks

import (
	"fmt"
	"testing"

	cb "github.com/cbergoon/merkletree"
	txaty "github.com/txaty/go-merkletree"
	weald "github.com/wealdtech/go-merkletree"
)

// The four axes are benchmarked separately because they have genuinely different
// stories, and a single "merkle tree benchmark" number would average them into
// something meaningless:
//
//   - Construction: hashing bound, and the axis where parallelism pays.
//   - Single proof: dominated by how the library finds the leaf, not by the walk.
//   - All proofs: where an O(n) lookup per proof becomes O(n²) over the set, and where
//     a library that precomputes proofs at build time is doing different work.
//   - Verification: checking one proof against a root.
//
// Not every library offers every axis. xsleonard/go-merkle has no proof API at all, so
// it appears only under construction. That is reported rather than worked around.

// ---------------------------------------------------------------------------
// Axis 1: construction
// ---------------------------------------------------------------------------

func BenchmarkConstruction(b *testing.B) {
	for _, n := range benchSizes {
		d := leafData(n)

		b.Run(fmt.Sprintf("cbergoon/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildCB(d); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("cbergoon-parallel/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildCB(d, cb.WithParallelism(0)); err != nil {
					b.Fatal(err)
				}
			}
		})

		// ModeTreeBuild is the comparable mode: it builds the tree and nothing else.
		// ModeProofGen does more work on purpose and is benchmarked under all proofs.
		b.Run(fmt.Sprintf("txaty/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildTxaty(d, txaty.ModeTreeBuild, false); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("txaty-parallel/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildTxaty(d, txaty.ModeTreeBuild, true); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("wealdtech/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildWeald(d); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("onrik/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildOnrik(d); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("xsleonard/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildXsleonard(d, true); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("jvsteiner/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buildJvsteiner(d)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Axis 2: a single proof, for the worst case leaf
// ---------------------------------------------------------------------------

// The last leaf is the worst case for any library that locates content by scanning, and
// the same as any other leaf for one that does not, so it is the position that
// distinguishes them.
func BenchmarkSingleProof(b *testing.B) {
	for _, n := range benchSizes {
		d := leafData(n)
		last := d[n-1]

		b.Run(fmt.Sprintf("cbergoon-scan/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d)
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

		b.Run(fmt.Sprintf("cbergoon-leafindex/n=%d", n), func(b *testing.B) {
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

		b.Run(fmt.Sprintf("cbergoon-byindex/n=%d", n), func(b *testing.B) {
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

		// The append form reuses the caller's buffers, which is the steady state of a
		// proof server: after the first proof it allocates nothing at all.
		b.Run(fmt.Sprintf("cbergoon-append/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d)
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
				if path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], n-1); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			// A number this small invites the suspicion that nothing happened, so the
			// last proof out of the timed loop is verified against the root.
			if ok, err := cb.VerifyProof(cbContent{data: last}, path, index, tree.MerkleRoot()); err != nil || !ok {
				b.Fatalf("timed loop produced an invalid proof: %v %v", ok, err)
			}
		})

		b.Run(fmt.Sprintf("txaty/n=%d", n), func(b *testing.B) {
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

		b.Run(fmt.Sprintf("wealdtech/n=%d", n), func(b *testing.B) {
			tree, err := buildWeald(d)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := tree.GenerateProof(last); err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("onrik/n=%d", n), func(b *testing.B) {
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

		b.Run(fmt.Sprintf("jvsteiner/n=%d", n), func(b *testing.B) {
			tree := buildJvsteiner(d)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := tree.GetChain(n - 1); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Axis 3: the whole proof set
// ---------------------------------------------------------------------------

// allProofSizes stops short of the largest construction size on purpose. Generating
// every proof from a library that locates leaves by scanning is quadratic, and at 65536
// leaves a single iteration of the scanning variant runs into minutes. The sizes here
// are enough to show the shape; ANALYSIS.md carries the extrapolation.
var allProofSizes = []int{16, 256, 4096}

func BenchmarkAllProofs(b *testing.B) {
	for _, n := range allProofSizes {
		d := leafData(n)

		perProof := func(b *testing.B, n int) {
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/proof")
		}

		b.Run(fmt.Sprintf("cbergoon-scan/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d)
			if err != nil {
				b.Fatal(err)
			}
			cs := cbContents(d)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, c := range cs {
					if _, _, err := tree.GetMerklePath(c); err != nil {
						b.Fatal(err)
					}
				}
			}
			perProof(b, n)
		})

		b.Run(fmt.Sprintf("cbergoon-leafindex/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d, cb.WithLeafIndex())
			if err != nil {
				b.Fatal(err)
			}
			cs := cbContents(d)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, c := range cs {
					if _, _, err := tree.GetMerklePath(c); err != nil {
						b.Fatal(err)
					}
				}
			}
			perProof(b, n)
		})

		b.Run(fmt.Sprintf("cbergoon-byindex/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < n; j++ {
					if _, _, err := tree.GetMerklePathByIndex(j); err != nil {
						b.Fatal(err)
					}
				}
			}
			perProof(b, n)
		})

		// The append form generates the same proofs into two buffers reused across the
		// whole set, which removes the per-proof allocations entirely.
		b.Run(fmt.Sprintf("cbergoon-append/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d)
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
				for j := 0; j < n; j++ {
					if path, index, err = tree.AppendMerklePathByIndex(path[:0], index[:0], j); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.StopTimer()
			perProof(b, n)
			// The last proof out of the timed loop is verified against the root, so
			// this benchmark cannot quietly degrade into measuring a no-op.
			if ok, err := cb.VerifyProof(cbContent{data: d[n-1]}, path, index, tree.MerkleRoot()); err != nil || !ok {
				b.Fatalf("timed loop produced an invalid proof: %v %v", ok, err)
			}
		})

		b.Run(fmt.Sprintf("txaty/n=%d", n), func(b *testing.B) {
			tree, err := buildTxaty(d, txaty.ModeTreeBuild, false)
			if err != nil {
				b.Fatal(err)
			}
			blocks := txatyBlocks(d)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, blk := range blocks {
					if _, err := tree.Proof(blk); err != nil {
						b.Fatal(err)
					}
				}
			}
			perProof(b, n)
		})

		// ModeProofGen is txaty's answer to this axis: it computes every proof during
		// construction. Included from a cold start, because that is the operation -
		// build a tree and come away holding all of its proofs.
		b.Run(fmt.Sprintf("txaty-proofgen/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tree, err := buildTxaty(d, txaty.ModeProofGen, false)
				if err != nil {
					b.Fatal(err)
				}
				if len(tree.Proofs) != n {
					b.Fatalf("got %d proofs, want %d", len(tree.Proofs), n)
				}
			}
			perProof(b, n)
		})

		b.Run(fmt.Sprintf("wealdtech/n=%d", n), func(b *testing.B) {
			tree, err := buildWeald(d)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, x := range d {
					if _, err := tree.GenerateProof(x); err != nil {
						b.Fatal(err)
					}
				}
			}
			perProof(b, n)
		})

		b.Run(fmt.Sprintf("onrik/n=%d", n), func(b *testing.B) {
			tree, err := buildOnrik(d)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < n; j++ {
					_ = tree.GetProof(j)
				}
			}
			perProof(b, n)
		})

		b.Run(fmt.Sprintf("jvsteiner/n=%d", n), func(b *testing.B) {
			tree := buildJvsteiner(d)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < n; j++ {
					if _, err := tree.GetChain(j); err != nil {
						b.Fatal(err)
					}
				}
			}
			perProof(b, n)
		})
	}
}

// ---------------------------------------------------------------------------
// Axis 4: verifying one proof
// ---------------------------------------------------------------------------

// Verification is where the libraries diverge most in what they are actually being
// asked to do, so read this axis with the difference in mind rather than as a ranking.
//
// merkletree's VerifyContent is the odd one out: it locates the content and then
// recomputes every hash on the path from that leaf to the root out of the tree it holds,
// so it both finds and checks. The others take a proof that has already been generated
// and replay it against a root, which is strictly less work and does not need the tree
// at all. Both are useful operations; they are not the same operation.
func BenchmarkVerification(b *testing.B) {
	for _, n := range benchSizes {
		d := leafData(n)
		last := d[n-1]

		// The like-for-like column: a proof generated in advance, replayed against a
		// root, with no tree involved. This is the same operation the other three
		// libraries perform below.
		b.Run(fmt.Sprintf("cbergoon-verifyproof/n=%d", n), func(b *testing.B) {
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

		b.Run(fmt.Sprintf("cbergoon-verifycontent-leafindex/n=%d", n), func(b *testing.B) {
			tree, err := buildCB(d, cb.WithLeafIndex())
			if err != nil {
				b.Fatal(err)
			}
			target := cbContent{data: last}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, err := tree.VerifyContent(target)
				if err != nil || !ok {
					b.Fatalf("verify failed: %v %v", ok, err)
				}
			}
		})

		b.Run(fmt.Sprintf("txaty/n=%d", n), func(b *testing.B) {
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

		b.Run(fmt.Sprintf("wealdtech/n=%d", n), func(b *testing.B) {
			tree, err := buildWeald(d)
			if err != nil {
				b.Fatal(err)
			}
			proof, err := tree.GenerateProof(last)
			if err != nil {
				b.Fatal(err)
			}
			root := tree.Root()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ok, err := weald.VerifyProofUsing(last, proof, root, wealdSHA256{}, nil)
				if err != nil || !ok {
					b.Fatalf("verify failed: %v %v", ok, err)
				}
			}
		})

		b.Run(fmt.Sprintf("onrik/n=%d", n), func(b *testing.B) {
			tree, err := buildOnrik(d)
			if err != nil {
				b.Fatal(err)
			}
			proof := tree.GetProof(n - 1)
			root := tree.Root()
			// onrik's VerifyProof starts its replay from the value it is handed, so
			// that value is the leaf hash rather than the leaf data. wealdtech's
			// equivalent takes the data and hashes it. Handing either one the other's
			// argument fails, which is worth knowing when porting between them.
			leafHash := tree.GetLeaf(n - 1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !tree.VerifyProof(proof, root, leafHash) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}
