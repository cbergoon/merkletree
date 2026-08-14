// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

// Command depthchart measures proof generation and proof verification across tree
// depths and writes the two charts the README carries.
//
// It reproduces the axes the txaty/go-merkletree project publishes - tree depth on x,
// nanoseconds on a log2 y - so that the two are directly comparable. A tree of depth d
// holds 2^d leaves, so the x axis is a doubling of work per step and the y axis has to
// be logarithmic for anything to be visible.
//
// The charts are emitted as SVG written by hand rather than by a plotting library, so
// regenerating them needs no dependency beyond this module and no toolchain beyond Go:
//
//	go run ./cmd/depthchart
//
// Timing uses testing.Benchmark, so each point gets an iteration count chosen from how
// long it actually takes rather than a fixed one. The quadratic series stop earlier than
// the rest; see maxDepth on each series for why.
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	cb "github.com/cbergoon/merkletree"
	txaty "github.com/txaty/go-merkletree"
	weald "github.com/wealdtech/go-merkletree"
)

// leafSize is held fixed so the x axis varies one thing: the number of leaves. Sixty
// four bytes is large enough that a leaf hash is a real SHA-256 block and small enough
// that the tree machinery is still visible rather than drowned by hashing.
const leafSize = 64

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

type content struct{ data []byte }

func (c content) CalculateHash() ([]byte, error) { s := sha256.Sum256(c.data); return s[:], nil }
func (c content) Equals(o cb.Content) (bool, error) {
	x, ok := o.(content)

	return ok && bytes.Equal(c.data, x.data), nil
}

type block struct{ data []byte }

func (b block) Serialize() ([]byte, error) { return b.data, nil }

type sha256Hash struct{}

func (sha256Hash) Hash(d []byte) []byte { s := sha256.Sum256(d); return s[:] }

func txatyHash(b []byte) ([]byte, error) { s := sha256.Sum256(b); return s[:], nil }

func leaves(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, leafSize)
		copy(b, fmt.Sprintf("leaf-%d-", i))
		for j := 16; j < leafSize; j++ {
			b[j] = byte(i*31 + j)
		}
		out = append(out, b)
	}

	return out
}

func contents(d [][]byte) []cb.Content {
	cs := make([]cb.Content, 0, len(d))
	for _, x := range d {
		cs = append(cs, content{data: x})
	}

	return cs
}

func blocks(d [][]byte) []txaty.DataBlock {
	bs := make([]txaty.DataBlock, 0, len(d))
	for _, x := range d {
		bs = append(bs, block{data: x})
	}

	return bs
}

// ---------------------------------------------------------------------------
// Series
// ---------------------------------------------------------------------------

// series is one line on one chart. fn does the whole measured operation from a cold
// start, because that is what "generate the proofs for all blocks" means: a caller with
// data and no tree yet.
type series struct {
	name     string
	color    string
	maxDepth int // 0 means the global maximum
	fn       func(d [][]byte) error
}

// proofSeries are the "proof generation for all blocks" lines: build a tree over the
// blocks and come away holding every proof.
var proofSeries = []series{
	{
		name:  "cbergoon/merkletree (append)",
		color: "#16a34a",
		fn: func(d [][]byte) error {
			t, err := cb.NewTree(contents(d))
			if err != nil {
				return err
			}
			// The proof slices are reused across every leaf, which is the whole
			// point of the Append forms: the loop allocates nothing per proof.
			var (
				path  [][]byte
				index []int64
			)
			for i := range d {
				if path, index, err = t.AppendMerklePathByIndex(path[:0], index[:0], i); err != nil {
					return err
				}
			}
			_ = index

			return nil
		},
	},
	{
		name:  "cbergoon/merkletree (append, parallel)",
		color: "#065f46",
		fn: func(d [][]byte) error {
			t, err := cb.NewTreeWithOptions(contents(d), cb.WithParallelism(0))
			if err != nil {
				return err
			}
			var (
				path  [][]byte
				index []int64
			)
			for i := range d {
				if path, index, err = t.AppendMerklePathByIndex(path[:0], index[:0], i); err != nil {
					return err
				}
			}
			_ = index

			return nil
		},
	},
	{
		name:  "cbergoon/merkletree (scan, no options)",
		color: "#94a3b8",
		// Quadratic: every proof scans every leaf. Runs the full range anyway,
		// because the divergence is the point and truncating the line would hide it.
		fn: func(d [][]byte) error {
			t, err := cb.NewTree(contents(d))
			if err != nil {
				return err
			}
			for _, c := range contents(d) {
				if _, _, err := t.GetMerklePath(c); err != nil {
					return err
				}
			}

			return nil
		},
	},
	{
		name:  "txaty/go-merkletree",
		color: "#f59e0b",
		fn: func(d [][]byte) error {
			_, err := txaty.New(&txaty.Config{HashFunc: txatyHash, Mode: txaty.ModeProofGen}, blocks(d))

			return err
		},
	},
	{
		name:  "txaty/go-merkletree (parallel)",
		color: "#dc2626",
		fn: func(d [][]byte) error {
			_, err := txaty.New(&txaty.Config{
				HashFunc:      txatyHash,
				Mode:          txaty.ModeProofGen,
				RunInParallel: true,
			}, blocks(d))

			return err
		},
	},
	{
		name:  "wealdtech/go-merkletree",
		color: "#2563eb",
		// Also quadratic: GenerateProof scans to locate the data it was given.
		fn: func(d [][]byte) error {
			t, err := weald.NewUsing(d, sha256Hash{}, nil)
			if err != nil {
				return err
			}
			for _, x := range d {
				if _, err := t.GenerateProof(x); err != nil {
					return err
				}
			}

			return nil
		},
	},
}

// verifySeries are the "proof verification" lines: check one proof against a root. The
// tree and the proof are prepared outside the timed region, because verifying is what a
// party holding a root and a proof does, and it has no tree.
var verifySeries = []struct {
	name    string
	color   string
	prepare func(d [][]byte) (func() error, error)
}{
	{
		name:  "cbergoon/merkletree (VerifyProof)",
		color: "#16a34a",
		prepare: func(d [][]byte) (func() error, error) {
			t, err := cb.NewTree(contents(d))
			if err != nil {
				return nil, err
			}
			target := content{data: d[len(d)-1]}
			path, index, err := t.GetMerklePathByIndex(len(d) - 1)
			if err != nil {
				return nil, err
			}
			root := t.MerkleRoot()

			return func() error {
				ok, err := cb.VerifyProof(target, path, index, root)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("proof did not verify")
				}

				return nil
			}, nil
		},
	},
	{
		name:  "txaty/go-merkletree",
		color: "#f59e0b",
		prepare: func(d [][]byte) (func() error, error) {
			t, err := txaty.New(&txaty.Config{HashFunc: txatyHash, Mode: txaty.ModeTreeBuild}, blocks(d))
			if err != nil {
				return nil, err
			}
			target := block{data: d[len(d)-1]}
			proof, err := t.Proof(target)
			if err != nil {
				return nil, err
			}

			return func() error {
				ok, err := t.Verify(target, proof)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("proof did not verify")
				}

				return nil
			}, nil
		},
	},
	{
		name:  "wealdtech/go-merkletree",
		color: "#2563eb",
		prepare: func(d [][]byte) (func() error, error) {
			t, err := weald.NewUsing(d, sha256Hash{}, nil)
			if err != nil {
				return nil, err
			}
			target := d[len(d)-1]
			proof, err := t.GenerateProof(target)
			if err != nil {
				return nil, err
			}
			root := t.Root()

			return func() error {
				ok, err := weald.VerifyProofUsing(target, proof, root, sha256Hash{}, nil)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("proof did not verify")
				}

				return nil
			}, nil
		},
	},
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

type point struct {
	depth int
	ns    float64
}

type line struct {
	name   string
	color  string
	points []point
}

func measure(fn func() error) float64 {
	var failed error
	r := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := fn(); err != nil {
				failed = err
				b.FailNow()
			}
		}
	})
	if failed != nil {
		fmt.Fprintf(os.Stderr, "measurement failed: %v\n", failed)
		os.Exit(1)
	}

	return float64(r.T.Nanoseconds()) / float64(r.N)
}

func main() {
	minDepth := flag.Int("min", 1, "smallest tree depth")
	maxDepth := flag.Int("max", 18, "largest tree depth")
	outDir := flag.String("out", ".", "directory to write the charts into")
	only := flag.String("only", "both", "which chart to measure: gen, ver, or both")
	flag.Parse()

	data := make(map[int][][]byte)
	for d := *minDepth; d <= *maxDepth; d++ {
		data[d] = leaves(1 << d)
	}

	start := time.Now()

	var genLines []line
	for _, s := range proofSeries {
		if *only == "ver" {
			break
		}
		top := *maxDepth
		if s.maxDepth > 0 && s.maxDepth < top {
			top = s.maxDepth
		}
		l := line{name: s.name, color: s.color}
		for d := *minDepth; d <= top; d++ {
			// txaty rejects a single data block, so depth 0 is not reachable and
			// depth 1 is the smallest tree every library will build.
			ns := measure(func() error { return s.fn(data[d]) })
			l.points = append(l.points, point{depth: d, ns: ns})
			fmt.Fprintf(os.Stderr, "  gen  %-42s depth %2d  %12.0f ns\n", s.name, d, ns)
		}
		genLines = append(genLines, l)
	}

	var verLines []line
	for _, s := range verifySeries {
		if *only == "gen" {
			break
		}
		l := line{name: s.name, color: s.color}
		for d := *minDepth; d <= *maxDepth; d++ {
			run, err := s.prepare(data[d])
			if err != nil {
				fmt.Fprintf(os.Stderr, "prepare failed: %v\n", err)
				os.Exit(1)
			}
			ns := measure(run)
			l.points = append(l.points, point{depth: d, ns: ns})
			fmt.Fprintf(os.Stderr, "  ver  %-42s depth %2d  %12.0f ns\n", s.name, d, ns)
		}
		verLines = append(verLines, l)
	}

	if len(genLines) > 0 {
		write(filepath.Join(*outDir, "proof-generation.svg"),
			renderSVG("Proof Generation for All Blocks", genLines, *minDepth, *maxDepth))
	}
	if len(verLines) > 0 {
		write(filepath.Join(*outDir, "proof-verification.svg"),
			renderSVG("Proof Verification", verLines, *minDepth, *maxDepth))
	}
	if len(genLines) > 0 && len(verLines) > 0 {
		write(filepath.Join(*outDir, "depthchart.md"), renderTable(genLines, verLines))
	}

	fmt.Fprintf(os.Stderr, "\ndone in %s\n", time.Since(start).Round(time.Second))
}

func write(path, body string) {
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
}

// ---------------------------------------------------------------------------
// SVG
// ---------------------------------------------------------------------------

const (
	svgW, svgH = 760, 560
	padL, padR = 78, 24
	padT, padB = 96, 64
)

// renderSVG draws the lines on a linear depth axis and a log2 time axis. It is written
// out by hand because a chart this shape is a few dozen lines of arithmetic, and a
// plotting dependency would be the only dependency in the repository.
func renderSVG(title string, lines []line, minD, maxD int) string {
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, l := range lines {
		for _, p := range l.points {
			e := math.Log2(p.ns)
			lo = math.Min(lo, e)
			hi = math.Max(hi, e)
		}
	}
	lo, hi = math.Floor(lo)-0.5, math.Ceil(hi)+0.5

	plotW := float64(svgW - padL - padR)
	plotH := float64(svgH - padT - padB)
	x := func(d int) float64 {
		if maxD == minD {
			return padL
		}

		return padL + plotW*float64(d-minD)/float64(maxD-minD)
	}
	y := func(ns float64) float64 {
		return padT + plotH*(hi-math.Log2(ns))/(hi-lo)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif">`, svgW, svgH, svgW, svgH)
	// A white plot ground, so the chart reads the same in a light or dark README.
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, svgW, svgH)
	fmt.Fprintf(&b, `<text x="%d" y="34" text-anchor="middle" font-size="19" font-weight="600" fill="#0f172a">%s</text>`, svgW/2, esc(title))

	// Horizontal gridlines. A chart spanning thirty powers of two needs them thinned
	// out; one spanning four would be bare without every one.
	step := 2.0
	if hi-lo <= 8 {
		step = 1
	}
	for e := math.Ceil(lo); e <= hi; e++ {
		if math.Mod(e, step) != 0 {
			continue
		}
		yy := y(math.Pow(2, e))
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#e2e8f0" stroke-width="1"/>`,
			float64(padL), yy, float64(svgW-padR), yy)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="end" font-size="12" fill="#475569">2^%d</text>`,
			float64(padL)-9, yy+4, int(e))
	}
	// Vertical gridlines every second depth.
	for d := minD; d <= maxD; d++ {
		if d%2 != 0 {
			continue
		}
		xx := x(d)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#f1f5f9" stroke-width="1"/>`,
			xx, float64(padT), xx, float64(svgH-padB))
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="12" fill="#475569">%d</text>`,
			xx, float64(svgH-padB)+20, d)
	}

	// Axes.
	fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#334155" stroke-width="1.4"/>`,
		float64(padL), float64(padT), float64(padL), float64(svgH-padB))
	fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#334155" stroke-width="1.4"/>`,
		float64(padL), float64(svgH-padB), float64(svgW-padR), float64(svgH-padB))
	fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" font-size="13" font-weight="600" fill="#0f172a">Tree Depth</text>`,
		svgW/2, svgH-16)
	fmt.Fprintf(&b, `<text transform="translate(20,%d) rotate(-90)" text-anchor="middle" font-size="13" font-weight="600" fill="#0f172a">Time (ns)</text>`,
		padT+int(plotH)/2)

	// Lines, drawn before the legend so the legend sits on top.
	for _, l := range lines {
		if len(l.points) == 0 {
			continue
		}
		var pts []string
		for _, p := range l.points {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f", x(p.depth), y(p.ns)))
		}
		fmt.Fprintf(&b, `<polyline fill="none" stroke="%s" stroke-width="2.2" stroke-linejoin="round" points="%s"/>`,
			l.color, strings.Join(pts, " "))
		for _, p := range l.points {
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3.1" fill="%s"/>`, x(p.depth), y(p.ns), l.color)
		}
	}

	// Legend, top left inside the plot where these curves leave room.
	lx, ly := float64(padL)+14, float64(padT)+14
	fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="300" height="%d" rx="5" fill="#ffffff" fill-opacity="0.92" stroke="#cbd5e1"/>`,
		lx, ly, 20*len(lines)+12)
	for i, l := range lines {
		yy := ly + 20 + float64(i*20)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="2.6"/>`,
			lx+10, yy-4, lx+34, yy-4, l.color)
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3.1" fill="%s"/>`, lx+22, yy-4, l.color)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" font-size="12.5" fill="#0f172a">%s</text>`, lx+42, yy, esc(l.name))
	}

	b.WriteString(`</svg>`)

	return b.String()
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// renderTable writes the same measurements as markdown, so the numbers behind the
// pictures are reviewable and diffable.
func renderTable(gen, ver []line) string {
	var b strings.Builder
	b.WriteString("# Depth sweep\n\nGenerated by `go run ./cmd/depthchart`. A tree of depth *d* holds 2^*d* leaves of ")
	fmt.Fprintf(&b, "%d bytes. Times are ns/op.\n", leafSize)

	section := func(title string, lines []line) {
		fmt.Fprintf(&b, "\n## %s\n\n| depth | leaves |", title)
		for _, l := range lines {
			fmt.Fprintf(&b, " %s |", l.name)
		}
		b.WriteString("\n|---|---|")
		for range lines {
			b.WriteString("---|")
		}
		b.WriteString("\n")

		depths := map[int]bool{}
		for _, l := range lines {
			for _, p := range l.points {
				depths[p.depth] = true
			}
		}
		var ds []int
		for d := range depths {
			ds = append(ds, d)
		}
		sort.Ints(ds)

		for _, d := range ds {
			fmt.Fprintf(&b, "| %d | %d |", d, 1<<d)
			for _, l := range lines {
				cell := "—"
				for _, p := range l.points {
					if p.depth == d {
						cell = fmt.Sprintf("%.0f", p.ns)
					}
				}
				fmt.Fprintf(&b, " %s |", cell)
			}
			b.WriteString("\n")
		}
	}

	section("Proof generation for all blocks", gen)
	section("Proof verification", ver)

	return b.String()
}
