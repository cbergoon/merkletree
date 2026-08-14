// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// WithParallelism must not change what a tree is, only how fast it is assembled. These
// tests hold a parallel build against the serial build of the same content and require
// the two to be indistinguishable, then cover the things goroutines add: error and panic
// delivery, and whether any concurrency happens at all.

type parallelMode struct {
	name string
	opts []TreeOption
}

var parallelModes = []parallelMode{
	{name: "default"},
	{name: "sorted", opts: []TreeOption{WithSortedSiblings()}},
	{name: "rfc6962", opts: []TreeOption{WithRFC6962()}},
}

// Sizes bracket the point where interior levels start being split up, and include odd
// counts so the padding leaf is exercised in both build paths.
var parallelSizes = []int{1, 2, 3, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 2048, 4097}

func parallelContents(n int) []Content {
	cs := make([]Content, 0, n)
	for i := 0; i < n; i++ {
		cs = append(cs, TestSHA256Content{x: fmt.Sprintf("item-%d", i)})
	}

	return cs
}

// assertTreesIdentical walks two trees together and requires every node to agree.
func assertTreesIdentical(t *testing.T, label string, want, got *MerkleTree) {
	t.Helper()

	if !bytes.Equal(want.MerkleRoot(), got.MerkleRoot()) {
		t.Fatalf("%s: expected root %x, got %x", label, want.MerkleRoot(), got.MerkleRoot())
	}
	if len(want.Leafs) != len(got.Leafs) {
		t.Fatalf("%s: expected %d leaves, got %d", label, len(want.Leafs), len(got.Leafs))
	}
	for i := range want.Leafs {
		if !bytes.Equal(want.Leafs[i].Hash, got.Leafs[i].Hash) {
			t.Fatalf("%s: leaf %d hash %x, got %x", label, i, want.Leafs[i].Hash, got.Leafs[i].Hash)
		}
		if want.Leafs[i].dup != got.Leafs[i].dup {
			t.Errorf("%s: leaf %d dup %t, got %t", label, i, want.Leafs[i].dup, got.Leafs[i].dup)
		}
		if want.Leafs[i].leaf != got.Leafs[i].leaf {
			t.Errorf("%s: leaf %d leaf flag %t, got %t", label, i, want.Leafs[i].leaf, got.Leafs[i].leaf)
		}
	}

	var walk func(path string, a, b *Node)
	walk = func(path string, a, b *Node) {
		if a == nil || b == nil {
			if a != b {
				t.Fatalf("%s: node %s present in one tree only", label, path)
			}

			return
		}
		if !bytes.Equal(a.Hash, b.Hash) {
			t.Fatalf("%s: node %s hash %x, got %x", label, path, a.Hash, b.Hash)
		}
		if (a.Parent == nil) != (b.Parent == nil) {
			t.Fatalf("%s: node %s parent linkage differs", label, path)
		}
		if b.Tree != got {
			t.Fatalf("%s: node %s does not point at its own tree", label, path)
		}
		walk(path+"L", a.Left, b.Left)
		walk(path+"R", a.Right, b.Right)
	}
	walk("root", want.Root, got.Root)

	if want.String() != got.String() {
		t.Errorf("%s: string forms differ", label)
	}
}

func TestParallelBuildMatchesSerial(t *testing.T) {
	for _, mode := range parallelModes {
		for _, n := range parallelSizes {
			cs := parallelContents(n)

			serial, err := NewTreeWithOptions(cs, mode.opts...)
			if err != nil {
				t.Fatalf("[%s/n=%d] error: unexpected error building serially: %v", mode.name, n, err)
			}

			for _, workers := range []int{0, 1, 2, 3, 8, 64, 4096} {
				opts := append(append([]TreeOption{}, mode.opts...), WithParallelism(workers))
				got, err := NewTreeWithOptions(cs, opts...)
				if err != nil {
					t.Fatalf("[%s/n=%d/w=%d] error: unexpected error: %v", mode.name, n, workers, err)
				}

				label := fmt.Sprintf("[%s/n=%d/w=%d]", mode.name, n, workers)
				assertTreesIdentical(t, label, serial, got)

				ok, err := got.VerifyTree()
				if err != nil {
					t.Fatalf("%s error: unexpected error verifying: %v", label, err)
				}
				if !ok {
					t.Errorf("%s error: expected the tree to verify", label)
				}
			}
		}
	}
}

// TestParallelBuildIsRepeatable runs the same parallel build many times over. A result
// that depended on the order goroutines finished in would show up as a root that moves
// between runs.
func TestParallelBuildIsRepeatable(t *testing.T) {
	for _, mode := range parallelModes {
		cs := parallelContents(2500)
		want, err := NewTreeWithOptions(cs, mode.opts...)
		if err != nil {
			t.Fatalf("[%s] error: unexpected error: %v", mode.name, err)
		}

		for i := 0; i < 50; i++ {
			opts := append(append([]TreeOption{}, mode.opts...), WithParallelism(0))
			got, err := NewTreeWithOptions(cs, opts...)
			if err != nil {
				t.Fatalf("[%s] error: unexpected error on pass %d: %v", mode.name, i, err)
			}
			if !bytes.Equal(want.MerkleRoot(), got.MerkleRoot()) {
				t.Fatalf("[%s] error: pass %d produced root %x, want %x", mode.name, i, got.MerkleRoot(), want.MerkleRoot())
			}
		}
	}
}

// concurrencyProbe records the greatest number of CalculateHash calls in flight at once.
type concurrencyProbe struct {
	current int32
	peak    int32
}

type probeContent struct {
	x     string
	probe *concurrencyProbe
}

func (c probeContent) CalculateHash() ([]byte, error) {
	inFlight := atomic.AddInt32(&c.probe.current, 1)
	for {
		peak := atomic.LoadInt32(&c.probe.peak)
		if inFlight <= peak || atomic.CompareAndSwapInt32(&c.probe.peak, peak, inFlight) {
			break
		}
	}
	// Linger so that overlap is observable rather than a matter of luck. A serial
	// build simply takes longer; it does not block.
	time.Sleep(time.Millisecond)
	atomic.AddInt32(&c.probe.current, -1)

	return TestSHA256Content{x: c.x}.CalculateHash()
}

func (c probeContent) Equals(other Content) (bool, error) {
	o, ok := other.(probeContent)
	if !ok {
		return false, nil
	}

	return c.x == o.x, nil
}

// TestParallelActuallyRunsConcurrently guards against the option quietly becoming a no-op,
// which would leave every other test in this file passing for the wrong reason.
func TestParallelActuallyRunsConcurrently(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs more than one processor to observe overlap")
	}

	build := func(workers int) int32 {
		probe := &concurrencyProbe{}
		cs := make([]Content, 0, 64)
		for i := 0; i < 64; i++ {
			cs = append(cs, probeContent{x: fmt.Sprintf("item-%d", i), probe: probe})
		}

		opts := []TreeOption{}
		if workers > 0 {
			opts = append(opts, WithParallelism(workers))
		}
		if _, err := NewTreeWithOptions(cs, opts...); err != nil {
			t.Fatalf("error: unexpected error: %v", err)
		}

		return atomic.LoadInt32(&probe.peak)
	}

	if peak := build(0); peak != 1 {
		t.Errorf("error: a serial build should never have two hashes in flight, saw %d", peak)
	}
	if peak := build(8); peak < 2 {
		t.Errorf("error: expected a parallel build to overlap content hashing, peak in flight was %d", peak)
	}
}

// TestParallelismOfOneIsSerial checks the documented boundary: one worker means the
// serial path, so a Content that is not safe for concurrent use is not surprised.
func TestParallelismOfOneIsSerial(t *testing.T) {
	probe := &concurrencyProbe{}
	cs := make([]Content, 0, 32)
	for i := 0; i < 32; i++ {
		cs = append(cs, probeContent{x: fmt.Sprintf("item-%d", i), probe: probe})
	}

	if _, err := NewTreeWithOptions(cs, WithParallelism(1)); err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if peak := atomic.LoadInt32(&probe.peak); peak != 1 {
		t.Errorf("error: WithParallelism(1) should not overlap, peak in flight was %d", peak)
	}
}

type indexFailContent struct {
	i    int
	fail bool
}

func (c indexFailContent) CalculateHash() ([]byte, error) {
	if c.fail {
		return nil, fmt.Errorf("content %d refused to hash", c.i)
	}

	return TestSHA256Content{x: fmt.Sprintf("item-%d", c.i)}.CalculateHash()
}

func (c indexFailContent) Equals(other Content) (bool, error) {
	o, ok := other.(indexFailContent)
	if !ok {
		return false, nil
	}

	return c.i == o.i, nil
}

// TestParallelErrorIsLowestIndex pins which of several failures is reported. Returning
// whichever goroutine lost the race would make the same input fail differently run to
// run.
func TestParallelErrorIsLowestIndex(t *testing.T) {
	cs := make([]Content, 0, 2000)
	for i := 0; i < 2000; i++ {
		cs = append(cs, indexFailContent{i: i, fail: i == 137 || i == 900 || i == 1801})
	}

	for i := 0; i < 50; i++ {
		_, err := NewTreeWithOptions(cs, WithParallelism(0))
		if err == nil {
			t.Fatal("error: expected an error")
		}
		if err.Error() != "content 137 refused to hash" {
			t.Fatalf("error: expected the lowest failing index reported, got %q", err.Error())
		}
	}
}

func TestParallelNilContentRejected(t *testing.T) {
	cs := make([]Content, 0, 500)
	for i := 0; i < 500; i++ {
		if i == 42 {
			cs = append(cs, nil)
			continue
		}
		cs = append(cs, TestSHA256Content{x: fmt.Sprintf("item-%d", i)})
	}

	for _, mode := range parallelModes {
		opts := append(append([]TreeOption{}, mode.opts...), WithParallelism(0))
		_, err := NewTreeWithOptions(cs, opts...)
		if !errors.Is(err, ErrNilContent) {
			t.Errorf("[%s] error: expected ErrNilContent, got %v", mode.name, err)
		}
	}
}

type panickingContent struct {
	i     int
	panic bool
}

func (c panickingContent) CalculateHash() ([]byte, error) {
	if c.panic {
		panic("content exploded")
	}

	return TestSHA256Content{x: fmt.Sprintf("item-%d", c.i)}.CalculateHash()
}

func (c panickingContent) Equals(other Content) (bool, error) { return false, nil }

// TestParallelPanicReachesCaller checks that a panic out of CalculateHash still arrives
// at the caller. Left alone in a worker goroutine it would take the process down instead,
// which is a worse outcome than the serial build gives.
func TestParallelPanicReachesCaller(t *testing.T) {
	cs := make([]Content, 0, 500)
	for i := 0; i < 500; i++ {
		cs = append(cs, panickingContent{i: i, panic: i == 300})
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("error: expected the panic to reach the caller")
		}
		if s, ok := r.(string); !ok || s != "content exploded" {
			t.Fatalf("error: expected the original panic value, got %v", r)
		}
	}()

	//nolint:errcheck // the panic is the subject of the test
	NewTreeWithOptions(cs, WithParallelism(0))
	t.Fatal("error: expected a panic")
}

// TestParallelRebuildAndSerialization covers the two places the setting outlives the
// original build: RebuildTree keeps it, and the serialized form deliberately drops it.
func TestParallelRebuildAndSerialization(t *testing.T) {
	cs := parallelContents(3000)

	want, err := NewTreeWithOptions(cs)
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	tree, err := NewTreeWithOptions(cs, WithParallelism(0))
	if err != nil {
		t.Fatalf("error: unexpected error: %v", err)
	}
	if tree.parallelism < 2 {
		t.Fatalf("error: expected WithParallelism(0) to resolve to GOMAXPROCS, got %d", tree.parallelism)
	}

	if err := tree.RebuildTree(); err != nil {
		t.Fatalf("error: unexpected error rebuilding: %v", err)
	}
	if tree.parallelism < 2 {
		t.Error("error: expected a rebuild to keep building in parallel")
	}
	assertTreesIdentical(t, "after rebuild", want, tree)

	data, err := tree.MarshalBinary()
	if err != nil {
		t.Fatalf("error: unexpected error marshaling: %v", err)
	}
	var decoded MerkleTree
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("error: unexpected error unmarshaling: %v", err)
	}
	if decoded.parallelism != 0 {
		t.Errorf("error: parallelism should not survive serialization, got %d", decoded.parallelism)
	}
	assertTreesIdentical(t, "after round trip", want, &decoded)
}

// TestParallelTreeSupportsEveryOperation checks that a tree built in parallel answers
// the rest of the API the same way, since the build is where the pointers get wired up.
func TestParallelTreeSupportsEveryOperation(t *testing.T) {
	for _, mode := range parallelModes {
		cs := parallelContents(1500)

		serial, err := NewTreeWithOptions(cs, mode.opts...)
		if err != nil {
			t.Fatalf("[%s] error: unexpected error: %v", mode.name, err)
		}
		opts := append(append([]TreeOption{}, mode.opts...), WithParallelism(0))
		got, err := NewTreeWithOptions(cs, opts...)
		if err != nil {
			t.Fatalf("[%s] error: unexpected error: %v", mode.name, err)
		}

		for _, i := range []int{0, 1, 7, 999, 1499} {
			ok, err := got.VerifyContent(cs[i])
			if err != nil {
				t.Fatalf("[%s] error: unexpected error verifying content: %v", mode.name, err)
			}
			if !ok {
				t.Errorf("[%s] error: expected content %d to verify", mode.name, i)
			}

			wantPath, wantIdx, err := serial.GetMerklePath(cs[i])
			if err != nil {
				t.Fatalf("[%s] error: unexpected error reading serial path: %v", mode.name, err)
			}
			gotPath, gotIdx, err := got.GetMerklePath(cs[i])
			if err != nil {
				t.Fatalf("[%s] error: unexpected error reading parallel path: %v", mode.name, err)
			}
			if len(wantPath) != len(gotPath) {
				t.Fatalf("[%s] error: path length %d, got %d", mode.name, len(wantPath), len(gotPath))
			}
			for k := range wantPath {
				if !bytes.Equal(wantPath[k], gotPath[k]) || wantIdx[k] != gotIdx[k] {
					t.Errorf("[%s] error: path element %d differs for content %d", mode.name, k, i)
				}
			}
		}
	}
}
