// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"math/big"
	"math/rand"
	"testing"
)

// compareBigEndian replaced a big.Int comparison on the path that decides which
// sibling is hashed first, and therefore what root a sorted tree produces. These tests
// hold it against the implementation it replaced rather than against a restatement of
// what it is meant to do.

// bigIntCompare is the original implementation, kept here as the oracle.
func bigIntCompare(a, b []byte) int {
	var aBig, bBig big.Int
	aBig.SetBytes(a)
	bBig.SetBytes(b)

	return aBig.Cmp(&bBig)
}

func TestCompareBigEndianMatchesBigInt(t *testing.T) {
	cases := [][2][]byte{
		// The pairs where a lexicographic comparison would disagree: read as
		// integers {0x01, 0x00} is 256 and {0xff} is 255, so a is the larger,
		// but bytes.Compare would call it smaller on the strength of 0x01 < 0xff.
		{{0x01, 0x00}, {0xff}},
		{{0xff}, {0x01, 0x00}},
		// Leading zeros carry no value, so these are equal.
		{{0x00, 0x01}, {0x01}},
		{{0x01}, {0x00, 0x00, 0x01}},
		{{0x00}, {}},
		{{}, {0x00, 0x00}},
		// Equal width, which is the case every same-strategy digest pair takes.
		{{0x01, 0x02}, {0x01, 0x03}},
		{{0xff, 0xff}, {0xff, 0xff}},
		{{0x00, 0x00}, {0x00, 0x00}},
		// Empty against non-empty.
		{{}, {0x01}},
		{{0x01}, {}},
	}

	for _, tc := range cases {
		a, b := tc[0], tc[1]
		want := bigIntCompare(a, b)
		if got := compareBigEndian(a, b); got != want {
			t.Errorf("error: compareBigEndian(%x, %x) = %d, big.Int says %d", a, b, got, want)
		}
	}
}

// TestCompareBigEndianExhaustiveShort covers every byte string up to two bytes long
// over an alphabet chosen to include the zero, low and high bytes.
func TestCompareBigEndianExhaustiveShort(t *testing.T) {
	alphabet := []byte{0x00, 0x01, 0x7f, 0xff}

	var inputs [][]byte
	inputs = append(inputs, []byte{})
	for _, x := range alphabet {
		inputs = append(inputs, []byte{x})
		for _, y := range alphabet {
			inputs = append(inputs, []byte{x, y})
		}
	}

	for _, a := range inputs {
		for _, b := range inputs {
			want := bigIntCompare(a, b)
			if got := compareBigEndian(a, b); got != want {
				t.Fatalf("error: compareBigEndian(%x, %x) = %d, big.Int says %d", a, b, got, want)
			}
		}
	}
}

func TestCompareBigEndianRandomAgreesWithBigInt(t *testing.T) {
	r := rand.New(rand.NewSource(1))

	for i := 0; i < 200000; i++ {
		a := make([]byte, r.Intn(9))
		b := make([]byte, r.Intn(9))
		r.Read(a)
		r.Read(b)
		// Bias towards leading zeros and shared prefixes, which is where the two
		// implementations are most likely to part company.
		if len(a) > 0 && r.Intn(3) == 0 {
			a[0] = 0
		}
		if len(b) > 0 && r.Intn(3) == 0 {
			b[0] = 0
		}
		if len(a) == len(b) && len(a) > 1 && r.Intn(2) == 0 {
			copy(b[:len(b)-1], a[:len(a)-1])
		}

		want := bigIntCompare(a, b)
		if got := compareBigEndian(a, b); got != want {
			t.Fatalf("error: compareBigEndian(%x, %x) = %d, big.Int says %d", a, b, got, want)
		}
	}
}

// TestCompareBigEndianDoesNotModifyInput guards the leading-zero trimming, which walks
// the slices it is given.
func TestCompareBigEndianDoesNotModifyInput(t *testing.T) {
	a := []byte{0x00, 0x00, 0x01, 0x02}
	b := []byte{0x00, 0x03}
	aCopy := append([]byte(nil), a...)
	bCopy := append([]byte(nil), b...)

	compareBigEndian(a, b)

	if string(a) != string(aCopy) {
		t.Errorf("error: compareBigEndian modified a: %x, want %x", a, aCopy)
	}
	if string(b) != string(bCopy) {
		t.Errorf("error: compareBigEndian modified b: %x, want %x", b, bCopy)
	}
}

// TestSortPairMatchesBigIntOrdering checks the swap decision itself, including that a
// numerically equal pair still swaps the way the original did.
func TestSortPairMatchesBigIntOrdering(t *testing.T) {
	r := rand.New(rand.NewSource(2))

	for i := 0; i < 50000; i++ {
		a := make([]byte, r.Intn(6))
		b := make([]byte, r.Intn(6))
		r.Read(a)
		r.Read(b)

		wantA, wantB := a, b
		if bigIntCompare(a, b) != -1 {
			wantA, wantB = b, a
		}

		gotA, gotB := sortPair(true, a, b)
		if string(gotA) != string(wantA) || string(gotB) != string(wantB) {
			t.Fatalf("error: sortPair(true, %x, %x) = (%x, %x), want (%x, %x)", a, b, gotA, gotB, wantA, wantB)
		}

		// Unsorted mode must never reorder.
		gotA, gotB = sortPair(false, a, b)
		if string(gotA) != string(a) || string(gotB) != string(b) {
			t.Fatalf("error: sortPair(false, %x, %x) reordered to (%x, %x)", a, b, gotA, gotB)
		}
	}
}

// TestSortAppendStillMatchesBigInt keeps the concatenating helper, which the tests use
// as a reference implementation when recomputing paths by hand, in step with the
// ordering the tree itself now applies.
func TestSortAppendStillMatchesBigInt(t *testing.T) {
	r := rand.New(rand.NewSource(3))

	for i := 0; i < 20000; i++ {
		a := make([]byte, r.Intn(6))
		b := make([]byte, r.Intn(6))
		r.Read(a)
		r.Read(b)

		first, second := a, b
		if bigIntCompare(a, b) != -1 {
			first, second = b, a
		}
		want := append(append([]byte{}, first...), second...)

		if got := sortAppend(true, a, b); string(got) != string(want) {
			t.Fatalf("error: sortAppend(true, %x, %x) = %x, want %x", a, b, got, want)
		}
	}
}
