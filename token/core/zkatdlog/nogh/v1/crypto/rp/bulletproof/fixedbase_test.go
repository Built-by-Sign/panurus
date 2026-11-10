/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bulletproof

import (
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/require"
)

type fixedBaseSetup struct {
	curve           *math.Curve
	pedersen        []*math.G1
	left, right     []*math.G1
	P, Q            *math.G1
	bitLength, rnds uint64
}

func newFixedBaseSetup(t *testing.T, bitLength, rounds uint64) *fixedBaseSetup {
	t.Helper()
	curve := math.Curves[math.BN254]
	rand, err := curve.Rand()
	require.NoError(t, err)
	gen := func() *math.G1 { return curve.GenG1.Mul(curve.NewRandomZr(rand)) }
	s := &fixedBaseSetup{curve: curve, pedersen: []*math.G1{gen(), gen()}, P: gen(), Q: gen(), bitLength: bitLength, rnds: rounds}
	for range bitLength {
		s.left = append(s.left, gen())
		s.right = append(s.right, gen())
	}

	return s
}

func (s *fixedBaseSetup) bases(t *testing.T) *fixedBases {
	t.Helper()
	fb, err := fixedBasesFor(s.curve, s.left, s.right, s.P, s.Q, s.pedersen)
	require.NoError(t, err)
	require.NotNil(t, fb)

	return fb
}

func TestFixedBasesMSMMatchesGenericMSM(t *testing.T) {
	s := newFixedBaseSetup(t, 64, 6)
	fb := s.bases(t)
	rand, err := s.curve.Rand()
	require.NoError(t, err)

	all := append(append(append([]*math.G1{}, s.left...), s.right...), s.P, s.Q, s.pedersen[0], s.pedersen[1])
	minusOne := s.curve.ModNeg(s.curve.NewZrFromUint64(1), s.curve.GroupOrder)
	// boundary scalars, a repeated base, and random scalars over every base
	idx := []int{0, 1, 2, 3, fb.qIdx(), fb.qIdx()}
	scalars := []*math.Zr{s.curve.NewZrFromUint64(0), s.curve.NewZrFromUint64(1), minusOne, s.curve.NewZrFromUint64(255), s.curve.NewRandomZr(rand), s.curve.NewRandomZr(rand)}
	for i := range all {
		idx = append(idx, i)
		scalars = append(scalars, s.curve.NewRandomZr(rand))
	}
	points := make([]*math.G1, len(idx))
	for i, j := range idx {
		points[i] = all[j]
	}

	got, err := fb.msm(idx, scalars)
	require.NoError(t, err)
	require.True(t, s.curve.MultiScalarMul(points, scalars).Equals(got))
}

func TestFixedBasesCommitBitsMatchesVectorCommitment(t *testing.T) {
	s := newFixedBaseSetup(t, 64, 6)
	fb := s.bases(t)
	rand, err := s.curve.Rand()
	require.NoError(t, err)
	one := s.curve.NewZrFromUint64(1)

	for _, value := range []uint64{0, 1, 115, 1 << 63, ^uint64(0)} {
		left := make([]*math.Zr, s.bitLength)
		right := make([]*math.Zr, s.bitLength)
		for i := range s.bitLength {
			left[i] = s.curve.NewZrFromUint64(value >> i & 1)
			right[i] = s.curve.ModSub(left[i], one, s.curve.GroupOrder)
		}
		rho := s.curve.NewRandomZr(rand)

		got, err := fb.commitBits(value, rho)
		require.NoError(t, err)
		want := CommitVectorPlusOne(left, right, s.left, s.right, rho, s.P, s.curve)
		require.True(t, want.Equals(got), "value %d", value)
	}
}

func TestRangeCorrectnessWithFixedBasesVerifies(t *testing.T) {
	s := newFixedBaseSetup(t, 64, 6)
	rand, err := s.curve.Rand()
	require.NoError(t, err)

	values := []uint64{0, ^uint64(0), 1_000_000_000_000_000}
	bfs := make([]*math.Zr, len(values))
	coms := make([]*math.G1, len(values))
	for i, v := range values {
		bfs[i] = s.curve.NewRandomZr(rand)
		coms[i] = s.pedersen[0].Mul2(s.curve.NewZrFromUint64(v), s.pedersen[1], bfs[i])
	}

	rc, err := NewRangeCorrectnessProver(coms, values, bfs, s.pedersen, s.left, s.right, s.P, s.Q, s.bitLength, s.rnds, s.curve, nil).Prove()
	require.NoError(t, err)

	verifier := NewRangeCorrectnessVerifier(s.pedersen, s.left, s.right, s.P, s.Q, s.bitLength, s.rnds, s.curve, nil)
	verifier.Commitments = coms
	require.NoError(t, verifier.Verify(rc))

	// a proof for one commitment must not verify against another
	verifier.Commitments = []*math.G1{coms[1], coms[0], coms[2]}
	require.Error(t, verifier.Verify(rc))
}

func TestFixedBasesOnlyForBN254(t *testing.T) {
	curve := math.Curves[math.BLS12_381_BBS_GURVY]
	g := curve.GenG1
	fb, err := fixedBasesFor(curve, []*math.G1{g}, []*math.G1{g}, g, g, []*math.G1{g, g})
	require.NoError(t, err)
	require.Nil(t, fb)
}

func BenchmarkRangeProverFixedBases(b *testing.B) {
	t := &testing.T{}
	s := newFixedBaseSetup(t, 64, 6)
	rand, _ := s.curve.Rand()
	bf := s.curve.NewRandomZr(rand)
	value := uint64(1_000_000_000)
	com := s.pedersen[0].Mul2(s.curve.NewZrFromUint64(value), s.pedersen[1], bf)
	fb, _ := fixedBasesFor(s.curve, s.left, s.right, s.P, s.Q, s.pedersen)

	for _, tc := range []struct {
		name  string
		bases *fixedBases
	}{{"generic", nil}, {"fixed", fb}} {
		b.Run(tc.name, func(b *testing.B) {
			for range b.N {
				p := NewRangeProver(com, value, s.pedersen, bf, s.left, s.right, s.P, s.Q, s.rnds, s.bitLength, s.curve, nil)
				p.bases = tc.bases
				if _, err := p.Prove(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
