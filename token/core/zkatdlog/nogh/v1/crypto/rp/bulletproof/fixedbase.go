/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bulletproof

import (
	"crypto/sha256"
	"sync"

	mathlib "github.com/IBM/mathlib"
	math2 "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/math"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

const (
	fixedBaseWindow  = 8
	fixedBaseWindows = (fr.Bits + fixedBaseWindow - 1) / fixedBaseWindow
)

// fixedBases precomputes 2^(8k)·B for every range proof base B on BN254, so a
// multi-scalar multiplication over them is a single bucket pass with no doublings.
// Base order: left generators, right generators, P, Q, Pedersen G, Pedersen H, sum of left generators.
type fixedBases struct {
	n     int
	table [][fixedBaseWindows]bn254.G1Affine
	curve *mathlib.Curve
}

var fixedBasesCache sync.Map // [sha256.Size]byte -> *fixedBases

// fixedBasesFor returns the shared table for these bases, or nil when the curve is not BN254.
func fixedBasesFor(curve *mathlib.Curve, left, right []*mathlib.G1, P, Q *mathlib.G1, pedersen []*mathlib.G1) (*fixedBases, error) {
	if _, isBN254 := math2.DispatchCurve(curve); !isBN254 {
		return nil, nil
	}
	if len(left) != len(right) || len(pedersen) < 2 {
		return nil, errors.New("invalid range proof bases")
	}
	bases := make([]*mathlib.G1, 0, 2*len(left)+4)
	bases = append(bases, left...)
	bases = append(bases, right...)
	bases = append(bases, P, Q, pedersen[0], pedersen[1])
	sumLeft := left[0].Copy()
	for _, g := range left[1:] {
		sumLeft.Add(g)
	}
	bases = append(bases, sumLeft)

	h := sha256.New()
	for _, b := range bases {
		_, _ = h.Write(b.Bytes())
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	if fb, ok := fixedBasesCache.Load(key); ok {
		return fb.(*fixedBases), nil
	}

	fb := &fixedBases{n: len(left), table: make([][fixedBaseWindows]bn254.G1Affine, len(bases)), curve: curve}
	jac := make([]bn254.G1Jac, fixedBaseWindows)
	for i, b := range bases {
		var a bn254.G1Affine
		if _, err := a.SetBytes(b.Bytes()); err != nil {
			return nil, errors.Wrap(err, "invalid range proof base")
		}
		var cur bn254.G1Jac
		cur.FromAffine(&a)
		for k := range jac {
			jac[k] = cur
			for range fixedBaseWindow {
				cur.DoubleAssign()
			}
		}
		copy(fb.table[i][:], bn254.BatchJacobianToAffineG1(jac))
	}
	actual, _ := fixedBasesCache.LoadOrStore(key, fb)

	return actual.(*fixedBases), nil
}

func (f *fixedBases) leftIdx(i int) int  { return i }
func (f *fixedBases) rightIdx(i int) int { return f.n + i }
func (f *fixedBases) pIdx() int          { return 2 * f.n }
func (f *fixedBases) qIdx() int          { return 2*f.n + 1 }
func (f *fixedBases) gIdx() int          { return 2*f.n + 2 }
func (f *fixedBases) hIdx() int          { return 2*f.n + 3 }
func (f *fixedBases) sumLeftIdx() int    { return 2*f.n + 4 }

type fixedBaseBuckets [1<<(fixedBaseWindow-1) + 1]bn254.G1Jac

var fixedBaseBucketPool = sync.Pool{New: func() any { return new(fixedBaseBuckets) }}

// msm returns sum_i scalars[i]·base[idx[i]], using signed window digits in [-128, 128).
// A scalar below 2^254 never carries past the last window.
func (f *fixedBases) msm(idx []int, scalars []*mathlib.Zr) (*mathlib.G1, error) {
	buckets := fixedBaseBucketPool.Get().(*fixedBaseBuckets)
	defer fixedBaseBucketPool.Put(buckets)
	*buckets = fixedBaseBuckets{}

	var s fr.Element
	var neg bn254.G1Affine
	for i, z := range scalars {
		math2.SetNativeFromZr[fr.Element, *fr.Element](z, &s)
		limbs := s.Bits()
		row := &f.table[idx[i]]
		carry := uint64(0)
		for k := range fixedBaseWindows {
			bit := k * fixedBaseWindow
			d := (limbs[bit/64]>>(bit%64))&(1<<fixedBaseWindow-1) + carry
			carry = 0
			if d >= 1<<(fixedBaseWindow-1) {
				carry = 1
				if d = 1<<fixedBaseWindow - d; d != 0 {
					neg.Neg(&row[k])
					buckets[d].AddMixed(&neg)
				}
			} else if d != 0 {
				buckets[d].AddMixed(&row[k])
			}
		}
	}
	var running, total bn254.G1Jac
	for d := len(buckets) - 1; d >= 1; d-- {
		running.AddAssign(&buckets[d])
		total.AddAssign(&running)
	}

	return f.toG1(&total)
}

// commitBits returns sum_i b_i·G_i + (b_i-1)·H_i + rho·P for the bits b_i of value.
// Every bit costs exactly one addition, of either G_i or -H_i.
func (f *fixedBases) commitBits(value uint64, rho *mathlib.Zr) (*mathlib.G1, error) {
	blind, err := f.msm([]int{f.pIdx()}, []*mathlib.Zr{rho})
	if err != nil {
		return nil, err
	}
	var acc bn254.G1Jac
	var negH bn254.G1Affine
	for i := range f.n {
		negH.Neg(&f.table[f.rightIdx(i)][0])
		pick := &negH
		if value>>i&1 == 1 {
			pick = &f.table[f.leftIdx(i)][0]
		}
		acc.AddMixed(pick)
	}
	sum, err := f.toG1(&acc)
	if err != nil {
		return nil, err
	}
	sum.Add(blind)

	return sum, nil
}

// commitVectors returns sum_i left_i·G_i + right_i·H_i (+ extra·P when extra is non-nil).
func (f *fixedBases) commitVectors(left, right []*mathlib.Zr, extra *mathlib.Zr) (*mathlib.G1, error) {
	idx := make([]int, 0, 2*f.n+1)
	scalars := make([]*mathlib.Zr, 0, 2*f.n+1)
	for i := range left {
		idx = append(idx, f.leftIdx(i), f.rightIdx(i))
		scalars = append(scalars, left[i], right[i])
	}
	if extra != nil {
		idx = append(idx, f.pIdx())
		scalars = append(scalars, extra)
	}

	return f.msm(idx, scalars)
}

// pedersen returns a·G + b·H.
func (f *fixedBases) pedersen(a, b *mathlib.Zr) (*mathlib.G1, error) {
	return f.msm([]int{f.gIdx(), f.hIdx()}, []*mathlib.Zr{a, b})
}

func (f *fixedBases) toG1(p *bn254.G1Jac) (*mathlib.G1, error) {
	var a bn254.G1Affine
	a.FromJacobian(p)
	raw := a.RawBytes()

	return f.curve.NewG1FromBytes(raw[:])
}
