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
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
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

const (
	fixedBaseBuckets = 1<<(fixedBaseWindow-1) + 1
	// below this many pending additions a batch inversion no longer pays off
	fixedBaseMinBatch = 16
)

// fixedBaseOp adds +-table[row][window] to bucket b.
type fixedBaseOp struct {
	row    uint32
	window uint8
	b      uint8
	neg    bool
}

// fixedBaseState is the per-call scratch space of msm.
type fixedBaseState struct {
	pending, next, batch []fixedBaseOp
	den, inv             []fp.Element
	aff                  [fixedBaseBuckets]bn254.G1Affine
	jac                  [fixedBaseBuckets]bn254.G1Jac
	occupied, used       [fixedBaseBuckets]bool
}

var fixedBaseStatePool = sync.Pool{New: func() any { return new(fixedBaseState) }}

// msm returns sum_i scalars[i]·base[idx[i]], using signed window digits in [-128, 128).
// A scalar below 2^254 never carries past the last window.
// Buckets are accumulated in affine form, one addition per bucket per batch, sharing
// one field inversion per batch; additions with equal x and the tail go to Jacobian buckets.
func (f *fixedBases) msm(idx []int, scalars []*mathlib.Zr) (*mathlib.G1, error) {
	native := make([]fr.Element, len(scalars))
	for i, z := range scalars {
		math2.SetNativeFromZr[fr.Element, *fr.Element](z, &native[i])
	}

	return f.msmFr(idx, native)
}

// msmFr is msm over native scalars.
func (f *fixedBases) msmFr(idx []int, scalars []fr.Element) (*mathlib.G1, error) {
	st := fixedBaseStatePool.Get().(*fixedBaseState)
	defer fixedBaseStatePool.Put(st)
	st.jac = [fixedBaseBuckets]bn254.G1Jac{}
	st.occupied = [fixedBaseBuckets]bool{}

	pending := st.pending[:0]
	for i := range scalars {
		limbs := scalars[i].Bits()
		row := uint32(idx[i]) // #nosec G115 -- a table row index
		carry := uint64(0)
		for k := range fixedBaseWindows {
			bit := k * fixedBaseWindow
			d := (limbs[bit/64]>>(bit%64))&(1<<fixedBaseWindow-1) + carry
			carry = 0
			if d >= 1<<(fixedBaseWindow-1) {
				carry = 1
				if d = 1<<fixedBaseWindow - d; d != 0 {
					pending = append(pending, fixedBaseOp{row: row, window: uint8(k), b: uint8(d), neg: true})
				}
			} else if d != 0 {
				pending = append(pending, fixedBaseOp{row: row, window: uint8(k), b: uint8(d)})
			}
		}
	}

	next := st.next[:0]
	for len(pending) >= fixedBaseMinBatch {
		st.used = [fixedBaseBuckets]bool{}
		batch := st.batch[:0]
		next = next[:0]
		for _, op := range pending {
			p := f.point(op)
			switch {
			case st.used[op.b]:
				next = append(next, op)
			case !st.occupied[op.b]:
				st.used[op.b], st.occupied[op.b] = true, true
				st.aff[op.b] = *p
				if op.neg {
					st.aff[op.b].Neg(p)
				}
			case st.aff[op.b].X.Equal(&p.X):
				st.used[op.b] = true
				addOp(&st.jac[op.b], p, op.neg)
			default:
				st.used[op.b] = true
				batch = append(batch, op)
			}
		}
		f.addAffineBatch(st, batch)
		st.batch = batch
		pending, next = next, pending
	}
	for _, op := range pending {
		addOp(&st.jac[op.b], f.point(op), op.neg)
	}
	st.pending, st.next = pending, next

	var running, total bn254.G1Jac
	for d := fixedBaseBuckets - 1; d >= 1; d-- {
		if st.occupied[d] {
			running.AddMixed(&st.aff[d])
		}
		running.AddAssign(&st.jac[d])
		total.AddAssign(&running)
	}

	return f.toG1(&total)
}

// addAffineBatch adds each op's point into its affine bucket; buckets are distinct and
// no op shares its bucket's x, so every denominator is non-zero.
func (f *fixedBases) addAffineBatch(st *fixedBaseState, batch []fixedBaseOp) {
	n := len(batch)
	if cap(st.den) < n {
		st.den, st.inv = make([]fp.Element, n), make([]fp.Element, n)
	}
	den, inv := st.den[:n], st.inv[:n]
	var acc fp.Element
	acc.SetOne()
	for j, op := range batch {
		den[j].Sub(&f.point(op).X, &st.aff[op.b].X)
		inv[j] = acc
		acc.Mul(&acc, &den[j])
	}
	acc.Inverse(&acc)
	for j := n - 1; j >= 0; j-- {
		inv[j].Mul(&inv[j], &acc)
		acc.Mul(&acc, &den[j])
	}
	var y2, lambda, x3, t fp.Element
	for j, op := range batch {
		p := f.point(op)
		a := &st.aff[op.b]
		y2 = p.Y
		if op.neg {
			y2.Neg(&y2)
		}
		lambda.Sub(&y2, &a.Y)
		lambda.Mul(&lambda, &inv[j])
		x3.Square(&lambda)
		x3.Sub(&x3, &a.X)
		x3.Sub(&x3, &p.X)
		t.Sub(&a.X, &x3)
		t.Mul(&t, &lambda)
		t.Sub(&t, &a.Y)
		a.X, a.Y = x3, t
	}
}

func (f *fixedBases) point(op fixedBaseOp) *bn254.G1Affine {
	return &f.table[op.row][op.window]
}

func addOp(acc *bn254.G1Jac, p *bn254.G1Affine, neg bool) {
	if !neg {
		acc.AddMixed(p)

		return
	}
	var n bn254.G1Affine
	n.Neg(p)
	acc.AddMixed(&n)
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
