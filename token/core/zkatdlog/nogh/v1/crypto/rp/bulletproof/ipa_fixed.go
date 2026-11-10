/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bulletproof

import (
	mathlib "github.com/IBM/mathlib"
	math2 "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/math"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// reduceFixed is reduce on the fixed-base table, with every scalar kept in native BN254
// field elements: it produces the same L, R, left and right as the generic path.
func (p *ipaProver) reduceFixed(x0 *mathlib.Zr) (*mathlib.Zr, *mathlib.Zr, []*mathlib.G1, []*mathlib.G1, error) {
	f := p.bases
	left := toFr(p.leftVector)
	right := toFr(p.rightVector)
	weights := toFr(p.rightWeights)
	var x0E fr.Element
	math2.SetNativeFromZr[fr.Element, *fr.Element](x0, &x0E)

	LArray := make([]*mathlib.G1, p.NumberOfRounds)
	RArray := make([]*mathlib.G1, p.NumberOfRounds)
	challenges := make([]fr.Element, 0, p.NumberOfRounds)
	idxL := make([]int, 0, len(left)+1)
	idxR := make([]int, 0, len(left)+1)
	scL := make([]fr.Element, 0, len(left)+1)
	scR := make([]fr.Element, 0, len(left)+1)

	for i := range p.NumberOfRounds {
		n := len(left) / 2
		leftIP := innerProductFr(left[:n], right[n:])
		rightIP := innerProductFr(left[n:], right[:n])
		s, sInv := sVectorFr(1<<i, challenges)

		idxL, idxR, scL, scR = idxL[:0], idxR[:0], scL[:0], scR[:0]
		for m := range 1 << i {
			for j := range n {
				gR, hL := j+(2*m+1)*n, j+2*m*n
				gL, hR := hL, gR
				idxL = append(idxL, f.leftIdx(gR), f.rightIdx(hL))
				idxR = append(idxR, f.leftIdx(gL), f.rightIdx(hR))
				scL = append(scL, mulFr(left[j], s[m]), weighted(right[n+j], sInv[m], weights, hL))
				scR = append(scR, mulFr(left[n+j], s[m]), weighted(right[j], sInv[m], weights, hR))
			}
		}
		idxL, idxR = append(idxL, f.qIdx()), append(idxR, f.qIdx())
		scL = append(scL, mulFr(x0E, leftIP))
		scR = append(scR, mulFr(x0E, rightIP))

		var err error
		if LArray[i], err = f.msmFr(idxL, scL); err != nil {
			return nil, nil, nil, nil, err
		}
		if RArray[i], err = f.msmFr(idxR, scR); err != nil {
			return nil, nil, nil, nil, err
		}

		// same chained transcript as the generic path
		p.Transcript.Absorb(LArray[i].Bytes())
		p.Transcript.Absorb(RArray[i].Bytes())
		x, err := p.Transcript.Squeeze()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		var xE, xInvE fr.Element
		math2.SetNativeFromZr[fr.Element, *fr.Element](x, &xE)
		xInvE.Inverse(&xE)
		challenges = append(challenges, xE)

		// left' = left[:n]·x + left[n:]·x⁻¹, right' = right[:n]·x⁻¹ + right[n:]·x
		var a, b fr.Element
		for k := range n {
			a.Mul(&left[k], &xE)
			b.Mul(&left[k+n], &xInvE)
			left[k].Add(&a, &b)
			a.Mul(&right[k], &xInvE)
			b.Mul(&right[k+n], &xE)
			right[k].Add(&a, &b)
		}
		left, right = left[:n], right[:n]
	}

	return fromFr(&left[0], p.Curve), fromFr(&right[0], p.Curve), LArray, RArray, nil
}

func mulFr(a, b fr.Element) fr.Element {
	var out fr.Element
	out.Mul(&a, &b)

	return out
}

// weighted returns r·sInv·weights[i], or r·sInv when there are no weights.
func weighted(r, sInv fr.Element, weights []fr.Element, i int) fr.Element {
	var out fr.Element
	out.Mul(&r, &sInv)
	if weights != nil {
		out.Mul(&out, &weights[i])
	}

	return out
}

// sVectorFr is ComputeSVector over native elements; n == 1 yields s = sInv = (1).
func sVectorFr(n int, challenges []fr.Element) ([]fr.Element, []fr.Element) {
	s := make([]fr.Element, n)
	sInv := make([]fr.Element, n)
	s[0].SetOne()
	sInv[0].SetOne()
	log2n := len(challenges)
	for r := range log2n {
		c := &challenges[log2n-1-r]
		var cInv fr.Element
		cInv.Inverse(c)
		half := 1 << r
		for i := range half {
			s[i+half].Mul(&s[i], c)
			s[i].Mul(&s[i], &cInv)
			sInv[i+half].Mul(&sInv[i], &cInv)
			sInv[i].Mul(&sInv[i], c)
		}
	}

	return s, sInv
}

func innerProductFr(a, b []fr.Element) fr.Element {
	var sum, t fr.Element
	for i := range a {
		t.Mul(&a[i], &b[i])
		sum.Add(&sum, &t)
	}

	return sum
}

func toFr(v []*mathlib.Zr) []fr.Element {
	if v == nil {
		return nil
	}
	out := make([]fr.Element, len(v))
	for i, z := range v {
		math2.SetNativeFromZr[fr.Element, *fr.Element](z, &out[i])
	}

	return out
}

func fromFr(e *fr.Element, c *mathlib.Curve) *mathlib.Zr {
	return math2.NativeToZr[fr.Element, *fr.Element](e, c)
}
