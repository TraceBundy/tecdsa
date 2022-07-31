package curve

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func all() []EccCurveType {
	return []EccCurveType{K256}
}

func randomFieldElement(curve EccCurveType) EccFieldElement {
	for {
		buf, err := crand.Prime(crand.Reader, 256)

		fe, err := Field.FromBytes(curve, buf.Bytes())
		if err == nil {
			return fe
		}
	}
}

func TestOneMinusOneIsZero(t *testing.T) {
	for _, curve := range all() {
		one := Field.One(curve)
		negOne := Field.Zero(curve).Negate(one)
		zero := one.Add(one, negOne)
		assert.True(t, zero.IsZero() == 1)
	}
}

func TestOneFromBytesEqOne(t *testing.T) {
	for _, curve := range all() {
		var ones [32]byte
		ones[31] = 1
		one := Field.One(curve)
		oneFromBytes, err := Field.FromBytes(curve, ones[:])
		assert.Nil(t, err)
		oneFromWideBytes, err := Field.FromBytesWide(curve, ones[:])
		assert.Nil(t, err)
		assert.True(t, one.Equal(oneFromBytes) == 1)
		assert.True(t, one.Equal(oneFromWideBytes) == 1)
	}
}

func TestXMinusXIsZero(t *testing.T) {
	for _, curve := range all() {
		for trial := 0; trial < 100; trial++ {
			val := randomFieldElement(curve)
			negVal := Field.Zero(curve).Negate(val)
			assert.Equal(t, 1, Field.Zero(curve).Add(val, negVal).IsZero())
			assert.Equal(t, 1, Field.Zero(curve).Add(negVal, val).IsZero())

		}
	}
}

func TestNegOneXNegOneIsOne(t *testing.T) {
	for _, curve := range all() {
		one := Field.One(curve)
		negOne := Field.Zero(curve).Negate(one)
		assert.Equal(t, 1, one.Equal(Field.Zero(curve).Mul(negOne, negOne)))
	}
}

func TestCTAssignIsConditional(t *testing.T) {
	for _, curve := range all() {
		fe1 := randomFieldElement(curve)
		fe2 := randomFieldElement(curve)
		dest := Field.Zero(curve)
		dest.Assign(fe1)
		dest.CAssign(fe2, 0)
		assert.Equal(t, 1, dest.Equal(fe1))
		dest.CAssign(fe2, 1)
		assert.Equal(t, 1, dest.Equal(fe2))
	}
}

func TestFromBytesIsInverseOfAsBytes(t *testing.T) {
	for _, curve := range all() {
		for i := 0; i < 100; i++ {
			buf, err := crand.Prime(crand.Reader, 256)
			ec, err := Field.FromBytes(curve, buf.Bytes())
			if err != nil {
				assert.Equal(t, hex.EncodeToString(buf.Bytes()), hex.EncodeToString(ec.AsBytes()))
			}
		}
	}
}

func TestInverseIsCorrect(t *testing.T) {
	for _, curve := range all() {

		one := Field.One(curve)
		for i := 0; i < 100; i++ {
			fe := randomFieldElement(curve)
			feInv := Field.Zero(curve).Invert(fe)
			if feInv.IsZero() == 1 {
				assert.Equal(t, 1, fe.IsZero())
			} else {
				assert.Equal(t, 1, one.Equal(fe.Mul(fe, feInv)))
			}
		}
	}
}

func TestInverseOfZeroIsZero(t *testing.T) {
	for _, curve := range all() {
		zero := Field.Zero(curve)
		assert.Equal(t, 1, zero.Invert(zero).IsZero())
	}
}

func TestInverseOfOneIsOne(t *testing.T) {
	for _, curve := range all() {
		one := Field.One(curve)
		assert.Equal(t, 1, one.Equal(Field.Zero(curve).Invert(one)))
	}
}

func TestSqrtIsConsistentWithMath(t *testing.T) {
	for _, curve := range all() {
		for i := 0; i < 100; i++ {
			fe := randomFieldElement(curve)
			feSqrt, valid := Field.Zero(curve).Sqrt(fe)
			if valid == 0 {
				feNeg := Field.Zero(curve).Negate(fe)
				_, valid := feNeg.Sqrt(feNeg)
				assert.Equal(t, 1, valid)
			} else {
				assert.Equal(t, 1, feSqrt.Mul(feSqrt, feSqrt).Equal(fe))
			}
		}
	}
}
func TestABValuesAreCorrect(t *testing.T) {
	for _, curve := range all() {
		a := Field.A(curve)
		b := Field.B(curve)
		for {
			x := randomFieldElement(curve)
			x3 := Field.Zero(curve).Mul(x, x)
			x3 = x3.Mul(x3, x)
			ax := Field.Zero(curve).Mul(x, a)
			x3AxB := Field.Zero(curve).Add(x3, ax)
			x3AxB = x3AxB.Add(x3AxB, b)
			y, validY := x3AxB.Sqrt(x3AxB)
			if validY == 0 {
				continue
			}
			_, err := Point.FromFieldElems(x, y)
			assert.Nil(t, err)
			break
		}
	}
}

func TestSswuZValuesAreCorrect(t *testing.T) {
	sswuZValue := func(curve EccCurveType) int {
		one := Field.One(curve)
		z := Field.SswuZ(curve)
		cnt := 0
		for {
			if z.IsZero() == 1 {
				break
			}
			z = z.Add(z, one)
			cnt++
		}
		return -cnt
	}
	assert.Equal(t, -11, sswuZValue(K256))
}

func TestSswuC2ValuesAreCorrect(t *testing.T) {
	for _, curve := range all() {
		z := Field.SswuZ(curve)
		c2 := Field.SswuC2(curve)
		negZ := z.Negate(z)
		sqrtNegZ, _ := negZ.Sqrt(negZ)
		assert.Equal(t, 1, c2.Equal(sqrtNegZ))
	}
}

func TestFromBytesOfMaxIntegerRejected(t *testing.T) {
	for _, curve := range all() {
		fieldLen := (curve.FieldBits() + 7) / 8
		tooLarge := make([]byte, fieldLen, fieldLen)
		for i, _ := range tooLarge {
			tooLarge[i] = 0xFF
		}
		_, err := Field.FromBytes(curve, tooLarge)
		assert.NotNil(t, err)
	}
}
