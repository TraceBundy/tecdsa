package curve

import (
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/pkg/errors"
)

func cmov(a EccFieldElement, b EccFieldElement, choice int) EccFieldElement {
	r := Field.A(a.CurveType())
	r.Assign(a)
	r.CAssign(b, choice)
	return r
}

func sqrtRatio(u EccFieldElement, v EccFieldElement) (EccFieldElement, int, error) {
	if u.CurveType() != v.CurveType() {
		return nil, 0, errors.New("curve mismatch")
	}
	if v.IsZero() == 1 {
		return nil, 0, errors.New("invalid arguments : v == 0")
	}
	curve := u.CurveType()
	if curve == K256 {
		c2 := Field.SswuC2(curve)
		tv1 := Field.Zero(curve).Square(v)
		tv2 := Field.Zero(curve).Mul(u, v)
		tv1 = tv1.Mul(tv1, tv2)
		y1 := Field.Zero(curve).Progenitor(tv1)

		y1 = y1.Mul(y1, tv2)
		y2 := Field.Zero(curve).Mul(y1, c2)
		tv3 := Field.Zero(curve).Square(y1)
		tv3 = tv3.Mul(tv3, v)
		isQr := tv3.Equal(u)
		y := cmov(y2, y1, isQr)
		return y, isQr, nil
	} else {
		z := Field.SswuZ(curve)
		vinv := Field.Zero(curve).Invert(v)
		uov := Field.Zero(curve).Mul(u, vinv)
		sqrtUov, uovIsQr := Field.Zero(curve).Sqrt(uov)
		zUov := Field.Zero(curve).Mul(z, uov)
		sqrtzUov, _ := Field.Zero(curve).Sqrt(zUov)
		return cmov(sqrtzUov, sqrtUov, uovIsQr), uovIsQr, nil
	}
}

func sswu(u EccFieldElement) (EccFieldElement, EccFieldElement, error) {
	curve := u.CurveType()
	a := Field.SswuA(curve)
	b := Field.SswuB(curve)
	z := Field.SswuZ(curve)
	one := Field.One(curve)

	tv1 := Field.Zero(curve).Mul(z, Field.Zero(curve).Square(u))
	tv2 := Field.Zero(curve).Square(tv1)
	tv2 = tv2.Add(tv2, tv1)
	tv3 := Field.Zero(curve).Add(tv2, one)
	tv3 = tv3.Mul(tv3, b)
	choice := 0
	if tv2.IsZero() == 0 {
		choice = 1
	}
	tv4 := cmov(z, Field.Zero(curve).Negate(tv2), choice)
	tv4 = tv4.Mul(tv4, a)
	tv2 = tv2.Square(tv3)
	tv6 := Field.Zero(curve).Square(tv4)
	tv5 := Field.Zero(curve).Mul(tv6, a)
	tv2 = tv2.Add(tv2, tv5)
	tv2 = tv2.Mul(tv2, tv3)
	tv6 = tv6.Mul(tv6, tv4)
	tv5 = Field.Zero(curve).Mul(tv6, b)
	tv2 = tv2.Add(tv2, tv5)
	x := Field.Zero(curve).Mul(tv1, tv3)
	y1, isGx1Square, err := sqrtRatio(tv2, tv6)
	if err != nil {
		return nil, nil, err
	}

	y := Field.Zero(curve).Mul(tv1, u)
	y = y.Mul(y, y1)
	x = cmov(x, tv3, isGx1Square)
	y = cmov(y, y1, isGx1Square)
	e1 := int(u.Sign() ^ y.Sign() ^ 1)
	y = cmov(Field.Zero(curve).Negate(y), y, e1)
	x = x.Mul(x, tv4.Invert(tv4))
	return x, y, nil
}

func MapToCurve(fe EccFieldElement) (EccPoint, error) {
	x, y, err := sswu(fe)
	if err != nil {
		return nil, err
	}
	if fe.CurveType() == K256 {
		x, y := sswuIsogenySecp256k1(x, y)

		return Point.FromFieldElems(x, y)
	} else {
		return Point.FromFieldElems(x, y)
	}
}

func HashToField(count int, curve EccCurveType, input []byte, domainSeparator []byte) ([]EccFieldElement, error) {
	pBits := curve.FieldBits()
	securityLevel := curve.SecurityLevel()
	fieldLen := (pBits + securityLevel + 7) / 8
	lenInBytes := count * fieldLen
	uniformBytes, err := seed.ExpandMessageXmd(input, domainSeparator, lenInBytes)
	if err != nil {
		return nil, err
	}
	out := make([]EccFieldElement, 0, count)
	for i := 0; i < count; i++ {
		fe, err := Field.FromBytesWide(curve, uniformBytes[i*fieldLen:(i+1)*fieldLen])
		if err != nil {
			return nil, err
		}
		out = append(out, fe)
	}
	return out, err
}

func HashToScalar(count int, curve EccCurveType, input []byte, domainSeparator []byte) ([]EccScalar, error) {
	sBits := curve.ScalarBits()
	securityLevel := curve.SecurityLevel()
	fieldLen := (sBits + securityLevel + 7) / 8
	lenInBytes := count * fieldLen
	uniformBytes, err := seed.ExpandMessageXmd(input, domainSeparator, lenInBytes)
	if err != nil {
		return nil, err
	}
	out := make([]EccScalar, 0, count)
	for i := 0; i < count; i++ {
		fe, err := Scalar.FromBytesWide(curve, uniformBytes[i*fieldLen:(i+1)*fieldLen])
		if err != nil {
			return nil, err
		}
		out = append(out, fe)
	}
	return out, err
}

func HashToCurveRo(curve EccCurveType, input []byte, domainSeparator []byte) (EccPoint, error) {
	u, err := HashToField(2, curve, input, domainSeparator)
	if err != nil {
		return nil, err
	}
	q0, err := MapToCurve(u[0])
	if err != nil {
		return nil, err
	}
	q1, err := MapToCurve(u[1])
	if err != nil {
		return nil, err
	}
	r := q0.AddPoints(q0, q1)
	return r, nil
}

/// Return x**2 + x*c1 + c2
func x2Xc1C2(x, c1, c2 EccFieldElement) EccFieldElement {
	r := Field.Zero(x.CurveType()).Add(x, c1)
	r = r.Mul(x, r)
	r = r.Add(r, c2)
	return r

}

// Return x**3 + x**2*c1 + x*c2 + c3
func x3X2c1Xc2C3(x, c1, c2, c3 EccFieldElement) EccFieldElement {
	r := x2Xc1C2(x, c1, c2)
	r = r.Mul(x, r)
	r = r.Add(r, c3)
	return r
}

/// Return x**3 * c1 + x**2 * c2 + x * c3 + c4
func x3c1X2c2Xc3C4(x, c1, c2, c3, c4 EccFieldElement) EccFieldElement {
	r := Field.Zero(x.CurveType()).Mul(x, c1)
	r = r.Add(r, c2)
	r = r.Mul(r, x)
	r = r.Add(r, c3)
	r = r.Mul(r, x)
	r = r.Add(r, c4)
	return r
}

var (
	K256C = [13]EccFieldElement{
		K256Field.FromHex("8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C"),
		K256Field.FromHex("534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262"),
		K256Field.FromHex("07D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581"),
		K256Field.FromHex("8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7"),
		K256Field.FromHex("EDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14"),
		K256Field.FromHex("D35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B"),
		K256Field.FromHex("2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84"),
		K256Field.FromHex("29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931"),
		K256Field.FromHex("C75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3"),
		K256Field.FromHex("4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C"),
		K256Field.FromHex("6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F"),
		K256Field.FromHex("7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573"),
		K256Field.FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B"),
	}
)

///Returns (x,y) where:
/// * x = x_num / x_den, where
///     * x_num = C0 * x'^3 + C1 * x'^2 + C2 * x' + C3
///     * x_den = x'^2 + C4 * x' + C5
/// * y = y' * y_num / y_den, where
///    * y_num = C6 * x'^3 + C7 * x'^2 + C8 * x' + C9
///    * y_den = x'^3 + C10 * x'^2 + C11 * x' + C12
///
/// where Ci refers to the constants in the variable K256C[i]
func sswuIsogenySecp256k1(x, y EccFieldElement) (EccFieldElement, EccFieldElement) {
	xnum := x3c1X2c2Xc3C4(x, K256C[0], K256C[1], K256C[2], K256C[3])
	xden := x2Xc1C2(x, K256C[4], K256C[5])
	ynum := x3c1X2c2Xc3C4(x, K256C[6], K256C[7], K256C[8], K256C[9])
	yden := x3X2c1Xc2C3(x, K256C[10], K256C[11], K256C[12])

	inv := Field.Zero(K256).Mul(xden, yden)

	inv = inv.Invert(inv)

	x = Field.Zero(K256).Mul(xnum, Field.Zero(K256).Mul(inv, yden))
	y = y.Mul(y, ynum.Mul(ynum, inv.Mul(inv, xden)))
	return x, y
}
