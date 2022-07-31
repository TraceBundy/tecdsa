package zk

import (
	"github.com/PlatONnetwork/tecdsa/curve"
	ro2 "github.com/PlatONnetwork/tecdsa/ro"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/pkg/errors"
)

var (
	ProofOfProductIns = proofOfProductInstance{}
)

type proofOfProductInstance struct{}
type ProofOfProduct struct {
	challenge curve.EccScalar
	response1 curve.EccScalar
	response2 curve.EccScalar
}

type ProofOfProductInstance struct {
	curveType  curve.EccCurveType
	g          curve.EccPoint
	h          curve.EccPoint
	lhsCom     curve.EccPoint
	rhsCom     curve.EccPoint
	productCom curve.EccPoint
}

func (proofOfProductInstance) FromWitness(lhs curve.EccScalar, rhs curve.EccScalar, rhsMasking curve.EccScalar, product curve.EccScalar, productMasking curve.EccScalar) *ProofOfProductInstance {
	curveType := lhs.CurveType()
	g := curve.Point.GeneratorG(curveType)
	h := curve.Point.GeneratorH(curveType)
	lhsCom := g.Clone().ScalarMul(g, lhs)
	rhsCom := curve.Point.MulPoints(g, rhs, h, rhsMasking)
	productCom := curve.Point.MulPoints(g, product, h, productMasking)
	return &ProofOfProductInstance{
		curveType:  curveType,
		g:          g,
		h:          h,
		lhsCom:     lhsCom,
		rhsCom:     rhsCom,
		productCom: productCom,
	}
}

func (proofOfProductInstance) FromCommitments(lhsCom curve.EccPoint, rhsCom curve.EccPoint, productCom curve.EccPoint) *ProofOfProductInstance {
	curveType := lhsCom.CurveType()
	g := curve.Point.GeneratorG(curveType)
	h := curve.Point.GeneratorH(curveType)
	return &ProofOfProductInstance{
		curveType:  curveType,
		g:          g,
		h:          h,
		lhsCom:     lhsCom,
		rhsCom:     rhsCom,
		productCom: productCom,
	}
}
func (p *ProofOfProductInstance) RecoverCommitment(proof *ProofOfProduct) (curve.EccPoint, curve.EccPoint) {
	r1Com := curve.Point.MulByG(proof.response1)
	r1Com = r1Com.SubPoints(r1Com, p.lhsCom.Clone().ScalarMul(p.lhsCom, proof.challenge))
	r2Com := curve.Point.MulPoints(p.rhsCom, proof.response1, p.h, proof.response2)
	r2Com = r2Com.SubPoints(r2Com, p.productCom.Clone().ScalarMul(p.productCom, proof.challenge))
	return r1Com, r2Com
}

func (p *ProofOfProductInstance) Create(seed seed.Seed, lhs curve.EccScalar, rhs curve.EccScalar, rhsMasking curve.EccScalar, product curve.EccScalar, productMasking curve.EccScalar, associatedData []byte) (*ProofOfProduct, error) {
	/*
		 lc = g^l
		 rc = g^r * h^rm
		 pc = g^p * h^pm
	l	 r1c = g^r1
		 r2c = rc^r1 * h^r2
		 ch = H(lc, rc, pc, r1c, r2c, associated_data)
		 s1 = (l * ch) + r1
		 s2 = (pm - l*rm)*ch + r2

		 r1c = g^s1 - lc^ch = g^((l * ch) + r1) - (g^l)ch
		 r2c = (rc^s1 * h^s2) - (pc ^ ch) = rc^((l * ch) + r1)*h^((pm - l*rm)*ch + r2) - (g^p * h^pm)^ch = rc^(1*ch)* rc^r1 * h^((pm-l*rm)*ch+r2) - g^(p*ch)*h^(pm*ch)
			=rc^s1*h^s2 - (g^p*h^pm)^ch = rc^s1*h^s2 - (g^(p*ch)*h^(pm*h))
		    = (g^r*h^rm)^(l*ch)+r1)*h^s2 - (g^(p*ch)*h^(pm*h))
		    = g^(r*l*ch+r*r1)*h^(rm*l*ch+rm*r1)*h^s2 - (g^(p*ch)*h^(pm*h))
		 =
	*/
	instance := ProofOfProductIns.FromWitness(lhs, rhs, rhsMasking, product, productMasking)
	rng := seed.Rng()
	r1 := curve.Scalar.Random(p.curveType, rng)
	r1Com := instance.g.Clone().ScalarMul(instance.g, r1)
	r2 := curve.Scalar.Random(p.curveType, rng)
	r2Com := curve.Point.MulPoints(instance.rhsCom, r1, instance.h, r2)
	challenge, err := instance.HashToChallenge(r1Com, r2Com, associatedData)
	if err != nil {
		return nil, err
	}
	response1 := lhs.Clone().Mul(lhs, challenge)
	response1 = response1.Add(response1, r1)
	response2 := productMasking.Clone().Sub(productMasking, lhs.Clone().Mul(lhs, rhsMasking))
	response2 = response2.Mul(response2, challenge)
	response2 = response2.Add(response2, r2)
	return &ProofOfProduct{
		challenge: challenge,
		response1: response1,
		response2: response2,
	}, err
}

func (p ProofOfProductInstance) HashToChallenge(c1 curve.EccPoint, c2 curve.EccPoint, associatedData []byte) (curve.EccScalar, error) {
	ro := ro2.NewRandomOracle(ProofOfEqualOpeningsDst)
	ro.AddBytesString("associated_data", associatedData)
	ro.AddPoint("instance_g", p.g)
	ro.AddPoint("instance_h", p.h)
	ro.AddPoint("instance_lhs", p.lhsCom)
	ro.AddPoint("instance_rhs", p.rhsCom)
	ro.AddPoint("instance_product", p.productCom)
	ro.AddPoint("commitment1", c1)
	ro.AddPoint("commitment2", c2)
	return ro.OutputScalar(p.curveType)
}

func (p *ProofOfProduct) Verify(lhsCom curve.EccPoint, rhsCom curve.EccPoint, productCom curve.EccPoint, associatedData []byte) error {
	instance := ProofOfProductIns.FromCommitments(lhsCom, rhsCom, productCom)
	r1Com, r2Com := instance.RecoverCommitment(p)
	challenge, err := instance.HashToChallenge(r1Com, r2Com, associatedData)
	if err != nil {
		return err
	}
	if p.challenge.Equal(challenge) == 0 {
		return errors.New("invalid proof")
	}
	return nil
}
