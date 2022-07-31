package poly

import (
	"github.com/PlatONnetwork/tecdsa/common"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
)

var (
	SimpleCM   = simpleCommitment{}
	PedersenCM = pedersenCommitment{}
)

type CommitmentOpeningBytes interface {
	ToCommitmentOpening() CommitmentOpening
}

type SimpleCommitmentOpeningBytes [1]curve.EccScalarBytes

func (s SimpleCommitmentOpeningBytes) ToCommitmentOpening() CommitmentOpening {
	return &SimpleCommitmentOpening{s[0].ToScalar()}
}

type PedersenCommitmentOpeningBytes [2]curve.EccScalarBytes

func (p PedersenCommitmentOpeningBytes) ToCommitmentOpening() CommitmentOpening {
	return &PedersenCommitmentOpening{p[0].ToScalar(), p[1].ToScalar()}
}

type CommitmentOpening interface {
	ToCommitmentOpeningBytes() CommitmentOpeningBytes
	Serialize() ([]byte, error)
	ToString() string
}
type commitmentOpening struct {
}
type SimpleCommitmentOpening [1]curve.EccScalar
type PedersenCommitmentOpening [2]curve.EccScalar

type commitmentOpeningCbor struct {
	CurveType  curve.EccCurveType
	CommitType PolynomialCommitmentType
	Message    cbor.RawMessage
}

//todo implement
func (commitmentOpening) OpenDealing() (CommitmentOpening, error) {
	return nil, nil
}
func (commitmentOpening) Deserialize(data []byte) (CommitmentOpening, error) {
	var c commitmentOpeningCbor
	if err := cbor.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	switch c.CommitType {
	case Simple:
		switch c.CurveType {
		case curve.K256:
			o := &SimpleCommitmentOpening{curve.Scalar.Zero(c.CurveType)}
			cbor.Unmarshal(c.Message, &o)
			return o, nil
		}

	case Pedersen:
		switch c.CurveType {
		case curve.K256:
			o := &PedersenCommitmentOpening{curve.Scalar.Zero(c.CurveType), curve.Scalar.Zero(c.CurveType)}
			cbor.Unmarshal(c.Message, &o)
			return o, nil
		}
	}
	return nil, errors.New("unknown commitment type")
}
func (commitmentOpening) FromBytes(bytes []byte) (CommitmentOpening, error) {
	return nil, nil
}
func (s SimpleCommitmentOpening) Serialize() ([]byte, error) {
	data, err := cbor.Marshal(s)
	if err != nil {
		return nil, err
	}
	c := &commitmentOpeningCbor{
		CurveType:  s[0].CurveType(),
		CommitType: Simple,
		Message:    data,
	}
	return cbor.Marshal(c)
}
func (s SimpleCommitmentOpening) ToString() string {
	return "CommitmentOpening::Simple(K256(REDACTED))"
}
func (s SimpleCommitmentOpening) ToCommitmentOpeningBytes() CommitmentOpeningBytes {
	return &SimpleCommitmentOpeningBytes{curve.Scalar.ToScalarBytes(s[0])}
}

func (p PedersenCommitmentOpening) Serialize() ([]byte, error) {
	data, err := cbor.Marshal(p)
	if err != nil {
		return nil, err
	}
	c := &commitmentOpeningCbor{
		CurveType:  p[0].CurveType(),
		CommitType: Simple,
		Message:    data,
	}
	return cbor.Marshal(c)
}
func (PedersenCommitmentOpening) ToString() string {
	return "CommitmentOpening::Pedersen(K256(REDACTED), K256(REDACTED))"
}
func (p PedersenCommitmentOpening) ToCommitmentOpeningBytes() CommitmentOpeningBytes {
	return &PedersenCommitmentOpeningBytes{curve.Scalar.ToScalarBytes(p[0]), curve.Scalar.ToScalarBytes(p[1])}
}

type SimpleCommitment struct {
	points []curve.EccPoint
}

func evaluateAt(points []curve.EccPoint, evalPoint common.NodeIndex) curve.EccPoint {
	curveType := points[0].CurveType()
	acc := curve.Point.Identity(curveType)
	for i := len(points) - 1; i >= 0; i-- {
		pt := points[i]
		acc = acc.MulByNodeIndex(evalPoint)
		acc = acc.AddPoints(acc, pt)
	}
	return acc
}

type polynomialCommitmentCbor struct {
	CurveType      curve.EccCurveType
	CommitmentType PolynomialCommitmentType
	Message        cbor.RawMessage
}
type simpleCommitment struct{}

func (simpleCommitment) New(points []curve.EccPoint) *SimpleCommitment {
	return &SimpleCommitment{points: points}
}
func (s simpleCommitment) Create(poly *Polynomial, num int) (*SimpleCommitment, error) {
	if poly.NonZeroCoefficients() > num {
		return nil, errors.New("Polynomial has more coefficients than expected")
	}
	points := make([]curve.EccPoint, num, num)
	for i, _ := range points {
		points[i] = curve.Point.MulByG(poly.Coeff(i))
	}
	return s.New(points), nil
}

func (s *SimpleCommitment) Serialize() ([]byte, error) {
	var data []byte
	var err error
	switch s.CurveType() {
	case curve.K256:
		ps := make([]*curve.Secp256k1Point, len(s.points), len(s.points))
		for i := range s.points {
			ps[i] = s.points[i].(*curve.Secp256k1Point)
		}
		data, err = cbor.Marshal(ps)
		if err != nil {
			return nil, err
		}
	}
	c := &polynomialCommitmentCbor{
		CurveType:      s.CurveType(),
		CommitmentType: Simple,
		Message:        data,
	}
	return cbor.Marshal(c)
}

func (s *SimpleCommitment) StableRepresentation() []byte {
	curveType := s.CurveType()
	r := make([]byte, 0, 2+s.Len()*curveType.PointBytes())
	commitmentTag := byte('S')
	r = append(r, commitmentTag)
	r = append(r, curveType.Tag())
	for _, point := range s.Points() {
		r = append(r, point.Serialize()...)
	}
	return r
}

func (s *SimpleCommitment) Type() PolynomialCommitmentType {
	return Simple
}

func (s *SimpleCommitment) Points() []curve.EccPoint {
	return s.points
}

func (s *SimpleCommitment) Len() int {
	return len(s.points)
}
func (s *SimpleCommitment) Equal(other PolynomialCommitment) int {
	if s.Len() != other.Len() {
		return 0
	}
	for i := range s.points {
		if s.points[i].Equal(other.Points()[i]) == 0 || s.points[i].CurveType() != other.Points()[i].CurveType() {
			return 0
		}
	}
	return 1
}
func (s *SimpleCommitment) CurveType() curve.EccCurveType {
	return s.points[0].CurveType()
}
func (s *SimpleCommitment) OpeningIfConsistent(index common.NodeIndex, opening CommitmentOpening) (CommitmentOpening, error) {
	if s.CheckOpening(index, opening) {
		return opening, nil
	}
	return nil, errors.New("invalid commitment")
}
func (s *SimpleCommitment) VerifyIs(ctype PolynomialCommitmentType, curveType curve.EccCurveType) error {
	if s.CurveType() != curveType {
		return errors.New("curve type mismatch")
	}
	if s.Type() != ctype {
		return errors.New("unexpected commitment type")
	}
	return nil
}

func (s *SimpleCommitment) ConstantTerm() curve.EccPoint {
	return s.points[0].Clone()
}
func (s *SimpleCommitment) EvaluateAt(evalPoint common.NodeIndex) curve.EccPoint {
	return evaluateAt(s.points, evalPoint)
}

func (s *SimpleCommitment) CheckOpening(evalPoint common.NodeIndex, opening CommitmentOpening) bool {
	o := opening.(*PedersenCommitmentOpening)
	return s.checkOpening(evalPoint, o[0])
}
func (s *SimpleCommitment) checkOpening(evalPoint common.NodeIndex, value curve.EccScalar) bool {
	eval := s.EvaluateAt(evalPoint)
	return eval.Equal(curve.Point.MulByG(value)) == 1
}

type PedersenCommitment struct {
	points []curve.EccPoint
}

type pedersenCommitment struct{}

func (pedersenCommitment) New(points []curve.EccPoint) *PedersenCommitment {
	return &PedersenCommitment{points: points}
}

func (p pedersenCommitment) Create(values *Polynomial, masking *Polynomial, num int) (*PedersenCommitment, error) {
	if values.NonZeroCoefficients() > num || masking.NonZeroCoefficients() > num {
		return nil, errors.New("Polynomial has more coefficients than expected")
	}
	points := make([]curve.EccPoint, num, num)
	for i, _ := range points {
		points[i] = curve.Point.Pedersen(values.Coeff(i), masking.Coeff(i))
	}
	return p.New(points), nil
}

func (p *PedersenCommitment) Serialize() ([]byte, error) {
	var data []byte
	var err error
	switch p.CurveType() {
	case curve.K256:
		ps := make([]*curve.Secp256k1Point, len(p.points), len(p.points))
		for i := range p.points {
			ps[i] = p.points[i].(*curve.Secp256k1Point)
		}
		data, err = cbor.Marshal(ps)
		if err != nil {
			return nil, err
		}
	}

	c := &polynomialCommitmentCbor{
		CurveType:      p.CurveType(),
		CommitmentType: Pedersen,
		Message:        data,
	}
	return cbor.Marshal(c)
}

func (p *PedersenCommitment) StableRepresentation() []byte {
	curveType := p.CurveType()
	r := make([]byte, 0, 2+p.Len()*curveType.PointBytes())
	commitmentTag := byte('P')
	r = append(r, commitmentTag)
	r = append(r, curveType.Tag())
	for _, point := range p.Points() {
		r = append(r, point.Serialize()...)
	}
	return r
}

func (p *PedersenCommitment) Type() PolynomialCommitmentType {
	return Pedersen
}

func (p *PedersenCommitment) Points() []curve.EccPoint {
	return p.points
}

func (p *PedersenCommitment) Len() int {
	return len(p.points)
}
func (p *PedersenCommitment) Equal(other PolynomialCommitment) int {
	if p.Len() != other.Len() {
		return 0
	}
	for i := range p.points {
		if p.points[i].Equal(other.Points()[i]) == 0 || p.points[i].CurveType() != other.Points()[i].CurveType() {
			return 0
		}
	}
	return 1
}
func (p *PedersenCommitment) CurveType() curve.EccCurveType {
	return p.points[0].CurveType()
}
func (p *PedersenCommitment) OpeningIfConsistent(index common.NodeIndex, opening CommitmentOpening) (CommitmentOpening, error) {
	if p.CheckOpening(index, opening) {
		return opening, nil
	}
	return nil, errors.New("invalid commitment")
}
func (p *PedersenCommitment) VerifyIs(ctype PolynomialCommitmentType, curveType curve.EccCurveType) error {
	if p.CurveType() != curveType {
		return errors.New("curve type mismatch")
	}
	if p.Type() != ctype {
		return errors.New("unexpected commitment type")
	}
	return nil
}

func (p *PedersenCommitment) ConstantTerm() curve.EccPoint {
	return p.points[0].Clone()
}
func (p *PedersenCommitment) EvaluateAt(evalPoint common.NodeIndex) curve.EccPoint {
	return evaluateAt(p.points, evalPoint)
}
func (p *PedersenCommitment) CheckOpening(evalPoint common.NodeIndex, opening CommitmentOpening) bool {
	o := opening.(*PedersenCommitmentOpening)
	return p.checkOpening(evalPoint, o[0], o[1])
}

func (p *PedersenCommitment) checkOpening(evalPoint common.NodeIndex, value curve.EccScalar, mask curve.EccScalar) bool {
	eval := p.EvaluateAt(evalPoint)
	return eval.Equal(curve.Point.Pedersen(value, mask)) == 1
}

const (
	Simple   = PolynomialCommitmentType(1)
	Pedersen = PolynomialCommitmentType(2)
)

type PolynomialCommitmentType int

type PolynomialCommitment interface {
	Serialize() ([]byte, error)
	StableRepresentation() []byte
	Type() PolynomialCommitmentType
	Points() []curve.EccPoint
	Len() int
	Equal(other PolynomialCommitment) int
	EvaluateAt(evalPoint common.NodeIndex) curve.EccPoint
	ConstantTerm() curve.EccPoint
	CurveType() curve.EccCurveType
	OpeningIfConsistent(index common.NodeIndex, opening CommitmentOpening) (CommitmentOpening, error)
	VerifyIs(ctype PolynomialCommitmentType, curveType curve.EccCurveType) error
	CheckOpening(evalPoint common.NodeIndex, opening CommitmentOpening) bool
}

type polynomialCommitment struct{}

func (polynomialCommitment) Deserialize(bytes []byte) (PolynomialCommitment, error) {
	var c polynomialCommitmentCbor
	if err := cbor.Unmarshal(bytes, &c); err != nil {
		return nil, err
	}
	switch c.CommitmentType {
	case Simple:
		switch c.CurveType {
		case curve.K256:
			var ps []*curve.Secp256k1Point
			if err := cbor.Unmarshal(c.Message, &ps); err != nil {
				return nil, err
			}
			points := make([]curve.EccPoint, len(ps), len(ps))
			for i, _ := range points {
				points[i] = ps[i]
			}
			return &SimpleCommitment{points: points}, nil
		}
	case Pedersen:
	}
	return nil, errors.New("invalid commitment")

}
