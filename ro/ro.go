package ro

import (
	"encoding/binary"
	"fmt"
	"github.com/PlatONnetwork/tecdsa/curve"
	"github.com/PlatONnetwork/tecdsa/seed"
	"github.com/pkg/errors"
	"math"
)

const (
	Bytestring = RandomOracleInputType(1)
	Integer    = RandomOracleInputType(2)
	Point      = RandomOracleInputType(3)
	Scalar     = RandomOracleInputType(4)
)

type RandomOracle struct {
	domainSeparator string
	inputSize       int
	inputs          map[string][]byte
}

type RandomOracleInputType uint8

func NewRandomOracle(domainSeparator string) *RandomOracle {
	return &RandomOracle{
		domainSeparator: domainSeparator,
		inputSize:       0,
		inputs:          make(map[string][]byte),
	}
}

func (r *RandomOracle) AddInput(name string, input []byte, ty RandomOracleInputType) error {
	if _, ok := r.inputs[name]; ok {
		return errors.New("random oracle input had same name")
	}

	if len(name) == 0 || len(name) > math.MaxUint8 {
		return errors.New("invalid name length")
	}

	if len(input) > math.MaxUint8 {
		return errors.New("invalid input length")
	}
	var encodedInput []byte
	encodedInput = append(encodedInput, []byte{byte(ty)}...)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(input)))
	encodedInput = append(encodedInput, buf[:]...)
	encodedInput = append(encodedInput, input...)
	r.inputSize += 1 + len(name) + len(encodedInput)
	r.inputs[name] = encodedInput
	return nil
}

func (r *RandomOracle) AddPoint(name string, pt curve.EccPoint) error {
	input := pt.Serialize()
	return r.AddInput(name, input, Point)
}

func (r *RandomOracle) AddPoints(name string, pts []curve.EccPoint) error {
	for i, pt := range pts {
		if err := r.AddPoint(fmt.Sprintf("%s[%d]", name, i), pt); err != nil {
			return err
		}
	}
	return nil
}

func (r *RandomOracle) AddScalar(name string, s curve.EccScalar) error {
	input := s.Serialize()

	return r.AddInput(name, input, Scalar)
}

func (r *RandomOracle) AddBytesString(name string, v []byte) error {
	return r.AddInput(name, v, Bytestring)
}

func (r *RandomOracle) AddUint64(name string, i uint64) error {
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], i)
	return r.AddInput(name, input[:], Bytestring)
}

func (r *RandomOracle) AddUint32(name string, i uint32) error {
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], uint64(i))
	return r.AddInput(name, input[:], Bytestring)
}

func (r *RandomOracle) OutputScalar(curveType curve.EccCurveType) (curve.EccScalar, error) {
	res, err := r.outputScalar(curveType, 1)
	if err != nil {
		return nil, err
	}
	return res[0], nil
}

func (r *RandomOracle) outputScalar(curveType curve.EccCurveType, cnt int) ([]curve.EccScalar, error) {
	roInput, err := r.formRoInput()
	if err != nil {
		return nil, err
	}
	return curve.Scalar.HashToSeveralScalar(curveType, cnt, roInput, []byte(fmt.Sprintf("%s-%s", r.domainSeparator, curveType.String())))
}
func (r *RandomOracle) formRoInput() ([]byte, error) {
	if len(r.inputs) == 0 {
		return nil, errors.New("invalid input length")
	}
	var input []byte
	for name, data := range r.inputs {
		input = append(input, byte(len(name)))
		input = append([]byte(name))
		input = append(data)
	}
	return input, nil
}

func (r *RandomOracle) OutputByteString(length int) (input []byte, err error) {
	if input, err = r.formRoInput(); err != nil {
		return nil, err
	}
	return seed.ExpandMessageXmd(input, []byte(r.domainSeparator), length)
}

func (r *RandomOracle) OutputPoint() (curve.EccPoint, error) {
	return nil, nil
}
