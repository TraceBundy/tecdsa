package curve

const (
	K256 = EccCurveType(1)
)

type EccCurveType int

func FromTag(tag uint8) EccCurveType {
	t := EccCurveType(0)
	switch tag {
	case 1:
		t = EccCurveType(K256)
	}
	return t
}
func (e EccCurveType) ScalarBits() int {
	bits := 0
	switch e {
	case K256:
		bits = 256
	}
	return bits
}
func (e EccCurveType) ScalarBytes() int {
	return (e.ScalarBits() + 7) / 8
}

func (e EccCurveType) FieldBits() int {
	bits := 0
	switch e {
	case K256:
		bits = 256
	}
	return bits
}
func (e EccCurveType) FieldBytes() int {
	return (e.FieldBits() + 7) / 8
}

func (e EccCurveType) SecurityLevel() int {
	level := 0
	switch e {
	case K256:
		level = 128
	}
	return level
}

func (e EccCurveType) PointBytes() int {
	return 1 + e.FieldBytes()
}

func (e EccCurveType) Tag() uint8 {
	tag := uint8(0)
	switch e {
	case K256:
		tag = 1
	}
	return tag
}

func (e EccCurveType) String() string {
	s := ""
	switch e {
	case K256:
		s = "secp256k1"
	}
	return s
}
