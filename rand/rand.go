package rand

type Rand interface {
	Uint32() uint32
	Uint64() uint64
	FillUint8([]uint8)
	XORKeyStream(dst, src []byte)
}

//func NewChaCha20(seed [32]byte) Rand {
//	var seed32 [8]uint32
//	seed32[0] = binary.BigEndian.Uint32(seed[0:4])
//	seed32[1] = binary.BigEndian.Uint32(seed[4:8])
//	seed32[2] = binary.BigEndian.Uint32(seed[8:12])
//	seed32[3] = binary.BigEndian.Uint32(seed[12:16])
//	seed32[4] = binary.BigEndian.Uint32(seed[16:20])
//	seed32[5] = binary.BigEndian.Uint32(seed[20:24])
//	seed32[6] = binary.BigEndian.Uint32(seed[24:28])
//	seed32[7] = binary.BigEndian.Uint32(seed[28:32])
//
//	return chacha20.Seeded20(seed32, 0)
//}
