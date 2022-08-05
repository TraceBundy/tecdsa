package key

type MasterEcdsaPublicKey struct {
	PublicKey []byte
}

type EcdsaPublicKey struct {
	PublicKey []byte
	ChainKey  []byte
}
