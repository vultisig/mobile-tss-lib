package tss

type Service interface {
	// KeygenECDSA generates a new ECDSA keypair
	KeygenECDSA(req *KeygenECDSARequest) (*KeygenECDSAResponse, error)
	// KeygenEDDSA generates a new EDDSA keypair
	KeygenEDDSA(req *KeygenEDDSARequest) (*KeygenEDDSAResponse, error)
	// KeysignECDSA signs a message using ECDSA
	KeysignECDSA(req *KeysignECDSARequest) (*KeysignECDSAResponse, error)
	// KeysignEDDSA signs a message using EDDSA
	KeysignEDDSA(req *KeysignEDDSARequest) (*KeysignEDDSAResponse, error)
	// ApplyKeygenData applies the keygen data to the service
	ApplyKeysignData(string) error
	// ApplyKeysignData applies the keysign data to the service
	ApplyKeygenData(string) error
}

type Messenger interface {
	SendToPeer(from, to, body string) error
}

type LocalStateAccessor interface {
	GetLocalState() (string, error)
	SaveLocalState(localState string) error
}
