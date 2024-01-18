package tss

import (
	"log"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

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

type KeygenECDSARequest struct{}
type KeygenECDSAResponse struct{}
type KeygenEDDSARequest struct{}
type KeygenEDDSAResponse struct{}
type KeysignECDSARequest struct{}
type KeysignECDSAResponse struct{}
type KeysignEDDSARequest struct{}
type KeysignEDDSAResponse struct{}

type ServiceImpl struct {
}

// ApplyKeygenData implements Service.
func (s *ServiceImpl) ApplyKeygenData(string) error {
	return nil
}

// ApplyKeysignData implements Service.
func (s *ServiceImpl) ApplyKeysignData(string) error {
	return nil
}

// NewService returns a new instance of the TSS service
func NewService() *ServiceImpl {
	preParams, _ := ecdsaKeygen.GeneratePreParams(1 * time.Minute)
	log.Printf("preParams: %v", preParams)
	return &ServiceImpl{}
}

func (s *ServiceImpl) KeygenECDSA(req *KeygenECDSARequest) (*KeygenECDSAResponse, error) {
	return nil, nil
}
func (s *ServiceImpl) KeygenEDDSA(req *KeygenEDDSARequest) (*KeygenEDDSAResponse, error) {
	return nil, nil
}

func (s *ServiceImpl) KeysignECDSA(req *KeysignECDSARequest) (*KeysignECDSAResponse, error) {
	return nil, nil
}
func (s *ServiceImpl) KeysignEDDSA(req *KeysignEDDSARequest) (*KeysignEDDSAResponse, error) {
	return nil, nil
}
