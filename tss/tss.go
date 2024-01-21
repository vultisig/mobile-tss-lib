package tss

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
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

type Messenger interface {
	SendToPeer(from, to, body string) error
}

type ServiceImpl struct {
	preParams *ecdsaKeygen.LocalPreParams
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
func NewService() (*ServiceImpl, error) {
	preParams, err := ecdsaKeygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-parameters: %w", err)
	}
	return &ServiceImpl{
		preParams: preParams,
	}, nil
}

func (s *ServiceImpl) getParties(allPartyKeys []string, localPartyKey string) ([]*tss.PartyID, *tss.PartyID, error) {
	var localPartyID *tss.PartyID
	var unSortedPartiesID []*tss.PartyID
	sort.Strings(allPartyKeys)
	for idx, item := range allPartyKeys {
		key := new(big.Int).SetBytes([]byte(item))
		partyID := tss.NewPartyID(strconv.Itoa(idx), item, key)
		if item == localPartyKey {
			localPartyID = partyID
		}
		unSortedPartiesID = append(unSortedPartiesID, partyID)
	}
	if localPartyID == nil {
		return nil, nil, errors.New("localPartyID not found")
	}
	partyIDs := tss.SortPartyIDs(unSortedPartiesID)
	return partyIDs, localPartyID, nil
}

func (s *ServiceImpl) KeygenECDSA(req *KeygenECDSARequest) (*KeygenECDSAResponse, error) {

	partyIDs, localPartyID, err := s.getParties(req.AllParties, req.LocalPartyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parties: %w", err)
	}
	ctx := tss.NewPeerContext(partyIDs)
	curve := tss.S256()
	totalPartiesCount := len(req.AllParties)
	threshod, err := GetThreshold(totalPartiesCount)

	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	params := tss.NewParameters(curve, ctx, localPartyID, totalPartiesCount, threshod)
	outCh := make(chan tss.Message, totalPartiesCount)                     // message channel
	endCh := make(chan *ecdsaKeygen.LocalPartySaveData, totalPartiesCount) // result channel
	localPartyECDSA := ecdsaKeygen.NewLocalParty(params, outCh, endCh, *s.preParams)
	_ = localPartyECDSA
	// kick off keygen
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
