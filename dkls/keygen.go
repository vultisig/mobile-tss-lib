package dkls

import (
	"encoding/base64"
	"fmt"

	session "go-wrapper/go-bindings/sessions"

	"github.com/vultisig/mobile-tss-lib/tss"
)

// DklsService is a struct contains all the necessary information to perform DKLS ECDSA Keygen and Keysign
type DklsService struct {
	messenger     tss.Messenger
	stateAccessor tss.LocalStateAccessor
}

func NewDklsService(msg tss.Messenger, stateAccessor tss.LocalStateAccessor) *DklsService {
	return &DklsService{
		messenger:     msg,
		stateAccessor: stateAccessor,
	}
}

// SetupMessage is a function that returns the
func (s *DklsService) SetupMessage(request tss.KeygenRequest) (string, error) {
	allParties := request.GetAllParties()
	if len(allParties) <= 1 {
		return "", fmt.Errorf("invalid number of parties")
	}
	threshold, err := tss.GetThreshold(len(allParties))
	if err != nil {
		return "", fmt.Errorf("failed to get threshold: %w", err)
	}
	result, err := session.DklsKeygenSetupMsgNew(uint32(threshold), nil, s.partyIDsToBytes(allParties))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(result), nil
}

func (s *DklsService) partyIDsToBytes(ids []string) []byte {
	if len(ids) == 0 {
		return nil
	}
	var result []byte
	for _, id := range ids {
		result = append(result, []byte(id)...)
		result = append(result, 0)
	}
	return result
}
