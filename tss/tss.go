package tss

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strconv"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

type ServiceImpl struct {
	preParams        *ecdsaKeygen.LocalPreParams
	messenger        Messenger
	stateAccessor    LocalStateAccessor
	inboundMessageCh chan string
}
type MessageFromTss struct {
	WireBytes   []byte `json:"wire_bytes"`
	From        string `json:"from"`
	IsBroadcast bool   `json:"is_broadcast"`
}

// ApplyKeygenData implements Service.
func (s *ServiceImpl) ApplyKeygenData(msg string) error {
	s.inboundMessageCh <- msg
	return nil
}

// ApplyKeysignData implements Service.
func (s *ServiceImpl) ApplyKeysignData(msg string) error {
	s.inboundMessageCh <- msg
	return nil
}

// NewService returns a new instance of the TSS service
func NewService(msg Messenger, stateAccessor LocalStateAccessor) (*ServiceImpl, error) {
	if msg == nil {
		return nil, errors.New("nil messenger")
	}
	if stateAccessor == nil {
		return nil, errors.New("nil state accessor")
	}
	preParams, err := ecdsaKeygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-parameters: %w", err)
	}
	return &ServiceImpl{
		preParams:        preParams,
		messenger:        msg,
		stateAccessor:    stateAccessor,
		inboundMessageCh: make(chan string),
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
	localState := &LocalState{
		KeygenCommitteeKeys: req.AllParties,
		LocalPartyKey:       req.LocalPartyID,
	}
	errChan := make(chan struct{})
	localPartyECDSA := ecdsaKeygen.NewLocalParty(params, outCh, endCh, *s.preParams)

	go func() {
		tErr := localPartyECDSA.Start()
		if tErr != nil {
			log.Println("failed to start keygen process", "error", tErr)
			close(errChan)
		}
	}()
	pubKey, err := s.processKeygen(localPartyECDSA, errChan, outCh, endCh, nil, localState, partyIDs)
	if err != nil {
		log.Println("failed to process keygen", "error", err)
		return nil, err
	}
	return &KeygenECDSAResponse{
		PubKey: pubKey,
	}, nil
}

func (s *ServiceImpl) processKeygen(localParty tss.Party,
	errCh <-chan struct{},
	outCh <-chan tss.Message,
	ecdsaEndCh <-chan *ecdsaKeygen.LocalPartySaveData,
	eddsaEndCh <-chan *eddsaKeygen.LocalPartySaveData,
	localState *LocalState,
	sortedPartyIds tss.SortedPartyIDs) (string, error) {
	for {
		// wait for result
		select {
		case <-errCh: // fail to start keygen process , exit immediately
			return "", errors.New("failed to start keygen process")
		case outMsg := <-outCh:
			// pass the message to messenger
			msgData, r, err := outMsg.WireBytes()
			if err != nil {
				return "", fmt.Errorf("failed to get wire bytes, error: %w", err)
			}
			jsonBytes, err := json.MarshalIndent(MessageFromTss{
				WireBytes:   msgData,
				From:        r.From.Id,
				IsBroadcast: r.IsBroadcast,
			}, "", "  ")
			if err != nil {
				return "", fmt.Errorf("failed to marshal message to json, error: %w", err)
			}
			// for debug
			log.Println("send message to peer", "message", string(jsonBytes))
			if r.IsBroadcast {
				for _, item := range localState.KeygenCommitteeKeys {
					// don't send message to itself
					if item == localState.LocalPartyKey {
						continue
					}
					if err := s.messenger.SendToPeer(r.From.Id, item, string(jsonBytes)); err != nil {
						return "", fmt.Errorf("failed to broadcast message to peer, error: %w", err)
					}
				}
			} else {
				for _, item := range r.To {
					if err := s.messenger.SendToPeer(r.From.Id, item.Id, string(jsonBytes)); err != nil {
						return "", fmt.Errorf("failed to send message to peer, error: %w", err)
					}
				}
			}
		case msg := <-s.inboundMessageCh:
			var msgFromTss MessageFromTss
			if err := json.Unmarshal([]byte(msg), &msgFromTss); err != nil {
				return "", fmt.Errorf("failed to unmarshal message from json, error: %w", err)
			}
			var fromParty *tss.PartyID
			for _, item := range sortedPartyIds {
				if item.Id == msgFromTss.From {
					fromParty = item
					break
				}
			}
			if fromParty == nil {
				return "", fmt.Errorf("failed to find from party,from:%s", msgFromTss.From)
			}
			ok, err := localParty.UpdateFromBytes(msgFromTss.WireBytes, fromParty, msgFromTss.IsBroadcast)
			if err != nil {
				return "", fmt.Errorf("failed to update from bytes, error: %w", err)
			}
			if !ok {
				return "", fmt.Errorf("failed to update from bytes, ok is false")
			}
		case saveData := <-ecdsaEndCh:
			pubKey, err := GetHexEncodedPubKey(saveData.ECDSAPub)
			if err != nil {
				return "", fmt.Errorf("failed to get hex encoded ecdsa pub key, error: %w", err)
			}
			localState.PubKey = pubKey
			localState.ECDSALocalData = *saveData
			if err := s.saveLocalStateData(localState); err != nil {
				return "", fmt.Errorf("failed to save local state data, error: %w", err)
			}

			return pubKey, nil
		case saveData := <-eddsaEndCh:
			pubKey, err := GetHexEncodedPubKey(saveData.EDDSAPub)
			if err != nil {
				return "", fmt.Errorf("failed to get hex encoded ecdsa pub key, error: %w", err)
			}
			localState.PubKey = pubKey
			localState.EDDSALocalData = *saveData
			if err := s.saveLocalStateData(localState); err != nil {
				return "", fmt.Errorf("failed to save local state data, error: %w", err)
			}
		case <-time.After(2 * time.Minute):
			return "", errors.New("keygen timeout, keygen didn't finish in 2 minutes")
		}
	}
}

func (s *ServiceImpl) saveLocalStateData(localState *LocalState) error {
	result, err := json.MarshalIndent(localState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal local state, error: %w", err)
	}
	if err := s.stateAccessor.SaveLocalState(string(result)); err != nil {
		return fmt.Errorf("failed to save local state, error: %w", err)
	}
	return nil
}

func (s *ServiceImpl) KeygenEDDSA(req *KeygenEDDSARequest) (*KeygenEDDSAResponse, error) {
	partyIDs, localPartyID, err := s.getParties(req.AllParties, req.LocalPartyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parties: %w", err)
	}
	ctx := tss.NewPeerContext(partyIDs)
	curve := tss.Edwards()
	totalPartiesCount := len(req.AllParties)
	threshod, err := GetThreshold(totalPartiesCount)

	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	params := tss.NewParameters(curve, ctx, localPartyID, totalPartiesCount, threshod)
	outCh := make(chan tss.Message, totalPartiesCount)                     // message channel
	endCh := make(chan *eddsaKeygen.LocalPartySaveData, totalPartiesCount) // result channel
	localState := &LocalState{
		KeygenCommitteeKeys: req.AllParties,
		LocalPartyKey:       req.LocalPartyID,
	}
	errChan := make(chan struct{})
	localPartyEDDSA := eddsaKeygen.NewLocalParty(params, outCh, endCh)

	go func() {
		tErr := localPartyEDDSA.Start()
		if tErr != nil {
			log.Println("failed to start keygen process", "error", tErr)
			close(errChan)
		}
	}()
	pubKey, err := s.processKeygen(localPartyEDDSA, errChan, outCh, nil, endCh, localState, partyIDs)
	if err != nil {
		log.Println("failed to process keygen", "error", err)
		return nil, err
	}
	return &KeygenEDDSAResponse{
		PubKey: pubKey,
	}, nil
}

func (s *ServiceImpl) KeysignECDSA(req *KeysignECDSARequest) (*KeysignECDSAResponse, error) {
	return nil, nil
}
func (s *ServiceImpl) KeysignEDDSA(req *KeysignEDDSARequest) (*KeysignEDDSAResponse, error) {
	return nil, nil
}
