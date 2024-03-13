package tss

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"strings"
	"time"

	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ecdsaResharing "github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	eddsaResharing "github.com/bnb-chain/tss-lib/v2/eddsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func (s *ServiceImpl) ReshareECDSA(req *ReshareRequest) (*ReshareResponse, error) {
	// ensure chaincode is set appropriately for ECDSA keygen
	if req.ChainCodeHex == "" {
		return nil, fmt.Errorf("ChainCodeHex is empty")
	}
	chaincode, err := hex.DecodeString(req.ChainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chain code hex, error: %w", err)
	}
	if len(chaincode) != 32 {
		return nil, fmt.Errorf("invalid chain code length")
	}
	oldPartiesCount := len(req.GetOldParties())
	oldThreshold, err := GetThreshold(oldPartiesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get old threshold: %w", err)
	}
	newPartiesCount := len(req.GetNewParties())
	threshold, err := GetThreshold(newPartiesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	var localECDSAPub *ecdsaKeygen.LocalPartySaveData
	resharePrefix := req.ResharePrefix
	// when a new member join the resharing process, it should not have the local state of the previous keygen
	if req.PubKey != "" {
		// restore the local saved data
		localStateStr, err := s.stateAccessor.GetLocalState(req.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get local state, error: %w", err)
		}
		var localState LocalState
		if err := json.Unmarshal([]byte(localStateStr), &localState); err != nil {
			return nil, fmt.Errorf("failed to unmarshal local state, error: %w", err)
		}
		if localState.ECDSALocalData.ECDSAPub == nil {
			return nil, errors.New("nil ecdsa pub key")
		}
		if localState.ChainCodeHex == "" {
			return nil, errors.New("nil chain code")
		}
		localECDSAPub = &localState.ECDSALocalData
		chainCodeBuf, err := hex.DecodeString(localState.ChainCodeHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode previous chain code hex, error: %w", err)
		}
		if !bytes.Equal(chaincode, chainCodeBuf) {
			return nil, fmt.Errorf("chain code not match, previous chain code: %s, new chain code: %s", localState.ChainCodeHex, req.ChainCodeHex)
		}
		resharePrefix = localState.ResharePrefix
	}
	// old parties, it's key will start with old-
	oldPartyIDs, oldLocalPartyID, err := s.getParties(req.GetOldParties(), req.LocalPartyID, resharePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get old keygen parties: %w", err)
	}
	newResharePrefix := getNewResharePrefix(req.NewParties)
	s.resharePrefix = newResharePrefix
	// new parties, it's key will start with a new reshare prefix
	partyIDs, localPartyID, err := s.getParties(req.GetNewParties(), req.LocalPartyID, newResharePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get new resharing parties: %w", err)
	}
	oldCtx := tss.NewPeerContext(oldPartyIDs)
	ctx := tss.NewPeerContext(partyIDs)
	curve := tss.S256()
	outCh := make(chan tss.Message, newPartiesCount+oldPartiesCount)                     // message channel
	endCh := make(chan *ecdsaKeygen.LocalPartySaveData, newPartiesCount+oldPartiesCount) // result channel
	errChan := make(chan struct{}, newPartiesCount+oldPartiesCount)
	var pubKey string
	var oldLocalPartyECDSA tss.Party
	var newLocalPartyECDSA tss.Party
	// when local party is in the new committee start the new committee first, since
	// it will be waiting for messages from the old committee
	if localPartyID != nil {
		// new committee member will get new local party save data after resharing is done
		newLocalPartyData := ecdsaKeygen.NewLocalPartySaveData(newPartiesCount)
		newLocalPartyData.LocalPreParams = *s.preParams
		params := tss.NewReSharingParameters(curve, oldCtx, ctx, localPartyID, oldPartiesCount, oldThreshold, newPartiesCount, threshold)
		newLocalPartyECDSA = ecdsaResharing.NewLocalParty(params, newLocalPartyData, outCh, endCh)
		go func() {
			tErr := newLocalPartyECDSA.Start()
			if tErr != nil {
				log.Println("failed to start new party keyshare process", "error", tErr)
				close(errChan)
			}
		}()
	}
	// when local party is in the old committee
	// start the old committee second, since it will be sending messages to new committee
	if oldLocalPartyID != nil {
		if localECDSAPub == nil {
			return nil, fmt.Errorf("if local party belongs to the old committee, it should have local state data, but got nil local state data, local party id: %s", req.LocalPartyID)
		}
		params := tss.NewReSharingParameters(curve, oldCtx, ctx, oldLocalPartyID, oldPartiesCount, oldThreshold, newPartiesCount, threshold)
		oldLocalPartyECDSA = ecdsaResharing.NewLocalParty(params, *localECDSAPub, outCh, endCh)
		go func() {
			tErr := oldLocalPartyECDSA.Start()
			if tErr != nil {
				log.Println("failed to start old party keyshare process", "error", tErr)
				close(errChan)
			}
		}()
	}

	newLocalState := &LocalState{
		KeygenCommitteeKeys: req.GetNewParties(),
		LocalPartyKey:       req.LocalPartyID,
		ChainCodeHex:        req.ChainCodeHex, // ChainCode will be used later for ECDSA key derivation
		ResharePrefix:       newResharePrefix,
	}

	pubKey, err = s.processResharing(oldLocalPartyECDSA, newLocalPartyECDSA, errChan, outCh, endCh, nil, newLocalState, partyIDs, oldPartyIDs)
	if err != nil {
		log.Println("failed to process resharing", "error", err)
		return nil, err
	}
	return &ReshareResponse{
		PubKey:        pubKey,
		ResharePrefix: newResharePrefix,
	}, nil
}

func (s *ServiceImpl) ResharingEdDSA(req *ReshareRequest) (*ReshareResponse, error) {
	var localEdDSAPubData *eddsaKeygen.LocalPartySaveData
	oldPartiesCount := len(req.GetOldParties())
	oldThreshold, err := GetThreshold(oldPartiesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get old threshold: %w", err)
	}
	newPartiesCount := len(req.GetNewParties())
	threshold, err := GetThreshold(newPartiesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	resharePrefix := req.ResharePrefix
	if req.PubKey != "" {
		// restore the local saved data
		localStateStr, err := s.stateAccessor.GetLocalState(req.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get local state, error: %w", err)
		}
		var localState LocalState
		if err := json.Unmarshal([]byte(localStateStr), &localState); err != nil {
			return nil, fmt.Errorf("failed to unmarshal local state, error: %w", err)
		}
		if localState.EDDSALocalData.EDDSAPub == nil {
			return nil, errors.New("nil EdDSA pub key")
		}
		localEdDSAPubData = &localState.EDDSALocalData
		resharePrefix = localState.ResharePrefix
	}
	// old parties
	oldPartyIDs, oldLocalPartyID, err := s.getParties(req.GetOldParties(), req.LocalPartyID, resharePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get old keygen parties: %w", err)
	}
	newResharePrefix := getNewResharePrefix(req.NewParties)
	s.resharePrefix = newResharePrefix
	// new parties
	partyIDs, newLocalPartyID, err := s.getParties(req.GetNewParties(), req.LocalPartyID, newResharePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to get new resharing parties: %w", err)
	}
	oldCtx := tss.NewPeerContext(oldPartyIDs)
	ctx := tss.NewPeerContext(partyIDs)
	curve := tss.Edwards()
	outCh := make(chan tss.Message, newPartiesCount+oldPartiesCount)                     // message channel
	endCh := make(chan *eddsaKeygen.LocalPartySaveData, newPartiesCount+oldPartiesCount) // result channel
	newLocalState := &LocalState{
		KeygenCommitteeKeys: req.GetNewParties(),
		LocalPartyKey:       req.LocalPartyID,
		ResharePrefix:       newResharePrefix,
	}
	errChan := make(chan struct{}, newPartiesCount+oldPartiesCount)
	var oldLocalPartyEdDSA tss.Party
	var newLocalPartyEdDSA tss.Party
	// when local party is in the new committee
	if newLocalPartyID != nil {
		// new committee member will get new local party save data after resharing is done
		newLocalPartyData := eddsaKeygen.NewLocalPartySaveData(newPartiesCount)
		params := tss.NewReSharingParameters(curve, oldCtx, ctx, newLocalPartyID, oldPartiesCount, oldThreshold, newPartiesCount, threshold)
		newLocalPartyEdDSA = eddsaResharing.NewLocalParty(params, newLocalPartyData, outCh, endCh)
		go func() {
			tErr := newLocalPartyEdDSA.Start()
			if tErr != nil {
				log.Println("failed to start new committee reshare process", "error", tErr)
				close(errChan)
			}
		}()
	}
	if oldLocalPartyID != nil {
		if localEdDSAPubData == nil {
			return nil, fmt.Errorf("if local party belongs to the old committee, it should have local state data, but got nil local state data, local party id: %s", req.LocalPartyID)
		}
		params := tss.NewReSharingParameters(curve, oldCtx, ctx, oldLocalPartyID, oldPartiesCount, oldThreshold, newPartiesCount, threshold)
		oldLocalPartyEdDSA = eddsaResharing.NewLocalParty(params, *localEdDSAPubData, outCh, endCh)
		go func() {
			tErr := oldLocalPartyEdDSA.Start()
			if tErr != nil {
				log.Println("failed to start old party keyshare process", "error", tErr)
				close(errChan)
			}
		}()
	}

	pubKey, err := s.processResharing(oldLocalPartyEdDSA, newLocalPartyEdDSA, errChan, outCh, nil, endCh, newLocalState, partyIDs, oldPartyIDs)
	if err != nil {
		log.Println("failed to process keyshare", "error", err)
		return nil, err
	}
	return &ReshareResponse{
		PubKey:        pubKey,
		ResharePrefix: newResharePrefix,
	}, nil
}

func getOutboundMessage(msgData []byte, from string, to string, isBroadcast bool) (string, error) {
	jsonBytes, err := json.MarshalIndent(MessageFromTss{
		WireBytes:   msgData,
		From:        from,
		To:          to,
		IsBroadcast: isBroadcast,
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal message to json, error: %w", err)
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}
func getNewResharePrefix(input string) string {
	result := crc32.Checksum([]byte(input), crc32.MakeTable(crc32.IEEE))
	return fmt.Sprintf("%x", result)
}
func (s *ServiceImpl) processResharing(oldLocalParty tss.Party,
	newLocalParty tss.Party,
	errCh <-chan struct{},
	outCh <-chan tss.Message,
	ecdsaEndCh <-chan *ecdsaKeygen.LocalPartySaveData,
	eddsaEndCh <-chan *eddsaKeygen.LocalPartySaveData,
	localState *LocalState,
	newSortedPartyIds tss.SortedPartyIDs,
	oldSortedPartyIds tss.SortedPartyIDs) (string, error) {

	for {
		select {
		case <-errCh: // fail to start keygen process , exit immediately
			return "", errors.New("failed to start resharing process")
		case outMsg := <-outCh:
			// pass the message to messenger
			msgData, r, err := outMsg.WireBytes()
			if err != nil {
				return "", fmt.Errorf("failed to get wire bytes, error: %w", err)
			}
			if r.To == nil {
				return "", fmt.Errorf("doesn't expect r.To to be nil during resharing")
			}
			for _, item := range r.To {
				// when moniker is the same as local party key, it means it's sending messages to parties on the same node
				if item.Moniker == localState.LocalPartyKey {
					fromPartyKey := string(r.From.GetKey())
					toPartyKey := string(item.GetKey())
					if fromPartyKey == toPartyKey {
						continue
					}
					if strings.HasPrefix(toPartyKey, s.resharePrefix) {
						if _, err := newLocalParty.UpdateFromBytes(msgData, r.From, r.IsBroadcast); err != nil {
							return "", fmt.Errorf("fail to apply message new committee local party")
						}
					} else {
						if _, err := oldLocalParty.UpdateFromBytes(msgData, r.From, r.IsBroadcast); err != nil {
							return "", fmt.Errorf("fail to apply message old committee local party")
						}
					}
				}
				outboundPayload, err := getOutboundMessage(msgData, string(r.From.GetKey()), string(item.GetKey()), r.IsBroadcast)
				if err != nil {
					return "", fmt.Errorf("failed to get outbound message, error: %w", err)
				}

				if err := s.messenger.Send(r.From.Moniker, item.Moniker, outboundPayload); err != nil {
					return "", fmt.Errorf("failed to send message to peer, error: %w", err)
				}
			}

		case msg := <-s.inboundMessageCh:
			// apply the message to the tss instance
			if _, err := s.applyReshareMessageToTssInstance(oldLocalParty, newLocalParty, msg, newSortedPartyIds, oldSortedPartyIds); err != nil {
				return "", fmt.Errorf("failed to apply message to tss instance, error: %w", err)
			}

		case saveData := <-ecdsaEndCh:
			if saveData.ECDSAPub == nil {
				continue
			}
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
			if saveData.EDDSAPub == nil {
				continue
			}
			pubKey, err := GetHexEncodedPubKey(saveData.EDDSAPub)
			if err != nil {
				return "", fmt.Errorf("failed to get hex encoded ecdsa pub key, error: %w", err)
			}
			localState.PubKey = pubKey
			localState.EDDSALocalData = *saveData
			if err := s.saveLocalStateData(localState); err != nil {
				return "", fmt.Errorf("failed to save local state data, error: %w", err)
			}
			return pubKey, nil
		case <-time.After(2 * time.Minute):
			return "", errors.New("keygen timeout, keygen didn't finish in 2 minutes")
		}
	}
}
func (s *ServiceImpl) applyReshareMessageToTssInstance(oldLocalParty, newLocalParty tss.Party,
	msg string,
	newSortedPartyIds tss.SortedPartyIDs,
	oldSortedPartyIds tss.SortedPartyIDs) (string, error) {
	var msgFromTss MessageFromTss
	originalBytes, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", fmt.Errorf("failed to decode message from base64, error: %w", err)
	}
	if err := json.Unmarshal(originalBytes, &msgFromTss); err != nil {
		return "", fmt.Errorf("failed to unmarshal message from json, error: %w", err)
	}

	var fromParty *tss.PartyID
	for _, item := range append(oldSortedPartyIds, newSortedPartyIds...) {
		if string(item.GetKey()) == msgFromTss.From {
			fromParty = item
			break
		}
	}
	if fromParty == nil {
		return "", fmt.Errorf("failed to find from party,from:%s", msgFromTss.From)
	}
	if strings.HasPrefix(msgFromTss.To, s.resharePrefix) {
		_, errUpdate := newLocalParty.UpdateFromBytes(msgFromTss.WireBytes, fromParty, msgFromTss.IsBroadcast)
		if errUpdate != nil {
			return "", fmt.Errorf("failed to update from bytes, error: %w", errUpdate)
		}
	} else {
		_, errUpdate := oldLocalParty.UpdateFromBytes(msgFromTss.WireBytes, fromParty, msgFromTss.IsBroadcast)
		if errUpdate != nil {
			return "", fmt.Errorf("failed to update from bytes, error: %w", errUpdate)
		}
	}
	return "", nil
}
