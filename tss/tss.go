package tss

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	ecdsaKeygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	eddsaKeygen "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	eddsaSigning "github.com/bnb-chain/tss-lib/v2/eddsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	blog "github.com/ipfs/go-log/v2"
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

// ApplyData accept the data from other peers , usually the communication is coordinate by the library user
func (s *ServiceImpl) ApplyData(msg string) error {
	s.inboundMessageCh <- msg
	return nil
}

// NewService returns a new instance of the TSS service
func NewService(msg Messenger, stateAccessor LocalStateAccessor, createPreParam bool) (*ServiceImpl, error) {
	if msg == nil {
		return nil, errors.New("nil messenger")
	}
	blog.SetAllLoggers(blog.LevelInfo)
	if stateAccessor == nil {
		return nil, errors.New("nil state accessor")
	}
	serviceImp := &ServiceImpl{
		messenger:        msg,
		stateAccessor:    stateAccessor,
		inboundMessageCh: make(chan string),
	}

	if createPreParam {
		preParams, err := ecdsaKeygen.GeneratePreParams(10 * time.Minute)
		if err != nil {
			return nil, fmt.Errorf("failed to generate pre-parameters: %w", err)
		}
		serviceImp.preParams = preParams
	}
	return serviceImp, nil
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

func (s *ServiceImpl) KeygenECDSA(req *KeygenRequest) (*KeygenResponse, error) {
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
	partyIDs, localPartyID, err := s.getParties(req.GetAllParties(), req.LocalPartyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parties: %w", err)
	}
	ctx := tss.NewPeerContext(partyIDs)
	curve := tss.S256()
	totalPartiesCount := len(req.GetAllParties())
	threshod, err := GetThreshold(totalPartiesCount)

	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	params := tss.NewParameters(curve, ctx, localPartyID, totalPartiesCount, threshod)
	outCh := make(chan tss.Message, totalPartiesCount*2)                   // message channel
	endCh := make(chan *ecdsaKeygen.LocalPartySaveData, totalPartiesCount) // result channel
	localState := &LocalState{
		KeygenCommitteeKeys: req.GetAllParties(),
		LocalPartyKey:       req.LocalPartyID,
		ChainCodeHex:        req.ChainCodeHex, // ChainCode will be used later for ECDSA key derivation
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
	return &KeygenResponse{
		PubKey: pubKey,
	}, nil
}
func (s *ServiceImpl) applyMessageToTssInstance(localParty tss.Party, msg string, sortedPartyIds tss.SortedPartyIDs) (string, error) {
	var msgFromTss MessageFromTss
	originalBytes, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", fmt.Errorf("failed to decode message from base64, error: %w", err)
	}
	if err := json.Unmarshal(originalBytes, &msgFromTss); err != nil {
		return "", fmt.Errorf("failed to unmarshal message from json, error: %w", err)
	}
	var fromParty *tss.PartyID
	for _, item := range sortedPartyIds {
		if item.Moniker == msgFromTss.From {
			fromParty = item
			break
		}
	}
	if fromParty == nil {
		return "", fmt.Errorf("failed to find from party,from:%s", msgFromTss.From)
	}
	_, errUpdate := localParty.UpdateFromBytes(msgFromTss.WireBytes, fromParty, msgFromTss.IsBroadcast)
	if errUpdate != nil {
		return "", fmt.Errorf("failed to update from bytes, error: %w", errUpdate)
	}

	return "", nil
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
				From:        r.From.Moniker,
				IsBroadcast: r.IsBroadcast,
			}, "", "  ")
			if err != nil {
				return "", fmt.Errorf("failed to marshal message to json, error: %w", err)
			}
			outboundPayload := base64.StdEncoding.EncodeToString(jsonBytes)
			if r.IsBroadcast || r.To == nil {
				for _, item := range localState.KeygenCommitteeKeys {
					// don't send message to itself
					if item == localState.LocalPartyKey {
						continue
					}
					if err := s.messenger.Send(r.From.Moniker, item, outboundPayload); err != nil {
						return "", fmt.Errorf("failed to broadcast message to peer, error: %w", err)
					}
				}
			} else {
				for _, item := range r.To {
					if err := s.messenger.Send(r.From.Moniker, item.Moniker, outboundPayload); err != nil {
						return "", fmt.Errorf("failed to send message to peer, error: %w", err)
					}
				}
			}
		case msg := <-s.inboundMessageCh:
			// apply the message to the tss instance
			if _, err := s.applyMessageToTssInstance(localParty, msg, sortedPartyIds); err != nil {
				return "", fmt.Errorf("failed to apply message to tss instance, error: %w", err)
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
			return pubKey, nil
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
	if err := s.stateAccessor.SaveLocalState(localState.PubKey, string(result)); err != nil {
		return fmt.Errorf("failed to save local state, error: %w", err)
	}
	return nil
}

func (s *ServiceImpl) KeygenEdDSA(req *KeygenRequest) (*KeygenResponse, error) {
	partyIDs, localPartyID, err := s.getParties(req.GetAllParties(), req.LocalPartyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parties: %w", err)
	}
	ctx := tss.NewPeerContext(partyIDs)
	curve := tss.Edwards()
	totalPartiesCount := len(req.GetAllParties())
	threshod, err := GetThreshold(totalPartiesCount)

	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	params := tss.NewParameters(curve, ctx, localPartyID, totalPartiesCount, threshod)
	outCh := make(chan tss.Message, totalPartiesCount*2)                   // message channel
	endCh := make(chan *eddsaKeygen.LocalPartySaveData, totalPartiesCount) // result channel
	localState := &LocalState{
		KeygenCommitteeKeys: req.GetAllParties(),
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
	return &KeygenResponse{
		PubKey: pubKey,
	}, nil
}

func (s *ServiceImpl) KeysignECDSA(req *KeysignRequest) (*KeysignResponse, error) {
	if err := s.validateKeysignRequest(req); err != nil {
		return nil, err
	}
	bytesToSign, err := base64.StdEncoding.DecodeString(req.MessageToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message to sign, error: %w", err)
	}
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
	chainCodeBuf, err := hex.DecodeString(localState.ChainCodeHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chain code hex, error: %w", err)
	}
	keysignCommittee := req.GetKeysignCommitteeKeys()
	if !Contains(keysignCommittee, localState.LocalPartyKey) {
		return nil, errors.New("local party not in keysign committee")
	}
	keysignPartyIDs, localPartyID, err := s.getParties(keysignCommittee, localState.LocalPartyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get keysign parties: %w", err)
	}
	threshold, err := GetThreshold(len(localState.KeygenCommitteeKeys))
	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	curve := tss.S256()
	outCh := make(chan tss.Message, len(keysignPartyIDs)*2)
	endCh := make(chan *common.SignatureData, len(keysignPartyIDs))
	errCh := make(chan struct{})
	pathBuf, err := GetDerivePathBytes(req.DerivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get derive path bytes, error: %w", err)
	}
	il, derivedKey, err := derivingPubkeyFromPath(localState.ECDSALocalData.ECDSAPub, chainCodeBuf, pathBuf, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from path, error: %w", err)
	}
	keyDerivationDelta := il
	localKey := []ecdsaKeygen.LocalPartySaveData{localState.ECDSALocalData}
	if err := signing.UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, localKey, &derivedKey.PublicKey, curve); err != nil {
		return nil, fmt.Errorf("failed to update public key and adjust big xj, error: %w", err)
	}
	ctx := tss.NewPeerContext(keysignPartyIDs)
	params := tss.NewParameters(curve, ctx, localPartyID, len(keysignPartyIDs), threshold)
	m := HashToInt(bytesToSign, curve)
	keysignParty := signing.NewLocalPartyWithKDD(m, params, localKey[0], keyDerivationDelta, outCh, endCh, 0)

	go func() {
		tErr := keysignParty.Start()
		if tErr != nil {
			log.Println("failed to start keysign process", "error", tErr)
			close(errCh)
		}
	}()
	sig, err := s.processKeySign(keysignParty, errCh, outCh, endCh, keysignPartyIDs)
	if err != nil {
		log.Println("failed to process keysign", "error", err)
		return nil, err
	}

	// let's verify the signature
	if ecdsa.Verify(localKey[0].ECDSAPub.ToECDSAPubKey(), bytesToSign, new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S)) {
		log.Println("signature is valid")
	} else {
		return nil, fmt.Errorf("invalid signature")
	}
	return &KeysignResponse{
		Msg:        req.MessageToSign,
		R:          base64.RawStdEncoding.EncodeToString(sig.R),
		S:          base64.RawStdEncoding.EncodeToString(sig.S),
		RecoveryID: base64.RawStdEncoding.EncodeToString(sig.SignatureRecovery),
	}, nil
}
func (s *ServiceImpl) processKeySign(localParty tss.Party,
	errCh <-chan struct{},
	outCh <-chan tss.Message,
	endCh <-chan *common.SignatureData,
	sortedPartyIds tss.SortedPartyIDs) (*common.SignatureData, error) {
	for {
		select {
		case <-errCh:
			return nil, errors.New("failed to start keysign process")
		case msg := <-outCh:
			msgData, r, err := msg.WireBytes()
			if err != nil {
				return nil, fmt.Errorf("failed to get wire bytes, error: %w", err)
			}
			jsonBytes, err := json.MarshalIndent(MessageFromTss{
				WireBytes:   msgData,
				From:        r.From.Moniker,
				IsBroadcast: r.IsBroadcast,
			}, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("failed to marshal message to json, error: %w", err)
			}
			// for debug
			log.Println("send message to peer", "message", string(jsonBytes))
			outboundPayload := base64.StdEncoding.EncodeToString(jsonBytes)
			if r.IsBroadcast {
				for _, item := range sortedPartyIds {
					// don't send message to itself
					// the reason we can do this is because we set Monitor to be the participant key
					if item.Moniker == localParty.PartyID().Moniker {
						continue
					}
					if err := s.messenger.Send(r.From.Moniker, item.Moniker, outboundPayload); err != nil {
						return nil, fmt.Errorf("failed to broadcast message to peer, error: %w", err)
					}
				}
			} else {
				for _, item := range r.To {
					if err := s.messenger.Send(r.From.Moniker, item.Moniker, outboundPayload); err != nil {
						return nil, fmt.Errorf("failed to send message to peer, error: %w", err)
					}
				}
			}
		case msg := <-s.inboundMessageCh:
			// apply the message to the tss instance
			if _, err := s.applyMessageToTssInstance(localParty, msg, sortedPartyIds); err != nil {
				return nil, fmt.Errorf("failed to apply message to tss instance, error: %w", err)
			}
		case sig := <-endCh: // finished keysign successfully
			return sig, nil
		case <-time.After(time.Minute):
			return nil, fmt.Errorf("fail to finish keysign after one minute")
		}
	}

}
func (s *ServiceImpl) KeysignEdDSA(req *KeysignRequest) (*KeysignResponse, error) {
	if err := s.validateKeysignRequest(req); err != nil {
		return nil, err
	}
	bytesToSign, err := base64.StdEncoding.DecodeString(req.MessageToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message to sign, error: %w", err)
	}
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
		return nil, errors.New("nil ecdsa pub key")
	}
	keysignCommittee := req.GetKeysignCommitteeKeys()
	if !Contains(keysignCommittee, localState.LocalPartyKey) {
		return nil, errors.New("local party not in keysign committee")
	}
	keysignPartyIDs, localPartyID, err := s.getParties(keysignCommittee, localState.LocalPartyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get keysign parties: %w", err)
	}
	threshold, err := GetThreshold(len(localState.KeygenCommitteeKeys))
	if err != nil {
		return nil, fmt.Errorf("failed to get threshold: %w", err)
	}
	// derivepath is not applicable for EdDSA
	curve := tss.Edwards()
	outCh := make(chan tss.Message, len(keysignPartyIDs)*3)
	endCh := make(chan *common.SignatureData, len(keysignPartyIDs))
	errCh := make(chan struct{})
	ctx := tss.NewPeerContext(keysignPartyIDs)
	params := tss.NewParameters(curve, ctx, localPartyID, len(keysignPartyIDs), threshold)
	m := HashToInt(bytesToSign, curve)
	keysignParty := eddsaSigning.NewLocalParty(m, params, localState.EDDSALocalData, outCh, endCh)

	go func() {
		tErr := keysignParty.Start()
		if tErr != nil {
			log.Println("failed to start keysign process", "error", tErr)
			close(errCh)
		}
	}()
	sig, err := s.processKeySign(keysignParty, errCh, outCh, endCh, keysignPartyIDs)
	if err != nil {
		log.Println("failed to process keysign", "error", err)
		return nil, err
	}
	pubKey := edwards.PublicKey{
		Curve: curve,
		X:     localState.EDDSALocalData.EDDSAPub.X(),
		Y:     localState.EDDSALocalData.EDDSAPub.Y(),
	}
	if edwards.Verify(&pubKey,
		bytesToSign,
		new(big.Int).SetBytes(sig.R),
		new(big.Int).SetBytes(sig.S)) {
		log.Println("signature is valid")
	} else {
		return nil, fmt.Errorf("invalid signature")

	}
	return &KeysignResponse{
		Msg:        req.MessageToSign,
		R:          base64.RawStdEncoding.EncodeToString(sig.R),
		S:          base64.RawStdEncoding.EncodeToString(sig.S),
		RecoveryID: base64.RawStdEncoding.EncodeToString(sig.SignatureRecovery),
	}, nil
}

func (*ServiceImpl) validateKeysignRequest(req *KeysignRequest) error {
	if req == nil {
		return errors.New("nil request")
	}
	if req.KeysignCommitteeKeys == "" {
		return errors.New("nil keysign committee keys")
	}
	if req.LocalPartyKey == "" {
		return errors.New("nil local party key")
	}
	if req.PubKey == "" {
		return errors.New("nil pub key")
	}
	if req.MessageToSign == "" {
		return errors.New("nil message to sign")
	}
	return nil
}
