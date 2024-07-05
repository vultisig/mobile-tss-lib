package coordinator

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"

	"github.com/vultisig/mobile-tss-lib/tss"
)

var log = slog.New(slog.NewTextHandler(os.Stderr, nil))

type ReshareInput struct {
	Server        string
	Session       string
	Key           string
	KeyFolder     string
	ChainCode     string
	PubKey        string
	PubKeyEdDSA   string
	ResharePrefix string
	OldParties    []string
}

type KeygenInput struct {
	Server      string
	Session     string
	Key         string
	KeyFolder   string
	Message     string
	ChainCode   string
	DerivePath  string
	PubKey      string
	PubKeyEdDSA string
}

type SignInput struct {
	Server      string
	Session     string
	Key         string
	KeyFolder   string
	Message     string
	ChainCode   string
	DerivePath  string
	PubKey      string
	PubKeyEdDSA string
}

// GenerateRandomChainCodeHex Generates a 32-byte random chain code encoded as a hexadecimal string.
// Does not take arg because it relies on the (secure) rng from the crypto pkg
func GenerateRandomChainCodeHex() (string, error) {
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	fillBytes(common.GetRandomPositiveInt(rand.Reader, max32b), chainCode)
	encodedChainCode := hex.EncodeToString(chainCode)
	return encodedChainCode, nil
}

// ExecuteKeyGeneration Orchestrates TSS keygen process for ECDSA & EdDSA
// including session management and message handling
func ExecuteKeyGeneration(input KeygenInput) (string, error) {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return "", fmt.Errorf("fail to register session: %w", err)
	}
	log.Debug("Registered session", "key", input.Key)
	var partiesJoined []string
	var err error
	if partiesJoined, err = waitForSessionStart(input.Server, input.Session); err != nil {
		return "", fmt.Errorf("fail to wait for session start: %w", err)
	}
	log.Debug("All parties have joined the session", "key", input.Key)

	messenger := &MessengerImp{
		Server:    input.Server,
		SessionID: input.Session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key:    input.Key,
		folder: input.KeyFolder,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, true)
	if err != nil {
		return "", fmt.Errorf("fail to create tss server: %w", err)
	}
	log.Debug("start downloading messages...")
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Debug("start ECDSA keygen...")
	resp, err := tssServerImp.KeygenECDSA(&tss.KeygenRequest{
		LocalPartyID: input.Key,
		AllParties:   strings.Join(partiesJoined, ","),
		ChainCodeHex: input.ChainCode,
	})
	if err != nil {
		return "", fmt.Errorf("fail to generate ECDSA key: %w", err)
	}
	log.Debug("ECDSA keygen success", "response", resp)
	time.Sleep(time.Second)
	log.Debug("start EDDSA keygen...")
	respEDDSA, errEDDSA := tssServerImp.KeygenEdDSA(&tss.KeygenRequest{
		LocalPartyID: input.Key,
		AllParties:   strings.Join(partiesJoined, ","),
		ChainCodeHex: input.ChainCode,
	})
	if errEDDSA != nil {
		return "", fmt.Errorf("fail to generate EDDSA key: %w", errEDDSA)
	}
	log.Debug("EDDSA keygen response success", "response", respEDDSA)
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Error("fail to end session", "error", err)
	}
	close(endCh)
	wg.Wait()
	return resp.PubKey, nil
}

// ExecuteKeyResharing Manages the key resharing process for ECDSA & EdDSA
// ensures all parties are synced and sessions are properly handled
func ExecuteKeyResharing(input ReshareInput) (string, error) {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return "", fmt.Errorf("fail to register session: %w", err)
	}

	var partiesJoined []string
	var err error
	if partiesJoined, err = waitForSessionStart(input.Server, input.Session); err != nil {
		return "", fmt.Errorf("fail to wait for session start: %w", err)
	}

	messenger := &MessengerImp{
		Server:    input.Server,
		SessionID: input.Session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key:    input.Key,
		folder: input.KeyFolder,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, true)
	if err != nil {
		return "", fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Debug("start ECDSA key resharing...")
	resp, err := tssServerImp.ReshareECDSA(&tss.ReshareRequest{
		PubKey:        input.PubKey,
		LocalPartyID:  input.Key,
		NewParties:    strings.Join(partiesJoined, ","), // new parties
		OldParties:    strings.Join(input.OldParties, ","),
		ChainCodeHex:  input.ChainCode,
		ResharePrefix: input.ResharePrefix,
	})
	if err != nil {
		return "", fmt.Errorf("fail to reshare ECDSA key: %w", err)
	}
	log.Debug("ECDSA reshare success", "response", resp)
	time.Sleep(time.Second)
	log.Debug("start EDDSA reshare...")
	respEDDSA, errEdDSA := tssServerImp.ResharingEdDSA(&tss.ReshareRequest{
		PubKey:        input.PubKeyEdDSA,
		LocalPartyID:  input.Key,
		NewParties:    strings.Join(partiesJoined, ","),
		OldParties:    strings.Join(input.OldParties, ","),
		ChainCodeHex:  input.ChainCode,
		ResharePrefix: input.ResharePrefix,
	})
	if errEdDSA != nil {
		return "", fmt.Errorf("fail to generate EDDSA key: %w", errEdDSA)
	}
	log.Debug("EDDSA reshare success", "response", respEDDSA)
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Error("fail to end session", "error", err)
	}
	close(endCh)
	wg.Wait()
	return "", nil
}

// ExecuteECDSAKeySigning Coordinates ECDSA signing process in a TSS env
// from session setup to computing and encoding the signature
func ExecuteECDSAKeySigning(input SignInput) (string, error) {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return "", fmt.Errorf("fail to register session: %w", err)
	}

	var partiesJoined []string
	var err error
	if partiesJoined, err = waitForSessionStart(input.Server, input.Session); err != nil {
		return "", fmt.Errorf("fail to wait for session start: %w", err)
	}

	messenger := &MessengerImp{
		Server:    input.Server,
		SessionID: input.Session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key:    input.Key,
		folder: input.KeyFolder,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, false)
	if err != nil {
		return "", fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	resp, err := tssServerImp.KeysignECDSA(&tss.KeysignRequest{
		PubKey:               input.PubKey,
		MessageToSign:        input.Message,
		LocalPartyKey:        input.Key,
		KeysignCommitteeKeys: strings.Join(partiesJoined, ","),
		DerivePath:           input.DerivePath,
	})
	if err != nil {
		return "", fmt.Errorf("fail to ECDSA key sign: %w", err)
	}

	rBytes, err := base64.RawStdEncoding.DecodeString(resp.R)
	if err != nil {
		return "", fmt.Errorf("fail to decode r: %w", err)
	}
	sBytes, err := base64.RawStdEncoding.DecodeString(resp.S)
	if err != nil {
		return "", fmt.Errorf("fail to decode s: %w", err)
	}
	signature := append(rBytes, sBytes...)
	signatureEncoded := base64.StdEncoding.EncodeToString(signature)
	log.Debug("ECDSA keysign success", "signature", signatureEncoded)
	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Error("fail to end session", "error", err)
	}
	close(endCh)
	wg.Wait()
	return signatureEncoded, nil
}

// ExecuteEdDSAKeySigning Coordinates EdDSA signing process in a TSS env
// from session setup to computing and encoding the signature
func ExecuteEdDSAKeySigning(input SignInput) (string, error) {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return "", fmt.Errorf("fail to register session: %w", err)
	}

	var partiesJoined []string
	var err error
	if partiesJoined, err = waitForSessionStart(input.Server, input.Session); err != nil {
		return "", fmt.Errorf("fail to wait for session start: %w", err)
	}

	messenger := &MessengerImp{
		Server:    input.Server,
		SessionID: input.Session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key:    input.Key,
		folder: input.KeyFolder,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, false)
	if err != nil {
		return "", fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Debug("start EDDSA keysign...")
	resp, err := tssServerImp.KeysignEdDSA(&tss.KeysignRequest{
		PubKey:               input.PubKey,
		MessageToSign:        input.Message,
		LocalPartyKey:        input.Key,
		KeysignCommitteeKeys: strings.Join(partiesJoined, ","),
	})
	if err != nil {
		return "", fmt.Errorf("fail to EDDSA key sign: %w", err)
	}

	rBytes, err := base64.RawStdEncoding.DecodeString(resp.R)
	if err != nil {
		return "", fmt.Errorf("fail to decode r: %w", err)
	}
	sBytes, err := base64.RawStdEncoding.DecodeString(resp.S)
	if err != nil {
		return "", fmt.Errorf("fail to decode s: %w", err)
	}
	signature := append(rBytes, sBytes...)
	signatureEncoded := base64.StdEncoding.EncodeToString(signature)
	log.Debug("EDDSA keysign success", "signature", signatureEncoded)

	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Error("fail to end session", "error", err)
	}
	close(endCh)
	wg.Wait()
	return signatureEncoded, nil
}
