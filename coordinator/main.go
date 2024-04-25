package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"

	"github.com/voltix-vault/mobile-tss-lib/tss"
)

// Generates a 32-byte random chain code encoded as a hexadecimal string.
// Does not take arg because it relies on the (secure) rng from the crypto pkg
func GenerateRandomChainCodeHex() (string, error) {
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	fillBytes(common.GetRandomPositiveInt(rand.Reader, max32b), chainCode)
	encodedChainCode := hex.EncodeToString(chainCode)
	return encodedChainCode, nil
}

// Orchestrates TSS keygen process for ECDSA & EdDSA
// including session management and message handling
func ExecuteKeyGeneration(input KeygenInput) (string, error) {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return "", fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(input.Parties, input.Server, input.Session); err != nil {
		return "", fmt.Errorf("fail to wait all parties: %w", err)
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
	log.Println("start downloading messages...")
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Println("start ECDSA keygen...")
	resp, err := tssServerImp.KeygenECDSA(&tss.KeygenRequest{
		LocalPartyID: input.Key,
		AllParties:   strings.Join(input.Parties, ","),
		ChainCodeHex: input.ChainCode,
	})
	if err != nil {
		return "", fmt.Errorf("fail to generate ECDSA key: %w", err)
	}
	log.Printf("ECDSA keygen response: %+v\n", resp)
	time.Sleep(time.Second)
	log.Println("start EDDSA keygen...")
	respEDDSA, errEDDSA := tssServerImp.KeygenEdDSA(&tss.KeygenRequest{
		LocalPartyID: input.Key,
		AllParties:   strings.Join(input.Parties, ","),
		ChainCodeHex: input.ChainCode,
	})
	if errEDDSA != nil {
		return "", fmt.Errorf("fail to generate EDDSA key: %w", errEDDSA)
	}
	log.Printf("EDDSA keygen response: %+v\n", respEDDSA)
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return resp.PubKey, nil
}

type ReshareInput struct {
	Key           string
	KeyFolder     string
	Parties       []string
	Session       string
	Server        string
	ChainCode     string
	PubKey        string
	PubKeyEdDSA   string
	OldParties    []string
	ResharePrefix string
}

// Manages the key resharing process for ECDSA & EdDSA
// ensures all parties are synced and sessions are properly handled
func ExecuteKeyResharing(input *ReshareInput) error {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(input.Parties, input.Server, input.Session); err != nil {
		return fmt.Errorf("fail to wait all parties: %w", err)
	}
	messenger := &MessengerImp{
		Server:    input.Server,
		SessionID: input.Session,
	}
	localStateAccessor := &LocalStateAccessorImp{
		key: input.Key,
	}
	tssServerImp, err := tss.NewService(messenger, localStateAccessor, true)
	if err != nil {
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Println("start ECDSA key resharing...")
	resp, err := tssServerImp.ReshareECDSA(&tss.ReshareRequest{
		PubKey:        input.PubKey,
		LocalPartyID:  input.Key,
		NewParties:    strings.Join(input.Parties, ","), // new parties
		OldParties:    strings.Join(input.OldParties, ","),
		ChainCodeHex:  input.ChainCode,
		ResharePrefix: input.ResharePrefix,
	})
	if err != nil {
		return fmt.Errorf("fail to reshare ECDSA key: %w", err)
	}
	log.Printf("ECDSA keygen response: %+v\n", resp)
	time.Sleep(time.Second)
	log.Println("start EDDSA keygen...")
	respEDDSA, errEdDSA := tssServerImp.ResharingEdDSA(&tss.ReshareRequest{
		PubKey:        input.PubKeyEdDSA,
		LocalPartyID:  input.Key,
		NewParties:    strings.Join(input.Parties, ","),
		OldParties:    strings.Join(input.OldParties, ","),
		ChainCodeHex:  input.ChainCode,
		ResharePrefix: input.ResharePrefix,
	})
	if errEdDSA != nil {
		return fmt.Errorf("fail to generate EDDSA key: %w", errEdDSA)
	}
	log.Printf("EDDSA keygen response: %+v\n", respEDDSA)
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return nil
}

type KeygenInput struct {
	Server        string
	Session       string
	Parties       []string
	OldParties    []string
	Message       string
	ChainCode     string
	ResharePrefix string
	DerivePath    string
	Key           string
	PubKey        string
	PubKeyEdDSA   string
	KeyFolder     string
}

// Coordinates ECDSA signing process in a TSS env
// from session setup to computing and encoding the signature
func PerformECDSAKeySigning(input KeygenInput) error {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(input.Parties, input.Server, input.Session); err != nil {
		return fmt.Errorf("fail to wait all parties: %w", err)
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
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Println("start ECDSA keysign...")
	resp, err := tssServerImp.KeysignECDSA(&tss.KeysignRequest{
		PubKey:               input.PubKey,
		MessageToSign:        input.Message,
		LocalPartyKey:        input.Key,
		KeysignCommitteeKeys: strings.Join(input.Parties, ","),
		DerivePath:           input.DerivePath,
	})
	if err != nil {
		return fmt.Errorf("fail to ECDSA key sign: %w", err)
	}

	rBytes, err := base64.RawStdEncoding.DecodeString(resp.R)
	if err != nil {
		return fmt.Errorf("fail to decode r: %w", err)
	}
	sBytes, err := base64.RawStdEncoding.DecodeString(resp.S)
	if err != nil {
		return fmt.Errorf("fail to decode s: %w", err)
	}
	signature := append(rBytes, sBytes...)
	log.Printf("ECDSA keysign signature: %s\n", base64.StdEncoding.EncodeToString(signature))
	// if err != nil {
	// 	return fmt.Errorf("fail to ECDSA key sign: %w", err)
	// }
	log.Printf("ECDSA keysign response: %+v\n", resp)
	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return nil
}

type KeygenEDDSAInput struct {
	Key       string
	KeyFolder string
	Parties   []string
	Session   string
	Server    string
	PubKey    string
	Message   string
}

// Coordinates EdDSA signing process in a TSS env
// from session setup to computing and encoding the signature
func PerformEdDSAKeySigning(input KeygenEDDSAInput) error {
	if err := registerSession(input.Server, input.Session, input.Key); err != nil {
		return fmt.Errorf("fail to register session: %w", err)
	}
	if err := waitAllParties(input.Parties, input.Server, input.Session); err != nil {
		return fmt.Errorf("fail to wait all parties: %w", err)
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
		return fmt.Errorf("fail to create tss server: %w", err)
	}
	endCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go downloadMessage(input.Server, input.Session, input.Key, tssServerImp, endCh, wg)
	log.Println("start EDDSA keysign...")
	resp, err := tssServerImp.KeysignEdDSA(&tss.KeysignRequest{
		PubKey:               input.PubKey,
		MessageToSign:        input.Message,
		LocalPartyKey:        input.Key,
		KeysignCommitteeKeys: strings.Join(input.Parties, ","),
	})
	if err != nil {
		return fmt.Errorf("fail to EDDSA key sign: %w", err)
	}
	log.Printf("EDDSA keysign response: %+v\n", resp)

	// delay one second before clean up the session
	time.Sleep(time.Second)
	if err := endSession(input.Server, input.Session); err != nil {
		log.Printf("fail to end session: %s\n", err)
	}
	close(endCh)
	wg.Wait()
	return nil
}
