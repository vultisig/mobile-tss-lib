package main

import (
	"strings"
	"syscall/js"

	coordinator "github.com/voltix-vault/mobile-tss-lib/coordinator"
)

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("generateRandomChainCodeHex", js.FuncOf(GenerateRandomChainCodeHex))
	js.Global().Set("executeKeyGeneration", js.FuncOf(ExecuteKeyGeneration))
	js.Global().Set("executeKeyResharing", js.FuncOf(ExecuteKeyResharing))
	js.Global().Set("ExecuteECDSAKeySigning", js.FuncOf(ExecuteECDSAKeySigning))
	js.Global().Set("ExecuteEdDSAKeySigning", js.FuncOf(ExecuteEdDSAKeySigning))
	<-c
}

func GenerateRandomChainCodeHex(this js.Value, p []js.Value) interface{} {
	chainCode, err := coordinator.GenerateRandomChainCodeHex()
	if err != nil {
		return err.Error()
	}
	return chainCode
}

func ExecuteKeyGeneration(this js.Value, p []js.Value) interface{} {
	input := coordinator.KeygenInput{
		Server:    p[0].String(),
		Session:   p[1].String(),
		Key:       p[2].String(),
		KeyFolder: p[3].String(),
		Parties:   strings.Split(p[4].String(), ","),
		ChainCode: p[5].String(),
	}
	key, err := coordinator.ExecuteKeyGeneration(input)
	if err != nil {
		return err.Error()
	}
	return key
}

func ExecuteKeyResharing(this js.Value, p []js.Value) interface{} {
	input := coordinator.ReshareInput{
		Server:        p[0].String(),
		Session:       p[1].String(),
		Key:           p[2].String(),
		KeyFolder:     p[3].String(),
		ChainCode:     p[4].String(),
		PubKey:        p[5].String(),
		PubKeyEdDSA:   p[6].String(),
		ResharePrefix: p[7].String(),
		Parties:       strings.Split(p[8].String(), ","),
		OldParties:    strings.Split(p[9].String(), ","),
	}
	key, err := coordinator.ExecuteKeyResharing(input)
	if err != nil {
		return err.Error()
	}
	return key
}

func ExecuteECDSAKeySigning(this js.Value, p []js.Value) interface{} {
	input := coordinator.SignInput{
		Server:      p[0].String(),
		Session:     p[1].String(),
		Key:         p[2].String(),
		KeyFolder:   p[3].String(),
		Parties:     strings.Split(p[4].String(), ","),
		Message:     p[5].String(),
		ChainCode:   p[6].String(),
		DerivePath:  p[7].String(),
		PubKey:      p[8].String(),
		PubKeyEdDSA: p[9].String(),
	}
	sig, err := coordinator.ExecuteECDSAKeySigning(input)
	if err != nil {
		return err.Error()
	}
	return sig
}

func ExecuteEdDSAKeySigning(this js.Value, p []js.Value) interface{} {
	input := coordinator.SignInput{
		Server:      p[0].String(),
		Session:     p[1].String(),
		Key:         p[2].String(),
		KeyFolder:   p[3].String(),
		Parties:     strings.Split(p[4].String(), ","),
		Message:     p[5].String(),
		ChainCode:   p[6].String(),
		DerivePath:  p[7].String(),
		PubKey:      p[8].String(),
		PubKeyEdDSA: p[9].String(),
	}
	sig, err := coordinator.ExecuteEdDSAKeySigning(input)
	if err != nil {
		return err.Error()
	}
	return sig
}
