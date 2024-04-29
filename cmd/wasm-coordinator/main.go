package wasmcoordinator

import (
	coordinator "github.com/voltix-vault/mobile-tss-lib/coordinator"
	"syscall/js"
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
		Server:      p[0].String(),
		Session:     p[1].String(),
		Key:         p[2].String(),
		KeyFolder:   p[3].String(),
		Parties:     p[4].String(),
		Message:     p[5].String(),
		ChainCode:   p[6].String(),
		DerivePath:  p[7].String(),
		PubKey:      p[8].String(),
		PubKeyEdDSA: p[9].String(),
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
		Parties:       p[8].String(),
		OldParties:    p[9].String(),
	}
	err := coordinator.ExecuteKeyResharing(input)
	if err != nil {
		return err.Error()
	}
	return nil
}

func ExecuteECDSAKeySigning(this js.Value, p []js.Value) interface{} {
	input := coordinator.SigningInput{
		Server:      p[0].String(),
		Session:     p[1].String(),
		Key:         p[2].String(),
		KeyFolder:   p[3].String(),
		Parties:     p[4].String(),
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
	input := coordinator.SigningInput{
		Server:      p[0].String(),
		Session:     p[1].String(),
		Key:         p[2].String(),
		KeyFolder:   p[3].String(),
		Parties:     p[4].String(),
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
