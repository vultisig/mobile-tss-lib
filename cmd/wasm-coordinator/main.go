package main

import (
	"fmt"
	"strings"
	"syscall/js"

	coordinator "github.com/voltix-vault/mobile-tss-lib/coordinator"
)

func main() {
	c := make(chan struct{}, 0)

	js.Global().Set("generateRandomChainCodeHex", js.FuncOf(GenerateRandomChainCodeHex))
	js.Global().Set("executeKeyGeneration", ExecuteKeyGeneration())
	js.Global().Set("executeKeyResharing", js.FuncOf(ExecuteKeyResharing))
	js.Global().Set("ExecuteECDSAKeySigning", js.FuncOf(ExecuteECDSAKeySigning))
	js.Global().Set("ExecuteEdDSAKeySigning", js.FuncOf(ExecuteEdDSAKeySigning))
	js.Global().Set("hello", Hello())

	<-c
}

func ExecuteKeyGeneration() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		server := args[0].String()
		session := args[1].String()
		key := args[2].String()
		keyFolder := args[3].String()
		parties := strings.Split(args[4].String(), ",")
		chainCode := args[5].String()
		fmt.Println(args[0].String(), args[1].String(), args[2].String(), args[3].String(), args[4].String(), args[5].String())

		// Handler for the Promise
		handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resolve := args[0]
			reject := args[1]

			// Run the key generation asynchronously
			go func() {
				input := coordinator.KeygenInput{
					Server:    server,
					Session:   session,
					Key:       key,
					KeyFolder: keyFolder,
					Parties:   parties,
					ChainCode: chainCode,
				}

				key, err := coordinator.ExecuteKeyGeneration(input)
				if err != nil {
					// Handle errors: reject the Promise if an error occurs
					errorConstructor := js.Global().Get("Error")
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
					return
				}

				// Resolve the Promise with the generated key
				resolve.Invoke(key)
			}()

			// The handler of a Promise returns nil as it doesn't produce an immediate value
			return nil
		})

		// Create and return the Promise object
		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})
}

func Hello() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return "Hello from Vultisign in Go"
	})
}

func GenerateRandomChainCodeHex(this js.Value, p []js.Value) interface{} {
	chainCode, err := coordinator.GenerateRandomChainCodeHex()
	if err != nil {
		return err.Error()
	}
	return chainCode
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
