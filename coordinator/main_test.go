package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func CleanTestingKeys() error {
	dir := "../keys"

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".json" {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	})

	return err
}

// func TestGenerateRandomChainCodeHex(t *testing.T) {
// 	got, err := GenerateRandomChainCodeHex()
// 	if err != nil {
// 		t.Errorf("got %q, wanted %q", got, err)
// 	}
// 	want := "test"

// 	if got != want {
// 		t.Errorf("got %q, wanted %q", got, want)
// 	}
// }

func TestExecuteKeyGeneration(t *testing.T) {
	if err := CleanTestingKeys(); err != nil {
		t.Errorf("Failed to clean up the keys folder: %q", err)
	}

	var wg sync.WaitGroup
	parties := []string{"first", "second", "third"}

	session := fmt.Sprintf("%d", rand.Int64N(1e6))
	chainCode := "80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0"
	server := "http://127.0.0.1:8080"

	paramsMap := map[string]KeygenInput{
		"first": {
			Server:    server,
			Session:   session,
			Parties:   parties,
			ChainCode: chainCode,
			Key:       "first",
			KeyFolder: "../keys/first",
		},
		"second": {
			Server:    server,
			Session:   session,
			Parties:   parties,
			ChainCode: chainCode,
			Key:       "second",
			KeyFolder: "../keys/second",
		},
		"third": {
			Server:    server,
			Session:   session,
			Parties:   parties,
			ChainCode: chainCode,
			Key:       "third",
			KeyFolder: "../keys/third",
		},
	}

	for _, party := range parties {
		partyConfig := paramsMap[party]
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("Joining gen party as", partyConfig.Key)
			publicKey, err := ExecuteKeyGeneration(partyConfig)
			if err != nil {
				t.Errorf("Execution for %s failed with %q", partyConfig.Key, err)
			}
			os.Setenv("PUBLIC_KEY", publicKey)
		}()
	}

	wg.Wait()
}

func TestExecuteKeySigning(t *testing.T) {
	var wg sync.WaitGroup
	parties := []string{"first", "third"}

	session := fmt.Sprintf("%d", rand.Int64N(1e12))

	publicKey := os.Getenv("PUBLIC_KEY")
	if publicKey == "" {
		t.Errorf("Public key not found in global state")
	}

	server := "http://127.0.0.1:8080"
	message := "aGVsbG8gd29ybGQK"
	derivationPath := "m/84'/0'/0'/0/0"
	chainCode := "80871c0f885f953e5206e461630a9222148797e66276a83224c7b9b0f75b3ec0"

	paramsMap := map[string]KeygenInput{
		"first": {
			Key:        "first",
			PubKey:     publicKey,
			Server:     server,
			Session:    session,
			Parties:    parties,
			ChainCode:  chainCode,
			DerivePath: derivationPath,
			Message:    message,
			KeyFolder:  "../keys/first",
		},
		"third": {
			Key:        "third",
			PubKey:     publicKey,
			Server:     server,
			Session:    session,
			Parties:    parties,
			ChainCode:  chainCode,
			DerivePath: derivationPath,
			Message:    message,
			KeyFolder:  "../keys/third",
		},
	}

	for _, party := range parties {
		partyConfig := paramsMap[party]
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("Joining signing party as", partyConfig.Key)
			err := PerformECDSAKeySigning(partyConfig)
			if err != nil {
				t.Errorf("Execution for %s failed with %q", partyConfig.Key, err)
			}
		}()
	}

	wg.Wait()
}
