package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"syscall/js"

	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/voltix-vault/mobile-tss-lib/tss"
)

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("recoverKey", js.FuncOf(recoverKey))
	<-c
}

type LimitedValueFlag struct {
	allowedValues []string
	value         *string
}

func (f *LimitedValueFlag) Set(value string) error {
	for _, allowed := range f.allowedValues {
		if allowed == value {
			*f.value = value
			return nil
		}
	}
	return errors.New("invalid value")
}

func (f *LimitedValueFlag) String() string {
	return *f.value
}

func (f *LimitedValueFlag) Names() []string {
	return []string{""}
}

var keytype string

func getLocalStateFromContent(fileName string, fileContent string, keytype string) (tss.LocalState, error) {
	var voltixBackup struct {
		Vault struct {
			Keyshares []struct {
				Pubkey   string `json:"pubkey"`
				Keyshare string `json:"keyshare"`
			} `json:"keyshares"`
		} `json:"vault"`
		Version string `json:"version"`
	}
	var localState tss.LocalState
	var err error

	// fmt.Println("fileName:", fileName)

	if strings.HasSuffix(fileName, ".hex") || strings.HasSuffix(fileName, ".dat") {
		// fmt.Println("decoding hex!!!")
		decodedBytes, decodeErr := hex.DecodeString(fileContent)
		if decodeErr != nil {
			return localState, decodeErr
		}
		fileContent = string(decodedBytes)
	}

	err = json.Unmarshal([]byte(fileContent), &voltixBackup)
	if err != nil {
		return localState, err
	}

	for _, item := range voltixBackup.Vault.Keyshares {
		if err := json.Unmarshal([]byte(item.Keyshare), &localState); err != nil {
			return localState, err
		}
		switch keytype {
		case "ECDSA":
			if localState.ECDSALocalData.ShareID != nil {
				return localState, nil
			}
		case "EdDSA":
			if localState.EDDSALocalData.ShareID != nil {
				return localState, nil
			}
		}
	}

	return localState, nil
}

func prettyPrint(data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		log.Fatalf("Error marshaling data: %v", err)
	}

	fmt.Println(string(jsonData))
}

func recoverKey(this js.Value, args []js.Value) interface{} {
	filesRaw := args[0].String()
	keytype = args[1].String()

	var files []struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}

	err := json.Unmarshal([]byte(filesRaw), &files)
	if err != nil {
		return err.Error()
	}

	isECDSA := keytype == "ECDSA"
	allSecret := make([]tss.LocalState, len(files))
	for i, f := range files {
		tssSecret, err := getLocalStateFromContent(f.Name, f.Content, keytype)
		// prettyPrint(tssSecret)
		if err != nil {
			return err
		}
		allSecret[i] = tssSecret
	}
	threshold := len(files)
	vssShares := make(vss.Shares, len(allSecret))
	for i, s := range allSecret {
		if isECDSA {
			share := vss.Share{
				Threshold: threshold,
				ID:        s.ECDSALocalData.ShareID,
				Share:     s.ECDSALocalData.Xi,
			}
			vssShares[i] = &share
		} else { // EdDSA
			share := vss.Share{
				Threshold: threshold,
				ID:        s.EDDSALocalData.ShareID,
				Share:     s.EDDSALocalData.Xi,
			}
			vssShares[i] = &share
		}
	}
	curve := binanceTss.S256()
	if !isECDSA {
		curve = binanceTss.Edwards()
	}
	tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
	if err != nil {
		return err
	}
	privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
	publicKey := privateKey.PubKey()
	hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
	// unharden derive all the keys
	fmt.Println("hex encoded pubkey:", hexPubKey)
	fmt.Println("hex encoded root privkey:", hex.EncodeToString(privateKey.Serialize()))
	net := &chaincfg.MainNetParams
	chaincode := allSecret[0].ChainCodeHex
	fmt.Println("chaincode:", chaincode)
	chaincodeBuf, err := hex.DecodeString(chaincode)
	if err != nil {
		return err
	}
	extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)

	supportedCoins := []struct {
		name       string
		derivePath string
		action     ActionFunc
	}{
		{
			name:       "bitcoin",
			derivePath: "m/84'/0'/0'/0/0",
			action:     showBitcoinKey,
		},
		{
			name:       "ethereum",
			derivePath: "m/44'/60'/0'/0/0",
			action:     showEthereumKey,
		},
		{
			name:       "thorchain",
			derivePath: "m/44'/931'/0'/0/0",
			action:     showThorchainKey,
		},
		{
			name:       "mayachain",
			derivePath: "m/44'/931'/0'/0/0",
			action:     showMayachainKey,
		},
	}

	results := make(map[string]Keys)

	for _, coin := range supportedCoins {
		key, err := getDerivedPrivateKeys(coin.derivePath, extendedPrivateKey)
		// fmt.Println("private key for coin:", coin.name, key)
		if err != nil {
			fmt.Printf("Error deriving private key for %s: %v\n", coin.name, err)
			continue
		}
		result, err := coin.action(key)
		if err != nil {
			fmt.Printf("Error showing keys for %s: %v\n", coin.name, err)
			continue
		}
		results[coin.name] = result
	}

	return js.ValueOf(map[string]interface{}{
		"keytype":                      keytype,
		"threshold":                    threshold,
		"privateKey":                   hex.EncodeToString(privateKey.Serialize()),
		"publicKey":                    hex.EncodeToString(publicKey.SerializeCompressed()),
		"hexPubKey":                    hexPubKey,
		"chaincode":                    chaincode,
		"extendedPrivateKey":           extendedPrivateKey.String(),
		"bitcoin_ExtendedPrivateKey":   results["bitcoin"].(*BitcoinKeys).ExtendedPrivateKey,
		"bitcoin_PublicKey":            results["bitcoin"].(*BitcoinKeys).PublicKey,
		"bitcoin_Address":              results["bitcoin"].(*BitcoinKeys).Address,
		"bitcoin_WIF":                  results["bitcoin"].(*BitcoinKeys).WIF,
		"ethereum_PrivateKey":          results["ethereum"].(*EthereumKeys).PrivateKey,
		"ethereum_PublicKey":           results["ethereum"].(*EthereumKeys).PublicKey,
		"ethereum_Address":             results["ethereum"].(*EthereumKeys).Address,
		"thorchain_ExtendedPrivateKey": results["thorchain"].(*ThorchainKeys).ExtendedPrivateKey,
		"thorchain_PrivateKey":         results["thorchain"].(*ThorchainKeys).PrivateKey,
		"thorchain_PublicKey":          results["thorchain"].(*ThorchainKeys).PublicKey,
		"thorchain_Address":            results["thorchain"].(*ThorchainKeys).Address,
		"mayachain_ExtendedPrivateKey": results["mayachain"].(*MayachainKeys).ExtendedPrivateKey,
		"mayachain_PrivateKey":         results["mayachain"].(*MayachainKeys).PrivateKey,
		"mayachain_PublicKey":          results["mayachain"].(*MayachainKeys).PublicKey,
		"mayachain_Address":            results["mayachain"].(*MayachainKeys).Address,
	})
}

func getDerivedPrivateKeys(derivePath string, rootPrivateKey *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
	pathBuf, err := tss.GetDerivePathBytes(derivePath)
	if err != nil {
		return nil, fmt.Errorf("get derive path bytes failed: %w", err)
	}
	key := rootPrivateKey
	for _, item := range pathBuf {
		key, err = key.Derive(item)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}
