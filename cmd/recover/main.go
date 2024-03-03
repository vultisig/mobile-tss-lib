package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	coskey "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli/v2"

	"github.com/voltix-vault/mobile-tss-lib/tss"
)

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

func main() {
	app := cli.App{
		Name:  "key-recover",
		Usage: "Recover a key from a set of TSS key shares , need at least threshold number of shares to recover the key",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:       "files",
				Usage:      "path to key share files",
				Required:   true,
				HasBeenSet: false,
			},
			&cli.GenericFlag{
				Name: "keytype",
				Value: &LimitedValueFlag{
					allowedValues: []string{"ECDSA", "EdDSA"},
					value:         &keytype,
				},
				Usage: "please specify the key type, ECDSA or EdDSA",
			},
		},
		Action: recoverAction,
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

// getTssSecretFile reads a file and returns the KeygenLocalState struct
func getLocalStateFromFile(file string) (tss.LocalState, error) {
	var localState tss.LocalState
	fileContent, err := os.ReadFile(file)
	if err != nil {
		return localState, err
	}
	err = json.Unmarshal(fileContent, &localState)
	if err != nil {
		return localState, err
	}
	return localState, nil
}

func recoverAction(context *cli.Context) error {
	files := context.StringSlice("files")
	if len(files) == 0 {
		return cli.ShowAppHelp(context)
	}
	isECDSA := keytype == "ECDSA"
	allSecret := make([]tss.LocalState, len(files))
	for i, f := range files {
		tssSecret, err := getLocalStateFromFile(f)
		if err != nil {
			return err
		}
		allSecret[i] = tssSecret
	}
	committeeSize := len(allSecret[0].KeygenCommitteeKeys)
	threshold, err := tss.GetThreshold(committeeSize)
	if err != nil {
		return err
	}
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
	chaincodeBuf, err := hex.DecodeString(chaincode)
	if err != nil {
		return err
	}
	extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)

	supportedCoins := []struct {
		name       string
		derivePath string
		action     func(*hdkeychain.ExtendedKey) error
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
	}
	for _, coin := range supportedCoins {
		fmt.Println("Recovering", coin.name, "key")
		key, err := getDerivedPrivateKeys(coin.derivePath, extendedPrivateKey)
		if err != nil {
			return fmt.Errorf("error deriving private key for %s: %w", coin.name, err)
		}
		if err := coin.action(key); err != nil {
			fmt.Println("error showing keys for ", coin.name, "error:", err)
		}
	}

	return nil
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
func showEthereumKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened public key for ethereum:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Println("hex encoded private key for ethereum:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("ethereum address:", crypto.PubkeyToAddress(*nonHardenedPubKey.ToECDSA()).Hex())
	return nil
}
func showBitcoinKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	net := &chaincfg.MainNetParams
	fmt.Println("non-hardened extended private key for bitcoin:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	wif, err := btcutil.NewWIF(nonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Println("hex encoded non-hardened public key for bitcoin:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Println("address:", addressPubKey.EncodeAddress())
	fmt.Println("WIF private key for bitcoin:", wif.String())
	return nil
}
func showThorchainKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {

	fmt.Println("non-hardened extended private key for THORChain:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened private key for THORChain:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("hex encoded non-hardened public key for THORChain:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("thor", "thorpub")
	config.SetBech32PrefixForValidator("thorv", "thorvpub")
	config.SetBech32PrefixForConsensusNode("thorc", "thorcpub")

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	addr := types.AccAddress(compressedPubkey.Address().Bytes())
	fmt.Println("address:", addr.String())
	return nil
}
