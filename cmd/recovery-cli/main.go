package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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
	"github.com/golang/protobuf/proto"
	"github.com/urfave/cli/v2"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"golang.org/x/term"

	"github.com/vultisig/mobile-tss-lib/tss"
)

type TssKeyType int

const (
	ECDSA TssKeyType = iota
	EdDSA
)

func (t TssKeyType) String() string {
	return [...]string{"ECDSA", "EdDSA"}[t]
}
func main() {
	app := cli.App{
		Name:  "key-recover",
		Usage: "Recover a key from a set of TSS key shares , need at least threshold number of shares to recover the key",
		Commands: []*cli.Command{
			{
				Name:   "decrypt",
				Action: decryptFileAction,
				Usage:  "decrypt files",
			},
			{
				Name: "recover",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:       "files",
						Usage:      "path to key share files",
						Required:   true,
						HasBeenSet: false,
					},
				},
				Action: recoverAction,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

// getLocalStateFromBak read the keyshare from backup file , ask password for decryption if the file is encrypted
func getLocalStateFromBak(inputFileName string) (map[TssKeyType]tss.LocalState, error) {
	filePathName, err := filepath.Abs(inputFileName)
	if err != nil {
		return nil, fmt.Errorf("error getting absolute path for file %s: %w", inputFileName, err)
	}
	_, err = os.Stat(filePathName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", inputFileName, err)
	}
	fileContent, err := readFileContent(filePathName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", inputFileName, err)
	}

	rawContent, err := base64.StdEncoding.DecodeString(string(fileContent))
	if err != nil {
		return nil, fmt.Errorf("error decoding file %s: %w", inputFileName, err)
	}
	var vaultContainer v1.VaultContainer
	if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
		return nil, fmt.Errorf("error unmarshalling file %s: %w", inputFileName, err)
	}
	var decryptedVault *v1.Vault
	// file is encrypted
	if vaultContainer.IsEncrypted {
		decryptedVault, err = decryptVault(&vaultContainer, inputFileName)
		if err != nil {
			return nil, fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
		}

	} else {
		vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vault: %w", err)
		}
		var v v1.Vault
		if err := proto.Unmarshal(vaultData, &v); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vault: %w", err)

		}
		decryptedVault = &v
	}
	localStates := make(map[TssKeyType]tss.LocalState)
	for _, keyshare := range decryptedVault.KeyShares {
		var localState tss.LocalState
		if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
			return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
		}
		if keyshare.PublicKey == decryptedVault.PublicKeyEcdsa {
			localStates[ECDSA] = localState
		} else {
			localStates[EdDSA] = localState
		}
	}
	return localStates, nil
}
func readDataFileContent(inputFilePathName string) ([]byte, error) {
	filePathName, err := filepath.Abs(inputFilePathName)
	if err != nil {
		return nil, fmt.Errorf("error getting absolute path for file %s: %w", inputFilePathName, err)
	}
	_, err = os.Stat(filePathName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", inputFilePathName, err)
	}
	fileContent, err := readFileContent(filePathName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", inputFilePathName, err)
	}
	buf, err := hex.DecodeString(string(fileContent))
	if err == nil {
		return buf, nil
	}
	fmt.Printf("Enter password to decrypt the vault(%s): ", inputFilePathName)
	pwdBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	password := string(pwdBytes)
	decryptedVault, err := DecryptVault(password, fileContent)
	if err != nil {
		return nil, fmt.Errorf("error decrypting file %s: %w", inputFilePathName, err)
	}
	return hex.DecodeString(string(decryptedVault))
}

// getTssSecretFile reads a file and returns the KeygenLocalState struct
func getLocalStateFromFile(file string) (map[TssKeyType]tss.LocalState, error) {
	var voltixBackup struct {
		Vault struct {
			Keyshares []struct {
				Pubkey   string `json:"pubkey"`
				Keyshare string `json:"keyshare"`
			} `json:"keyshares"`
		} `json:"vault"`
		Version string `json:"version"`
	}
	fileContent, err := readDataFileContent(file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(fileContent, &voltixBackup)
	if err != nil {
		return nil, err
	}
	localStates := make(map[TssKeyType]tss.LocalState)
	for _, item := range voltixBackup.Vault.Keyshares {
		var localState tss.LocalState
		if err := json.Unmarshal([]byte(item.Keyshare), &localState); err != nil {
			return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
		}
		if localState.ECDSALocalData.ShareID != nil {
			localStates[ECDSA] = localState
		}
		if localState.EDDSALocalData.ShareID != nil {
			localStates[EdDSA] = localState
		}
	}
	return localStates, nil
}

type tempLocalState struct {
	FileName   string
	LocalState map[TssKeyType]tss.LocalState
}

func recoverAction(context *cli.Context) error {
	files := context.StringSlice("files")
	if len(files) == 0 {
		return cli.ShowAppHelp(context)
	}

	allSecret := make([]tempLocalState, 0, len(files))
	for _, f := range files {
		if isBakFile(f) {
			result, err := getLocalStateFromBak(f)
			if err != nil {
				return fmt.Errorf("error reading file %s: %w", f, err)
			}
			allSecret = append(allSecret, tempLocalState{
				FileName:   f,
				LocalState: result,
			})
		}
		if strings.HasSuffix(f, "dat") {
			result, err := getLocalStateFromFile(f)
			if err != nil {
				return fmt.Errorf("error reading file %s: %w", f, err)
			}
			allSecret = append(allSecret, tempLocalState{
				FileName:   f,
				LocalState: result,
			})
		}
	}
	threshold := len(files)
	keyTypes := []TssKeyType{ECDSA, EdDSA}
	for _, keyType := range keyTypes {
		if err := getKeys(threshold, allSecret, keyType); err != nil {
			return err
		}
	}

	return nil
}
func getKeys(threshold int, allSecrets []tempLocalState, keyType TssKeyType) error {
	vssShares := make(vss.Shares, len(allSecrets))
	for i, s := range allSecrets {
		if keyType == ECDSA {
			share := vss.Share{
				Threshold: threshold,
				ID:        s.LocalState[ECDSA].ECDSALocalData.ShareID,
				Share:     s.LocalState[ECDSA].ECDSALocalData.Xi,
			}
			vssShares[i] = &share
		} else { // EdDSA
			share := vss.Share{
				Threshold: threshold,
				ID:        s.LocalState[EdDSA].EDDSALocalData.ShareID,
				Share:     s.LocalState[EdDSA].EDDSALocalData.Xi,
			}
			vssShares[i] = &share
		}
	}
	curve := binanceTss.S256()
	if keyType == EdDSA {
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
	fmt.Printf("hex encoded root pubkey(%s):%s\n", keyType, hexPubKey)
	fmt.Printf("hex encoded root privkey(%s):%s\n", keyType, hex.EncodeToString(privateKey.Serialize()))
	if keyType == ECDSA {
		net := &chaincfg.MainNetParams
		chaincode := allSecrets[0].LocalState[ECDSA].ChainCodeHex
		fmt.Println("chaincode:", chaincode)
		chaincodeBuf, err := hex.DecodeString(chaincode)
		if err != nil {
			return err
		}
		extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)
		fmt.Println("extended private key full:", extendedPrivateKey.String())

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
				name:       "bitcoinCache",
				derivePath: "m/44'/145'/0'/0/0",
				action:     showBitcoinCashKey,
			},
			{
				name:       "litecoin",
				derivePath: "m/84'/2'/0'/0/0",
				action:     showLitecoinKey,
			},
			{
				name:       "dogecoin",
				derivePath: "m/44'/3'/0'/0/0",
				action:     showDogecoinKey,
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
			{
				name:       "atomchain",
				derivePath: "m/44'/118'/0'/0/0",
				action:     showAtomKey,
			},
			{
				name:       "kujirachain",
				derivePath: "m/44'/118'/0'/0/0",
				action:     showKujiKey,
			},
			{
				name:       "dydx",
				derivePath: "m/44'/118'/0'/0/0",
				action:     showDydxKey,
			},
			{
				name:       "terrachain",
				derivePath: "m/44'/118'/0'/0/0", //Terra (LUNA) also supports m/44'/330'/0'/0/0 but for re-use - using LUNC
				action:     showTerraKey,
			},
		}
		for _, coin := range supportedCoins {
			fmt.Println("Recovering", coin.name, "key....")
			key, err := getDerivedPrivateKeys(coin.derivePath, extendedPrivateKey)
			if err != nil {
				return fmt.Errorf("error deriving private key for %s: %w", coin.name, err)
			}
			fmt.Println("private key for ", coin.name, ":", key.String())
			if err := coin.action(key); err != nil {
				fmt.Println("error showing keys for ", coin.name, "error:", err)
			}
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
	fmt.Println("WIF private key for bitcoin: p2wpkh:", wif.String())
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

func showMayachainKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	fmt.Println("non-hardened extended private key for MAYAChain:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened private key for MAYAChain:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("hex encoded non-hardened public key for MAYAChain:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	// Generate the address bytes
	addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())
	// Use sdk.Bech32ifyAccPub with the correct prefix
	bech32Addr := sdk.MustBech32ifyAddressBytes("maya", addrBytes)
	fmt.Println("address:", bech32Addr)
	return nil
}

func showAtomKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	fmt.Println("non-hardened extended private key for GAIAChain:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened private key for GAIAChain:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("hex encoded non-hardened public key for GAIAChain:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("cosmos", "cosmospub")
	config.SetBech32PrefixForValidator("cosmosvaloper", "cosmosvaloperpub")
	config.SetBech32PrefixForConsensusNode("cosmosvalcons", "cosmosvalconspub")

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	addr := types.AccAddress(compressedPubkey.Address().Bytes())
	fmt.Println("address:", addr.String())
	return nil
}

func showKujiKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	fmt.Println("non-hardened extended private key for Kuji Chain:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened private key for Kuji Chain:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("hex encoded non-hardened public key for Kuji Chain:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))


	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}

	// Generate the address bytes
	addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())
	// Use sdk.Bech32ifyAccPub with the correct prefix
	bech32Addr := sdk.MustBech32ifyAddressBytes("kujira", addrBytes)
	
	fmt.Println("address:", bech32Addr)
	return nil
}

func showTerraKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	fmt.Println("non-hardened extended private key for Terra Chain:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened private key for Terra Chain:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("hex encoded non-hardened public key for Terra Chain:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))


	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}

	// Generate the address bytes
	addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())
	// Use sdk.Bech32ifyAccPub with the correct prefix
	bech32Addr := sdk.MustBech32ifyAddressBytes("terra", addrBytes)

	fmt.Println("address:", bech32Addr)
	return nil
}

func showDydxKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	fmt.Println("non-hardened extended private key for DYDX Chain:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Println("hex encoded non-hardened private key for DYDX Chain:", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Println("hex encoded non-hardened public key for DYDX Chain:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))


	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}

	// Generate the address bytes
	addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())
	// Use sdk.Bech32ifyAccPub with the correct prefix
	bech32Addr := sdk.MustBech32ifyAddressBytes("dydx", addrBytes)

	fmt.Println("address:", bech32Addr)
	return nil
}



func decryptFileAction(ctx *cli.Context) error {
	for _, item := range ctx.Args().Slice() {
		filePathName, err := filepath.Abs(item)
		if err != nil {
			fmt.Printf("error getting absolute path for file %s: %s\n", item, err)
			continue
		}
		_, err = os.Stat(filePathName)
		if err != nil {
			fmt.Printf("error reading file %s: %s\n", item, err)
			continue
		}

		fileContent, err := readFileContent(filePathName)
		if err != nil {
			fmt.Printf("error reading file %s: %s\n", item, err)
			continue
		}

		if isBakFile(filePathName) {
			rawContent, err := base64.StdEncoding.DecodeString(string(fileContent))
			if err != nil {
				fmt.Printf("error decoding file %s: %s\n", item, err)
				continue
			}
			var vaultContainer v1.VaultContainer
			if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
				fmt.Printf("error unmarshalling file %s: %s\n", item, err)
				continue
			}
			// file is encrypted
			if vaultContainer.IsEncrypted {
				decryptedVault, err := decryptVault(&vaultContainer, filePathName)
				if err != nil {
					fmt.Printf("error decrypting file %s: %s\n", item, err)
					continue
				}
				fmt.Printf("%+v", decryptedVault)
			} else {
				fmt.Println("File is not encrypted")
			}
		}
	}
	return nil
}
func decryptVault(vaultContainer *v1.VaultContainer, inputFileName string) (*v1.Vault, error) {
	vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault: %w", err)
	}
	fmt.Printf("Enter password to decrypt the vault(%s): ", inputFileName)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	password := string(bytePassword)
	decryptedVault, err := DecryptVault(password, vaultData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
	}
	var vault v1.Vault
	if err := proto.Unmarshal(decryptedVault, &vault); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}
	return &vault, nil
}

func DecryptVault(password string, vault []byte) ([]byte, error) {
	// Hash the password to create a key
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(vault) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the vault
	nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]

	// Decrypt the vault
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func isBakFile(fileName string) bool {
	return strings.HasSuffix(fileName, ".bak") || strings.HasSuffix(fileName, ".vult")
}

func readFileContent(fi string) ([]byte, error) {
	return os.ReadFile(fi)
}
