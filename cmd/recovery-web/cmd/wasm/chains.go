package main

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	coskey "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type EthereumKeys struct {
	PrivateKey string
	PublicKey  string
	Address    string
}

type BitcoinKeys struct {
	ExtendedPrivateKey string
	PublicKey          string
	Address            string
	WIF                string
}

type ThorchainKeys struct {
	ExtendedPrivateKey string
	PrivateKey         string
	PublicKey          string
	Address            string
}

type MayachainKeys struct {
	ExtendedPrivateKey string
	PrivateKey         string
	PublicKey          string
	Address            string
}

type Keys interface{}

type ActionFunc func(*hdkeychain.ExtendedKey) (Keys, error)

func showEthereumKey(extendedPrivateKey *hdkeychain.ExtendedKey) (Keys, error) {
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return nil, err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	keys := &EthereumKeys{
		PrivateKey: hex.EncodeToString(nonHardenedPrivKey.Serialize()),
		PublicKey:  hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()),
		Address:    crypto.PubkeyToAddress(*nonHardenedPubKey.ToECDSA()).Hex(),
	}
	return keys, nil
}

func showBitcoinKey(extendedPrivateKey *hdkeychain.ExtendedKey) (Keys, error) {
	net := &chaincfg.MainNetParams
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return nil, err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return nil, err
	}
	wif, err := btcutil.NewWIF(nonHardenedPrivKey, net, true)
	if err != nil {
		return nil, err
	}

	addressPubKey, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return nil, err
	}

	keys := &BitcoinKeys{
		ExtendedPrivateKey: extendedPrivateKey.String(),
		PublicKey:          hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()),
		Address:            addressPubKey.EncodeAddress(),
		WIF:                wif.String(),
	}
	return keys, nil
}

func showThorchainKey(extendedPrivateKey *hdkeychain.ExtendedKey) (Keys, error) {
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return nil, err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("thor", "thorpub")
	config.SetBech32PrefixForValidator("thorv", "thorvpub")
	config.SetBech32PrefixForConsensusNode("thorc", "thorcpub")

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	addr := types.AccAddress(compressedPubkey.Address().Bytes())

	keys := &ThorchainKeys{
		ExtendedPrivateKey: extendedPrivateKey.String(),
		PrivateKey:         hex.EncodeToString(nonHardenedPrivKey.Serialize()),
		PublicKey:          hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()),
		Address:            addr.String(),
	}
	return keys, nil
}

func showMayachainKey(extendedPrivateKey *hdkeychain.ExtendedKey) (Keys, error) {
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return nil, err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("maya", "mayapub")
	config.SetBech32PrefixForValidator("mayav", "mayavpub")
	config.SetBech32PrefixForConsensusNode("mayac", "mayacpub")

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	addr := types.AccAddress(compressedPubkey.Address().Bytes())

	keys := &MayachainKeys{
		ExtendedPrivateKey: extendedPrivateKey.String(),
		PrivateKey:         hex.EncodeToString(nonHardenedPrivKey.Serialize()),
		PublicKey:          hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()),
		Address:            addr.String(),
	}
	return keys, nil
}
