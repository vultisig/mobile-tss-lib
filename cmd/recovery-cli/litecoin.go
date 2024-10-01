package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/ltcutil"
)

func showLitecoinKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	net := &ltcchaincfg.MainNetParams
	fmt.Println("non-hardened extended private key for litcoin:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	wif, err := ltcutil.NewWIF(nonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := ltcutil.NewAddressWitnessPubKeyHash(ltcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Println("hex encoded non-hardened public key for litecoin:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Println("address:", addressPubKey.EncodeAddress())
	fmt.Println("WIF private key for litecoin:", wif.String())
	return nil
}
