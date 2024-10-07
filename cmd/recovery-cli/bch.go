package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/gcash/bchd/bchec"
	bchChainCfg "github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
)

func showBitcoinCashKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	net := &bchChainCfg.MainNetParams
	fmt.Println("non-hardened extended private key for bitcoinCash:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	bchNonHardenedPrivKey, _ := bchec.PrivKeyFromBytes(bchec.S256(), nonHardenedPrivKey.Serialize())
	wif, err := bchutil.NewWIF(bchNonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Println("hex encoded non-hardened public key for bitcoinCash:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Println("address:", addressPubKey.EncodeAddress())
	fmt.Println("WIF private key for bitcoinCash:", wif.String())
	return nil
}
