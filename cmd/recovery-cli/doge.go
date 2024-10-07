package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	dogec "github.com/eager7/dogd/btcec"
	dogechaincfg "github.com/eager7/dogd/chaincfg"
	"github.com/eager7/dogutil"
)

func showDogecoinKey(extendedPrivateKey *hdkeychain.ExtendedKey) error {
	net := &dogechaincfg.MainNetParams
	fmt.Println("non-hardened extended private key for dogecoin:", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	dogutilNonHardenedPrivKey, _ := dogec.PrivKeyFromBytes(dogec.S256(), nonHardenedPrivKey.Serialize())
	wif, err := dogutil.NewWIF(dogutilNonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := dogutil.NewAddressPubKeyHash(dogutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Println("hex encoded non-hardened public key for dogecoin:", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Println("address:", addressPubKey.EncodeAddress())
	fmt.Println("WIF private key for dogecoin:", wif.String())
	return nil
}
