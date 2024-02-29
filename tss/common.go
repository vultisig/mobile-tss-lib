package tss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	tcrypto "github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
)

// GetThreshold calculates the threshold value based on the input value.
// It takes an integer value as input and returns the threshold value and an error.
// If the input value is negative, it returns an error with the message "negative input".
func GetThreshold(value int) (int, error) {
	if value < 0 {
		return 0, errors.New("negative input")
	}
	threshold := int(math.Ceil(float64(value)*2.0/3.0)) - 1
	return threshold, nil
}

// GetHexEncodedPubKey returns the hexadecimal encoded string representation of an ECDSA/EDDSA public key.
// It takes a pointer to an ECPoint as input and returns the encoded string and an error.
// If the ECPoint is nil, it returns an empty string and an error indicating a nil ECPoint.
// If the ECPoint is not on the curve, it returns an empty string and an error indicating an invalid ECPoint.
func GetHexEncodedPubKey(pubKey *tcrypto.ECPoint) (string, error) {
	if pubKey == nil {
		return "", errors.New("nil ECPoint")
	}
	if !pubKey.IsOnCurve() {
		return "", errors.New("invalid ECPoint")
	}
	var pubKeyBytes []byte
	if pubKey.Curve().Params().Name == "secp256k1" {
		pubKeyBytes = elliptic.MarshalCompressed(pubKey.Curve(), pubKey.X(), pubKey.Y())
	} else { // EdDSA
		pubKeyBytes = pubKey.Y().Bytes()
		if pubKey.X().Sign() < 0 {
			pubKeyBytes[len(pubKeyBytes)-1] |= 0x80
		}
	}
	return hex.EncodeToString(pubKeyBytes), nil

}

// Contains checks if a given string slice contains a specific search term.
// It iterates through the slice and returns true if the search term is found, false otherwise.
func Contains(s []string, searchterm string) bool {
	for _, item := range s {
		if item == searchterm {
			return true
		}
	}
	return false
}

// HashToInt converts a byte slice hash to a big.Int value using the provided elliptic curve.
// If the length of the hash is greater than the orderBytes of the curve, it truncates the hash.
// It then performs a right shift on the resulting big.Int value to ensure it fits within the orderBits of the curve.
// The converted big.Int value is returned.
func HashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func GetDerivedPubKey(hexPubKey, hexChainCode, path string, isEdDSA bool) (string, error) {
	if len(hexPubKey) == 0 {
		return "", errors.New("empty pub key")
	}
	if len(hexChainCode) == 0 {
		return "", errors.New("empty chain code")
	}
	if len(path) == 0 {
		return "", errors.New("empty path")
	}
	pubKeyBuf, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", fmt.Errorf("decode hex pub key failed: %w", err)
	}
	chainCodeBuf, err := hex.DecodeString(hexChainCode)
	if err != nil {
		return "", fmt.Errorf("decode hex chain code failed: %w", err)
	}
	curve := tss.S256()
	if isEdDSA {
		curve = tss.Edwards()
	}
	// elliptic.UnmarshalCompressed doesn't work, probably because of a curve
	// thus here we use btcec.ParsePubKey to unmarshal the compressed public key
	pubKey, err := btcec.ParsePubKey(pubKeyBuf)
	if err != nil {
		return "", fmt.Errorf("parse pub key failed: %w", err)
	}

	ecPoint, err := tcrypto.NewECPoint(curve, pubKey.X(), pubKey.Y())
	if err != nil {
		return "", fmt.Errorf("new ec point failed: %w", err)
	}
	if len(chainCodeBuf) != 32 {
		return "", errors.New("invalid chain code length")
	}
	pathBuf, err := GetDerivePathBytes(path)
	if err != nil {
		return "", fmt.Errorf("get derive path bytes failed: %w", err)
	}
	_, extendedKey, err := derivingPubkeyFromPath(ecPoint, chainCodeBuf, pathBuf, curve)
	if err != nil {
		return "", fmt.Errorf("deriving pubkey from path failed: %w", err)
	}
	return hex.EncodeToString(elliptic.MarshalCompressed(curve, extendedKey.X, extendedKey.Y)), nil
}

func derivingPubkeyFromPath(masterPub *tcrypto.ECPoint, chainCode []byte, path []uint32, ec elliptic.Curve) (*big.Int, *ckd.ExtendedKey, error) {
	// build ecdsa key pair
	pk := ecdsa.PublicKey{
		Curve: ec,
		X:     masterPub.X(),
		Y:     masterPub.Y(),
	}

	net := &chaincfg.MainNetParams
	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode[:],
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    net.HDPrivateKeyID[:],
	}

	return ckd.DeriveChildKeyFromHierarchy(path, extendedParentPk, ec.Params().N, ec)
}
func GetDerivePathBytes(derivePath string) ([]uint32, error) {
	var pathBuf []uint32
	for _, item := range strings.Split(derivePath, "/") {
		if len(item) == 0 {
			continue
		}
		if item == "m" {
			continue
		}
		result := strings.Trim(item, "'")
		intResult, err := strconv.Atoi(result)
		if err != nil {
			return nil, fmt.Errorf("invalid path: %w", err)
		}
		pathBuf = append(pathBuf, uint32(intResult))
	}
	return pathBuf, nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func GetDERSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{
		R: r,
		S: s,
	})
}
