package tss

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math"
	"math/big"

	tcrypto "github.com/bnb-chain/tss-lib/v2/crypto"
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
	ecdsaPubKey := pubKey.ToECDSAPubKey()
	pubKeyBytes := elliptic.MarshalCompressed(ecdsaPubKey.Curve, ecdsaPubKey.X, ecdsaPubKey.Y)
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
