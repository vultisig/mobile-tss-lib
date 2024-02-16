package tss

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestHashToInt(t *testing.T) {
	// Test case 1: hash length is less than orderBytes
	hash1 := []byte{0x01, 0x02, 0x03}
	expected1 := new(big.Int).SetBytes(hash1)
	result1 := HashToInt(hash1, elliptic.P256())
	if result1.Cmp(expected1) != 0 {
		t.Errorf("Test case 1 failed. Expected: %v, got: %v", expected1, result1)
	}

	// Test case 2: hash length is equal to orderBytes
	hash2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	expected2 := new(big.Int).SetBytes(hash2)
	result2 := HashToInt(hash2, elliptic.P256())
	if result2.Cmp(expected2) != 0 {
		t.Errorf("Test case 2 failed. Expected: %v, got: %v", expected2, result2)
	}

	// Test case 3: hash length is greater than orderBytes
	hash3 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32, 0x33}
	expected3 := new(big.Int).SetBytes(hash3[:(elliptic.P256().Params().N.BitLen()+7)/8])
	result3 := HashToInt(hash3, elliptic.P256())
	if result3.Cmp(expected3) != 0 {
		t.Errorf("Test case 3 failed. Expected: %v, got: %v", expected3, result3)
	}
}

func TestContains(t *testing.T) {
	// Test case 1: searchterm is present in the slice
	slice1 := []string{"apple", "banana", "cherry"}
	searchterm1 := "banana"
	expected1 := true
	result1 := Contains(slice1, searchterm1)
	if result1 != expected1 {
		t.Errorf("Test case 1 failed. Expected: %v, got: %v", expected1, result1)
	}

	// Test case 2: searchterm is not present in the slice
	slice2 := []string{"apple", "banana", "cherry"}
	searchterm2 := "grape"
	expected2 := false
	result2 := Contains(slice2, searchterm2)
	if result2 != expected2 {
		t.Errorf("Test case 2 failed. Expected: %v, got: %v", expected2, result2)
	}

	// Test case 3: empty slice
	slice3 := []string{}
	searchterm3 := "apple"
	expected3 := false
	result3 := Contains(slice3, searchterm3)
	if result3 != expected3 {
		t.Errorf("Test case 3 failed. Expected: %v, got: %v", expected3, result3)
	}
}

func TestGetDerivedPubKey(t *testing.T) {
	// Test case 1: valid inputs
	hexPubKey1 := "0247059f0de83d397b769a61ba271166cefb7676d5e4087dee2e74a6d13dbe901a"
	hexChainCode1 := "8fadb2291a5985819919e418f150e3c5338c6f2a18fb41d64b8eb334ea1c4519"
	path1 := "m/84'/0'/0'/0/0"
	expected1 := "028acdd3137a6f54ce82caeb68c32b9c0baa640665e6f51201c3d4646907deb47d"
	result1, err1 := GetDerivedPubKey(hexPubKey1, hexChainCode1, path1, false)
	if err1 != nil {
		t.Errorf("Test case 1 failed. Unexpected error: %v", err1)
	}
	if result1 != expected1 {
		t.Errorf("Test case 1 failed. Expected: %v, got: %v", expected1, result1)
	}

	// Test case 2: empty pub key
	hexPubKey2 := ""
	hexChainCode2 := "0123456789abcdef0123456789abcdef"
	path2 := "m/0/1/2"
	_, err2 := GetDerivedPubKey(hexPubKey2, hexChainCode2, path2, false)
	if err2 == nil {
		t.Errorf("Test case 2 failed. Expected error, but got nil")
	}

	// Test case 3: empty chain code
	hexPubKey3 := "0123456789abcdef"
	hexChainCode3 := ""
	path3 := "m/0/1/2"
	_, err3 := GetDerivedPubKey(hexPubKey3, hexChainCode3, path3, false)
	if err3 == nil {
		t.Errorf("Test case 3 failed. Expected error, but got nil")
	}

	// Test case 4: empty path
	hexPubKey4 := "0123456789abcdef"
	hexChainCode4 := "0123456789abcdef0123456789abcdef"
	path4 := ""
	_, err4 := GetDerivedPubKey(hexPubKey4, hexChainCode4, path4, false)
	if err4 == nil {
		t.Errorf("Test case 4 failed. Expected error, but got nil")
	}

	// Test case 5: invalid hex pub key
	hexPubKey5 := "invalid"
	hexChainCode5 := "0123456789abcdef0123456789abcdef"
	path5 := "m/0/1/2"
	_, err5 := GetDerivedPubKey(hexPubKey5, hexChainCode5, path5, false)
	if err5 == nil {
		t.Errorf("Test case 5 failed. Expected error, but got nil")
	}

	// Test case 6: invalid hex chain code
	hexPubKey6 := "0123456789abcdef"
	hexChainCode6 := "invalid"
	path6 := "m/0/1/2"
	_, err6 := GetDerivedPubKey(hexPubKey6, hexChainCode6, path6, false)
	if err6 == nil {
		t.Errorf("Test case 6 failed. Expected error, but got nil")
	}

	// Test case 7: invalid path
	hexPubKey7 := "0123456789abcdef"
	hexChainCode7 := "0123456789abcdef0123456789abcdef"
	path7 := "m/0/1/invalid"
	_, err7 := GetDerivedPubKey(hexPubKey7, hexChainCode7, path7, false)
	if err7 == nil {
		t.Errorf("Test case 7 failed. Expected error, but got nil")
	}

	// Test case 8: invalid chain code length
	hexPubKey8 := "0123456789abcdef"
	hexChainCode8 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
	path8 := "m/0/1/2"
	_, err8 := GetDerivedPubKey(hexPubKey8, hexChainCode8, path8, false)
	if err8 == nil {
		t.Errorf("Test case 8 failed. Expected error, but got nil")
	}

}
