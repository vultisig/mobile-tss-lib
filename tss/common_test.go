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
