package main

import (
	"math/big"
)

func fillBytes(x *big.Int, buf []byte) []byte {
	b := x.Bytes()
	if len(b) > len(buf) {
		panic("buffer too small")
	}
	offset := len(buf) - len(b)
	for i := range buf {
		if i < offset {
			buf[i] = 0
		} else {
			buf[i] = b[i-offset]
		}
	}
	return buf
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	amap := make(map[string]int)
	for _, val := range a {
		amap[val]++
	}

	for _, val := range b {
		if amap[val] == 0 {
			return false
		}
		amap[val]--
	}

	return true
}
