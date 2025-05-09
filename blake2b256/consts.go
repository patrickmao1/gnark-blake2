package blake2b256

import (
	"math/big"
)

const (
	w      = 64 // word size (bits)
	rounds = 12
	r1     = 32
	r2     = 24
	r3     = 16
	r4     = 63
)

var iv [8]*big.Int

func init() {
	iv[0] = new(big.Int).SetUint64(0x6a09e667f3bcc908)
	iv[1] = new(big.Int).SetUint64(0xbb67ae8584caa73b)
	iv[2] = new(big.Int).SetUint64(0x3c6ef372fe94f82b)
	iv[3] = new(big.Int).SetUint64(0xa54ff53a5f1d36f1)
	iv[4] = new(big.Int).SetUint64(0x510e527fade682d1)
	iv[5] = new(big.Int).SetUint64(0x9b05688c2b3e6c1f)
	iv[6] = new(big.Int).SetUint64(0x1f83d9abfb41bd6b)
	iv[7] = new(big.Int).SetUint64(0x5be0cd19137e2179)
}

var sigma = [10][16]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}
