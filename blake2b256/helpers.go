package blake2b256

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
	"slices"
)

func encodeRoundIndex(api frontend.API, roundIndex frontend.Variable, maxRounds int) []frontend.Variable {
	ret := make([]frontend.Variable, maxRounds)
	for i := 0; i < maxRounds; i++ {
		isAtRound := api.IsZero(api.Sub(roundIndex, big.NewInt(int64(i))))
		ret[i] = api.Select(isAtRound, 1, 0)
	}
	return ret
}

func newEmptyState(dd int) [][8]frontend.Variable {
	hs := make([][8]frontend.Variable, dd)
	for i, v := range iv {
		if i == 0 {
			hs[0][i] = new(big.Int).Xor(v, big.NewInt(0x01010000^32)) // omitting kk as we don't support secret key
		} else {
			hs[0][i] = v
		}
	}
	return hs
}

func xorBits(api frontend.API, out, v1, v2 []frontend.Variable) {
	if len(v1) != len(v2) {
		panic("xor: v1 and v2 must have the same length")
	}
	for i, v1b := range v1 {
		out[i] = api.Xor(v2[i], v1b)
	}
}

func xorWords(api frontend.API, out, ws1, ws2 []frontend.Variable) {
	if len(ws1) != len(ws2) {
		panic("xorWords: v1 and v2 must have the same length")
	}
	for i := range ws1 {
		out[i] = xorWord(api, ws1[i], ws2[i])
	}
}

func xorWord(api frontend.API, w1, w2 frontend.Variable) frontend.Variable {
	w1Bits := api.ToBinary(w1, w)
	w2Bits := api.ToBinary(w2, w)
	xorBits(api, w1Bits, w1Bits, w2Bits)
	return api.FromBinary(w1Bits...)
}

func rotr[T any](v []T, r int) []T {
	l := len(v)
	// rotate v by r to the right
	return append(v[l-r:], v[:l-r]...)
}

func selectAssign(api frontend.API, s frontend.Variable, v1, v2 []frontend.Variable) []frontend.Variable {
	for i := range v1 {
		v1[i] = api.Select(s, v1[i], v2[i])
	}
	return v1
}

func flipBits(api frontend.API, vs []frontend.Variable) []frontend.Variable {
	ret := make([]frontend.Variable, len(vs))
	for i, v := range vs {
		ret[i] = api.IsZero(v)
	}
	return ret
}

func bytesToWords(api frontend.API, bs []frontend.Variable) []frontend.Variable {
	if len(bs)%8 != 0 {
		panic("bytesToWords: invalid input data length")
	}

	var ws []frontend.Variable

	for i := 0; i < len(bs)/8; i++ {
		wordBytes := bs[i*w/8 : (i+1)*w/8]
		slices.Reverse(wordBytes)
		wordBits := make([]frontend.Variable, 0, w)
		for _, b := range wordBytes {
			wordBits = append(wordBits, api.ToBinary(b, 8)...)
		}
		ws = append(ws, api.FromBinary(wordBits...))
	}

	return ws
}

func wordsToBytes(api frontend.API, ws []frontend.Variable) []frontend.Variable {
	var bs []frontend.Variable
	for _, word := range ws {
		bits := api.ToBinary(word, w)
		bits = flipByGroup(bits, 8)
		for j := 0; j < 8; j++ {
			bs = append(bs, api.FromBinary(bits[j*8:(j+1)*8]...))
		}
	}
	return bs
}

func flipByGroup(in []frontend.Variable, size int) []frontend.Variable {
	res := make([]frontend.Variable, len(in))
	copy(res, in)
	for i := 0; i < len(res)/size/2; i++ {
		for j := 0; j < size; j++ {
			a := i*size + j
			b := len(res) - (i+1)*size + j
			res[a], res[b] = res[b], res[a]
		}
	}
	return res
}
