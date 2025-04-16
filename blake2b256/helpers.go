package blake2b256

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"math/big"
	"sync"
)

var once sync.Once

func init() {
	once.Do(func() {
		solver.RegisterHint(divHint)
	})
}

func PadZero(data []byte) []byte {
	if len(data)%128 != 0 {
		data = append(data, make([]byte, 128-len(data)%128)...)
	}
	return data
}

func encodeSelector(api frontend.API, ll frontend.Variable, maxRounds int) ([]frontend.Variable, frontend.Variable) {
	roundIndex, _ := div(api, api.Add(ll, 127), 128)
	roundIndex = api.Sub(roundIndex, 1)
	ret := make([]frontend.Variable, maxRounds)
	for i := 0; i < maxRounds; i++ {
		isAtRound := api.IsZero(api.Sub(roundIndex, big.NewInt(int64(i))))
		ret[i] = api.Select(isAtRound, 1, 0)
	}
	return ret, roundIndex
}

func isEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
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

func rotl[T any](v []T, r int) []T {
	// rotate v by r to the left
	return append(v[r:], v[:r]...)
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
		//bits = flipByGroup(bits, 8)
		for j := 0; j < 8; j++ {
			bs = append(bs, api.FromBinary(bits[j*8:(j+1)*8]...))
		}
	}
	return bs
}

func div(api frontend.API, a, b frontend.Variable) (frontend.Variable, frontend.Variable) {
	out, err := api.Compiler().NewHint(divHint, 2, a, b)
	if err != nil {
		panic(fmt.Errorf("failed to initialize div hint instance: %s", err.Error()))
	}
	q, r := out[0], out[1]
	orig := api.Add(api.Mul(q, b), r)
	api.AssertIsEqual(orig, a)
	api.AssertIsEqual(api.Cmp(r, b), -1)
	rangeChecker := rangecheck.New(api)
	rangeChecker.Check(q, 64)
	return q, r
}

func divHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != 2 {
		return fmt.Errorf("QuoRemHint: input len must be 2")
	}
	if len(out) != 2 {
		return fmt.Errorf("QuoRemHint: output len must be 2")
	}
	out[0] = new(big.Int)
	out[1] = new(big.Int)
	out[0].QuoRem(in[0], in[1], out[1])
	return nil
}
