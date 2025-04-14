package circuits

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
)

func PadZero(data []byte) []byte {
	if len(data)%128 != 0 {
		data = append(data, make([]byte, 128-len(data)%128)...)
	}
	return data
}

// This implementation of Blake2b-256 follows the description provided by
// https://gist.github.com/sooryan/8d1b2c19bf0b971c11366b0680908d4b
// with no support for secret key

type Blake2b struct {
	api frontend.API
}

func NewBlake2b(api frontend.API) *Blake2b {
	return &Blake2b{api}
}

func (blake2b *Blake2b) Blake2bBytes(padded []frontend.Variable, roundIndex frontend.Variable) [32]frontend.Variable {
	api := blake2b.api

	if len(padded)%16 != 0 {
		panic("invalid input data length")
	}

	dd := len(padded) / 128 // num blocks

	// combine every 8 bytes into a 64-bit word
	ws := bytesToWords(api, padded)

	// group words into 16-word blocks
	var m [][16]frontend.Variable
	for i := 0; i < dd; i++ {
		m = append(m, [16]frontend.Variable{})
		for j := 0; j < 16; j++ {
			m[i][j] = ws[i*16+j]
		}
	}

	hashWords := blake2b.Blake2bBlocks(m, roundIndex)

	// decompose the 64-bit words into bytes
	bs := wordsToBytes(api, hashWords[:])

	var ret [32]frontend.Variable
	copy(ret[:], bs)
	return ret
}

func (blake2b *Blake2b) Blake2bBlocks(m [][16]frontend.Variable, roundIndex frontend.Variable) [4]frontend.Variable {
	api := blake2b.api

	dd := len(m)
	hs := newEmptyState(dd + 1)
	sel := blake2b.encodeRoundIndex(roundIndex, dd)

	for i := 0; i < dd-1; i++ {
		hs[i+1] = blake2b.compress(hs[i], m[i], big.NewInt(int64(i)), false)
	}
	blake2b.compress(hs[dd], m[dd-1], big.NewInt(int64(dd-1)), true)

	// multiplex the dd states into 1 output state
	selected := [8]frontend.Variable{}
	for i := 1; i < len(hs); i++ {
		for j := 0; j < 8; j++ {
			cur := api.Select(sel[i], hs[i][j], 0)
			selected[j] = api.Add(selected[j], cur)
		}
	}

	return [4]frontend.Variable{selected[0], selected[1], selected[2], selected[3]}
}

// FUNCTION F( h[0..7], m[0..15], t, f )
//
// // Initialize local work vector v[0..15]
// v[0..7] := h[0..7]              // First half from state.
// v[8..15] := IV[0..7]            // Second half from IV.
//
// v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
// v[13] := v[13] ^ (t >> w)       // High word.
//
// IF f = TRUE THEN                // last block flag?
// v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
// END IF.
//
// // Cryptographic mixing
// FOR i = 0 TO r - 1 DO           // Ten or twelve rounds.
//
// // Message word selection permutation for this round.
// s[0..15] := SIGMA[i mod 10][0..15]
//
// v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
// v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
// v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
// v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )
//
// v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
// v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
// v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
// v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
//
// # END FOR
//
// FOR i = 0 TO 7 DO               // XOR the two halves.
// h[i] := h[i] ^ v[i] ^ v[i + 8]
// END FOR.
//
// RETURN h[0..7]                  // New state.
//
// END FUNCTION.
func (blake2b *Blake2b) compress(h [8]frontend.Variable, m [16]frontend.Variable, t *big.Int, f frontend.Variable) [8]frontend.Variable {
	api := blake2b.api

	var v [16]frontend.Variable
	copy(v[:8], h[:8])
	for i, val := range iv {
		v[i+8] = val
	}

	tt := api.ToBinary(t, w)
	v12 := api.ToBinary(v[12], w)
	api.Xor(v12, tt)
	v[12] = api.FromBinary(v12...)

	tt = api.ToBinary(t.Rsh(t, 64), w)
	v13 := api.ToBinary(v[13], w)
	api.Xor(v13, tt)
	v[13] = api.FromBinary(v13...)

	v14 := api.ToBinary(v[14], w)
	v14 = selectAssign(api, f, flipBits(api, v14), v14)
	v[14] = api.FromBinary(v14...)

	for i := 0; i < rounds; i++ {
		s := sigma[i%10]

		v = blake2b.mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		v = blake2b.mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		v = blake2b.mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		v = blake2b.mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])

		v = blake2b.mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		v = blake2b.mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		v = blake2b.mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		v = blake2b.mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	newH := xorAssign(api, h[:], v[:8])
	newH = xorAssign(api, newH, v[8:16])
	copy(h[:], newH[:])
	return h
}

// v[a] := (v[a] + v[b] + x) mod 2**w
// v[d] := (v[d] ^ v[a]) >>> R1
// v[c] := (v[c] + v[d])     mod 2**w
// v[b] := (v[b] ^ v[c]) >>> R2
// v[a] := (v[a] + v[b] + y) mod 2**w
// v[d] := (v[d] ^ v[a]) >>> R3
// v[c] := (v[c] + v[d])     mod 2**w
// v[b] := (v[b] ^ v[c]) >>> R4
func (blake2b *Blake2b) mix(v [16]frontend.Variable, a, b, c, d int, x, y frontend.Variable) [16]frontend.Variable {
	v = blake2b.mixSingle(v, a, b, c, d, r1, r2, x)
	return blake2b.mixSingle(v, a, b, c, d, r3, r4, y)
}

// v[a] := (v[a] + v[b] + z) mod 2**w
// v[d] := (v[d] ^ v[a]) >>> R1
// v[c] := (v[c] + v[d])     mod 2**w
// v[b] := (v[b] ^ v[c]) >>> R2
func (blake2b *Blake2b) mixSingle(v [16]frontend.Variable, a, b, c, d, r1, r2 int, z frontend.Variable) [16]frontend.Variable {
	api := blake2b.api

	// v[a] := (v[a] + v[b] + z) mod 2**w
	vaBits := api.ToBinary(api.Add(v[a], v[b], z), w)
	v[a] = api.FromBinary(vaBits...)

	// v[d] := (v[d] ^ v[a]) >>> R1
	vdBits := api.ToBinary(v[d])
	vdBits = xorAssign(api, vdBits, vaBits)
	vdBits = rotr(vdBits, r1)
	v[d] = api.FromBinary(vdBits...)

	// v[c] := (v[c] + v[d])     mod 2**w
	vcBits := api.ToBinary(api.Add(v[c], v[d]), w)
	v[c] = api.FromBinary(vcBits...)

	// v[b] := (v[b] ^ v[c]) >>> R2
	vbBits := api.ToBinary(v[b])
	vbBits = xorAssign(api, vbBits, vcBits)
	vbBits = rotr(vbBits, r2)
	v[b] = api.FromBinary(vbBits...)

	return v
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

func (blake2b *Blake2b) encodeRoundIndex(roundIndex frontend.Variable, maxRounds int) []frontend.Variable {
	api := blake2b.api

	ret := make([]frontend.Variable, maxRounds)
	for i := 0; i < maxRounds; i++ {
		isAtRound := api.IsZero(api.Sub(roundIndex, big.NewInt(int64(i))))
		ret[i] = api.Select(isAtRound, 1, 0)
	}
	return ret
}

func xorAssign(api frontend.API, v1, v2 []frontend.Variable) []frontend.Variable {
	if len(v1) != len(v2) {
		panic("xor: v1 and v2 must have the same length")
	}
	for i, v1b := range v1 {
		v1[i] = api.Xor(v2[i], v1b)
	}
	return v1
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
		var acc frontend.Variable
		for j, byt := range wordBytes {
			offset := new(big.Int).Lsh(big.NewInt(1), uint(64-(j+1)*8))
			acc = api.MulAcc(acc, byt, offset)
		}
		ws = append(ws, acc)
	}

	return ws
}

func wordsToBytes(api frontend.API, ws []frontend.Variable) []frontend.Variable {
	var bs []frontend.Variable
	for _, word := range ws {
		bits := api.ToBinary(word, w)
		bits = flipByGroup(bits, 8)
		for j := 0; j < 8; j++ {
			bs = append(bs, api.FromBinary(bits[j*8:(j+1)*8]))
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
