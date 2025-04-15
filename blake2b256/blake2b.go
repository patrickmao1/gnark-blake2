package blake2b256

import (
	"fmt"
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

func (blake2b *Blake2b) Blake2bBytes(padded []frontend.Variable, ll frontend.Variable) [32]frontend.Variable {
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

	hashWords := blake2b.Blake2bBlocks(m, ll)

	// decompose the 64-bit words into bytes
	bs := wordsToBytes(api, hashWords[:])

	var ret [32]frontend.Variable
	copy(ret[:], bs)
	return ret
}

func (blake2b *Blake2b) Blake2bBlocks(m [][16]frontend.Variable, ll frontend.Variable) [4]frontend.Variable {
	api := blake2b.api

	dd := len(m)
	hs := newEmptyState(dd + 1)
	sel, roundIndex := encodeSelector(api, ll, dd)
	fmt.Println("sel", sel, "roundIndex", roundIndex)

	for i := 0; i < dd; i++ {
		atFinalRound := isEqual(api, i, roundIndex)
		f := api.Select(atFinalRound, 1, 0)
		t := api.Select(atFinalRound, ll, (i+1)*128)
		hs[i+1] = blake2b.compress(hs[i], m[i], t, f)
	}
	for i, block := range m {
		fmt.Printf("blocks[%d] %d\n", i, block)
	}
	for i, h := range hs {
		fmt.Printf("h[%d] %d\n", i, h)
	}
	hs = hs[1:]

	// multiplex the dd states into 1 Output state
	selected := [8]frontend.Variable{}
	for i := range selected {
		selected[i] = new(big.Int)
	}
	for i := 0; i < len(hs); i++ {
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
func (blake2b *Blake2b) compress(h [8]frontend.Variable, m [16]frontend.Variable, t, f frontend.Variable) [8]frontend.Variable {
	api := blake2b.api

	var v [16]frontend.Variable
	copy(v[:8], h[:8])
	for i, val := range iv {
		v[i+8] = val
	}

	fmt.Println("t", t)
	v[12] = xorWord(api, v[12], t)
	//v[13] = xorWord(api, v[13], t.Rsh(t, 64))

	v14 := api.ToBinary(v[14], w)
	v14 = selectAssign(api, f, flipBits(api, v14), v14)
	v[14] = api.FromBinary(v14...)

	fmt.Println("init v", v)
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

	newH := make([]frontend.Variable, 8)
	xorWords(api, newH, h[:], v[:8])
	xorWords(api, newH, newH, v[8:16])
	copy(h[:], newH[:])
	return h
}

// v[a] := (v[a] + v[b] + x) mod 2**w
// v[d] := (v[d] ^ v[a]) <<< R1
// v[c] := (v[c] + v[d])     mod 2**w
// v[b] := (v[b] ^ v[c]) <<< R2
// v[a] := (v[a] + v[b] + y) mod 2**w
// v[d] := (v[d] ^ v[a]) <<< R3
// v[c] := (v[c] + v[d])     mod 2**w
// v[b] := (v[b] ^ v[c]) <<< R4
func (blake2b *Blake2b) mix(v [16]frontend.Variable, a, b, c, d int, x, y frontend.Variable) [16]frontend.Variable {
	v = blake2b.mixSingle(v, a, b, c, d, r1, r2, x)
	v = blake2b.mixSingle(v, a, b, c, d, r3, r4, y)
	//fmt.Println("mix out", v)
	return v
}

// v[a] := (v[a] + v[b] + z) mod 2**w
// v[d] := (v[d] ^ v[a]) <<< R1
// v[c] := (v[c] + v[d])     mod 2**w
// v[b] := (v[b] ^ v[c]) <<< R2
func (blake2b *Blake2b) mixSingle(v [16]frontend.Variable, a, b, c, d, r1, r2 int, z frontend.Variable) [16]frontend.Variable {
	api := blake2b.api

	// v[a] := (v[a] + v[b] + z) mod 2**w
	vaBits := api.ToBinary(api.Add(v[a], v[b], z), w+2) // adding 3 w-bit words can have at most w+2 bits
	vaBits = vaBits[:w]                                 // ignore the hi bits to achieve "mod 2**w"
	v[a] = api.FromBinary(vaBits...)
	fmt.Printf("a %d v[a] %d\n", a, v[a])

	// v[d] := (v[d] ^ v[a]) <<< R1
	vdBits := api.ToBinary(v[d], w)
	xorBits(api, vdBits, vdBits, vaBits)
	vdBits = rotl(vdBits, r1)
	v[d] = api.FromBinary(vdBits...)
	fmt.Printf("d %d v[d] %d\n", d, v[d])

	// v[c] := (v[c] + v[d])     mod 2**w
	vcBits := api.ToBinary(api.Add(v[c], v[d]), w+1)
	vcBits = vcBits[:w]
	v[c] = api.FromBinary(vcBits...)
	fmt.Printf("c %d v[c] %d\n", c, v[c])

	// v[b] := (v[b] ^ v[c]) <<< R2
	vbBits := api.ToBinary(v[b], w)
	xorBits(api, vbBits, vbBits, vcBits)
	//fmt.Printf("xor bits %d\n", vbBits)
	vbBits = rotl(vbBits, r2)
	v[b] = api.FromBinary(vbBits...)
	//fmt.Printf("R2 %d b %d v[b] %d\n", r2, b, vbBits)
	fmt.Printf("R2 %d b %d v[b] %d\n", r2, b, v[b])

	return v
}
