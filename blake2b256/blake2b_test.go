package blake2b256

import (
	"encoding/hex"
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBlake2bBytes(t *testing.T) {
	msg, err := hex.DecodeString("abcd")
	require.NoError(t, err)
	padded := PadZero(msg)
	input := make([]frontend.Variable, len(padded))
	for i, b := range padded {
		input[i] = b
	}
	hash, err := hex.DecodeString("9606e52f00c679e548b5155af5026f5af4130d7a15c990a791fff8d652c464f5")
	require.NoError(t, err)
	output := [32]frontend.Variable{}
	for i, b := range hash {
		output[i] = b
	}

	circuit := &TestCircuit{
		Input:  input,
		Len:    2,
		Output: output,
	}
	assignment := &TestCircuit{
		Input:  input,
		Len:    2,
		Output: output,
	}

	//cc, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	//require.NoError(t, err)
	//fmt.Println("constraints", cc.GetNbConstraints())

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(bls12381.ID))
}

type TestCircuit struct {
	Input  []frontend.Variable `gnark:",public"`
	Len    frontend.Variable
	Output [32]frontend.Variable
}

func (t *TestCircuit) Define(api frontend.API) error {
	b2b := NewBlake2b(api)
	h := b2b.Blake2bBytes(t.Input, t.Len)
	fmt.Printf("input %.2x\n", t.Input)
	fmt.Printf("expected %.2x\n", t.Output)
	fmt.Printf("actual %.2x\n", h)
	for i, b := range h {
		api.AssertIsEqual(b, t.Output[i])
	}
	return nil
}
