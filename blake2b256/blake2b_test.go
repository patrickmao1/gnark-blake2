package blake2b256

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCompile(t *testing.T) {
	circuit, _ := genTestCircuitAssignment(t, "e13855a4bc1e6225acd25d3c338f356560bbc09ebed59e07ab2add0fac62a7ede3ccdd984c291be1166a1456c53fde851d972e9f02e55e4ddc0b34bce22a98cdf9404d21515e2bf30e77fc3a76b4267a8dc47ba7bdccaf98de294e2446f295fa8b5dcd887359f27bf785d745da399b0d4e37bfd970e003a437dae626c0c856b6")
	cc, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	require.NoError(t, err)
	fmt.Println("constraints", cc.GetNbConstraints())
}

func TestSingleBlock(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := genTestCircuitAssignment(t, "ABCD")
	assert.ProverSucceeded(circuit, assignment, test.WithCurves(bls12381.ID))

	circuit, assignment = genTestCircuitAssignment(t, "3dae4586e574baa630a1fa083156f683")
	assert.ProverSucceeded(circuit, assignment, test.WithCurves(bls12381.ID))
}

func TestMultiBlocks(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := genTestCircuitAssignment(t, "083cd1907ccacb2f7c7ce8efb62c0fb633311f71ba61ab20e51f12e73fc8a189c9b3544f49a49de56865134146cca399998898bb417e54ef42cafb3184d9b5f19a")
	assert.ProverSucceeded(circuit, assignment, test.WithCurves(bls12381.ID))
}

func TestSingleBlockBoundary(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := genTestCircuitAssignment(t, "a707fce9f6068f2de157feaf2a8608e56b40097abc87216e94d6fdb8f0ee7d0d5975602679da94e3432a10feebdea339c788ec6ff70c0a9520262cab4fdea2a8")
	assert.ProverSucceeded(circuit, assignment, test.WithCurves(bls12381.ID))
}

func TestMultiBlockBoundary(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := genTestCircuitAssignment(t, "e13855a4bc1e6225acd25d3c338f356560bbc09ebed59e07ab2add0fac62a7ede3ccdd984c291be1166a1456c53fde851d972e9f02e55e4ddc0b34bce22a98cdf9404d21515e2bf30e77fc3a76b4267a8dc47ba7bdccaf98de294e2446f295fa8b5dcd887359f27bf785d745da399b0d4e37bfd970e003a437dae626c0c856b6")
	assert.ProverSucceeded(circuit, assignment, test.WithCurves(bls12381.ID))
}

func TestInvalidAssignment(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := genTestCircuitAssignment(t, "e13855a4bc1e6225acd25d3c338f356560bbc09ebed59e07ab2add0fac62a7ede3ccdd984c291be1166a1456c53fde851d972e9f02e55e4ddc0b34bce22a98cdf9404d21515e2bf30e77fc3a76b4267a8dc47ba7bdccaf98de294e2446f295fa8b5dcd887359f27bf785d745da399b0d4e37bfd970e003a437dae626c0c856b6")
	assignment.Output[0] = 1
	assert.ProverFailed(circuit, assignment, test.WithCurves(bls12381.ID))
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

func genTestCircuitAssignment(t *testing.T, hexMsg string) (circuit *TestCircuit, assignment *TestCircuit) {
	msg, err := hex.DecodeString(hexMsg)
	require.NoError(t, err)
	fmt.Printf("msg %d, len %d\n", msg, len(msg))
	padded := PadZero(msg)
	input := make([]frontend.Variable, len(padded))
	for i, b := range padded {
		input[i] = b
	}

	b2b := crypto.BLAKE2b_256.New()
	b2b.Write(msg)
	hash := b2b.Sum(nil)
	output := [32]frontend.Variable{}
	for i, b := range hash {
		output[i] = b
	}

	circuit = &TestCircuit{
		Input:  input,
		Len:    len(msg),
		Output: output,
	}
	assignment = &TestCircuit{
		Input:  input,
		Len:    len(msg),
		Output: output,
	}
	return
}
