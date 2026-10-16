package auths

import (
	"math/big"
	"testing"
)

func coordinateEncoding(value *big.Int, negative bool) []byte {
	encoded := make([]byte, 32)
	value.FillBytes(encoded)
	for left, right := 0, 31; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	if negative {
		encoded[31] |= 128
	}
	return encoded
}

func TestEd25519CanonicalEncodingBoundaries(t *testing.T) {
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for offset := int64(0); offset < 19; offset++ {
		value := new(big.Int).Add(prime, big.NewInt(offset))
		for _, negative := range []bool{false, true} {
			if canonicalEd25519Encoding(coordinateEncoding(value, negative)) {
				t.Fatal("out-of-field coordinate accepted")
			}
		}
	}
	for _, value := range []*big.Int{big.NewInt(1), new(big.Int).Sub(prime, big.NewInt(1))} {
		if !canonicalEd25519Encoding(coordinateEncoding(value, false)) {
			t.Fatal("canonical boundary refused")
		}
		if canonicalEd25519Encoding(coordinateEncoding(value, true)) {
			t.Fatal("negative zero accepted")
		}
	}
	if !canonicalEd25519Encoding(coordinateEncoding(big.NewInt(0), true)) {
		t.Fatal("nonzero-x sign choice refused")
	}
	for _, length := range []int{0, 31, 33} {
		if canonicalEd25519Encoding(make([]byte, length)) {
			t.Fatal("incorrect width accepted")
		}
	}
}

func TestEd25519StrictRejectsWeakSignature(t *testing.T) {
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for _, value := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(prime, big.NewInt(1))} {
		for _, negative := range []bool{false, true} {
			if strictEd25519PointEncoding(coordinateEncoding(value, negative)) {
				t.Fatal("small-order point accepted")
			}
		}
	}
	identity := coordinateEncoding(big.NewInt(1), false)
	signature := make([]byte, 64)
	signature[0] = 1
	if verifySignature("ed25519-v1", identity, []byte("unrelated message"), signature) {
		t.Fatal("a weak key and R must not authenticate an arbitrary message")
	}
}

func TestEd25519OrderEightPointsAreExcluded(t *testing.T) {
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	y, ok := new(big.Int).SetString("55188659117513257062467267217118295137698188065244968500265048394206261417927", 10)
	if !ok {
		t.Fatal("public torsion coordinate")
	}
	for _, value := range []*big.Int{y, new(big.Int).Sub(prime, y)} {
		for _, negative := range []bool{false, true} {
			encoded := coordinateEncoding(value, negative)
			if !canonicalEd25519Encoding(encoded) {
				t.Fatal("canonical torsion form refused")
			}
			if strictEd25519PointEncoding(encoded) {
				t.Fatal("order-eight point accepted")
			}
		}
	}
}
