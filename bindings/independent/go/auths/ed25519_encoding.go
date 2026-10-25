package auths

import "math/big"

// canonicalEd25519Encoding implements RFC 8032 section 5.1.3's field/sign
// form. It does not replace curve-point or signature verification.
func canonicalEd25519Encoding(raw []byte) bool {
	if len(raw) != 32 {
		return false
	}
	encoded := make([]byte, 32)
	for i := range raw {
		encoded[31-i] = raw[i]
	}
	negative := encoded[0]&0x80 != 0
	encoded[0] &= 0x7f
	ordinate := new(big.Int).SetBytes(encoded)
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	orderTwo := new(big.Int).Sub(new(big.Int).Set(prime), big.NewInt(1))
	return ordinate.Cmp(prime) < 0 && (!negative || (ordinate.Cmp(big.NewInt(1)) != 0 && ordinate.Cmp(orderTwo) != 0))
}

// For a valid point, y=0 or ±1 has order dividing four; [2]P has y=0
// exactly when d*y^4+2*y^2-1=0. Substituting RFC 8032's d=-121665/121666
// gives the remaining order-eight cases, without decoding an x-coordinate.
// Point recovery and signature verification remain the crypto primitive.
func strictEd25519PointEncoding(raw []byte) bool {
	if !canonicalEd25519Encoding(raw) {
		return false
	}
	encoded := make([]byte, 32)
	for i := range raw {
		encoded[31-i] = raw[i]
	}
	encoded[0] &= 0x7f
	y := new(big.Int).SetBytes(encoded)
	prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	orderTwo := new(big.Int).Sub(new(big.Int).Set(prime), big.NewInt(1))
	if y.Sign() == 0 || y.Cmp(big.NewInt(1)) == 0 || y.Cmp(orderTwo) == 0 {
		return false
	}
	square := new(big.Int).Mul(y, y)
	square.Mod(square, prime)
	fourth := new(big.Int).Mul(square, square)
	polynomial := new(big.Int).Mul(fourth, big.NewInt(121665))
	polynomial.Sub(polynomial, new(big.Int).Mul(square, big.NewInt(243332)))
	polynomial.Add(polynomial, big.NewInt(121666))
	polynomial.Mod(polynomial, prime)
	return polynomial.Sign() != 0
}
