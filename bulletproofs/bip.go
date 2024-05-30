package bulletproofs

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"strconv"

	"github.com/developerblockchain/zkrp/crypto/p256"
	"github.com/developerblockchain/zkrp/util/bn"
	"github.com/developerblockchain/zkrp/util/byteconversion"
)

var SEEDU = "BulletproofsDoesNotNeedTrustedSetupU"

/*
InnerProductParams 包含用于计算 Pedersen 承诺的椭圆曲线生成器
commitments.
*/
type InnerProductParams struct {
	N  int64
	Cc *big.Int
	Uu *p256.P256
	H  *p256.P256
	Gg []*p256.P256
	Hh []*p256.P256
	P  *p256.P256
}

/*
InnerProductProof 内积证明及其参数配置
*/
type InnerProductProof struct {
	N      int64
	Ls     []*p256.P256
	Rs     []*p256.P256
	U      *p256.P256
	P      *p256.P256
	Gg     *p256.P256
	Hh     *p256.P256
	A      *big.Int
	B      *big.Int
	Params InnerProductParams
}

/*
SetupInnerProduct 初始化
*/
func setupInnerProduct(H *p256.P256, g, h []*p256.P256, c *big.Int, N int64) (InnerProductParams, error) {
	var params InnerProductParams

	if N <= 0 {
		return params, errors.New("N must be greater than zero")
	} else {
		params.N = N
	}
	if H == nil {
		// seedh：=BulletproofsDoesNotNeedTrustedSetupH
		params.H, _ = p256.MapToGroup(SEEDH)
	} else {
		params.H = H
	}
	if g == nil {
		params.Gg = make([]*p256.P256, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Gg[i], _ = p256.MapToGroup(SEEDH + "g" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Gg = g
	}
	if h == nil {
		params.Hh = make([]*p256.P256, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Hh[i], _ = p256.MapToGroup(SEEDH + "h" + strconv.FormatInt(i, 10))
		}
	} else {
		params.Hh = h
	}
	params.Cc = c
	params.Uu, _ = p256.MapToGroup(SEEDU)
	//设置无穷远点
	params.P = new(p256.P256).SetInfinity()

	return params, nil
}

/*
proveInnerProduct 生成内积证明
*/
func proveInnerProduct(a, b []*big.Int, P *p256.P256, params InnerProductParams) (InnerProductProof, error) {
	var (
		proof InnerProductProof
		n, m  int64
		Ls    []*p256.P256
		Rs    []*p256.P256
	)

	n = int64(len(a))
	m = int64(len(b))

	if n != m {
		return proof, errors.New("size of first array argument must be equal to the second")
	}

	// Fiat-Shamir:
	// x = Hash(g,h,P,c)
	x, _ := hashIP(params.Gg, params.Hh, P, params.Cc, params.N)
	// Pprime = P.u^(x.c)
	ux := new(p256.P256).ScalarMult(params.Uu, x)
	uxc := new(p256.P256).ScalarMult(ux, params.Cc)
	PP := new(p256.P256).Multiply(P, uxc)
	// Execute Protocol 2 recursively
	proof = computeBipRecursive(a, b, params.Gg, params.Hh, ux, PP, n, Ls, Rs)
	proof.Params = params
	proof.Params.P = PP
	return proof, nil
}

/*
computeBipRecursive
*/
func computeBipRecursive(a, b []*big.Int, g, h []*p256.P256, u, P *p256.P256, n int64, Ls, Rs []*p256.P256) InnerProductProof { // (11)
	var (
		proof                            InnerProductProof
		cL, cR, x, xinv, x2, x2inv       *big.Int
		L, R, Lh, Rh, Pprime             *p256.P256
		gprime, hprime, gprime2, hprime2 []*p256.P256
		aprime, bprime, aprime2, bprime2 []*big.Int
	)
	//比论文多了两个变量 ls rs 是两个椭圆曲线点组成的数组
	if n == 1 { //(14)
		// recursion end
		proof.A = a[0]
		proof.B = b[0]
		proof.Gg = g[0]
		proof.Hh = h[0]
		proof.P = P
		proof.U = u
		proof.Ls = Ls
		proof.Rs = Rs

	} else { // recursion

		// nprime := n / 2
		nprime := n / 2 // (20)

		// Compute cL = < a[:n'], b[n':] >                                    // (21)
		cL, _ = ScalarProduct(a[:nprime], b[nprime:])
		// Compute cR = < a[n':], b[:n'] >                                    // (22)
		cR, _ = ScalarProduct(a[nprime:], b[:nprime])
		// Compute L = g[n':]^(a[:n']).h[:n']^(b[n':]).u^cL                   // (23)
		L, _ = VectorExp(g[nprime:], a[:nprime])
		Lh, _ = VectorExp(h[:nprime], b[nprime:])
		L.Multiply(L, Lh)
		L.Multiply(L, new(p256.P256).ScalarMult(u, cL))

		// Compute R = g[:n']^(a[n':]).h[n':]^(b[:n']).u^cR                   // (24)
		R, _ = VectorExp(g[:nprime], a[nprime:])
		Rh, _ = VectorExp(h[nprime:], b[:nprime])
		R.Multiply(R, Rh)
		R.Multiply(R, new(p256.P256).ScalarMult(u, cR))

		// Fiat-Shamir:                                                       // (26)
		x, _, _ = HashBP(L, R)
		//中国剩余定理中的模反元素求解方法，简单来说就是求逆元
		//模反元素 模数下的逆元，即满足 x^(n-1) ≡ 1 (mod n) 的整数 x
		// order表示阶数
		//xinv =  x^-1
		xinv = bn.ModInverse(x, ORDER)

		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		//vectorScalarExp 向量的幂次运算
		//vectorecadd 求两个向量的哈达玛积
		gprime = vectorScalarExp(g[:nprime], xinv)
		gprime2 = vectorScalarExp(g[nprime:], x)
		gprime, _ = VectorECAdd(gprime, gprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		hprime = vectorScalarExp(h[:nprime], x)
		hprime2 = vectorScalarExp(h[nprime:], xinv)
		hprime, _ = VectorECAdd(hprime, hprime2)

		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = bn.Mod(bn.Multiply(x, x), ORDER)
		x2inv = bn.ModInverse(x2, ORDER)
		Pprime = new(p256.P256).ScalarMult(L, x2)
		Pprime.Multiply(Pprime, P)
		Pprime.Multiply(Pprime, new(p256.P256).ScalarMult(R, x2inv))

		// Compute a' = a[:n'].x      + a[n':].x^(-1)                         // (33)
		aprime, _ = VectorScalarMul(a[:nprime], x)
		aprime2, _ = VectorScalarMul(a[nprime:], xinv)
		aprime, _ = VectorAdd(aprime, aprime2)
		// Compute b' = b[:n'].x^(-1) + b[n':].x                              // (34)
		bprime, _ = VectorScalarMul(b[:nprime], xinv)
		bprime2, _ = VectorScalarMul(b[nprime:], x)
		bprime, _ = VectorAdd(bprime, bprime2)

		Ls = append(Ls, L)
		Rs = append(Rs, R)
		// recursion computeBipRecursive(g',h',u,P'; a', b')                  // (35)
		proof = computeBipRecursive(aprime, bprime, gprime, hprime, u, Pprime, nprime, Ls, Rs)
	}
	proof.N = n
	return proof
}

/*
Verify 验证内积.
*/
func (proof InnerProductProof) Verify() (bool, error) {

	logn := len(proof.Ls)
	var (
		x, xinv, x2, x2inv                   *big.Int
		ngprime, nhprime, ngprime2, nhprime2 []*p256.P256
	)

	gprime := proof.Params.Gg
	hprime := proof.Params.Hh
	Pprime := proof.Params.P
	nprime := proof.N
	for i := int64(0); i < int64(logn); i++ {
		nprime = nprime / 2                        // (20)
		x, _, _ = HashBP(proof.Ls[i], proof.Rs[i]) // (26)
		xinv = bn.ModInverse(x, ORDER)
		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		ngprime = vectorScalarExp(gprime[:nprime], xinv)
		ngprime2 = vectorScalarExp(gprime[nprime:], x)
		gprime, _ = VectorECAdd(ngprime, ngprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		nhprime = vectorScalarExp(hprime[:nprime], x)
		nhprime2 = vectorScalarExp(hprime[nprime:], xinv)
		hprime, _ = VectorECAdd(nhprime, nhprime2)
		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = bn.Mod(bn.Multiply(x, x), ORDER)
		x2inv = bn.ModInverse(x2, ORDER)
		Pprime.Multiply(Pprime, new(p256.P256).ScalarMult(proof.Ls[i], x2))
		Pprime.Multiply(Pprime, new(p256.P256).ScalarMult(proof.Rs[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := bn.Multiply(proof.A, proof.B)
	ab = bn.Mod(ab, ORDER)
	// Compute right hand side 是直接从proof中拿出来得，而不是上面算出来得
	rhs := new(p256.P256).ScalarMult(gprime[0], proof.A)
	hb := new(p256.P256).ScalarMult(hprime[0], proof.B)
	rhs.Multiply(rhs, hb)
	rhs.Multiply(rhs, new(p256.P256).ScalarMult(proof.U, ab))
	// Compute inverse of left hand side
	//取反操作即 np = -np
	//这个Pprime是通过上面循环计算出来得，来验证是否和上面得p相等。
	//因为是椭圆曲线上得点，没法直接用=来判断是否相等，所以要进行取反操作，然后将其乘以右值，如果成立则两边相乘结果为0
	//-a*a = -a + a = 0(无穷远点)
	nP := Pprime.Neg(Pprime)
	nP.Multiply(nP, rhs)
	// If both sides are equal then nP must be zero                               // (17)
	c := nP.IsZero()
	return c, nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []*p256.P256, P *p256.P256, c *big.Int, n int64) (*big.Int, error) {
	//使用 Go 语言中的标准库 sha256 来计算字符串的 SHA-256 哈希值。具体来说，它通过调用 sha256.New() 方法创建了一个 SHA256 哈希对象 digest,然后使用 digest.Write() 方法将字符串 P 写入到哈希对象中进行计算。
	//SHA-256 是一种常用的哈希函数，它可以将任意长度的消息压缩成一个固定长度的哈希值。
	digest := sha256.New()
	digest.Write([]byte(P.String()))

	for i := int64(0); i < n; i++ {
		digest.Write([]byte(g[i].String()))
		digest.Write([]byte(h[i].String()))
	}

	digest.Write([]byte(c.String()))
	output := digest.Sum(nil)
	tmp := output[0:]
	result, err := byteconversion.FromByteArray(tmp)

	return result, err
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []*p256.P256, a, b []*big.Int) *p256.P256 {
	var (
		result *p256.P256
	)

	ga, _ := VectorExp(g, a)
	hb, _ := VectorExp(h, b)
	result = new(p256.P256).Multiply(ga, hb)
	return result
}

/*
VectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(a []*p256.P256, b *big.Int) []*p256.P256 {
	var (
		result []*p256.P256
		n      int64
	)
	n = int64(len(a))
	result = make([]*p256.P256, n)
	for i := int64(0); i < n; i++ {
		result[i] = new(p256.P256).ScalarMult(a[i], b)
	}
	return result
}
