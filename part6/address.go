package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"log"
	"math/big"
)

//链上身份隐私保护
func NewGSPFS(curve elliptic.Curve, private *ecdsa.PrivateKey, xG ECPoint) (*GSPFSProof, error) {

	//curve := elliptic.P256()
	//private, err := ecdsa.GenerateKey(curve, rand.Reader)
	//x

	x := private.D
	//fmt.Printf("x:+%v", x)
	//fmt.Println()

	//A=xG
	//xG := ECPoint{private.PublicKey.X, private.PublicKey.Y}
	//G
	G := ECPoint{curve.Params().Gx, curve.Params().Gy}
	//u
	//fmt.Printf("G:+%v", G)
	//fmt.Println()
	//fmt.Printf("xG:+%v", xG)
	//fmt.Println()
	u, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		log.Panic(err)
	}
	//t1=ug
	t1x, t1y := curve.ScalarBaseMult(u.Bytes())
	ug := ECPoint{t1x, t1y}
	//fmt.Printf("ug:%v", ug)
	//fmt.Println()
	//c
	challenge := Makechallenge(G.Bytes(), xG.Bytes(), ug.Bytes())
	//ca 是对的
	//cax, cay := curve.ScalarMult(xG.X, xG.Y, challenge.Bytes())
	//ca := ECPoint{cax, cay}
	//fmt.Println()
	//fmt.Printf("ca:%v", ca)
	//fmt.Println()
	//s = u + c*x v=u-cx
	v := new(big.Int).Sub(u, new(big.Int).Mul(challenge, x))
	//fmt.Printf("s:%v", v)
	//fmt.Println()
	//vg 是对的
	//vgx, vgy := curve.ScalarBaseMult(v.Bytes())
	//vg := ECPoint{vgx, vgy}
	//fmt.Printf("vg:%v", vg)
	//fmt.Println()
	//vg+ca
	//tox := new(big.Int).Add(vgx, cax)
	//toy := new(big.Int).Add(vgy, cay)
	//fmt.Println()
	//fmt.Printf("tox:+%v,toy:+%v", tox, toy)

	return &GSPFSProof{G, ug, v, challenge}, nil

}
func Makechallenge(arr ...[]byte) *big.Int {
	curve := elliptic.P256()
	hasher := sha256.New()
	for _, v := range arr {
		hasher.Write(v)
	}
	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c = new(big.Int).Mod(c, curve.Params().N)
	return c
}
func (proof *GSPFSProof) Verifygspfs(c elliptic.Curve, A ECPoint) (bool, error) {
	//fmt.Println()
	//fmt.Println("======this is verify=====")
	//fmt.Printf("Ax=xG:%v", A)
	if proof == nil {
		return false, &errorProof{"GSPFSProof.Verify", fmt.Sprintf("passed proof is nil")}
	}
	// 使用给定的a再次计算挑战值 testc = hash(g,a,t1)
	testC := Makechallenge(proof.Base.Bytes(), A.Bytes(), proof.RandCommit.Bytes())
	//fmt.Println()
	//fmt.Printf("testC:%v", testC)
	//判断挑战值是否相等
	if testC.Cmp(proof.Challenge) != 0 {
		return false, &errorProof{"GSPFSProof.Verify", "calculated challenge and proof's challenge do not agree!"}
	}
	// s:vG=hidenvalue*G
	sx, sy := c.ScalarBaseMult(proof.HiddenValue.Bytes())

	//fmt.Println()
	//fmt.Printf("sx:%v,sy:%v", sx, sy)
	//c:CA = cxg
	cx, cy := c.ScalarMult(A.X, A.Y, proof.Challenge.Bytes())
	tot1 := proof.RandCommit
	//fmt.Println()
	//fmt.Printf("cx:+%v,cy:+%v", cx, cy)
	//t1 = ug=randomcommit
	//tot=s+c=t1+ca
	//t1x, t1y := c.Add(sx, sy, cx, cy)
	t1x := new(big.Int).Add(cx, sx)
	t1y := new(big.Int).Add(cy, sy)
	tot := ECPoint{t1x, t1y}
	//fmt.Println()
	//fmt.Printf("t1x:%v,t1y:%v", t1x, t1y)
	// right： cxG + (u - cx)G == uG
	if !proof.RandCommit.Equal(tot1) {
		fmt.Println()
		fmt.Printf("tot is :+%v", tot)
		return false, &errorProof{"GSPFSProof.Verify", "proof's final value and verification final value do not agree!"}
	}
	return true, nil
}

//*****************
