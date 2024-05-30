package main

import (
	"crypto/rand"
	"github.com/mit-dci/zksigma"
	"math/big"
)

var ZKLedgerCurve1 zksigma.ZKPCurveParams

func GenPedCommit(zkpcp ZKPCurveParams, value *big.Int) (ECPoint, *big.Int, error) {
	// randomValue = rand() mod N
	randomValue, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
	if err != nil {
		return Zero, nil, err
	}
	return PedCommitR(zkpcp, value, randomValue), randomValue, nil
}

// 根据给定的随机值生成承诺
func PedCommitwithR(zkpcp ZKPCurveParams, value, randomValue *big.Int) ECPoint {

	// modValue = value mod N
	modValue := new(big.Int).Mod(value, zkpcp.C.Params().N)
	modRandom := new(big.Int).Mod(randomValue, zkpcp.C.Params().N)

	// mG, rH :: lhs, rhs
	lhs := zkpcp.Mult(zkpcp.G, modValue)
	rhs := zkpcp.Mult(zkpcp.H, modRandom)

	//mG + rH
	return zkpcp.Add(lhs, rhs)
}

// 打开承诺
func OpenPedersen(zkpcp ZKPCurveParams, value, randomValue *big.Int, pcomm ECPoint) bool {
	return PedCommitR(zkpcp, value, randomValue).Equal(pcomm)

}
