package bulletproofs

import (
	"fmt"
	"math/big"
	"testing"
	"time"
)

/*
测试内积证明模块 <a,b>=c.
*/
func TestInnerProduct(t *testing.T) {
	var (
		innerProductParams InnerProductParams
		a                  []*big.Int
		b                  []*big.Int
	)
	c := new(big.Int).SetInt64(142)
	innerProductParams, _ = setupInnerProduct(nil, nil, nil, c, 4)

	a = make([]*big.Int, innerProductParams.N)
	a[0] = new(big.Int).SetInt64(2)
	a[1] = new(big.Int).SetInt64(-1)
	a[2] = new(big.Int).SetInt64(10)
	a[3] = new(big.Int).SetInt64(6)
	b = make([]*big.Int, innerProductParams.N)
	b[0] = new(big.Int).SetInt64(1)
	b[1] = new(big.Int).SetInt64(2)
	b[2] = new(big.Int).SetInt64(10)
	b[3] = new(big.Int).SetInt64(7)
	Ctime := time.Now()
	//开始计算内积证明
	fmt.Println("开始计算内积证明")
	commit := commitInnerProduct(innerProductParams.Gg, innerProductParams.Hh, a, b)
	C2 := time.Now()
	sub := C2.Sub(Ctime)
	fmt.Println("commit:", commit)
	fmt.Print("构造承诺的时间是:", sub)
	c3 := time.Now()
	fmt.Println("开始生成证明：")
	proof, _ := proveInnerProduct(a, b, commit, innerProductParams)
	fmt.Println("proof:", proof)
	fmt.Println("开始验证")
	ok, _ := proof.Verify()
	c4 := time.Now()
	sub1 := c4.Sub(c3)
	fmt.Print("验证的时间是:", sub1)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}
