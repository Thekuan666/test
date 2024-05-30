package bulletproofs

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math"
	"math/big"
	"testing"
	"time"
)

func TestXEqualsRangeStart(t *testing.T) {
	//2^32
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(0)
	//初始化参数设置
	params := setupRange(t, rangeEnd)
	fmt.Println(params)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x equal to range start should verify successfully")
	}
}

//大于范围测试
func TestXLowerThanRangeStart(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(-1)

	params := setupRange(t, rangeEnd)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x lower than range start should not verify")
	}
}

//小于范围测试
func TestXHigherThanRangeEnd(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(rangeEnd + 1)

	params := setupRange(t, rangeEnd)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x higher than range end should not verify")
	}
}

//等于范围边界测试
func TestXEqualToRangeEnd(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(rangeEnd)
	params := setupRange(t, rangeEnd)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x equal to range end should not verify")
	}
}

func TestXWithinRange(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(3)
	params := setupRange(t, rangeEnd)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func setupRange(t *testing.T, rangeEnd int64) BulletProofSetupParams {
	params, err := Setup(rangeEnd)
	if err != nil {
		t.Errorf("Invalid range end: %s", err)
		t.FailNow()
	}
	return params
}

func proveAndVerifyRange(x *big.Int, params BulletProofSetupParams) bool {
	t1 := time.Now()
	proof, _ := Prove(x, params)
	t2 := time.Now()
	fmt.Println("proof的时间为", t2.Sub(t1))
	fmt.Println(proof)
	t3 := time.Now()
	ok, _ := proof.Verify()
	t4 := time.Now()
	fmt.Println("verify的时间为", t4.Sub(t3))
	fmt.Print("verify result:", ok)
	return ok
}

func TestJsonEncodeDecode(t *testing.T) {
	params, _ := Setup(MAX_RANGE_END)
	proof, _ := Prove(new(big.Int).SetInt64(18), params)
	jsonEncoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal("encode error:", err)
	}

	// network transfer takes place here

	var decodedProof BulletProof
	//unmarshal将jsonEncoded值存储到decodeProof中
	err = json.Unmarshal(jsonEncoded, &decodedProof)
	if err != nil {
		t.Fatal("decode error:", err)
	}

	assert.Equal(t, proof, decodedProof, "should be equal")

	ok, err := decodedProof.Verify()
	if err != nil {
		t.Fatal("verify error:", err)
	}
	assert.True(t, ok, "should verify")
}
