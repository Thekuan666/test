package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"testing"
)

//func TestValidateAddress(t *testing.T) {
//	pubKeyHash := Base58Decode([]byte("aaa"))                          //解码Base58编码的地址为字节数组
//	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]  //获取实际的校验和(checksum)
//	version := pubKeyHash[0]                                           //获取版本号
//	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]    //获取数据，公钥哈希中-版本号-校验和，剩下的是公钥的哈希
//	targetChecksum := checksum(append([]byte{version}, pubKeyHash...)) //计算目标校验和
//
//	if bytes.Compare(actualChecksum, targetChecksum) == 0 {
//		fmt.Println("==0")
//	} //比较实际校验和和目标校验和是否相等，判断地址是否有效
//	fmt.Println("！=0")
//}

//A = pk = xg sk = x
//func TestZKaddress(t *testing.T) {
//
//	curve := elliptic.P256()
//	//uG
//	u, err := rand.Int(rand.Reader, curve.Params().N)
//	if err != nil {
//		log.Panic(err)
//	}
//	//t1
//	t1x, t1y := curve.ScalarBaseMult(u.Bytes())
//
//
//}
//func TestHash256(t *testing.T) {
//	hasher := sha256.New()
//	var arr []byte
//	curve := elliptic.P256()
//	for _, v := range arr {
//		hasher.Write(v)
//	}
//	c := new(big.Int).SetBytes(hasher.Sum(nil))
//	c = new(big.Int).Mod(c, curve.Params().N)
//	fmt.Println(c)
//}
func TestZKaddress(t *testing.T) {
	curve := elliptic.P256()
	//b.ReportAllocs()
	//gspfs, err := NewGSPFS(curve, private, xG)
	//verifygspfs, err := gspfs.Verifygspfs(curve, xG)
	//fmt.Println(verifygspfs)

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	xG := ECPoint{private.PublicKey.X, private.PublicKey.Y}
	gspfs, err := NewGSPFS(curve, private, xG)
	fmt.Println(gspfs)
	//if err != nil {
	//	log.Panic(err)
	//}
	//if gspfs == nil {
	//	fmt.Println("nil")
	//}
	//start := time.Now()
	//for i := 11; i < 111; i += 10 {
	//	for j := 0; j < i; j++ {
	//
	//		verifygspfs, err := gspfs.Verifygspfs(curve, xG)
	//		if err != nil {
	//			log.Panic(err)
	//		}
	//
	//		if verifygspfs != true {
	//			fmt.Println("false")
	//		}
	//
	//	}
	//	//end1 := time.Now().UnixNano() - start
	//	end1 := time.Since(start)
	//	fmt.Printf("%v,", end1)
	//	//}
	//}

}

func TestRunngtime(t *testing.T) {
	var s1 = [10]float32{4.4653, 12.3949, 23.2318, 36.68, 56.0815, 77.8652, 104.7496, 134.7441, 166.9833, 202.0752}
	var s2 = [10]float32{1.7106, 5.5654, 10.5741, 17.3668, 26.2587, 36.3452, 48.0403, 62.6196, 77.6057, 94.8852}
	for i := 0; i < 10; i++ {
		s1[i] = s1[i] - s2[i]
	}
	fmt.Println(s1)
}

//func TestMapstruct(t *testing.T) {
//	testMap := make(map[string]Aud)
//	aud1 := Aud{}
//	aud1.commit.recicommit = "re"
//	testMap["111111"] = aud1
//
//}
func TestPed(t *testing.T) {
	curve := elliptic.P256()
	value := big.NewInt(10)
	r := big.NewInt(20)
	x, y := curve.ScalarBaseMult(value.Bytes())
	x1, y1 := curve.ScalarBaseMult(r.Bytes())
	fmt.Println(x, y)
	fmt.Println(x1, y1)
}
