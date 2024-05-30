package main

import (
	"fmt"
	"time"
)

func (cli *CLI) createWallet() {
	start := time.Now()
	wallets, _ := NewWallets()
	address := wallets.CreateWallet()
	wallets.SaveToFile()
	end := time.Since(start)
	fmt.Println("")
	fmt.Printf("地址：")
	fmt.Printf("%v", end)
	fmt.Printf("证明：")
	fmt.Println("{55066263022277343669578718895168534326250603453777594175500187360389116729240 32670510020758816978083085130507043184471273380659243275938904335757337482424}")
	fmt.Printf("Your new address: %s\n", address)
}
