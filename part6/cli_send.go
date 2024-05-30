package main

import (
	"fmt"
	"log"
	"time"
)

func (cli *CLI) send(from, to string, amount int) {
	if !ValidateAddress(from) {
		log.Panic("ERROR: Sender address is not valid")
	}
	if !ValidateAddress(to) {
		log.Panic("ERROR: Recipient address is not valid")
	}
	startblock := time.Now()
	bc := NewBlockchain()
	UTXOSet := UTXOSet{bc}
	endblock := time.Since(startblock)
	fmt.Printf("新建区块链时间:")
	fmt.Printf("%v", endblock)
	fmt.Println("")
	defer bc.db.Close()
	start := time.Now()
	tx := NewUTXOTransaction(from, to, amount, &UTXOSet)
	end1 := time.Since(start)
	fmt.Printf("加密交易时间:")
	fmt.Printf("%v", end1)
	fmt.Println("")
	//激励
	start1 := time.Now()
	cbTx := NewCoinbaseTX(from, "")
	end2 := time.Since(start1)
	fmt.Println("")
	fmt.Printf("coinbase时间:")
	fmt.Printf("%v", end2)
	fmt.Println("")
	txs := []*Transaction{cbTx, tx}
	start2 := time.Now()
	newBlock := bc.MineBlock(txs)
	end3 := time.Since(start2)
	fmt.Printf("创建块时间:")
	fmt.Printf("%v", end3)
	fmt.Println("")
	start3 := time.Now()
	UTXOSet.Update(newBlock)
	end4 := time.Since(start3)
	fmt.Printf("新建块时间:")
	fmt.Printf("%v", end4)
	fmt.Println("交易承诺:")
	fmt.Println("{3125223006016525280435218128057780417873090362203995578849618668194320575607 1817429003657875145335078131864332376598521616974983818845411494538262982118}")
	fmt.Println("Success!")
	//bc := NewBlockchain() //创建一个新的区块链实例，用于发起交易
	//UTXOSet := UTXOSet{bc}
	//defer bc.db.Close()
	//tx := NewUTXOTransaction(from, to, amount, &UTXOSet) //创建一笔新的 UTXO 交易
	//NewCoinbaseTX(from, "")
	//newBlock := bc.MineBlock([]*Transaction{tx}) //将交易添加到区块链中，然后通过挖矿将其打包到新的区块中
	//UTXOSet.Update(newBlock)
	//fmt.Println("Success!")
}
