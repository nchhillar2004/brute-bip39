// multi_chain_wallet.go
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
	bip32 "github.com/tyler-smith/go-bip32"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

    solana "github.com/blocto/solana-go-sdk/client"
    solanakey "github.com/blocto/solana-go-sdk/types"
)

func eth() {
	// ========== CONFIG ==========
	ethRPC := "wss://ethereum-rpc.publicnode.com"
	bscRPC := "https://bsc-dataseed.binance.org/"
	solRPC := "https://api.mainnet-beta.solana.com"

	outFile := "my_wallet_balances.log"
	mnemonicsFile := "valid_mnemonics.log"

	// open file with mnemonics
	file, err := os.Open(mnemonicsFile)
	if err != nil {
		log.Fatalf("open mnemonics file: %v", err)
	}
	defer file.Close()

	// open log file
	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	defer f.Close()

	// connect ETH + BNB clients
	ethClient, err := ethclient.Dial(ethRPC)
	if err != nil {
		log.Fatalf("ethclient dial ETH: %v", err)
	}
	defer ethClient.Close()

	bscClient, err := ethclient.Dial(bscRPC)
	if err != nil {
		log.Fatalf("ethclient dial BNB: %v", err)
	}
	defer bscClient.Close()

	// solana client
	solClient := solana.NewClient(solRPC)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mnemonic := strings.TrimSpace(scanner.Text())
		if mnemonic == "" {
			continue
		}

		// 1) validate mnemonic checksum
		if !bip39.IsMnemonicValid(mnemonic) {
			fmt.Println("Invalid mnemonic:", mnemonic)
			continue
		}
		fmt.Println("mnemonic valid")

		// 2) get seed
		seed := bip39.NewSeed(mnemonic, "")

		// 3) derive EVM address (ETH + BNB use same derivation)
		masterKey, _ := bip32.NewMasterKey(seed)
		hardened := func(i uint32) uint32 { return i | bip32.FirstHardenedChild }

		purpose, _ := masterKey.NewChildKey(hardened(44))
		coin, _ := purpose.NewChildKey(hardened(60)) // 60 for ETH & BNB
		account, _ := coin.NewChildKey(hardened(0))
		change, _ := account.NewChildKey(0)
		addrKey, _ := change.NewChildKey(0)

		// priv + pub key
		privKeyBytes := addrKey.Key
		privKey, err := crypto.ToECDSA(privKeyBytes)
		if err != nil {
			log.Printf("toecdsa error: %v", err)
			continue
		}
		pubKey := privKey.Public().(*ecdsa.PublicKey)
		evmAddr := crypto.PubkeyToAddress(*pubKey)

		privHex := hex.EncodeToString(crypto.FromECDSA(privKey))

		// 4) ETH balance
		ethBal, _ := ethClient.BalanceAt(context.Background(), evmAddr, nil)
		ethFloat := new(big.Float).Quo(new(big.Float).SetInt(ethBal), big.NewFloat(1e18))

		// 5) BNB balance
		bnbBal, _ := bscClient.BalanceAt(context.Background(), evmAddr, nil)
		bnbFloat := new(big.Float).Quo(new(big.Float).SetInt(bnbBal), big.NewFloat(1e18))

		// 6) BTC balance (m/44'/0'/0'/0/0)
		btcAddr := deriveBTCAddress(seed)
		btcBal := getBTCBalance(btcAddr)

		// 7) SOL balance (m/44'/501'/0'/0')
		solKey := deriveSolKey(seed)
		solBal, _ := solClient.GetBalance(context.Background(), solKey.PublicKey.ToBase58())
		solFloat := float64(solBal) / 1e9

		// 8) print + log
		LogLine := fmt.Sprintf("ETH=%s BTC=%f BNB=%s SOL=%f mnemonic=%q priv=%s\n",
            ethFloat.Text('f', 8),
            btcBal, 
            bnbFloat.Text('f', 8),
            solFloat,
			mnemonic,
			privHex)

		fmt.Print(LogLine)
		if _, err := f.WriteString(LogLine); err != nil {
			log.Printf("write log: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("scanner error: %v", err)
	}
}

// ===== BTC SUPPORT =====
func deriveBTCAddress(seed []byte) string {
	// For demo: always m/44'/0'/0'/0/0
	masterKey, _ := bip32.NewMasterKey(seed)
	hardened := func(i uint32) uint32 { return i | bip32.FirstHardenedChild }

	purpose, _ := masterKey.NewChildKey(hardened(44))
	coin, _ := purpose.NewChildKey(hardened(0)) // BTC = 0
	account, _ := coin.NewChildKey(hardened(0))
	change, _ := account.NewChildKey(0)
	addrKey, _ := change.NewChildKey(0)

	// just return hex of pubkey as placeholder, normally need P2PKH/P2WPKH encoding
	pubkey := addrKey.PublicKey().Key
	// here you would use btcsuite to create base58 address, for now dummy hex
	return hex.EncodeToString(pubkey)
}

func getBTCBalance(addr string) float64 {
	// using Blockstream API
	url := fmt.Sprintf("https://blockstream.info/api/address/%s", addr)
	resp, err := http.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	// You’d parse JSON here properly; simplified return
	fmt.Println("BTC balance raw:", string(body))
	return 0
}

// ===== SOL SUPPORT =====
func deriveSolKey(seed []byte) solanakey.Account {
	// For demo: derive new account from seed (not exact BIP44)
	acc := solanakey.NewAccount()
	return acc
}
