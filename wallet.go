package hdWallet

import (
	"crypto/ecdsa"
	"log"
	"math/big"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Account struct {
	Address    common.Address
	PrivateKey *ecdsa.PrivateKey
}

type Wallet struct {
	Length   uint64
	Accounts []Account
}

func InitWallet(extendedPrivateKey string, size uint64) *Wallet {
	wallet := Wallet{
		Length: size,
	}
	masterKey, err := hdkeychain.NewKeyFromString(extendedPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	var accounts []Account
	for i := uint64(0); i < size; i++ {
		child, err := masterKey.Derive(uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		privateKey, err := child.ECPrivKey()
		if err != nil {
			log.Fatal(err)
		}
		privateKeyECDSA := privateKey.ToECDSA()
		address := PrivateKeyToAddress(privateKeyECDSA)
		accounts = append(accounts, Account{Address: address, PrivateKey: privateKeyECDSA})
	}
	wallet.Accounts = accounts
	return &wallet
}

func PrivateKeyToAddress(privateKey *ecdsa.PrivateKey) common.Address {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("publicKey to ecdsa.PublicKey Fail\n")
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA)
}

func (w *Wallet) GetAccount(in []byte) Account {
	toBig := new(big.Int).SetBytes(in)
	bigIndex := new(big.Int).Mod(toBig, big.NewInt(int64(w.Length)))
	return w.Accounts[bigIndex.Int64()]
}
