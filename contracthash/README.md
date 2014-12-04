Go port of [https://github.com/Blockstream/contracthashtool](https://github.com/Blockstream/contracthashtool) because learning, and a bit of bikeshedding. 

## Installation:
```go get github.com/roasbeef/sidechains-playground/contracthash```

## Example:
```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/conformal/btcnet"
	"github.com/conformal/btcutil"
	"github.com/roasbeef/sidechains-playground/contracthash"
)

func main() {
	// Testnet derivation with params from original tool implementation
	testnet := &btcnet.TestNet3Params
	redeemScript, _ := hex.DecodeString("5121038695b28f1649c711aedb1fec8df54874334cfb7ddf31ba3132a94d00bdc9715251ae")
	addr, _ := btcutil.DecodeAddress("mqWkEAFeQdrQvyaWNRn5vijPJeiQAjtxL2", testnet)
	nonce, _ := hex.DecodeString("3a11be476485a6273fad4a0e09117d42")

	// Let's create that lovely contract.
	contract, _ := contracthash.DeriveContractHash(redeemScript, &addr, &nonce, testnet)

	fmt.Printf("Nonce: %x \n", contract.Nonce)
	fmt.Printf("P2SH: %v \n", contract.PayToContractAddr.String())
	fmt.Printf("Redeemscript: %x \n", contract.RedeemScript)

	// Aaand homomorphic derivation!
	privKey, _ := btcutil.DecodeWIF("cMcpaCT6pHkyS4347i4rSmecaQtLiu1eH28NWmBiePn8bi6N4kzh")
	key, _ := contracthash.DeriveClaimKey(privKey, nonce, &addr, testnet)

	fmt.Printf("Claim key: %v \n ", key.String())
}
```
