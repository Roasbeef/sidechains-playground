package contracthash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

func DeriveClaimKey(privKey *btcutil.WIF, nonce []byte, addr *btcutil.Address, netParams *btcnet.Params) (*btcutil.WIF, error) {
	contractData, err := computeContractData(nonce, *addr)
	if err != nil {
		return nil, err
	}

	tweak, err := computeTweak(privKey.PrivKey.PubKey(), contractData)
	if err != nil {
		return nil, err
	}

	tweakInt := new(big.Int).SetBytes(tweak.Bytes())

	curve := btcec.S256()
	order := curve.Params().N

	derivedSecret := new(big.Int).Mod(
		new(big.Int).Add(tweakInt, privKey.PrivKey.D), order)
	claimKey, _ := btcec.PrivKeyFromBytes(curve, derivedSecret.Bytes())

	wifKey, err := btcutil.NewWIF(claimKey, netParams, true)
	if err != nil {
		return nil, err
	}

	return wifKey, err
}

func GenerateContract(contractTemplate []byte, addr *btcutil.Address, nonce *[]byte, netParams *btcnet.Params) (*Contract, error) {
func DeriveContractHash(contractTemplate []byte, addr *btcutil.Address, nonce *[]byte, netParams *btcnet.Params) (*Contract, error) {
	// Extract info about the contract template redeemscript.
	scriptType, addrs, numRequiredSigs, err := btcscript.ExtractPkScriptAddrs(
		contractTemplate, &btcnet.TestNet3Params)
	if err != nil {
		return nil, err
	}

	// Abort if the redeemscript isn't multi-sig.
	if scriptType != btcscript.MultiSigTy {
		return nil, errors.New(
			"The contractTemplate must be a multi-sig redeemscript")
	}

	// Read a fresh 16-byte nonce from the OS if a nonce isn't provided.
	if nonce == nil {
		nonce := make([]byte, 0, 16)
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error reading random nonce: ", err))
		}
	}

	contractData, err := computeContractData(*nonce, *addr)
	if err != nil {
		return nil, err
	}

	// Extract pubkeys from wrapper type.
	fedPubKeys := make([]*btcec.PublicKey, 0, len(addrs))
	for _, addr := range addrs {
		fedPubKeys = append(fedPubKeys, addr.(*btcutil.AddressPubKey).PubKey())
	}

	derivedKeys := make([]*btcutil.AddressPubKey, 0, len(fedPubKeys))
	curve := btcec.S256()
	for _, fedKey := range fedPubKeys {
		tweak, err := computeTweak(fedKey, contractData)
		if err != nil {
			return nil, err
		}

		tweakInt := new(big.Int).SetBytes(tweak.Bytes())
		if tweakInt.Cmp(curve.Params().N) > 0 {
			return nil, errors.New("Current tweak exceeds order, " +
				"pick a new nonce!")
		}

		tX, tY := curve.ScalarBaseMult(tweak.Bytes())
		nX, nY := curve.Add(tX, tY, fedKey.X, fedKey.Y)
		point := (&btcec.PublicKey{curve, nX, nY}).SerializeCompressed()
		derivedKey, _ := btcutil.NewAddressPubKey(point, netParams)
		derivedKeys = append(derivedKeys, derivedKey)
	}

	script, err := btcscript.MultiSigScript(derivedKeys, numRequiredSigs)
	if err != nil {
		return nil, err
	}

	p2shAddr, err := btcutil.NewAddressScriptHash(script, netParams)
	if err != nil {
		return nil, err
	}

	contract := &Contract{
		Nonce:             *nonce,
		RedeemScript:      script,
		PayToContractAddr: p2shAddr,
	}

	return contract, nil
}

type Contract struct {
	Nonce             []byte
	RedeemScript      []byte
	PayToContractAddr *btcutil.AddressScriptHash
}

func computeTweak(fedKey *btcec.PublicKey, tweakData []byte) (*btcwire.ShaHash, error) {
	mac := hmac.New(sha256.New, fedKey.SerializeCompressed())
	mac.Write(tweakData)
	digest := mac.Sum(nil)

	sha, err := btcwire.NewShaHash(digest)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to compute tweak:", err))
	}

	return sha, nil
}

func computeContractData(nonce []byte, addr btcutil.Address) ([]byte, error) {
	var addressType string
	switch addr.(type) {
	case *btcutil.AddressScriptHash:
		addressType = "P2SH"
	case *btcutil.AddressPubKeyHash:
		addressType = "P2PH"
	default:
		addressType = "UNKNOWN"
	}

	if addressType == "UNKNOWN" {
		return nil, errors.New("Unsupported address type")
	}

	hashBytes := addr.ScriptAddress()

	// 4 bytes for addr type, 16 for nonce, 20 for hash160
	contractData := make([]byte, 0, 4+16+20)
	contractData = append(contractData, []byte(addressType)...)
	contractData = append(contractData, nonce...)
	contractData = append(contractData, hashBytes...)

	return contractData, nil
}
