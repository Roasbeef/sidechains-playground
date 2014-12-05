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

// secp256k1
var curve = btcec.S256()
var secp256k1_Order = curve.Params().N

// DeriveClaimKey derives a private key based on a contract hash and a
// functionary's public key, allowing a member of the federation to sign-off on
// redemption of the output payed to the contract hash.
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

	// derivedKey = tweak + privKey
	derivedSecret := new(big.Int).Mod(
		new(big.Int).Add(tweakInt, privKey.PrivKey.D), secp256k1_Order)
	claimKey, _ := btcec.PrivKeyFromBytes(curve, derivedSecret.Bytes())

	wifKey, err := btcutil.NewWIF(claimKey, netParams, true)
	if err != nil {
		return nil, err
	}

	return wifKey, err
}

// DeriveContractHash homomorphically derives a pay-to-contract-address
// based on the passed nonce and contractTemplate (a multi-sig
// redeemScript with the federations public keys). The derivation method
// is described in Appendix A of the sidechains whitepaper.
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

	// Read a fresh 16-byte nonce from the OS if one isn't provided.
	if nonce == nil {
		nonce := make([]byte, 0, 16)
		_, err = io.ReadFull(rand.Reader, nonce)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error reading random nonce: %v", err))
		}
	}

	// The contract whose hash we'd like to pay to.
	contractData, err := computeContractData(*nonce, *addr)
	if err != nil {
		return nil, err
	}

	// Extract pubkeys from the wrapper type.
	fedPubKeys := make([]*btcec.PublicKey, 0, len(addrs))
	for _, addr := range addrs {
		fedPubKeys = append(fedPubKeys, addr.(*btcutil.AddressPubKey).PubKey())
	}

	derivedKeys := make([]*btcutil.AddressPubKey, 0, len(fedPubKeys))
	for _, fedKey := range fedPubKeys {
		tweak, err := computeTweak(fedKey, contractData)
		if err != nil {
			return nil, err
		}

		tweakInt := new(big.Int).SetBytes(tweak.Bytes())
		if tweakInt.Cmp(secp256k1_Order) > 0 {
			return nil, errors.New("Current tweak exceeds order, " +
				"pick a new nonce!")
		}

		// PCC_i = P_i + G x Tweak_i
		tX, tY := curve.ScalarBaseMult(tweak.Bytes())
		nX, nY := curve.Add(tX, tY, fedKey.X, fedKey.Y)
		point := (&btcec.PublicKey{Curve: curve, X: nX, Y: nY}).SerializeCompressed()
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

// computeTweak computes a unique tweak for a given federation key and contract.
// The tweak is the output of a HMAC-SHA256 with the fed pub keys as our secret,
// and the contract as our message.
func computeTweak(fedKey *btcec.PublicKey, contract []byte) (*btcwire.ShaHash, error) {
	mac := hmac.New(sha256.New, fedKey.SerializeCompressed())
	mac.Write(contract)
	digest := mac.Sum(nil)

	sha, err := btcwire.NewShaHash(digest)
	if err != nil {
		return nil, err
	}

	return sha, nil
}

// computeContractData creates the contract who's hash will be payed to.
// Our contract is 40 bytes of data: four bytes of a four character abreviation
// of passed address type, 16 bytes for the passed nonce, and finally 20 bytes
// for the decoded base58 address.
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

	contractData := make([]byte, 0, 40)
	contractData = append(contractData, []byte(addressType)...)
	contractData = append(contractData, nonce...)
	contractData = append(contractData, hashBytes...)

	return contractData, nil
}
