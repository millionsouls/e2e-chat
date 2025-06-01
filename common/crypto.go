package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var ErrSharedSecretMismatch = errors.New("***Shared secret mismatch***")

type EncryptedMessage struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Cipher []byte `json:"cipher"`
	Nonce  []byte `json:"nonce"`
}

func ModExp(base, exp, mod *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, mod)
}

func DHDeriveSymmetricKey(a *big.Int, b *big.Int, p *big.Int) ([32]byte, *big.Int, error) {
	secret := ModExp(a, b, p)

	sharedSecret := secret.Bytes()
	key := sha256.Sum256(sharedSecret)
	return key, secret, nil
}

func EncryptAES(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func DecryptAES(key [32]byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func DHGenKeyPair(prime, gen *big.Int) (*big.Int, *big.Int, error) {
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(prime, big.NewInt(2)))
	if err != nil {
		return nil, nil, err
	}
	priv.Add(priv, big.NewInt(1)) // ensure priv ∈ [1, p-2]
	pub := ModExp(gen, priv, prime)
	return priv, pub, nil
}
