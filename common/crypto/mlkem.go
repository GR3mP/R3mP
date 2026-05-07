// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

const (
	MLKEM768PubKeySize     = 1184
	MLKEM768CiphertextSize = 1088
	MLKEM768SharedSeedSize = 32
)

type KeyPair768 struct {
	DecapsKey *mlkem.DecapsulationKey768
	EncapsKey *mlkem.EncapsulationKey768
}

func Generate768() (*KeyPair768, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &KeyPair768{
		DecapsKey: dk,
		EncapsKey: dk.EncapsulationKey(),
	}, nil
}

func Encapsulate768(pubKeyBytes []byte) (sharedSecret []byte, ciphertext []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(pubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid encapsulation key: %w", err)
	}

	secret, ct := ek.Encapsulate()
	return secret, ct, nil
}

func (kp *KeyPair768) Decapsulate(ciphertext []byte) ([]byte, error) {
	secret, err := kp.DecapsKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}
	return secret, nil
}

func GenerateMlKemSeed768() ([]byte, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func GenDecapsulationKey(seed []byte) (*mlkem.DecapsulationKey768, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return dk, nil
}
