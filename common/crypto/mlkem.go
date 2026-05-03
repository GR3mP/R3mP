// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	// "crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	// "log"
)

// Func generate met, bytes ML_KEM768.
func GenKeyMlKem() (*mlkem.DecapsulationKey768, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk, dk.Bytes(), nil
}

// Func generate 64 seed byte.
func GenerateMlKemSeed768() ([]byte, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// Func generate new decapsulation key using a 64-byte seed of the form "d || z".
func GenDecapsulationKey(seed []byte) (*mlkem.DecapsulationKey768, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// Func get 64 byte key.
func GetKeyBytes(dk *mlkem.DecapsulationKey768) []byte {
	return dk.Bytes()
}
