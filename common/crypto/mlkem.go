// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	// "crypto/ecdh"
	"crypto/mlkem"
	// "crypto/rand"
	// "log"
)

func GenKeyMlKem() (*mlkem.DecapsulationKey768, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk, dk.Bytes(), nil
}
