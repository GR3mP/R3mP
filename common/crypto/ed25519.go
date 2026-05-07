// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	// "fmt"
)

type EdKeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func GenerateEdKeyPair() (*EdKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EdKeyPair{Public: pub, Private: priv}, nil
}

func (kp *EdKeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.Private, message)
}

func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}
