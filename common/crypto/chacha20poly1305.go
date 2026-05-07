// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidKey      = errors.New("crypto: invalid key size")
	ErrCiphertextShort = errors.New("crypto: ciphertext too short")
	ErrAuthFailed      = errors.New("crypto: authentication failed")
)

func EncryptXAEAD(secret, plaintext, ad []byte) ([]byte, error) {
	if len(secret) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKey
	}

	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: rand read failed: %w", err)
	}

	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

func DecryptXAEAD(secret, ciphertext, ad []byte) ([]byte, error) {
	if len(secret) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKey
	}

	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}

	ns := aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrCiphertextShort
	}

	nonce, actualPayload := ciphertext[:ns], ciphertext[ns:]

	plaintext, err := aead.Open(nil, nonce, actualPayload, ad)
	if err != nil {
		return nil, ErrAuthFailed
	}

	return plaintext, nil
}
