// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type DerivedKeys struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientIV       []byte
	ServerIV       []byte
}

func DeriveSessionKeys(masterSecret []byte, salt []byte, info string) (*DerivedKeys, error) {
	hash := sha256.New
	kdf := hkdf.New(hash, masterSecret, salt, []byte(info))

	keys := &DerivedKeys{
		ClientWriteKey: make([]byte, 32),
		ServerWriteKey: make([]byte, 32),
		ClientIV:       make([]byte, 24),
		ServerIV:       make([]byte, 24),
	}

	if _, err := io.ReadFull(kdf, keys.ClientWriteKey); err != nil {
		return nil, fmt.Errorf("hkdf: failed to derive client key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerWriteKey); err != nil {
		return nil, fmt.Errorf("hkdf: failed to derive server key: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ClientIV); err != nil {
		return nil, fmt.Errorf("hkdf: failed to derive client IV: %w", err)
	}
	if _, err := io.ReadFull(kdf, keys.ServerIV); err != nil {
		return nil, fmt.Errorf("hkdf: failed to derive server IV: %w", err)
	}

	return keys, nil
}
