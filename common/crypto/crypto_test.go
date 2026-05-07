// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	"bytes"
	"testing"
)

func TestFullCryptoPipeline(t *testing.T) {
	t.Run("X509_And_Identity", func(t *testing.T) {
		info := CertificateInfo{
			CommonName:   "R3mP-Node-01",
			Organization: "GlebCryptoLab",
			ExpiryYears:  1,
		}
		certDER, priv, err := GenerateX509SelfSigned(info)
		if err != nil {
			t.Fatalf("Failed to gen X509: %v", err)
		}

		err = VerifyCertificate(certDER, certDER)
		if err != nil {
			t.Errorf("Self-verification failed: %v", err)
		}

		if len(priv) == 0 {
			t.Error("Private key is empty")
		}
	})

	t.Run("Handshake_Integration", func(t *testing.T) {
		aliceKP, err := Generate768()
		if err != nil {
			t.Fatalf("Alice ML-KEM gen failed: %v", err)
		}
		alicePub := aliceKP.EncapsKey.Bytes()

		bobSecret, ciphertext, err := Encapsulate768(alicePub)
		if err != nil {
			t.Fatalf("Bob Encapsulate failed: %v", err)
		}

		aliceSecret, err := aliceKP.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("Alice Decapsulate failed: %v", err)
		}

		if !bytes.Equal(aliceSecret, bobSecret) {
			t.Fatal("Shared secrets do not match!")
		}

		salt := []byte("R3mP-salt-v1")
		info := "session-context-123"

		aliceKeys, err := DeriveSessionKeys(aliceSecret, salt, info)
		if err != nil {
			t.Fatalf("Alice HKDF failed: %v", err)
		}
		bobKeys, err := DeriveSessionKeys(bobSecret, salt, info)
		if err != nil {
			t.Fatalf("Bob HKDF failed: %v", err)
		}

		if !bytes.Equal(aliceKeys.ClientWriteKey, bobKeys.ClientWriteKey) {
			t.Fatal("HKDF derived keys do not match!")
		}

		originalMsg := []byte("Top Secret Message for R3mP")
		ad := []byte("header-data")

		encrypted, err := EncryptXAEAD(aliceKeys.ClientWriteKey, originalMsg, ad)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := DecryptXAEAD(bobKeys.ClientWriteKey, encrypted, ad)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if !bytes.Equal(originalMsg, decrypted) {
			t.Error("Decrypted message is corrupted")
		}
	})
}

func BenchmarkMLKEM_Encapsulate(b *testing.B) {
	kp, _ := Generate768()
	pub := kp.EncapsKey.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Encapsulate768(pub)
	}
}

func BenchmarkChaCha20_Poly1305_1K(b *testing.B) {
	key := make([]byte, 32)
	data := make([]byte, 1024)
	ad := []byte("ad")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptXAEAD(key, data, ad)
	}
}
