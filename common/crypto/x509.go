// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the GNU GPL v.3 license
// (you can find the license file in the root folder).

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	// "errors"
	"fmt"
	"math/big"
	"time"
)

type CertificateInfo struct {
	CommonName   string
	Organization string
	ExpiryYears  int
}

func GenerateX509SelfSigned(info CertificateInfo) (certDER []byte, priv ed25519.PrivateKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   info.CommonName,
			Organization: []string{info.Organization},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(info.ExpiryYears, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return certDER, priv, nil
}

func EncodeToPEM(certDER []byte) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return string(pem.EncodeToMemory(block))
}

func VerifyCertificate(rootCertDER, nodeCertDER []byte) error {
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return fmt.Errorf("root parse error: %w", err)
	}

	nodeCert, err := x509.ParseCertificate(nodeCertDER)
	if err != nil {
		return fmt.Errorf("node parse error: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := nodeCert.Verify(opts); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}
