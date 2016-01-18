package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func fileExists(file string) bool {
	_, err := os.Stat(file)
	// no error, or error is not a "NotExist" error
	// then file exists
	return err == nil || !os.IsNotExist(err)
}

func makeExpiredName(filePath string) error {
	newName := fmt.Sprintf("%s.%s", filePath,
		time.Now().Format("20060102-150405"))
	return os.Rename(filePath, newName)
}

func newCSR(domain string, bits int) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	l := log.WithField("domain", domain)

	l.Infof("Generating %d-bit RSA key", bits)
	certKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           []string{domain},
	}

	l.Debugln("Generating CSR")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	return csr, certKey, nil
}
