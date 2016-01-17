package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ericchiang/letsencrypt"
	log "github.com/sirupsen/logrus"
)

func fileExists(file string) bool {
	_, err := os.Stat(file)
	// no error, or error is not a "NotExist" error
	// then file exists
	return err == nil || !os.IsNotExist(err)
}

func makeTimeStampFile(filePath string) error {
	newName := fmt.Sprintf("%s.%s", filePath,
		time.Now().Format("20060102-150405"))
	return os.Rename(filePath, newName)
}

func getChain() []byte {
	certs := make([][]byte, len(chainURLs))
	var wg sync.WaitGroup
	for i, url := range chainURLs {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			resp, err := http.Get(url)
			if err != nil {
				log.Fatalln(err)
				return
			}
			defer resp.Body.Close()
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatalln(err)
				return
			}
			certs[i] = data
		}(i, url)
	}
	wg.Wait()
	result := make([]byte, 0, 1024*1024)
	for _, data := range certs {
		result = append(result, data...)
		if result[len(result)-1] != 10 {
			result = append(result, 10)
		}
	}
	return result
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

func getAccountKey(cli *letsencrypt.Client, keyFile string, bits int) (*rsa.PrivateKey, error) {
	var accountKey *rsa.PrivateKey
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Infof("Generating new %d-bit account key", bits)

		accountKey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		if _, err = cli.NewRegistration(accountKey); err != nil {
			return nil, err
		}
		b := &pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(accountKey),
			Type:  "RSA PRIVATE KEY",
		}
		err = ioutil.WriteFile(keyFile, pem.EncodeToMemory(b), 0600)
		if err != nil {
			return nil, err
		}
	}

	if accountKey == nil {
		pemData, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		b, _ := pem.Decode(pemData)
		if b.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("key file wrong type, expected RSA PRIVATE KEY")
		}
		accountKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
	}
	return accountKey, nil
}
