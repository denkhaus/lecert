package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ericchiang/letsencrypt"
	log "github.com/sirupsen/logrus"
)

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

func (cli *Client) validateDomainOwnership(domain string) error {
	l := log.WithField("domain", domain)
	l.Debug("asking for challenges")
	auth, _, err := cli.NewAuthorization(cli.accountKey, "dns", domain)
	if err != nil {
		return err
	}
	chals := auth.Combinations(supportedChallengs...)
	if len(chals) == 0 {
		return fmt.Errorf("no supported challenge combinations")
	}

	for _, chal := range chals {
		for _, chal := range chal {
			l.Debug("challenge:", chal.Type)
			if chal.Type != letsencrypt.ChallengeHTTP {
				return fmt.Errorf("unsupported challenge type was requested")
			}
			path, resource, err := chal.HTTP(cli.accountKey)
			if err != nil {
				return err
			}
			cli.SetResource(path, resource)
			err = cli.ChallengeReady(cli.accountKey, chal)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (cli *Client) fulfilCSR(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	for _, domain := range csr.DNSNames {
		err := cli.validateDomainOwnership(domain)
		if err != nil {
			return nil, err
		}
	}
	err := cli.validateDomainOwnership(csr.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	res, err := cli.NewCertificate(cli.accountKey, csr)
	if err != nil {
		return nil, err
	}

	return res.Certificate, nil

}
