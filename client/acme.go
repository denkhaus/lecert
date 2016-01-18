package client

import (
	"crypto/x509"
	"fmt"

	"github.com/ericchiang/letsencrypt"
	log "github.com/sirupsen/logrus"
)

func (cli *Client) ValidateDomainOwnership(domain string) error {
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

func (cli *Client) FulfillCSR(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	for _, domain := range csr.DNSNames {
		err := cli.ValidateDomainOwnership(domain)
		if err != nil {
			return nil, err
		}
	}
	err := cli.ValidateDomainOwnership(csr.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	res, err := cli.NewCertificate(cli.accountKey, csr)
	if err != nil {
		return nil, err
	}

	return res.Certificate, nil

}
