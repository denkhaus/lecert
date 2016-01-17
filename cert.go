package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"
)

type PemCert struct {
	cert     *x509.Certificate
	buf      []byte
	filePath string
}

func NewPemCert(certFile string) *PemCert {
	pc := new(PemCert)
	pc.filePath = certFile
	return pc
}

func (p *PemCert) Parse() error {
	buf, err := ioutil.ReadFile(p.filePath)
	if err != nil {
		return err
	}
	p.buf = buf

	block, _ := pem.Decode(p.buf)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	p.cert = cert

	return nil
}

func (p *PemCert) IsExpiredAt(expire time.Time) bool {
	return p.cert.NotAfter.Before(expire)
}

func (p *PemCert) ExpiresIn() time.Duration {
	return p.cert.NotAfter.Sub(time.Now())
}
