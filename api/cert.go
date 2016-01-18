package api

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	"github.com/juju/errors"
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
		return errors.Annotate(err, "read certificate")
	}
	p.buf = buf

	block, _ := pem.Decode(p.buf)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Annotate(err, "parse certificate")
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

func (p *PemCert) ExpireTime() time.Time {
	return p.cert.NotAfter
}
