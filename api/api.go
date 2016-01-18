package api

import (
	"crypto/x509"
	"encoding/pem"

	"io/ioutil"
	"path/filepath"

	"github.com/denkhaus/lecert/client"
	"github.com/denkhaus/lecert/config"
	"github.com/dustin/go-humanize"
	"github.com/juju/errors"

	log "github.com/sirupsen/logrus"
)

type Api struct {
	cnf *config.Config
	cli *client.Client
}

func (p *Api) VerifyCertificate(domain string) error {
	l := log.WithField("domain", domain)
	certFile := filepath.Join(p.cnf.OutputDir, domain+".crt.pem")

	if !fileExists(certFile) {
		return errors.New("certificate does not exist")
	}

	cert := NewPemCert(certFile)
	if err := cert.Parse(); err != nil {
		return errors.Annotate(err, "parse certificate")
	}

	l.Infof("certificate will expire in %s", humanize.Time(cert.ExpireTime()))
	return nil
}

func (p *Api) RenewCertificate(domain string) error {
	l := log.WithField("domain", domain)
	csrFile := filepath.Join(p.cnf.OutputDir, domain+".csr.pem")
	crtFile := filepath.Join(p.cnf.OutputDir, domain+".crt.pem")

	if !fileExists(csrFile) {
		return errors.New("signing request file does not exist")
	}

	if !fileExists(crtFile) {
		return errors.New("certificate does not exist")
	}

	data, err := ioutil.ReadFile(csrFile)
	if err != nil {
		return errors.Annotate(err, "read csr file")
	}

	b, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}

	if err != nil {
		return errors.Annotatef(err, "parse csr file %q", csrFile)

	}

	if csr.Subject.CommonName != domain {
		return errors.Errorf("domain mismatch: signing request is for domain %s", csr.Subject.CommonName)
	}

	cert, err := p.cli.FulfillCSR(csr)
	if err != nil {
		return errors.Annotate(err, "fulfil csr")
	}

	data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	if p.cnf.Chain {
		data = append(data, p.cli.Chain()...)
	}

	if err = makeExpiredName(crtFile); err != nil {
		return errors.Annotate(err, "make crt expired")
	}

	if err = ioutil.WriteFile(crtFile, data, 0600); err != nil {
		return errors.Annotate(err, "write certificate")
	}

	l.Infof("Certificate successfull renewed")
	return nil
}

func (p *Api) GenerateCertificate(domain string) error {
	l := log.WithField("domain", domain)
	certFile := filepath.Join(p.cnf.OutputDir, domain+".crt.pem")
	csrFile := filepath.Join(p.cnf.OutputDir, domain+".csr.pem")
	keyFile := filepath.Join(p.cnf.OutputDir, domain+".key.pem")

	if fileExists(certFile) || fileExists(keyFile) {
		return errors.Errorf("cert and/or key already exists")
	}

	csr, key, err := newCSR(domain, p.cnf.Bits)
	if err != nil {
		return errors.Annotate(err, "new csr")
	}

	cert, err := p.cli.FulfillCSR(csr)
	if err != nil {
		return errors.Annotate(err, "fulfil csr")
	}

	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	err = ioutil.WriteFile(csrFile, data, 0600)
	if err != nil {
		return errors.Annotate(err, "write csr file")
	}

	data = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	err = ioutil.WriteFile(keyFile, data, 0600)
	if err != nil {
		return errors.Annotate(err, "write key file")
	}

	data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if p.cnf.Chain {
		data = append(data, p.cli.Chain()...)
	}

	err = ioutil.WriteFile(certFile, data, 0600)
	if err != nil {
		return errors.Annotate(err, "write crt file")
	}

	l.Infof("Certificate successfull generated")
	return nil
}

func (p *Api) SignCSR(csrFile string) error {

	if !fileExists(csrFile) {
		return errors.Errorf("csr file %q does not exist", csrFile)
	}

	data, err := ioutil.ReadFile(csrFile)
	if err != nil {
		return errors.Annotate(err, "read csr file")
	}

	b, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}
	if err != nil {
		return errors.Annotate(err, "parse csr")
	}

	l := log.WithField("domain", csr.Subject.CommonName)
	certFile := filepath.Join(p.cnf.OutputDir, csr.Subject.CommonName+".crt.pem")
	if fileExists(certFile) {
		return errors.Errorf("cert already exists for %q", csr.Subject.CommonName)
	}

	cert, err := p.cli.FulfillCSR(csr)
	if err != nil {
		return errors.Annotate(err, "fulfil csr")
	}

	data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if p.cnf.Chain {
		data = append(data, p.cli.Chain()...)
	}

	err = ioutil.WriteFile(certFile, data, 0600)
	if err != nil {
		return errors.Annotate(err, "write crt file")
	}

	l.Infoln("Sign csr successfull")
	return nil
}

func New(cnf *config.Config) (*Api, error) {
	cli, err := client.New(cnf)
	if err != nil {
		return nil, errors.Annotate(err, "new client")
	}

	api := Api{cnf: cnf, cli: cli}
	return &api, nil
}
