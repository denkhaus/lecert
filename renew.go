package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	renewCmd = &cobra.Command{
		Use:   "renew <domains...>",
		Short: "Renew existing certificate(s).",
		Run:   runRenew,
	}
)

func runRenew(cmd *cobra.Command, args []string) {
	c, err := getConfig(cmd)
	if err != nil {
		log.Fatalln(err)
	}

	cli, err := c.getClient()
	if err != nil {
		log.Fatalln(err)
	}

	for _, domain := range args {
		l := log.WithField("domain", domain)
		csrFile := filepath.Join(c.outputDir, domain+".csr.pem")
		crtFile := filepath.Join(c.outputDir, domain+".crt.pem")

		if !fileExists(csrFile) {
			l.Warnln("skip: signing request file does not exist")
			continue
		}

		if !fileExists(crtFile) {
			l.Warnln("skip: certificate does not exist")
			continue
		}

		data, err := ioutil.ReadFile(csrFile)
		if err != nil {
			l.Fatalln(err)
		}
		b, _ := pem.Decode(data)
		var csr *x509.CertificateRequest
		if b == nil {
			csr, err = x509.ParseCertificateRequest(data)
		} else {
			csr, err = x509.ParseCertificateRequest(b.Bytes)
		}
		if err != nil {
			l.Warnln("couldn't parse '"+csrFile+"':", err)
			continue
		}

		if csr.Subject.CommonName != domain {
			l.Warnf("skip: domain mismatch: signing request is for domain %s" + csr.Subject.CommonName)
			continue
		}

		cert, err := cli.fulfilCSR(csr)
		if err != nil {
			l.Fatalln(err)
		}

		data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if c.chain {
			data = append(data, c.chainData...)
		}

		if err = makeTimeStampFile(crtFile); err != nil {
			l.Fatalln(err)
		}

		if err = ioutil.WriteFile(crtFile, data, 0600); err != nil {
			l.Fatalln(err)
		}
		l.Infof("Renewed certificate")
	}
}
