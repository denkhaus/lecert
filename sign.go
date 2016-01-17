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
	signCmd = &cobra.Command{
		Use:   "sign <CSR files...>",
		Short: "Fulfill existing CSR(s).",
		Run:   runSign,
	}
)

func runSign(cmd *cobra.Command, args []string) {
	c, err := getConfig(cmd)
	if err != nil {
		log.Fatalln(err)
	}

	cli, err := c.getClient()
	if err != nil {
		log.Fatalln(err)
	}

	for _, csrFile := range args {
		data, err := ioutil.ReadFile(csrFile)
		if err != nil {
			log.Fatalln(err)
		}
		b, _ := pem.Decode(data)
		var csr *x509.CertificateRequest
		if b == nil {
			csr, err = x509.ParseCertificateRequest(data)
		} else {
			csr, err = x509.ParseCertificateRequest(b.Bytes)
		}
		if err != nil {
			log.Warnln("couldn't parse '"+csrFile+"':", err)
			continue
		}

		certFile := filepath.Join(c.outputDir, csr.Subject.CommonName+".crt.pem")
		if fileExists(certFile) {
			log.Warnln("skip: cert exists for " + csr.Subject.CommonName)
			continue
		}

		cert, err := cli.fulfilCSR(csr)
		if err != nil {
			log.Fatalln(err)
		}

		data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if c.chain {
			data = append(data, c.chainData...)
		}
		err = ioutil.WriteFile(certFile, data, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		log.Infoln("Generated certificate for:", csr.Subject.CommonName)
	}
}
