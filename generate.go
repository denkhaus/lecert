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
	genCmd = &cobra.Command{
		Use:   "generate <domains...>",
		Short: "Generate and sign new certificate(s).",
		Run:   runGen,
	}
)

func runGen(cmd *cobra.Command, args []string) {
	c, err := getConfig(cmd)
	if err != nil {
		log.Fatalln(err)
	}

	cli, err := c.getClient()
	if err != nil {
		log.Fatalln(err)
	}

	for _, domain := range args {
		certFile := filepath.Join(c.outputDir, domain+".crt.pem")
		csrFile := filepath.Join(c.outputDir, domain+".csr.pem")
		keyFile := filepath.Join(c.outputDir, domain+".key.pem")

		if fileExists(certFile) || fileExists(keyFile) {
			log.Warnln("skip: cert and/or key exists for " + domain)
			continue
		}

		l := log.WithField("domain", domain)
		csr, key, err := newCSR(domain, c.bits)
		if err != nil {
			l.Fatalln("certificate generation failed:", err)
		}

		cert, err := cli.fulfilCSR(csr)
		if err != nil {
			l.Fatalln(err)
		}

		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
		err = ioutil.WriteFile(csrFile, data, 0600)
		if err != nil {
			log.Fatalln(err)
		}

		data = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		err = ioutil.WriteFile(keyFile, data, 0600)
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

		log.Infoln("Generated certificate for:", domain)
	}
}
