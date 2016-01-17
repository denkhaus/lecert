package main

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	verifyCmd = &cobra.Command{
		Use:   "verify <domains...>",
		Short: "Verify existing certificates.",
		Run:   runVerify,
	}
)

func runVerify(cmd *cobra.Command, args []string) {
	c, err := getConfig(cmd)
	if err != nil {
		log.Fatalln(err)
	}

	for _, domain := range args {
		l := log.WithField("domain", domain)
		certFile := filepath.Join(c.outputDir, domain+".crt.pem")

		if !fileExists(certFile) {
			l.Warnln("skip: cert not exists for " + domain)
			continue
		}

		cert := NewPemCert(certFile)
		if err := cert.Parse(); err != nil {
			l.Fatalf("parse certificate: %s", err)
		}

		l.Infof("certificate will expire in %s", cert.ExpiresIn())
	}
}
