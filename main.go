package main

import (
	"crypto/rsa"

	"github.com/ericchiang/letsencrypt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const acmeURL = "https://acme-v01.api.letsencrypt.org/directory"

// const acmeURL = "http://localhost:4000/directory"

var chainURLs = []string{
	"https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
	"https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
	"https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
	"https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
	"https://letsencrypt.org/certs/isrgrootx1.pem",
}

var supportedChallengs = []string{
	letsencrypt.ChallengeHTTP,
}

type Client struct {
	*letsencrypt.Client
	*HTTPChallengeResponder
	accountKey *rsa.PrivateKey
}

var (
	mainCmd = &cobra.Command{
		Use:   "letsencrypt-getcert",
		Short: "Simple utility for generating signed TLS certificates.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			v, _ := cmd.Flags().GetBool("verbose")
			if v {
				log.SetLevel(log.DebugLevel)
				log.Debugln("verbose mode enabled")
			}
		},
	}
)

func init() {
	cobra.EnablePrefixMatching = true
	mainCmd.PersistentFlags().StringP("bind", "b", ":80", "Bind address. The binding address:port for the server. Note, port 80 on the domain(s) must be mapped to this address.")
	mainCmd.PersistentFlags().StringP("acme-url", "u", acmeURL, "ACME URL. URL to the ACME directory to use.")
	mainCmd.PersistentFlags().StringP("output-dir", "d", ".", "Output directory. Certificates and keys will be stored here.")
	mainCmd.PersistentFlags().StringP("account-key", "k", "acme.key", "ACME account key (PEM format). The account key to use with this CA. If it doesn't exist, one will be generated.")
	mainCmd.PersistentFlags().Int("bits", 4096, "Bits for RSA key generation.")
	mainCmd.PersistentFlags().Bool("chain", false, "Include full chain. If set, download and include all LE certificates in the chain.")
	mainCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose mode. Logs extra messages for debugging.")
}

func main() {
	mainCmd.AddCommand(genCmd, signCmd, verifyCmd)
	mainCmd.Execute()
}
