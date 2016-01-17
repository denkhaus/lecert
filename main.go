package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

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

type Config struct {
	bindAddress string
	acmeURL     string
	outputDir   string
	keyFile     string
	bits        int
	chain       bool
	chainData   []byte
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

	genCmd = &cobra.Command{
		Use:   "generate <domains...>",
		Short: "Generate and sign new certificate(s).",
		Run:   runGen,
	}

	verifyCmd = &cobra.Command{
		Use:   "verify <domains...>",
		Short: "Verify existing certificates.",
		Run:   runVerify,
	}

	signCmd = &cobra.Command{
		Use:   "sign <CSR files...>",
		Short: "Fulfill existing CSR(s).",
		Run:   runSign,
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

func getChain() []byte {
	certs := make([][]byte, len(chainURLs))
	var wg sync.WaitGroup
	for i, url := range chainURLs {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			resp, err := http.Get(url)
			if err != nil {
				log.Fatalln(err)
				return
			}
			defer resp.Body.Close()
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatalln(err)
				return
			}
			certs[i] = data
		}(i, url)
	}
	wg.Wait()
	result := make([]byte, 0, 1024*1024)
	for _, data := range certs {
		result = append(result, data...)
		if result[len(result)-1] != 10 {
			result = append(result, 10)
		}
	}
	return result
}

func getConfig(cmd *cobra.Command) (*Config, error) {
	var err error
	var c Config
	c.acmeURL, err = cmd.Flags().GetString("acme-url")
	if err != nil {
		return nil, err
	}
	c.keyFile, err = cmd.Flags().GetString("account-key")
	if err != nil {
		return nil, err
	}
	c.bindAddress, err = cmd.Flags().GetString("bind")
	if err != nil {
		return nil, err
	}
	c.outputDir, err = cmd.Flags().GetString("output-dir")
	if err != nil {
		return nil, err
	}
	c.bits, err = cmd.Flags().GetInt("bits")
	if err != nil {
		return nil, err
	}
	c.chain, err = cmd.Flags().GetBool("chain")
	if err != nil {
		return nil, err
	}
	if c.chain {
		c.chainData = getChain()
	}
	return &c, nil
}

func (c *Config) getClient() (*Client, error) {

	lcli, err := letsencrypt.NewClient(c.acmeURL)
	if err != nil {
		return nil, err
	}

	os.MkdirAll(c.outputDir, 0700)
	accountKey, err := getAccountKey(lcli, c.keyFile, c.bits)
	if err != nil {
		return nil, err
	}

	h, err := NewHTTPChallengeResponder(c.bindAddress)
	if err != nil {
		return nil, err
	}

	return &Client{Client: lcli, accountKey: accountKey, HTTPChallengeResponder: h}, nil
}

func fileExists(file string) bool {
	_, err := os.Stat(file)
	// no error, or error is not a "NotExist" error
	// then file exists
	return err == nil || !os.IsNotExist(err)
}

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

		data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
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

func runVerify(cmd *cobra.Command, args []string) {
	c, err := getConfig(cmd)
	if err != nil {
		log.Fatalln(err)
	}

	dtExpire := time.Now().Add(time.Hour * 24 * 7 * 2)

	for _, domain := range args {
		l := log.WithField("domain", domain)
		certFile := filepath.Join(c.outputDir, domain+".crt.pem")
		if fileExists(certFile) {
			l.Warnln("skip: cert not exists for " + domain)
			continue
		}

		cert := NewPemCert(certFile)
		if err := cert.Parse(); err != nil {
			l.Fatalf("parse certificate: %s", err)
		}

		l.Infof("certificate will expire in %s", cert.ExpiresIn())
		if cert.IsExpiredAt(dtExpire) {
			l.Infof("certificate will be expired at %s", domain, dtExpire)
		}
	}
}

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

func main() {
	mainCmd.AddCommand(genCmd, signCmd, verifyCmd)
	mainCmd.Execute()
}
