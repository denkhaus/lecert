package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/denkhaus/lecert/config"
	"github.com/ericchiang/letsencrypt"
	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
)

var AllowRenewTs = time.Duration(24 * time.Hour * 14)

var supportedChallengs = []string{
	letsencrypt.ChallengeHTTP,
}

const AcmeURL = "https://acme-v01.api.letsencrypt.org/directory"

var chainURLs = []string{
	"https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem",
	"https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.pem",
	"https://letsencrypt.org/certs/letsencryptauthorityx1.pem",
	"https://letsencrypt.org/certs/letsencryptauthorityx2.pem",
	"https://letsencrypt.org/certs/isrgrootx1.pem",
}

type ChallengeResponder interface {
	SetResource(path, resource string) error
}

type Client struct {
	*letsencrypt.Client
	ChallengeResponder
	accountKey *rsa.PrivateKey
}

func getAccountKey(cli *letsencrypt.Client, keyFile string, bits int) (*rsa.PrivateKey, error) {
	var accountKey *rsa.PrivateKey
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Infof("Generating new %d-bit account key", bits)

		accountKey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, errors.Annotate(err, "rsa generate key")
		}

		if _, err = cli.NewRegistration(accountKey); err != nil {
			return nil, errors.Annotate(err, "new registration")
		}
		b := &pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(accountKey),
			Type:  "RSA PRIVATE KEY",
		}
		err = ioutil.WriteFile(keyFile, pem.EncodeToMemory(b), 0600)
		if err != nil {
			return nil, errors.Annotate(err, "write key file")
		}
	}

	if accountKey == nil {
		pemData, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, errors.Annotate(err, "read key file")
		}
		b, _ := pem.Decode(pemData)
		if b.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("key file wrong type, expected RSA PRIVATE KEY")
		}
		accountKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		if err != nil {
			return nil, errors.Annotate(err, "parse private key")
		}
	}
	return accountKey, nil
}

func (p *Client) Chain() []byte {
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

func New(cnf *config.Config) (*Client, error) {
	lcli, err := letsencrypt.NewClient(cnf.AcmeURL)
	if err != nil {
		return nil, errors.Annotate(err, "new le client")
	}

	os.MkdirAll(cnf.OutputDir, 0700)
	accountKey, err := getAccountKey(lcli, cnf.KeyFile, cnf.Bits)
	if err != nil {
		return nil, errors.Annotate(err, "get account key")
	}

	var resp ChallengeResponder
	if cnf.ModeStandalone {
		h, err := NewHTTPChallengeResponder(cnf.BindAddress)
		if err != nil {
			return nil, errors.Annotate(err, "new http challenge responder")
		}
		resp = h
	}
	if cnf.ModeWebRoot {
		h, err := NewWebRootChallengeResponder(cnf.RootPath)
		if err != nil {
			return nil, errors.Annotate(err, "new webroot challenge responder")
		}
		resp = h
	}

	if resp == nil {
		return nil, errors.New("challenge responder undefined")
	}

	return &Client{Client: lcli, accountKey: accountKey, ChallengeResponder: resp}, nil
}
