package main

import (
	"os"

	"github.com/ericchiang/letsencrypt"
	"github.com/spf13/cobra"
)

type Config struct {
	bindAddress string
	acmeURL     string
	outputDir   string
	keyFile     string
	bits        int
	chain       bool
	chainData   []byte
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
