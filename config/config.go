package config

import "github.com/spf13/cobra"

type Config struct {
	BindAddress string
	AcmeURL     string
	OutputDir   string
	KeyFile     string
	Bits        int
	Chain       bool
}

func NewFromCli(cmd *cobra.Command) (*Config, error) {
	var err error
	var c Config
	c.AcmeURL, err = cmd.Flags().GetString("acme-url")
	if err != nil {
		return nil, err
	}
	c.KeyFile, err = cmd.Flags().GetString("account-key")
	if err != nil {
		return nil, err
	}
	c.BindAddress, err = cmd.Flags().GetString("bind")
	if err != nil {
		return nil, err
	}
	c.OutputDir, err = cmd.Flags().GetString("output-dir")
	if err != nil {
		return nil, err
	}
	c.Bits, err = cmd.Flags().GetInt("bits")
	if err != nil {
		return nil, err
	}
	c.Chain, err = cmd.Flags().GetBool("chain")
	if err != nil {
		return nil, err
	}

	return &c, nil
}
