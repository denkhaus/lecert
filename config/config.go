package config

import (
	"errors"

	"github.com/spf13/cobra"
)

type Config struct {
	BindAddress    string
	AcmeURL        string
	OutputDir      string
	KeyFile        string
	RootPath       string
	Bits           int
	Chain          bool
	ModeWebRoot    bool
	ModeStandalone bool
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
	c.ModeWebRoot, err = cmd.Flags().GetBool("webroot")
	if err != nil {
		return nil, err
	}
	c.ModeStandalone, err = cmd.Flags().GetBool("standalone")
	if err != nil {
		return nil, err
	}
	c.RootPath, err = cmd.Flags().GetString("root-path")
	if err != nil {
		return nil, err
	}

	if !c.ModeWebRoot && !c.ModeStandalone {
		return nil, errors.New("mode: specify runmode either <--webroot, --standalone>")
	}

	if c.ModeWebRoot && c.ModeStandalone {
		return nil, errors.New("mode: specify either '--webroot' OR '--standalone'")
	}
	if c.ModeWebRoot && c.RootPath == "" {
		return nil, errors.New("root-path is undefined")
	}

	return &c, nil
}
