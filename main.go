package main

import (
	"github.com/denkhaus/lecert/api"
	"github.com/denkhaus/lecert/client"
	"github.com/denkhaus/lecert/config"
	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	mainCmd = &cobra.Command{
		Use:   "lecert",
		Short: "Simple utility for generating signed TLS certificates.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			v, _ := cmd.Flags().GetBool("verbose")
			if v {
				log.SetLevel(log.DebugLevel)
				log.Debugln("verbose mode enabled")
			}
		},
	}
	signCmd = &cobra.Command{
		Use:   "sign <CSR files...>",
		Short: "Fulfill existing CSR(s).",
		Run:   runSign,
	}
	verifyCmd = &cobra.Command{
		Use:   "verify <domains...>",
		Short: "Verify existing certificate(s).",
		Run:   runVerify,
	}
	genCmd = &cobra.Command{
		Use:   "generate <domains...>",
		Short: "Generate and sign new certificate(s).",
		Run:   runGen,
	}
	renewCmd = &cobra.Command{
		Use:   "renew <domains...>",
		Short: "Renew existing certificate(s).",
		Run:   runRenew,
	}
	ensureCmd = &cobra.Command{
		Use:   "ensure <domains...>",
		Short: "Create non existing certificate(s) or renew if necessary.",
		Run:   runEnsure,
	}
)

func init() {
	cobra.EnablePrefixMatching = true
	mainCmd.PersistentFlags().StringP("bind", "b", ":80", "Bind address. The binding address:port for the server. Note, port 80 on the domain(s) must be mapped to this address.")
	mainCmd.PersistentFlags().StringP("acme-url", "u", client.AcmeURL, "ACME URL. URL to the ACME directory to use.")
	mainCmd.PersistentFlags().StringP("output-dir", "d", ".", "Output directory. Certificates and keys will be stored here.")
	mainCmd.PersistentFlags().StringP("account-key", "k", "acme.key", "ACME account key (PEM format). The account key to use with this CA. If it doesn't exist, one will be generated.")
	mainCmd.PersistentFlags().Int("bits", 4096, "Bits for RSA key generation.")
	mainCmd.PersistentFlags().Bool("chain", false, "Include full chain. If set, download and include all LE certificates in the chain.")
	mainCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose mode. Logs extra messages for debugging.")
}

func createApi(cmd *cobra.Command) *api.Api {
	log.Debug("create api")
	c, err := config.NewFromCli(cmd)
	if err != nil {
		log.Fatalln(errors.Annotate(err, "new config"))
	}

	api, err := api.New(c)
	if err != nil {
		log.Fatalln(errors.Annotate(err, "new api"))
	}

	return api
}

func runRenew(cmd *cobra.Command, args []string) {
	api := createApi(cmd)
	log.Debug("process renew")
	for _, domain := range args {
		l := log.WithField("domain", domain)
		if err := api.RenewCertificate(domain); err != nil {
			l.Error(errors.Annotate(err, "renew certificate"))
		}
	}
}

func runEnsure(cmd *cobra.Command, args []string) {
	api := createApi(cmd)
	log.Debug("process ensure")
	for _, domain := range args {
		l := log.WithField("domain", domain)
		if err := api.EnsureCertificate(domain); err != nil {
			l.Error(errors.Annotate(err, "ensure certificate"))
		}
	}
}

func runGen(cmd *cobra.Command, args []string) {
	api := createApi(cmd)
	log.Debug("process generate")
	for _, domain := range args {
		l := log.WithField("domain", domain)
		if err := api.GenerateCertificate(domain); err != nil {
			l.Error(errors.Annotate(err, "renew certificate"))
		}
	}
}

func runVerify(cmd *cobra.Command, args []string) {
	api := createApi(cmd)
	log.Debug("process verify")
	for _, domain := range args {
		l := log.WithField("domain", domain)
		if _, err := api.VerifyCertificate(domain); err != nil {
			l.Error(errors.Annotate(err, "renew certificate"))
		}
	}
}

func runSign(cmd *cobra.Command, args []string) {
	api := createApi(cmd)
	log.Debug("process sign")
	for _, domain := range args {
		l := log.WithField("domain", domain)
		if err := api.GenerateCertificate(domain); err != nil {
			l.Error(errors.Annotate(err, "renew certificate"))
		}
	}
}

func main() {
	mainCmd.AddCommand(genCmd, signCmd, verifyCmd, renewCmd, ensureCmd)
	mainCmd.Execute()
}
