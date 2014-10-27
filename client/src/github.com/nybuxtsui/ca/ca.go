package main

import (
	"os"

	"github.com/nybuxtsui/ca/third_party/github.com/codegangsta/cli"

	"github.com/nybuxtsui/ca/cmd"
	"github.com/nybuxtsui/ca/depot"
)

func main() {
	app := cli.NewApp()
	app.Name = "ca"
	app.Version = "0.1.0"
	app.Usage = "A very simple CA manager written in Go."
	app.Flags = []cli.Flag{
		cli.StringFlag{"depot-path", depot.DefaultFileDepotDir, "Location to store certificates, keys and other files."},
	}
	app.Commands = []cli.Command{
		cmd.NewInitCommand(),
		cmd.NewNewCertCommand(),
		cmd.NewSignCommand(),
		cmd.NewChainCommand(),
		cmd.NewExportCommand(),
		cmd.NewStatusCommand(),
	}
	app.Before = func(c *cli.Context) error {
		cmd.InitDepot(c.String("depot-path"))
		return nil
	}

	app.Run(os.Args)
}
