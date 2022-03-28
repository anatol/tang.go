package main

import (
	"os"

	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	Args struct {
		Address string   `positional-arg-name:"address" required:"true"`
		Key     []string `positional-arg-name:"key" required:"true"`
	} `positional-args:"true"`
}

func exchange() error {
	ks, err := tang.ReadKeys(opts.Args.Key...)
	if err != nil {
		return err
	}

	return tang.ReverseTangHandshake(opts.Args.Address, ks)
}

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if err := exchange(); err != nil {
		panic(err)
	}
}
