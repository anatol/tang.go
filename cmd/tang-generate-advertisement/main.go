package main

import (
	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
	"os"
)

var opts struct {
	Args struct {
		Output string   `positional-arg-name:"output" required:"true"`
		Key    []string `positional-arg-name:"key" required:"true"`
	} `positional-args:"true"`
}

func process() error {
	ks, err := tang.ReadKeys(opts.Args.Key...)
	if err != nil {
		return err
	}

	return os.WriteFile(opts.Args.Output, ks.DefaultAdvertisement, 0644)
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

	if err := process(); err != nil {
		panic(err)
	}
}
