package main

import (
	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
	"github.com/lestrrat-go/jwx/jwk"
	"os"
	"path/filepath"
	"strings"
)

var opts struct {
	Args struct {
		Output string   `positional-arg-name:"output" required:"true"`
		Key    []string `positional-arg-name:"key" required:"true"`
	} `positional-args:"true"`
}

func process() error {
	ks := tang.NewKeySet()

	for _, d := range opts.Args.Key {
		err := filepath.Walk(d, func(path string, f os.FileInfo, err error) error {
			if f.IsDir() {
				return nil
			}

			if !strings.HasSuffix(f.Name(), ".jwk") {
				return nil
			}

			rawKey, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			jwkKey, err := jwk.ParseKey(rawKey)
			if err != nil {
				return err
			}

			advertised := f.Name()[0] != '.'
			return ks.AppendKey(jwkKey, advertised)
		})
		if err != nil {
			return err
		}
	}

	if err := ks.RecomputeAdvertisements(); err != nil {
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
