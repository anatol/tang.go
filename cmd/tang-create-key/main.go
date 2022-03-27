package main

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"os"
	"path"

	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
	"github.com/lestrrat-go/jwx/jwk"
)

var opts struct {
	Args struct {
		Dir string `positional-arg-name:"dir" required:"true"`
		Sig string `positional-arg-name:"sig"`
		Exc string `positional-arg-name:"exc"`
	} `positional-args:"true"`
}

const (
	defaultAlgo = crypto.SHA256
)

func writeKey(fn func() (jwk.Key, error), name string) error {
	key, err := fn()
	if err != nil {
		return err
	}

	if name == "" {
		thp, err := key.Thumbprint(defaultAlgo)
		if err != nil {
			return err
		}
		name = base64.RawURLEncoding.EncodeToString(thp)
	}
	name += ".jwk"

	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path.Join(opts.Args.Dir, name), data, 0644)
}

func generate() error {
	if err := writeKey(tang.GenerateVerifyKey, opts.Args.Sig); err != nil {
		return err
	}

	if err := writeKey(tang.GenerateExchangeKey, opts.Args.Exc); err != nil {
		return err
	}

	return nil
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

	if err := generate(); err != nil {
		panic(err)
	}
}
