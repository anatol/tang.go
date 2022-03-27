package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
	"github.com/lestrrat-go/jwx/jwk"
)

const (
	defaultAlgo = crypto.SHA256
)

var opts struct {
	Create struct {
		Args struct {
			Dir string `positional-arg-name:"dir" required:"true"`
			Sig string `positional-arg-name:"sig"`
			Exc string `positional-arg-name:"exc"`
		} `positional-args:"true"`
	} `command:"create" description:"Generate a Tang key"`
	Advertisement struct {
		Output string `long:"output" description:"output file for generate advertisement, print to STDOUT if not specified"`
		Args   struct {
			Key []string `positional-arg-name:"key" required:"true"`
		} `positional-args:"true"`
	} `command:"adv" description:"Generate a Tang advertisement"`
	Thumbprint struct {
		Alg  string `long:"alg" description:"Hash algorithm" default:"sha256" choice:"sha1" choice:"sha256"`
		Args struct {
			Key string `positional-arg-name:"key" required:"true"`
		} `positional-args:"true"`
	} `command:"thp" description:"Generate key thumbprint"`
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

	switch parser.Active.Name {
	case "create":
		err = createKey()
	case "adv":
		err = generateAdvertisement()
	case "thp":
		err = generateThumbprint()
	}

	if err != nil {
		panic(err)
	}
}

func byHashName(name string) (crypto.Hash, error) {
	switch name {
	case "sha1":
		return crypto.SHA1, nil
	case "sha256":
		return crypto.SHA256, nil
	default:
		return 0, fmt.Errorf("unknown hash algorithm: %s", name)
	}
}

func generateThumbprint() error {
	data, err := ioutil.ReadFile(opts.Thumbprint.Args.Key)
	if err != nil {
		return err
	}
	keys, err := jwk.Parse(data)
	if err != nil {
		return err
	}

	h, err := byHashName(opts.Thumbprint.Alg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for iter := keys.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		thp, err := key.Thumbprint(h)
		if err != nil {
			return err
		}
		fmt.Println(base64.RawURLEncoding.EncodeToString(thp))
	}

	return nil
}

func generateAdvertisement() error {
	ks, err := tang.ReadKeys(opts.Advertisement.Args.Key...)
	if err != nil {
		return err
	}

	filename := opts.Advertisement.Output
	if filename == "" {
		fmt.Println(string(ks.DefaultAdvertisement))
		return nil
	} else {
		return os.WriteFile(filename, ks.DefaultAdvertisement, 0644)
	}
}

func writeKey(fn func() (jwk.Key, error), dir, name string) error {
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

	filename := path.Join(dir, name)
	return os.WriteFile(filename, data, 0644)
}

func createKey() error {
	if err := writeKey(tang.GenerateVerifyKey, opts.Create.Args.Dir, opts.Create.Args.Sig); err != nil {
		return err
	}
	if err := writeKey(tang.GenerateExchangeKey, opts.Create.Args.Dir, opts.Create.Args.Exc); err != nil {
		return err
	}

	return nil
}
