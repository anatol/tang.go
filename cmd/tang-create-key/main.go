package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/jessevdk/go-flags"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"os"
	"path"
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

func writeKey(key jwk.Key, name string) error {
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

func generateSig() error {
	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}
	sig, err := jwk.New(k)
	if err != nil {
		return err
	}

	if err := sig.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpVerify, jwk.KeyOpSign}); err != nil {
		return err
	}
	if err := sig.Set(jwk.AlgorithmKey, jwa.ES512); err != nil {
		return err
	}

	return writeKey(sig, opts.Args.Sig)
}

func generateExchange() error {
	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}
	exc, err := jwk.New(k)
	if err != nil {
		return err
	}

	if err := exc.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpDeriveKey}); err != nil {
		return err
	}
	if err := exc.Set(jwk.AlgorithmKey, "ECMR"); err != nil {
		return err
	}

	return writeKey(exc, opts.Args.Exc)
}

func generate() error {
	if err := generateSig(); err != nil {
		return err
	}
	if err := generateExchange(); err != nil {
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
