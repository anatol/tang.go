package main

import (
	"bufio"
	"github.com/anatol/tang.go"
	"github.com/jessevdk/go-flags"
	"github.com/lestrrat-go/jwx/jwk"
	"net"
	"os"
	"path/filepath"
	"strings"
)

var opts struct {
	Args struct {
		Address string   `positional-arg-name:"address" required:"true"`
		Key     []string `positional-arg-name:"key" required:"true"`
	} `positional-args:"true"`
}

func loadKeys() (*tang.KeySet, error) {
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
			return nil, err
		}
	}
	return ks, nil
}

func exchange() error {
	conn, err := net.Dial("tcp", opts.Args.Address)
	if err != nil {
		return err
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	thp, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	key, err := r.ReadString('\n')
	if err != nil {
		return err
	}

	ks, err := loadKeys()
	if err != nil {
		return err
	}

	out, err := ks.Recover(thp, []byte(key))
	if err != nil {
		return err
	}

	_, err = conn.Write(out)
	return err
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
