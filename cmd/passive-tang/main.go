package main

import (
	"bufio"
	"net"
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

	ks, err := tang.ReadKeys(opts.Args.Key...)
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
