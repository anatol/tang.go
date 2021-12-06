package main

import (
	"flag"
	"github.com/anatol/tang.go"
	"log"
	"strconv"
)

var (
	port    = flag.Int("port", 80, "http port")
	dir     = flag.String("dir", "/var/db/tang", "directory with keys")
	verbose = flag.Bool("verbose", false, "increase verbosity of the application")
)

func main() {
	var err error

	flag.Parse()

	srv := tang.NewServer()
	srv.Keys, err = tang.ReadKeysFromDir(*dir)
	if err != nil {
		log.Fatal(err)
	}
	srv.Addr = ":" + strconv.Itoa(*port)
	log.Fatal(srv.ListenAndServe())
}
