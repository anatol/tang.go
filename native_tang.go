package tang

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"
)

// A server implementation that redirects requests to the native "tangd" binary.
// This code is useful for tests

type nativeTang struct {
	keysDir   string
	tangdPath string
	listener  net.Listener
	port      int
}

func newNativeTang(keysDir string, port int) (*nativeTang, error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	// different OS use different tang server binary location
	tangLocations := []string{
		"/usr/lib/",
		"/usr/lib/x86_64-linux-gnu/",
	}

	var tangdPath string

	for _, l := range tangLocations {
		if _, err := os.Stat(l + "tangd"); err == nil {
			tangdPath = l + "tangd"
			break
		}
	}
	if tangdPath == "" {
		return nil, fmt.Errorf("unable to find tangd binary")
	}

	s := &nativeTang{
		keysDir:   keysDir,
		tangdPath: tangdPath,
		listener:  l,
		port:      l.Addr().(*net.TCPAddr).Port,
	}
	go s.serve()
	return s, nil
}

func (s *nativeTang) stop() {
	_ = s.listener.Close()
}

func (s *nativeTang) serve() {
	for {
		conn, err := s.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.Println("accept error", err)
			return
		}
		s.handleConection(conn)
		if err := conn.Close(); err != nil {
			log.Print(err)
		}
	}
}

func (s *nativeTang) handleConection(conn net.Conn) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Println("read error", err)
		return
	}
	if n == 0 {
		return
	}

	tangCmd := exec.Command(s.tangdPath, s.keysDir)
	tangCmd.Stdin = bytes.NewReader(buf[:n])
	tangCmd.Stdout = conn
	if testing.Verbose() {
		tangCmd.Stderr = os.Stderr
	}
	if err := tangCmd.Run(); err != nil {
		log.Println(err)
	}
}
