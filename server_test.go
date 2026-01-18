package tang

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/anatol/clevis.go"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"
)

func startTangd(t *testing.T, port int) (int, func()) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	require.NoError(t, err)

	port = listener.Addr().(*net.TCPAddr).Port

	srv := NewServer()
	keys, err := ReadKeys("testdata/keys")
	require.NoError(t, err)
	srv.Keys = keys
	go srv.Serve(listener)
	return port, func() { _ = srv.Shutdown(context.Background()) }
}

func startNativeTangd(t *testing.T, port int) (int, func()) {
	srv, err := NewNativeServer("testdata/keys", port)
	require.NoError(t, err)
	return srv.Port, func() { srv.Stop() }
}

func runTest(t *testing.T, nativeTangEncrypt, nativeClevisEncrypt, nativeTangDecrypt, nativeClevisDecrypt bool, thp string) {
	if nativeTangEncrypt == nativeTangDecrypt {
		// when we switch tang between different instances there is a chance of grabbing used port under our feet
		// only "single-tang-instance" tests can be run in parallel
		t.Parallel()
	}

	var port int
	var stopTang func()

	if nativeTangEncrypt {
		port, stopTang = startNativeTangd(t, 0)
	} else {
		port, stopTang = startTangd(t, 0)
	}
	defer stopTang()

	var config string
	if thp != "" {
		config = fmt.Sprintf(`{"url": "http://localhost:%d", "thp": "%s"}`, port, thp)
	} else {
		config = fmt.Sprintf(`{"url": "http://localhost:%d"}`, port)
	}

	inputText := "foobar; hello; world!"
	var encryptedData, decryptedData []byte

	if nativeClevisEncrypt {
		args := []string{"encrypt", "tang", config}
		if thp == "" {
			args = append(args, "-y")
		}
		encryptCmd := exec.Command("clevis", args...)
		encryptCmd.Stdin = strings.NewReader(inputText)
		var cmdOut bytes.Buffer
		encryptCmd.Stdout = &cmdOut
		if testing.Verbose() {
			encryptCmd.Stderr = os.Stderr
		}
		require.NoError(t, encryptCmd.Run())
		encryptedData = cmdOut.Bytes()
	} else {
		var err error
		encryptedData, err = clevis.Encrypt([]byte(inputText), "tang", config)
		require.NoError(t, err)
	}

	// decryption

	if nativeTangEncrypt != nativeTangDecrypt {
		stopTang()

		if nativeTangDecrypt {
			port, stopTang = startNativeTangd(t, port)
		} else {
			port, stopTang = startTangd(t, port)
		}
		defer stopTang()
	}

	if nativeClevisDecrypt {
		decryptCmd := exec.Command("clevis", "decrypt")
		decryptCmd.Stdin = bytes.NewReader(encryptedData)
		var cmdOut bytes.Buffer
		decryptCmd.Stdout = &cmdOut
		if testing.Verbose() {
			decryptCmd.Stderr = os.Stderr
		}
		require.NoError(t, decryptCmd.Run())
		decryptedData = cmdOut.Bytes()
	} else {
		var err error
		decryptedData, err = clevis.Decrypt(encryptedData)
		require.NoError(t, err)
	}

	require.Equal(t, inputText, string(decryptedData))
}

func TestTang(t *testing.T) {
	t.Parallel()

	bools := []bool{true, false}
	thps := []string{"", "mNmsEWEFdNeALqktQvbhWpHqIZzZ6jMkxQxYBSRMfKQ", "D9PhbUsoRR8X7JplTtba1ZEhgg_NKf_5waxK9k_gjLg"}

	for _, nativeTangEncrypt := range bools {
		for _, nativeTangDecrypt := range bools {
			for _, nativeClevisEncrypt := range bools {
				for _, nativeClevisDecrypt := range bools {
					for _, thp := range thps {
						name := fmt.Sprintf("nativeTangEncrypt=%v, nativeTangDecrypt=%v, nativeClevisEncrypt=%v, nativeClevisDecrypt=%v, thp=%s", nativeTangEncrypt, nativeTangDecrypt, nativeClevisEncrypt, nativeClevisDecrypt, thp)
						f := func(t *testing.T) {
							runTest(t, nativeTangEncrypt, nativeClevisEncrypt, nativeTangDecrypt, nativeClevisDecrypt, thp)
						}
						t.Run(name, f)
					}
				}
			}
		}
	}
}

func TestAdvertisingIsPublicKey(t *testing.T) {
	t.Parallel()

	port, stopTang := startTangd(t, 0)
	defer stopTang()

	signThps := []string{"", "mNmsEWEFdNeALqktQvbhWpHqIZzZ6jMkxQxYBSRMfKQ", "D9PhbUsoRR8X7JplTtba1ZEhgg_NKf_5waxK9k_gjLg", "Gf9gc2pdFn4J0I2Ix9zNvd_2nqIr6MD-UaaSmqxSzcI"}
	for _, thp := range signThps {
		url := fmt.Sprintf("http://localhost:%d/adv/%s", port, thp)
		resp, err := http.Get(url)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		msg, err := jws.Parse(data)
		require.NoError(t, err)
		keys, err := jwk.Parse(msg.Payload())
		require.NoError(t, err)

		for i := range keys.Len() {
			key, _ := keys.Key(i)

			switch key.(type) {
			case jwk.ECDSAPublicKey:
				continue
			default:
				require.Fail(t, "only public ECDSA keys are expected in the advertisement")
			}
		}
	}
}

func TestDeriveKeysAreNotAccessible(t *testing.T) {
	t.Parallel()

	port, stopTang := startTangd(t, 0)
	defer stopTang()

	deriveThps := []string{"pTCu5WAbp69L1WqIOYdjRzQ004EdLQNgA0EioUqdFho", "dFS8kG4bYnFTimBT8X6z-CuOpiKzrQeqeSdPV8GA_5M"}
	for _, thp := range deriveThps {
		url := fmt.Sprintf("http://localhost:%d/adv/%s", port, thp)
		resp, err := http.Get(url)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Empty(t, body)
	}
}

func encryptWithTang(t *testing.T, nativeTang bool, thp string, errorMessage string) {
	var port int
	var stopTang func()
	if nativeTang {
		port, stopTang = startNativeTangd(t, 0)
	} else {
		port, stopTang = startTangd(t, 0)
	}
	defer stopTang()

	config := fmt.Sprintf(`{"url": "http://localhost:%d", "thp": "%s"}`, port, thp)

	encryptCmd := exec.Command("clevis", "encrypt", "tang", config)
	encryptCmd.Stdin = strings.NewReader("some text")
	var cmdErr bytes.Buffer
	encryptCmd.Stderr = &cmdErr
	require.Error(t, encryptCmd.Run())
	require.Contains(t, string(cmdErr.Bytes()), errorMessage)
}

func TestRecoverKeyBodyTooLarge(t *testing.T) {
	t.Parallel()

	port, stopTang := startTangd(t, 0)
	defer stopTang()

	// Create a body larger than 64KB
	body := bytes.Repeat([]byte("x"), 64*1024+1)

	url := fmt.Sprintf("http://localhost:%d/rec/somethumbprint", port)
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestEncryptWithInvalidThp(t *testing.T) {
	t.Parallel()

	bools := []bool{true, false}
	thps := map[string]string{
		"Gf9gc2": "Unable to fetch advertisement:", // does not exist
		"Gf9gc2pdFn4J0I2Ix9zNvd_2nqIr6MD-UaaSmqxSzcI": "Trusted JWK 'Gf9gc2pdFn4J0I2Ix9zNvd_2nqIr6MD-UaaSmqxSzcI' did not sign the advertisement!", // not advertised
	}

	for _, nativeTang := range bools {
		for thp, errorMessage := range thps {
			encryptWithTang(t, nativeTang, thp, errorMessage)
		}
	}
}
