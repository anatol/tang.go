package tang

import (
	"bufio"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReverseTangHandshake(t *testing.T) {
	ks, err := ReadKeys("testdata/keys")
	require.NoError(t, err)

	l, err := net.Listen("tcp", ":0")
	port := l.Addr().(*net.TCPAddr).Port

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)

		buff := bufio.NewReader(conn)
		adv, _, err := buff.ReadLine()
		require.NoError(t, err)
		require.Equal(t, ks.DefaultAdvertisement, adv)

		_, err = conn.Write([]byte("dFS8kG4bYnFTimBT8X6z-CuOpiKzrQeqeSdPV8GA_5M\n"))
		require.NoError(t, err)
		xferKey := `{"alg":"ECMR","crv":"P-521","kty":"EC","x":"AJHmF7pamkUGBoBoYiOHPz3GzeD8kexttzWvJ2BsQLslgwcZkhODKCo_OJ2WYnDPy4o4b3NIIpdpg8hgklxVjJVe","y":"AJi3YqTPNJOeboS7etpeqCrv3hWfI2yRL0JPVmPMm98lfxZfemkzSAYvuBX0a0hRXQw_HGULBsESUNaMYmxtj7GZ"}`
		_, err = conn.Write([]byte(xferKey + "\n"))
		require.NoError(t, err)

		returnKey, _, err := buff.ReadLine()
		require.NoError(t, err)
		require.Equal(t, `{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AU9g1_ZVW3Ar3iB9d4FMQ3HuTKP6qc7Fww8dGY5rOXn1TCqd6LRXmxsDGbvZX2EmzJwI0BBERymAtOvKBram2QIU","y":"AXHt-jUcqX-D9qch4ZGDudbD--PIhHHq9UhEqhvoUws9-RYbd8JJTFYe2PQCF4qs2XTh27hnAMbOhGSbsLEYRJR4"}`, string(returnKey))

		wg.Done()
	}()

	require.NoError(t, ReverseTangHandshake(":"+strconv.Itoa(port), ks))
	wg.Wait()
}
