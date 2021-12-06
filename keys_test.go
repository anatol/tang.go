package tang

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"
	"math/big"
	"math/rand"
	"testing"
)

func TestReadKeysFromDir(t *testing.T) {
	t.Parallel()

	keys, err := ReadKeysFromDir("testdata/keys")
	require.NoError(t, err)
	require.Len(t, keys.keys, 8)
	// check that derived keys present with its thumbprint
	require.Contains(t, keys.byThumbprint, "Gf9gc2pdFn4J0I2Ix9zNvd_2nqIr6MD-UaaSmqxSzcI")
	require.Contains(t, keys.byThumbprint, "mNmsEWEFdNeALqktQvbhWpHqIZzZ6jMkxQxYBSRMfKQ")
	require.Contains(t, keys.byThumbprint, "pOaR6sgOhaNqjnX6b5KEQPJSLHTrlN14-OPVCCAUdis")
	require.Contains(t, keys.byThumbprint, "pTCu5WAbp69L1WqIOYdjRzQ004EdLQNgA0EioUqdFho")
	require.Contains(t, keys.byThumbprint, "ThXKQTmFOFaEUsLok3ji8iK5L_yhnQ2Wda88VdnFcI0")
	require.Contains(t, keys.byThumbprint, "taHuYvEa75GTGAccW8u94zeUz5Z6HbM9cCT6T27TQjE")

	payload := `{"keys":[{"alg":"ES512","crv":"P-521","key_ops":["sign","verify"],"kty":"EC","x":"AM8zO6IcjLdz8gXve0Zk3lMnyyC01Ssk3le-MxfA5H96o1v82nF1WiyjYaFOqs22uO5SAyBowdqkH35ncI06oH_D","y":"AZyVs2E2NG8Jfm4eDZ8Vi0h-r2SHZZNlv6JVRb36rtFEMWOFToS7sXCK3rIsj28C-CXVRfhBqYJ2Ojf7UIa6XdMP"},{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AP98N8OTULnSt7B4l_PcV2dqaX1ev0rPqini2MnPFE-kxEDZ1rAsFuI8tWwAiQVKKqbR3bsuzwpuSJ1AZFaN1gGq","y":"ABTPo_P76CzPOTqyf248PZKyd3HOmPzSHsN7MdXGkMMUORXRVQzhQPzqfH_oQoaOh7Pd6cYhtncAZb-P3PgISFNx"},{"alg":"ES512","crv":"P-521","key_ops":["sign","verify"],"kty":"EC","x":"AWyFgBsVjKf2Bt2fixrRTDW3j81UaWikqjxCpXkKst3o_pOO-CbpZQvR_xLP9vN4AnNndB-tyME6Z5F5c7uFKGDP","y":"AWo220Mzz6rmd5xjt4Ppbt3upTflj13gIkObsW3I5kFEfwmWYl8NYLV9__Fizd7L5vg-W7YWzf5bDasvryLv3Hvk"},{"alg":"ECMR","crv":"P-521","key_ops":["deriveKey"],"kty":"EC","x":"AOLdTU96iPUxCapPox8FUtsxt6assAVXidnWg2ldTajzWd-WiXufnGLgW2LfTYH8dk_XpzFHL_e1fzkaS9XtmJxd","y":"ARRFWvw59O2N3X0xCGPgz9eLtoBS951YKpZPU03VFnC40mR_lqfJ64ixeKmN3xXzemsFaFz9YqcgCHEqDuP4BNFZ"}]}`
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	props := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(keys.defaultAdvertisement, &props))
	sigs := props["signatures"].([]interface{})
	require.Equal(t, encodedPayload, props["payload"])
	protected := sigs[0].(map[string]interface{})["protected"].(string)
	require.Equal(t, "eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9", protected)
}

func TestKeySetAdvertisement(t *testing.T) {
	s := rand.NewSource(128822)
	r := rand.New(s)

	ks := NewKeySet()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), r)
	require.NoError(t, err)
	key, err := jwk.New(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpVerify, jwk.KeyOpSign}))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES512))
	require.NoError(t, ks.AppendKey(key, true))
	require.NoError(t, ks.RecomputeAdvertisements())
	require.NotEmpty(t, ks.defaultAdvertisement)
}

func TestKeySetRecovery(t *testing.T) {
	s := rand.NewSource(128822)
	r := rand.New(s)

	ks := NewKeySet()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), r)
	require.NoError(t, err)
	key, err := jwk.New(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpDeriveKey}))
	require.NoError(t, key.Set(jwk.AlgorithmKey, "ECMR"))
	require.NoError(t, ks.AppendKey(key, true))

	privRec, err := ecdsa.GenerateKey(elliptic.P521(), r)
	require.NoError(t, err)
	pubRec := privRec.Public()
	keyRec, err := jwk.New(pubRec)
	require.NoError(t, err)
	require.NoError(t, keyRec.Set(jwk.AlgorithmKey, "ECMR"))
	finalKey, err := ks.RecoverKey("B6wNLgG_M8E74OvJdWh2xLyg2p4_tFKHGM1ATrN3Cic", keyRec)
	require.NoError(t, err)

	var finalKeyPub ecdsa.PublicKey
	require.NoError(t, finalKey.Raw(&finalKeyPub))
	var x, y big.Int
	x.SetString("2744693066802777671821007383432974482496811340219460645217810747434742267693851682332644953667648200908691396615002059978144196841588532542201916612360765108", 10)
	y.SetString("2873557793078908927199515169649759937500640399120582979866951236596370676364197155893206288697220088797849526301010746443706778278001243099019849683423166086", 10)
	require.Equal(t, finalKeyPub.X, &x)
	require.Equal(t, finalKeyPub.Y, &y)
}
