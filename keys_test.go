package tang

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func TestReadKeysFromDir(t *testing.T) {
	t.Parallel()

	keys, err := ReadKeys("testdata/keys")
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
	require.NoError(t, json.Unmarshal(keys.DefaultAdvertisement, &props))
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
	key, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpVerify, jwk.KeyOpSign}))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES512()))
	require.NoError(t, ks.AppendKey(key, true))
	require.NoError(t, ks.RecomputeAdvertisements())
	require.NotEmpty(t, ks.DefaultAdvertisement)
}

func TestKeySetRecovery(t *testing.T) {
	fromHex := func(s string) []byte {
		b, _ := hex.DecodeString(s)
		return b
	}

	ks := NewKeySet()

	// hex sequence generated from the output of 'openssl ecparam -genkey -name secp521r1 -noout -outform der -out key.pem'
	priv, err := x509.ParseECPrivateKey(fromHex("3081DC0201010442007CAE038657B693D23CAC83B28664FE34A7B9FFBEEA893ED36A65C4A672A11DEFB079A0A132C36BD1BCA7BB1ED9C77C89B33B1BE319CC200ED8C40D961ECC28577EA00706052B81040023A181890381860004003F5DE10A4FE5AEDE01E1B5EFABF0088B44AC70D9ADA4A837AE556CEC395E94C11213E12B28F24EBA23B20BA0E9847D1A422D8340B340CA5BC43EBA2473C5E2070F01DB4367644ED4D3DC0D97BC1149B2350DB75FD5FC9212537226BE1C9054CC14911640A92892636A3471FEBD5D9AB632AD780C736267CC90411448F93E1D28A8FBE7"))
	require.NoError(t, err)
	key, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyOpsKey, []jwk.KeyOperation{jwk.KeyOpDeriveKey}))
	require.NoError(t, key.Set(jwk.AlgorithmKey, "ECMR"))
	require.NoError(t, ks.AppendKey(key, true))

	privRec, err := x509.ParseECPrivateKey(fromHex("3081DC02010104420178A7AA5E16809CA33EE016C2DB68E1C6AB82FF30EB7266F50E1EBE930DF02283EDEFAF9445BE6B69E3B9C85A96507A0463105E217C71F35C1495BCFFD3FF8A3632A00706052B81040023A18189038186000400337664B30F61E663748F871FF33794098EC8E3655C59253DC661415F648A4D2A9AD0869A735ED23E8782C98C9E7DCEB35971284D3BE5EC82DE7C6D90346771AAB500EDB4E8BB34E661F85F48470A36C8C06018368EA15630057A5364680CC707A9293C8A2B6877BE52CC2693CA3A73EC9116A6AF91480E79A9977F757999C0555DE62D"))
	require.NoError(t, err)
	pubRec := privRec.Public()
	keyRec, err := jwk.Import(pubRec)
	require.NoError(t, err)
	require.NoError(t, keyRec.Set(jwk.AlgorithmKey, "ECMR"))
	finalKey, err := ks.RecoverKey("MJ_6bzhVzBlQMQbsbEUPZPVQDO4zJn7ZiKBgA-Yam4xSqd_j5iIlMzSZB5jMeGBW", keyRec)
	require.NoError(t, err)

	var finalKeyPub ecdsa.PublicKey
	require.NoError(t, jwk.Export(finalKey, &finalKeyPub))
	var x, y big.Int
	x.SetString("4059619385703187168607578245292802951393074713794243871602010746622107603864550766837138331615122629968188702032595290339263963931017955701265851263179914674", 10)
	y.SetString("3382257000801780367474077533931492841352335347160322479301815377887171453342766324536073054008650134593489733582468776405841257185311162221940705092549351346", 10)
	require.Equal(t, &x, finalKeyPub.X)
	require.Equal(t, &y, finalKeyPub.Y)
}
