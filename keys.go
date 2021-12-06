package tang

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"os"
	"path"
	"strings"
)

var algos = []crypto.Hash{
	crypto.SHA1,   /* S1 */
	crypto.SHA224, /* S224 */
	crypto.SHA256, /* S256 */
	crypto.SHA384, /* S384 */
	crypto.SHA512, /* S512 */
}

// KeySet represents a set of all keys handled by Tang
type KeySet struct {
	keys                 []*tangKey
	byThumbprint         map[string]*tangKey // base64(thumbprint)->key map
	defaultAdvertisement []byte
}

type tangKey struct {
	jwk.Key
	advertised    bool
	advertisement []byte
}

// NewKeySet creates a new KeySet instance
func NewKeySet() *KeySet {
	set := &KeySet{}
	set.byThumbprint = make(map[string]*tangKey)
	return set
}

// ReadKeysFromDir reads all keys from the given directory and makes a KeySet instace out of it.
// Any key file that starts  from "." (dot) is marked as non-advertised.
func ReadKeysFromDir(dir string) (*KeySet, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("unable to read keys from %s: %v", dir, err)
	}

	set := NewKeySet()

	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".jwk") {
			continue
		}

		rawKey, err := os.ReadFile(path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		jwkKey, err := jwk.ParseKey(rawKey)
		if err != nil {
			return nil, err
		}

		advertised := e.Name()[0] != '.'
		if err := set.AppendKey(jwkKey, advertised); err != nil {
			return nil, err
		}
	}

	if err := set.RecomputeAdvertisements(); err != nil {
		return nil, err
	}

	return set, nil
}

// RecomputeAdvertisements recomputes advertisement files for the keys and default for the KeySet itself
func (ks *KeySet) RecomputeAdvertisements() error {
	advertisedKeys := jwk.NewSet()
	signKeys := jwk.NewSet()

	for _, k := range ks.keys {
		if k.advertised {
			if keyValidForUse(k, []jwk.KeyOperation{jwk.KeyOpVerify, jwk.KeyOpSign}) {
				signKeys.Add(k)
				advertisedKeys.Add(k)
			}
			if keyValidForUse(k, []jwk.KeyOperation{jwk.KeyOpDeriveKey}) {
				advertisedKeys.Add(k)
			}
		}
	}

	// TOTHINK: upstream tang creates a new pair of keys if none exists in the dir
	if advertisedKeys.Len() == 0 {
		return fmt.Errorf("no advertised keys found")
	}
	if signKeys.Len() == 0 {
		return fmt.Errorf("no sign keys found")
	}

	advertisedKeys, err := jwk.PublicSetOf(advertisedKeys)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(advertisedKeys)
	if err != nil {
		return err
	}

	defaultAdvertisement, err := signPayload(payload, signKeys)
	if err != nil {
		return err
	}

	ks.defaultAdvertisement = defaultAdvertisement

	for _, k := range ks.keys {
		if keyValidForUse(k, []jwk.KeyOperation{jwk.KeyOpSign}) {
			if k.advertised {
				k.advertisement = ks.defaultAdvertisement
			} else {
				// non-advertized sets need additionally sign payload with advertized key
				signSet, err := signKeys.Clone()
				if err != nil {
					return err
				}
				signSet.Add(k)
				advertisement, err := signPayload(payload, signSet)
				if err != nil {
					return err
				}
				k.advertisement = advertisement
			}
		}
	}

	return nil
}

// AppendKey appends the given key to the KeySet. Advertisements are not recalculated.
func (ks *KeySet) AppendKey(jwkKey jwk.Key, advertised bool) error {
	k := &tangKey{jwkKey, advertised, nil}

	ks.keys = append(ks.keys, k)

	for _, a := range algos {
		thpBytes, err := k.Thumbprint(a)
		if err != nil {
			return err
		}
		thp := base64.RawURLEncoding.EncodeToString(thpBytes)
		ks.byThumbprint[thp] = k
	}

	return nil
}

// RecoverKey performs server-side recover of the ECMR algorithm
func (ks *KeySet) RecoverKey(thp string, webKey jwk.Key) (jwk.Key, error) {
	key, found := ks.byThumbprint[thp]
	if !found {
		return nil, fmt.Errorf("key '%s' not found", thp)
	}

	if !keyValidForUse(key, []jwk.KeyOperation{jwk.KeyOpDeriveKey}) {
		return nil, fmt.Errorf("key '%s' is not a derive key", thp)
	}
	if key.Algorithm() != "ECMR" {
		return nil, fmt.Errorf("key '%s' is not ECMR", thp)
	}

	return key.exchange(webKey)
}

// Recover performs server-side recover of the ECMR algorithm
func (ks *KeySet) Recover(thp string, data []byte) ([]byte, error) {
	kty, err := jwk.ParseKey(data)
	if err != nil {
		return nil, err
	}

	xfrKey, err := ks.RecoverKey(thp, kty)
	if err != nil {
		return nil, err
	}

	return json.Marshal(xfrKey)
}

func (k *tangKey) exchange(kty jwk.Key) (jwk.Key, error) {
	if len(kty.KeyOps()) != 0 && !keyValidForUse(kty, []jwk.KeyOperation{jwk.KeyOpDeriveKey}) {
		return nil, fmt.Errorf("expecting derive key in the request")
	}
	if kty.KeyType() != jwa.EC {
		return nil, fmt.Errorf("expecting EC key in the request")
	}
	if kty.Algorithm() != "ECMR" {
		return nil, fmt.Errorf("expecting ECMR key in the request")
	}

	var webKey ecdsa.PublicKey
	if err := kty.Raw(&webKey); err != nil {
		return nil, err
	}

	var ecKey ecdsa.PrivateKey
	if err := k.Raw(&ecKey); err != nil {
		return nil, err
	}

	ecCurve := ecKey.Curve
	if !ecCurve.IsOnCurve(webKey.X, webKey.Y) {
		return nil, fmt.Errorf("requesting EC point is not on the curve")
	}

	x, y := ecCurve.ScalarMult(webKey.X, webKey.Y, ecKey.D.Bytes())

	xfrKey, err := jwk.New(&ecdsa.PublicKey{Curve: ecCurve, X: x, Y: y})
	if err != nil {
		return nil, err
	}
	if err := xfrKey.Set(jwk.AlgorithmKey, "ECMR"); err != nil {
		return nil, err
	}
	if err := xfrKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpDeriveKey}); err != nil {
		return nil, err
	}

	return xfrKey, nil
}

func keyValidForUse(k jwk.Key, use []jwk.KeyOperation) bool {
	for _, u := range use {
		matches := false
		for _, o := range k.KeyOps() {
			if o == u {
				matches = true
				break
			}
		}

		if !matches {
			return false
		}
	}

	return true
}

func signPayload(payload []byte, signKeys jwk.Set) ([]byte, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := jws.NewMessage()
	m.SetPayload(payload)
	for iter := signKeys.Iterate(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		h := jws.NewHeaders()
		if err := h.Set(jws.AlgorithmKey, key.Algorithm()); err != nil {
			return nil, err
		}
		if err := h.Set(jws.ContentTypeKey, "jwk-set+json"); err != nil {
			return nil, err
		}

		marshalledProtected, err := json.Marshal(h)
		if err != nil {
			return nil, err
		}
		var p bytes.Buffer
		p.WriteString(base64.RawURLEncoding.EncodeToString(marshalledProtected))
		p.WriteByte('.')
		p.WriteString(base64.RawURLEncoding.EncodeToString(payload))

		signer, err := jws.NewSigner(jwa.SignatureAlgorithm(key.Algorithm()))
		if err != nil {
			return nil, err
		}
		signature, err := signer.Sign(p.Bytes(), key)
		if err != nil {
			return nil, err
		}

		sig := jws.NewSignature()
		sig.SetProtectedHeaders(h)
		sig.SetSignature(signature)
		m.AppendSignature(sig)
	}

	advertisement, err := m.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return advertisement, nil
}
