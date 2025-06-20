package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	pb "github.com/TheNoobiCat/go-libp2p/core/crypto/pb"
	"github.com/TheNoobiCat/go-libp2p/core/internal/catch"
)

// RsaPrivateKey is a rsa private key
type RsaPrivateKey struct {
	sk rsa.PrivateKey
}

// RsaPublicKey is a rsa public key
type RsaPublicKey struct {
	k rsa.PublicKey

	cached []byte
}

// GenerateRSAKeyPair generates a new rsa private and public key
func GenerateRSAKeyPair(bits int, src io.Reader) (PrivKey, PubKey, error) {
	if bits < MinRsaKeyBits {
		return nil, nil, ErrRsaKeyTooSmall
	}
	if bits > maxRsaKeyBits {
		return nil, nil, ErrRsaKeyTooBig
	}
	priv, err := rsa.GenerateKey(src, bits)
	if err != nil {
		return nil, nil, err
	}
	pk := priv.PublicKey
	return &RsaPrivateKey{sk: *priv}, &RsaPublicKey{k: pk}, nil
}

// Verify compares a signature against input data
func (pk *RsaPublicKey) Verify(data, sig []byte) (success bool, err error) {
	defer func() {
		catch.HandlePanic(recover(), &err, "RSA signature verification")

		// To be safe
		if err != nil {
			success = false
		}
	}()
	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(&pk.k, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (pk *RsaPublicKey) Type() pb.KeyType {
	return pb.KeyType_RSA
}

func (pk *RsaPublicKey) Raw() (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "RSA public-key marshaling") }()
	return x509.MarshalPKIXPublicKey(&pk.k)
}

// Equals checks whether this key is equal to another
func (pk *RsaPublicKey) Equals(k Key) bool {
	// make sure this is a rsa public key
	other, ok := (k).(*RsaPublicKey)
	if !ok {
		return basicEquals(pk, k)
	}

	return pk.k.N.Cmp(other.k.N) == 0 && pk.k.E == other.k.E
}

// Sign returns a signature of the input data
func (sk *RsaPrivateKey) Sign(message []byte) (sig []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "RSA signing") }()
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, &sk.sk, crypto.SHA256, hashed[:])
}

// GetPublic returns a public key
func (sk *RsaPrivateKey) GetPublic() PubKey {
	return &RsaPublicKey{k: sk.sk.PublicKey}
}

func (sk *RsaPrivateKey) Type() pb.KeyType {
	return pb.KeyType_RSA
}

func (sk *RsaPrivateKey) Raw() (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "RSA private-key marshaling") }()
	b := x509.MarshalPKCS1PrivateKey(&sk.sk)
	return b, nil
}

// Equals checks whether this key is equal to another
func (sk *RsaPrivateKey) Equals(k Key) bool {
	// make sure this is a rsa public key
	other, ok := (k).(*RsaPrivateKey)
	if !ok {
		return basicEquals(sk, k)
	}

	a := sk.sk
	b := other.sk

	// Don't care about constant time. We're only comparing the public half.
	return a.PublicKey.N.Cmp(b.PublicKey.N) == 0 && a.PublicKey.E == b.PublicKey.E
}

// UnmarshalRsaPrivateKey returns a private key from the input x509 bytes
func UnmarshalRsaPrivateKey(b []byte) (key PrivKey, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "RSA private-key unmarshaling") }()
	sk, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	if sk.N.BitLen() < MinRsaKeyBits {
		return nil, ErrRsaKeyTooSmall
	}
	if sk.N.BitLen() > maxRsaKeyBits {
		return nil, ErrRsaKeyTooBig
	}
	return &RsaPrivateKey{sk: *sk}, nil
}

// UnmarshalRsaPublicKey returns a public key from the input x509 bytes
func UnmarshalRsaPublicKey(b []byte) (key PubKey, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "RSA public-key unmarshaling") }()
	pub, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not actually an rsa public key")
	}
	if pk.N.BitLen() < MinRsaKeyBits {
		return nil, ErrRsaKeyTooSmall
	}
	if pk.N.BitLen() > maxRsaKeyBits {
		return nil, ErrRsaKeyTooBig
	}

	return &RsaPublicKey{k: *pk}, nil
}
