// the custom wrapper i made for dilithium post quantum keys


package crypto

import (
	"crypto/rand"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
)

type DilithiumPrivKeyWrapper struct {
	Key *mode3.PrivateKey
}

type DilithiumPubKeyWrapper struct {
    Key *mode3.PublicKey
}


// wrapper functions for private key
func (d *DilithiumPrivKeyWrapper) Sign(data []byte) ([]byte, error) {
	signature, err := d.Key.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (d *DilithiumPrivKeyWrapper) GetPublic() PubKey {
	return &DilithiumPubKeyWrapper{Key: d.Key.Public().(*mode3.PublicKey)}
}

func (d *DilithiumPrivKeyWrapper) Raw() ([]byte, error) {
	raw, err := d.Key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (d *DilithiumPrivKeyWrapper) Equals(other Key) bool {
	if otherWrapper, ok := other.(*DilithiumPrivKeyWrapper); ok {
		return d.Key.Equal(otherWrapper.Key)
	}
	return false
}

func (d *DilithiumPrivKeyWrapper) Type() pb.KeyType {
	return pb.KeyType_Dilithium
}


// wrapper functions for public key
func (d *DilithiumPubKeyWrapper) Verify(data []byte, sig []byte) (bool, error) {
	result := mode3.Verify(d.Key, data, sig)

	return result, nil
}

func (d *DilithiumPubKeyWrapper) Raw() ([]byte, error) {
	raw, err := d.Key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (d *DilithiumPubKeyWrapper) Equals(other Key) bool {
	if otherWrapper, ok := other.(*DilithiumPubKeyWrapper); ok {
		return d.Key.Equal(otherWrapper.Key)
	}
	return false
}

func (d *DilithiumPubKeyWrapper) Type() pb.KeyType {
	return pb.KeyType_Dilithium
}

func UnmarshalDilithiumPublicKey(data []byte) (PubKey, error) {
	var key mode3.PublicKey
	if err := key.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &DilithiumPubKeyWrapper{Key: &key}, nil
}

// UnmarshalEd25519PrivateKey returns a private key from input bytes.
func UnmarshalDilithiumPrivateKey(data []byte) (PrivKey, error) {
	var key mode3.PrivateKey
	if err := key.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &DilithiumPrivKeyWrapper{Key: &key}, nil
}
