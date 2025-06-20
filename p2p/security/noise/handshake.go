package noise

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/TheNoobiCat/go-libp2p/core/crypto"
	"github.com/TheNoobiCat/go-libp2p/core/peer"
	"github.com/TheNoobiCat/go-libp2p/core/sec"
	"github.com/TheNoobiCat/go-libp2p/p2p/security/noise/pb"

	"github.com/flynn/noise"
	pool "github.com/libp2p/go-buffer-pool"
	"google.golang.org/protobuf/proto"
)

// payloadSigPrefix is prepended to our Noise static key before signing with
// our libp2p identity key.
const payloadSigPrefix = "noise-libp2p-static-key:"

// All noise session share a fixed cipher suite
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// runHandshake exchanges handshake messages with the remote peer to establish
// a noise-libp2p session. It blocks until the handshake completes or fails.
func (s *secureSession) runHandshake(ctx context.Context) (err error) {
	defer func() {
		if rerr := recover(); rerr != nil {
			fmt.Fprintf(os.Stderr, "caught panic: %s\n%s\n", rerr, debug.Stack())
			err = fmt.Errorf("panic in Noise handshake: %s", rerr)
		}
	}()

	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating static keypair: %w", err)
	}

	cfg := noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     s.initiator,
		StaticKeypair: kp,
		Prologue:      s.prologue,
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return fmt.Errorf("error initializing handshake state: %w", err)
	}

	// set a deadline to complete the handshake, if one has been supplied.
	// clear it after we're done.
	if deadline, ok := ctx.Deadline(); ok {
		if err := s.SetDeadline(deadline); err == nil {
			// schedule the deadline removal once we're done handshaking.
			defer s.SetDeadline(time.Time{})
		}
	}

	// We can re-use this buffer for all handshake messages.
	hbuf := pool.Get(2 << 10)
	defer pool.Put(hbuf)

	if s.initiator {
		// stage 0 //
		// Handshake Msg Len = len(DH ephemeral key)
		if err := s.sendHandshakeMessage(hs, nil, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}

		// stage 1 //
		plaintext, err := s.readHandshakeMessage(hs)
		if err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}
		rcvdEd, err := s.handleRemoteHandshakePayload(plaintext, hs.PeerStatic())
		if err != nil {
			return err
		}
		if s.initiatorEarlyDataHandler != nil {
			if err := s.initiatorEarlyDataHandler.Received(ctx, s.insecureConn, rcvdEd); err != nil {
				return err
			}
		}

		// stage 2 //
		// Handshake Msg Len = len(DHT static key) +  MAC(static key is encrypted) + len(Payload) + MAC(payload is encrypted)
		var ed *pb.NoiseExtensions
		if s.initiatorEarlyDataHandler != nil {
			ed = s.initiatorEarlyDataHandler.Send(ctx, s.insecureConn, s.remoteID)
		}
		payload, err := s.generateHandshakePayload(kp, ed)
		if err != nil {
			return err
		}
		if err := s.sendHandshakeMessage(hs, payload, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}
		return nil
	} else {
		// stage 0 //
		if _, err := s.readHandshakeMessage(hs); err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}

		// stage 1 //
		// Handshake Msg Len = len(DH ephemeral key) + len(DHT static key) +  MAC(static key is encrypted) + len(Payload) +
		// MAC(payload is encrypted)
		var ed *pb.NoiseExtensions
		if s.responderEarlyDataHandler != nil {
			ed = s.responderEarlyDataHandler.Send(ctx, s.insecureConn, s.remoteID)
		}
		payload, err := s.generateHandshakePayload(kp, ed)
		if err != nil {
			return err
		}
		if err := s.sendHandshakeMessage(hs, payload, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}

		// stage 2 //
		plaintext, err := s.readHandshakeMessage(hs)
		if err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}
		rcvdEd, err := s.handleRemoteHandshakePayload(plaintext, hs.PeerStatic())
		if err != nil {
			return err
		}
		if s.responderEarlyDataHandler != nil {
			if err := s.responderEarlyDataHandler.Received(ctx, s.insecureConn, rcvdEd); err != nil {
				return err
			}
		}
		return nil
	}
}

// setCipherStates sets the initial cipher states that will be used to protect
// traffic after the handshake.
//
// It is called when the final handshake message is processed by
// either sendHandshakeMessage or readHandshakeMessage.
func (s *secureSession) setCipherStates(cs1, cs2 *noise.CipherState) {
	if s.initiator {
		s.enc = cs1
		s.dec = cs2
	} else {
		s.enc = cs2
		s.dec = cs1
	}
}

// sendHandshakeMessage sends the next handshake message in the sequence.
//
// If payload is non-empty, it will be included in the handshake message.
// If this is the final message in the sequence, calls setCipherStates
// to initialize cipher states.
func (s *secureSession) sendHandshakeMessage(hs *noise.HandshakeState, payload []byte, hbuf []byte) error {
	// the first two bytes will be the length of the noise handshake message.
	bz, cs1, cs2, err := hs.WriteMessage(hbuf[:LengthPrefixLength], payload)
	if err != nil {
		return err
	}

	// bz will also include the length prefix as we passed a slice of LengthPrefixLength length
	// to hs.Write().
	binary.BigEndian.PutUint16(bz, uint16(len(bz)-LengthPrefixLength))

	_, err = s.writeMsgInsecure(bz)
	if err != nil {
		return err
	}

	if cs1 != nil && cs2 != nil {
		s.setCipherStates(cs1, cs2)
	}
	return nil
}

// readHandshakeMessage reads a message from the insecure conn and tries to
// process it as the expected next message in the handshake sequence.
//
// If the message contains a payload, it will be decrypted and returned.
//
// If this is the final message in the sequence, it calls setCipherStates
// to initialize cipher states.
func (s *secureSession) readHandshakeMessage(hs *noise.HandshakeState) ([]byte, error) {
	l, err := s.readNextInsecureMsgLen()
	if err != nil {
		return nil, err
	}

	buf := pool.Get(l)
	defer pool.Put(buf)

	if err := s.readNextMsgInsecure(buf); err != nil {
		return nil, err
	}

	msg, cs1, cs2, err := hs.ReadMessage(nil, buf)
	if err != nil {
		return nil, err
	}
	if cs1 != nil && cs2 != nil {
		s.setCipherStates(cs1, cs2)
	}
	return msg, nil
}

// generateHandshakePayload creates a libp2p handshake payload with a
// signature of our static noise key.
func (s *secureSession) generateHandshakePayload(localStatic noise.DHKey, ext *pb.NoiseExtensions) ([]byte, error) {
	// obtain the public key from the handshake session, so we can sign it with
	// our libp2p secret key.
	localKeyRaw, err := crypto.MarshalPublicKey(s.LocalPublicKey())
	if err != nil {
		return nil, fmt.Errorf("error serializing libp2p identity key: %w", err)
	}

	// prepare payload to sign; perform signature.
	toSign := append([]byte(payloadSigPrefix), localStatic.Public...)
	signedPayload, err := s.localKey.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("error sigining handshake payload: %w", err)
	}

	// create payload
	payloadEnc, err := proto.Marshal(&pb.NoiseHandshakePayload{
		IdentityKey: localKeyRaw,
		IdentitySig: signedPayload,
		Extensions:  ext,
	})
	if err != nil {
		return nil, fmt.Errorf("error marshaling handshake payload: %w", err)
	}
	return payloadEnc, nil
}

// handleRemoteHandshakePayload unmarshals the handshake payload object sent
// by the remote peer and validates the signature against the peer's static Noise key.
// It returns the data attached to the payload.
func (s *secureSession) handleRemoteHandshakePayload(payload []byte, remoteStatic []byte) (*pb.NoiseExtensions, error) {
	// unmarshal payload
	nhp := new(pb.NoiseHandshakePayload)
	err := proto.Unmarshal(payload, nhp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling remote handshake payload: %w", err)
	}

	// unpack remote peer's public libp2p key
	remotePubKey, err := crypto.UnmarshalPublicKey(nhp.GetIdentityKey())
	if err != nil {
		return nil, err
	}
	id, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}

	// check the peer ID if enabled
	if s.checkPeerID && s.remoteID != id {
		return nil, sec.ErrPeerIDMismatch{Expected: s.remoteID, Actual: id}
	}

	// verify payload is signed by asserted remote libp2p key.
	sig := nhp.GetIdentitySig()
	msg := append([]byte(payloadSigPrefix), remoteStatic...)
	ok, err := remotePubKey.Verify(msg, sig)
	if err != nil {
		return nil, fmt.Errorf("error verifying signature: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("handshake signature invalid")
	}

	// set remote peer key and id
	s.remoteID = id
	s.remoteKey = remotePubKey
	return nhp.Extensions, nil
}
