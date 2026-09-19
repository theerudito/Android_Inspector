package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"filippo.io/edwards25519"
)

// BoringSSL SPAKE2 over Edwards25519, matching AOSP pairing_auth.cpp.
const (
	spake2ClientName = "adb pair client\x00"
	spake2ServerName = "adb pair server\x00"
)

type spake2Role int

const (
	spake2Alice spake2Role = iota // pairing client (phone)
	spake2Bob                     // pairing server (host)
)

var (
	spake2M = mustEdwardsPoint("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e")
	spake2N = mustEdwardsPoint("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778")
	scalar8 = mustScalar8()
)

type spake2Auth struct {
	role             spake2Role
	myName           []byte
	theirName        []byte
	priv             *edwards25519.Scalar
	passwordScalar   *edwards25519.Scalar
	passwordHash     []byte
	msg              []byte
	cipher           *pairingAEAD
	processedMessage bool
}

func newSPAKE2(role spake2Role, password []byte) (*spake2Auth, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("pairing password is required")
	}
	auth := &spake2Auth{role: role, passwordHash: sha512Sum(password)}
	if role == spake2Alice {
		auth.myName = []byte(spake2ClientName)
		auth.theirName = []byte(spake2ServerName)
	} else {
		auth.myName = []byte(spake2ServerName)
		auth.theirName = []byte(spake2ClientName)
	}

	uniform := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, uniform); err != nil {
		return nil, fmt.Errorf("generate pairing scalar: %w", err)
	}
	priv, err := edwards25519.NewScalar().SetUniformBytes(uniform)
	if err != nil {
		return nil, fmt.Errorf("reduce pairing scalar: %w", err)
	}
	auth.priv = edwards25519.NewScalar().Multiply(priv, scalar8)

	passwordScalar, err := edwards25519.NewScalar().SetUniformBytes(auth.passwordHash)
	if err != nil {
		return nil, fmt.Errorf("reduce pairing password: %w", err)
	}
	auth.passwordScalar = passwordScalar

	maskBase := spake2N
	if role == spake2Alice {
		maskBase = spake2M
	}
	p := new(edwards25519.Point).ScalarBaseMult(auth.priv)
	mask := new(edwards25519.Point).ScalarMult(auth.passwordScalar, maskBase)
	auth.msg = new(edwards25519.Point).Add(p, mask).Bytes()
	return auth, nil
}

func (a *spake2Auth) finish(theirMsg []byte) error {
	if a.processedMessage {
		return fmt.Errorf("pairing cipher already initialized")
	}
	if len(theirMsg) != 32 {
		return fmt.Errorf("invalid SPAKE2 message size")
	}
	a.processedMessage = true

	qStar, err := new(edwards25519.Point).SetBytes(theirMsg)
	if err != nil {
		return fmt.Errorf("decode peer SPAKE2 point: %w", err)
	}
	peersMaskBase := spake2M
	if a.role == spake2Alice {
		peersMaskBase = spake2N
	}
	peersMask := new(edwards25519.Point).ScalarMult(a.passwordScalar, peersMaskBase)
	q := new(edwards25519.Point).Subtract(qStar, peersMask)
	shared := new(edwards25519.Point).ScalarMult(a.priv, q).Bytes()

	h := sha512.New()
	if a.role == spake2Alice {
		writeLengthPrefixed(h, a.myName)
		writeLengthPrefixed(h, a.theirName)
		writeLengthPrefixed(h, a.msg)
		writeLengthPrefixed(h, theirMsg)
	} else {
		writeLengthPrefixed(h, a.theirName)
		writeLengthPrefixed(h, a.myName)
		writeLengthPrefixed(h, theirMsg)
		writeLengthPrefixed(h, a.msg)
	}
	writeLengthPrefixed(h, shared)
	writeLengthPrefixed(h, a.passwordHash)
	a.cipher, err = newPairingAEAD(h.Sum(nil))
	return err
}

func writeLengthPrefixed(h hash.Hash, data []byte) {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(data)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(data)
}

func sha512Sum(in []byte) []byte {
	sum := sha512.Sum512(in)
	return sum[:]
}

func mustEdwardsPoint(hexStr string) *edwards25519.Point {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		panic(err)
	}
	return point
}

func mustScalar8() *edwards25519.Scalar {
	var raw [32]byte
	raw[0] = 8
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(raw[:])
	if err != nil {
		panic(err)
	}
	return scalar
}
