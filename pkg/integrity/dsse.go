// Copyright (c) 2022-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const metadataMediaType = "application/vnd.sylabs.sif-metadata+json"

type dsseEncoder struct {
	es          *dsse.EnvelopeSigner
	h           crypto.Hash
	payloadType string
}

var errMultipleHashes = errors.New("multiple hash algorithms specified")

// newDSSEEncoder returns an encoder that signs messages in DSSE format, with key material from ss.
func newDSSEEncoder(ss ...signature.Signer) (*dsseEncoder, error) {
	var h crypto.Hash

	dss := make([]dsse.SignVerifier, 0, len(ss))
	for i, s := range ss {
		ds, err := newDSSESigner(s)
		if err != nil {
			return nil, err
		}

		// All signers must use the same hash, since the descriptor can only express one value.
		if i == 0 {
			h = ds.HashFunc()
		} else if h != ds.HashFunc() {
			return nil, errMultipleHashes
		}

		dss = append(dss, ds)
	}

	es, err := dsse.NewEnvelopeSigner(dss...)
	if err != nil {
		return nil, err
	}

	return &dsseEncoder{
		es:          es,
		h:           h,
		payloadType: metadataMediaType,
	}, nil
}

// signMessage signs the message from r in DSSE format, and writes the result to w. On success, the
// hash function is returned.
func (en *dsseEncoder) signMessage(w io.Writer, r io.Reader) (crypto.Hash, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}

	e, err := en.es.SignPayload(en.payloadType, body)
	if err != nil {
		return 0, err
	}

	return en.h, json.NewEncoder(w).Encode(e)
}

type dsseDecoder struct {
	vs          []signature.Verifier
	threshold   int
	payloadType string
}

// newDSSEDecoder returns a decoder that verifies messages in DSSE format using key material from
// vs.
func newDSSEDecoder(vs ...signature.Verifier) *dsseDecoder {
	return &dsseDecoder{
		vs:          vs,
		threshold:   1, // Envelope considered verified if at least one verifier succeeds.
		payloadType: metadataMediaType,
	}
}

var (
	errDSSEVerifyEnvelopeFailed  = errors.New("dsse: verify envelope failed")
	errDSSEUnexpectedPayloadType = errors.New("unexpected DSSE payload type")
)

// verifyMessage reads a message from r, verifies its signature(s), and returns the message
// contents. On success, the accepted public keys are set in vr.
func (de *dsseDecoder) verifyMessage(r io.Reader, h crypto.Hash, vr *VerifyResult) ([]byte, error) {
	vs := make([]dsse.Verifier, 0, len(de.vs))
	for _, v := range de.vs {
		dv, err := newDSSEVerifier(v, options.WithCryptoSignerOpts(h))
		if err != nil {
			return nil, err
		}

		vs = append(vs, dv)
	}

	v, err := dsse.NewMultiEnvelopeVerifier(de.threshold, vs...)
	if err != nil {
		return nil, err
	}

	var e dsse.Envelope
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return nil, err
	}

	vr.aks, err = v.Verify(&e)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDSSEVerifyEnvelopeFailed, err)
	}

	if e.PayloadType != de.payloadType {
		return nil, fmt.Errorf("%w: %v", errDSSEUnexpectedPayloadType, e.PayloadType)
	}

	return e.DecodeB64Payload()
}

type dsseSigner struct {
	s    signature.Signer
	opts []signature.SignOption
	h    crypto.Hash
	pub  crypto.PublicKey
}

// newDSSESigner returns a dsse.SignVerifier that uses s to sign. The SHA-256 hash algorithm is
// used unless s implements the crypto.SignerOpts interface and specifies an alternative algorithm.
// Note that the returned value is suitable only for signing, and not verification.
func newDSSESigner(s signature.Signer) (*dsseSigner, error) {
	var opts []signature.SignOption

	so, ok := s.(crypto.SignerOpts)
	if !ok {
		// Unable to determine hash algorithm used by signer, so override with SHA256.
		so = crypto.SHA256
		opts = append(opts, options.WithCryptoSignerOpts(so))
	}

	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}

	return &dsseSigner{
		s:    s,
		opts: opts,
		h:    so.HashFunc(),
		pub:  pub,
	}, nil
}

// Sign signs the supplied data.
func (s *dsseSigner) Sign(data []byte) ([]byte, error) {
	return s.s.SignMessage(bytes.NewReader(data), s.opts...)
}

// HashFunc returns an identifier for the hash function used to produce the message passed to
// Signer.Sign, or else zero to indicate no hashing.
func (s *dsseSigner) HashFunc() crypto.Hash {
	return s.h
}

var errSignNotImplemented = errors.New("sign not implemented")

// Verify is not implemented, but required for the dsse.SignVerifier interface.
func (s *dsseSigner) Verify(data, sig []byte) error {
	return errSignNotImplemented
}

// Public returns the public key associated with s.
func (s *dsseSigner) Public() crypto.PublicKey {
	return s.pub
}

// KeyID returns the key ID associated with s.
func (s dsseSigner) KeyID() (string, error) {
	return dsse.SHA256KeyID(s.pub)
}

type dsseVerifier struct {
	v    signature.Verifier
	opts []signature.VerifyOption
	pub  crypto.PublicKey
}

// newDSSEVerifier returns a dsse.Verifier that uses v to verify according to opts.
func newDSSEVerifier(v signature.Verifier, opts ...signature.VerifyOption) (*dsseVerifier, error) {
	pub, err := v.PublicKey()
	if err != nil {
		return nil, err
	}

	return &dsseVerifier{
		v:    v,
		opts: opts,
		pub:  pub,
	}, nil
}

// Verify verifies that sig is a valid signature of data.
func (v *dsseVerifier) Verify(data, sig []byte) error {
	return v.v.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data), v.opts...)
}

// Public returns the public key associated with v.
func (v *dsseVerifier) Public() crypto.PublicKey {
	return v.pub
}

// KeyID returns the key ID associated with v.
func (v *dsseVerifier) KeyID() (string, error) {
	return dsse.SHA256KeyID(v.pub)
}

// isDSSESignature returns true if r contains a signature in a DSSE envelope.
func isDSSESignature(r io.Reader) bool {
	var e dsse.Envelope
	if err := json.NewDecoder(r).Decode(&e); err != nil {
		return false
	}

	return metadataMediaType == e.PayloadType
}
