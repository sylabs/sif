// Copyright (c) 2022-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
)

func Test_dsseEncoder_signMessage(t *testing.T) {
	tests := []struct {
		name     string
		signers  []signature.Signer
		wantErr  error
		wantHash crypto.Hash
	}{
		{
			name: "MultipleHashAlgorithms",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA256),
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA384),
			},
			wantErr: errMultipleHashes,
		},
		{
			name: "Multi",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			wantHash: crypto.SHA256,
		},
		{
			name: "ED25519",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "ed25519-private.pem", crypto.Hash(0)),
			},
			wantHash: crypto.Hash(0),
		},
		{
			name: "RSA_SHA256",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA256),
			},
			wantHash: crypto.SHA256,
		},
		{
			name: "RSA_SHA384",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA384),
			},
			wantHash: crypto.SHA384,
		},
		{
			name: "RSA_SHA512",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA512),
			},
			wantHash: crypto.SHA512,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			en, err := newDSSEEncoder(tt.signers...)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, wantErr %v", got, want)
			}

			if err == nil {
				ht, err := en.signMessage(&b, strings.NewReader(testMessage))
				if err != nil {
					t.Fatal(err)
				}

				if got, want := ht, tt.wantHash; got != want {
					t.Errorf("got hash %v, want %v", got, want)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

// corruptPayloadType corrupts the payload type of e and re-signs the envelope. The result is a
// cryptographically valid envelope with an unexpected payload types.
func corruptPayloadType(t *testing.T, en *dsseEncoder, e *dsse.Envelope) {
	body, err := e.DecodeB64Payload()
	if err != nil {
		t.Fatal(err)
	}

	bad, err := en.es.SignPayload("bad", body)
	if err != nil {
		t.Fatal(err)
	}

	*e = *bad
}

// corruptPayload corrupts the payload in e. The result is that the signature(s) in e do not match
// the payload.
func corruptPayload(t *testing.T, _ *dsseEncoder, e *dsse.Envelope) {
	body, err := e.DecodeB64Payload()
	if err != nil {
		t.Fatal(err)
	}

	e.Payload = base64.StdEncoding.EncodeToString(body[:len(body)-1])
}

// corruptSignatures corrupts the signature(s) in e. The result is that the signature(s) in e do
// not match the payload.
func corruptSignatures(t *testing.T, _ *dsseEncoder, e *dsse.Envelope) {
	for i, sig := range e.Signatures {
		b, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Fatal(err)
		}

		sig.Sig = base64.StdEncoding.EncodeToString(b[:len(b)-1])

		e.Signatures[i] = sig
	}
}

func Test_dsseDecoder_verifyMessage(t *testing.T) {
	tests := []struct {
		name        string
		signers     []signature.Signer
		corrupter   func(*testing.T, *dsseEncoder, *dsse.Envelope)
		de          *dsseDecoder
		wantErr     error
		wantMessage string
		wantKeys    []crypto.PublicKey
	}{
		{
			name: "CorruptPayloadType",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			corrupter: corruptPayloadType,
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantErr: errDSSEUnexpectedPayloadType,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "CorruptPayload",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			corrupter: corruptPayload,
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantErr:  errDSSEVerifyEnvelopeFailed,
			wantKeys: []crypto.PublicKey{},
		},
		{
			name: "CorruptSignatures",
			signers: []signature.Signer{
				getTestSigner(t, "rsa-private.pem", crypto.SHA256),
			},
			corrupter: corruptSignatures,
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantErr:  errDSSEVerifyEnvelopeFailed,
			wantKeys: []crypto.PublicKey{},
		},
		{
			name: "Multi_SHA256",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "ecdsa-private.pem", crypto.SHA256),
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256),
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ecdsa-public.pem"),
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "Multi_SHA256_ECDSA",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "ecdsa-private.pem", crypto.SHA256),
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ecdsa-public.pem"),
			},
		},
		{
			name: "Multi_SHA256_RSA",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "ecdsa-private.pem", crypto.SHA256),
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "ECDSA_SHA256",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "ecdsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ecdsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ecdsa-public.pem"),
			},
		},
		{
			name: "ED25519",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "ed25519-private.pem", crypto.Hash(0)),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "ed25519-public.pem", crypto.Hash(0)),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "ed25519-public.pem"),
			},
		},
		{
			name: "RSA_SHA256",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA256),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA256),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "RSA_SHA384",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA384),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA384),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
		{
			name: "RSA_SHA512",
			signers: []signature.Signer{
				getTestSignerWithOpts(t, "rsa-private.pem", crypto.SHA512),
			},
			de: newDSSEDecoder(
				getTestVerifier(t, "rsa-public.pem", crypto.SHA512),
			),
			wantMessage: testMessage,
			wantKeys: []crypto.PublicKey{
				getTestPublicKey(t, "rsa-public.pem"),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.Buffer{}

			en, err := newDSSEEncoder(tt.signers...)
			if err != nil {
				t.Fatal(err)
			}

			// Sign and encode message.
			h, err := en.signMessage(&b, strings.NewReader(testMessage))
			if err != nil {
				t.Fatal(err)
			}

			// Introduce corruption, if applicable.
			if tt.corrupter != nil {
				var e dsse.Envelope
				if err := json.Unmarshal(b.Bytes(), &e); err != nil {
					t.Fatal(err)
				}

				tt.corrupter(t, en, &e)

				b.Reset()
				if err := json.NewEncoder(&b).Encode(e); err != nil {
					t.Fatal(err)
				}
			}

			// Decode and verify message.
			var vr VerifyResult
			message, err := tt.de.verifyMessage(bytes.NewReader(b.Bytes()), h, &vr)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if got, want := string(message), tt.wantMessage; got != want {
				t.Errorf("got message %v, want %v", got, want)
			}

			if got, want := vr.Keys(), tt.wantKeys; !reflect.DeepEqual(got, want) {
				t.Errorf("got keys %#v, want %#v", got, want)
			}
		})
	}
}
