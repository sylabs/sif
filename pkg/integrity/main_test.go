// Copyright (c) 2020-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sylabs/sif/v2/pkg/sif"
)

var corpus = filepath.Join("..", "..", "test", "images")

// fixedTime returns a fixed time value, useful for ensuring tests are deterministic.
func fixedTime() time.Time {
	return time.Unix(1504657553, 0)
}

// loadContainer loads a container from path for read-only access.
func loadContainer(t *testing.T, path string) *sif.FileImage {
	t.Helper()

	f, err := sif.LoadContainerFromPath(path, sif.OptLoadWithFlag(os.O_RDONLY))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.UnloadContainer(); err != nil {
			t.Error(err)
		}
	})

	return f
}

// getTestSigner returns a Signer read from the PEM file at path.
func getTestSigner(t *testing.T, name string, h crypto.Hash) signature.Signer { //nolint:ireturn
	t.Helper()

	path := filepath.Join("..", "..", "test", "keys", name)

	sv, err := signature.LoadSignerFromPEMFile(path, h, cryptoutils.SkipPassword)
	if err != nil {
		t.Fatal(err)
	}

	return sv
}

type wrapSigner struct {
	signature.Signer
	h crypto.Hash
}

func (s *wrapSigner) HashFunc() crypto.Hash { return s.h }

// getTestSignerWithOpts returns a Signer read from the PEM file at path, wrapped to implement the
// crypto.SignerOpts interface.
func getTestSignerWithOpts(t *testing.T, name string, h crypto.Hash) *wrapSigner {
	t.Helper()

	return &wrapSigner{
		Signer: getTestSigner(t, name, h),
		h:      h,
	}
}

// getTestVerifier returns a Verifier read from the PEM file at path.
func getTestVerifier(t *testing.T, name string, h crypto.Hash) signature.Verifier { //nolint:ireturn
	t.Helper()

	sv, err := signature.LoadVerifier(getTestPublicKey(t, name), h)
	if err != nil {
		t.Fatal(err)
	}

	return sv
}

// getTestPublicKey returns a PublicKey read from the PEM file at path.
func getTestPublicKey(t *testing.T, name string) crypto.PublicKey {
	t.Helper()

	path := filepath.Join("..", "..", "test", "keys", name)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := cryptoutils.UnmarshalPEMToPublicKey(b)
	if err != nil {
		t.Fatal(err)
	}

	return pub
}

// getTestEntity returns a fixed test PGP entity.
func getTestEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	f, err := os.Open(filepath.Join("..", "..", "test", "keys", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	el, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(el), 1; got != want {
		t.Fatalf("got %v entities, want %v", got, want)
	}
	return el[0]
}
