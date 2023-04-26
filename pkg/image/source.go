// Copyright (c) 2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sylabs/sif/v2/pkg/sif"
)

type extra struct {
	MimeType string `json:"MimeType"`
}

func (e extra) MarshalBinary() ([]byte, error) {
	return json.Marshal(e)
}

func (e *extra) UnmarshalBinary(b []byte) error {
	return json.Unmarshal(bytes.TrimRight(b, "\x00"), e)
}

// getMimeType returns the mimeType associated with descriptor d.
func getMimeType(d sif.Descriptor) string {
	var e extra
	if err := d.GetMetadata(&e); err != nil {
		return ""
	}
	return e.MimeType
}

func withMimeType(want string) sif.DescriptorSelectorFunc {
	return func(d sif.Descriptor) (bool, error) {
		return want == getMimeType(d), nil
	}
}

// descriptorsByMIMEType returns all descriptors in fi of type mimeType.
func (s *sifImageSource) descriptorsByMIMEType(mimeType string) []sif.Descriptor {
	ds, err := s.fi.GetDescriptors(withMimeType(mimeType))
	if err != nil {
		return nil
	}
	return ds
}

var (
	errMultIndex         = errors.New("multiple indexes found")
	errNoPrimaryManifest = errors.New("no primary manifest found")
)

// getIndexOrPrimaryManifest attempts to find an image index, or (singular) primary image manifest.
func (s *sifImageSource) indexOrPrimaryManifest() ([]byte, string, error) {
	if s.cachedManifest != nil {
		return s.cachedManifest, s.cachedManifestType, nil
	}

	// Look for an image index first.
	if ds := s.descriptorsByMIMEType(imgspecv1.MediaTypeImageIndex); len(ds) == 1 {
		b, err := ds[0].GetData()
		if err != nil {
			return nil, "", err
		}

		s.cachedManifest = b
		s.cachedManifestType = imgspecv1.MediaTypeImageIndex
		return s.cachedManifest, s.cachedManifestType, nil
	} else if len(ds) > 1 {
		return nil, "", errMultIndex
	}

	// If no image index found, perhaps there is a single manifest?
	if ds := s.descriptorsByMIMEType(imgspecv1.MediaTypeImageManifest); len(ds) == 1 {
		b, err := ds[0].GetData()
		if err != nil {
			return nil, "", err
		}

		s.cachedManifest = b
		s.cachedManifestType = imgspecv1.MediaTypeImageManifest
		return s.cachedManifest, s.cachedManifestType, nil
	}
	return nil, "", errNoPrimaryManifest
}

func withDigest(want digest.Digest) sif.DescriptorSelectorFunc {
	return func(d sif.Descriptor) (bool, error) {
		got, err := digest.Canonical.FromReader(d.GetReader())
		if err != nil {
			return false, err
		}

		return got == want, nil
	}
}

// descriptorByDigest returns the first descriptor in fi matching digest d.
func (s *sifImageSource) descriptorByDigest(want digest.Digest) (sif.Descriptor, error) {
	return s.fi.GetDescriptor(withDigest(want))
}

type sifImageSource struct {
	ref sifReference
	fi  *sif.FileImage

	cachedManifest     []byte
	cachedManifestType string
}

// newImageSource returns an ImageSource for reading from a SIF.
func newImageSource(ref sifReference) (types.ImageSource, error) {
	fi, err := ref.image(false)
	if err != nil {
		return nil, err
	}

	return &sifImageSource{ref: ref, fi: fi}, nil
}

// Reference returns the reference used to set up this source, as specified by the user.
func (s *sifImageSource) Reference() types.ImageReference {
	return s.ref
}

// Close removes resources associated with an initialized ImageSource, if any.
func (s *sifImageSource) Close() error {
	return s.fi.UnloadContainer()
}

// GetManifest returns the image's manifest along with its MIME type (which may be empty when it
// can't be determined but the manifest is available).
//
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve
// (when the primary manifest is a manifest list); this never happens if the primary manifest is
// not a manifest list (e.g. if the source never returns manifest lists).
func (s *sifImageSource) GetManifest(_ context.Context, instanceDigest *digest.Digest) ([]byte, string, error) {
	if instanceDigest == nil {
		return s.indexOrPrimaryManifest()
	}

	d, err := s.descriptorByDigest(*instanceDigest)
	if err != nil {
		return nil, "", err
	}

	b, err := d.GetData()
	if err != nil {
		return nil, "", err
	}

	return b, getMimeType(d), nil
}

// GetBlob returns a stream for the specified blob, and the blob’s size (or -1 if unknown).
//
// The Digest field in BlobInfo is guaranteed to be provided, Size may be -1 and MediaType may be
// optionally provided.
func (s *sifImageSource) GetBlob(_ context.Context, bi types.BlobInfo, _ types.BlobInfoCache) (io.ReadCloser, int64, error) { //nolint:lll
	d, err := s.descriptorByDigest(bi.Digest)
	if err != nil {
		return nil, 0, err
	}
	return io.NopCloser(d.GetReader()), d.Size(), nil
}

// HasThreadSafeGetBlob indicates whether GetBlob can be executed concurrently.
func (s *sifImageSource) HasThreadSafeGetBlob() bool {
	return false
}

// GetSignatures returns the image's signatures.
//
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve
// signatures for (when the primary manifest is a manifest list); this never happens if the primary
// manifest is not a manifest list (e.g. if the source never returns manifest lists).
func (s *sifImageSource) GetSignatures(_ context.Context, _ *digest.Digest) ([][]byte, error) {
	return nil, nil
}

// LayerInfosForCopy returns either nil (meaning the values in the manifest are fine), or updated
// values for the layer blobsums that are listed in the image's manifest. If values are returned,
// they should be used when using GetBlob() to read the image's layers.
//
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve
// BlobInfos for (when the primary manifest is a manifest list); this never happens if the primary
// manifest is not a manifest list (e.g. if the source never returns manifest lists).
func (s *sifImageSource) LayerInfosForCopy(_ context.Context, _ *digest.Digest) ([]types.BlobInfo, error) {
	return nil, nil
}
