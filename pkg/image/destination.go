// Copyright (c) 2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package image

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sylabs/sif/v2/pkg/sif"
)

var errSignaturesNotSupported = errors.New("signatures not supported")

type sifImageDestination struct {
	ref sifReference
	fi  *sif.FileImage
}

// newImageDestination returns an ImageDestination for a SIF. If the file does not exist, it is
// created.
func newImageDestination(ref sifReference) (types.ImageDestination, error) {
	fi, err := ref.image(true)
	if err != nil {
		return nil, err
	}

	return &sifImageDestination{ref: ref, fi: fi}, nil
}

// Reference returns the reference used to set up this destination.
func (d *sifImageDestination) Reference() types.ImageReference {
	return d.ref
}

// Close removes resources associated with an initialized ImageDestination, if any.
func (d *sifImageDestination) Close() error {
	return d.fi.UnloadContainer()
}

// SupportedManifestMIMETypes tells which manifest mime types the destination supports If an empty
// slice or nil is returned, then any mime type can be tried to upload.
func (d *sifImageDestination) SupportedManifestMIMETypes() []string {
	return []string{
		imgspecv1.MediaTypeImageManifest,
		imgspecv1.MediaTypeImageIndex,
	}
}

// SupportsSignatures returns an error (to be displayed to the user) if the destination certainly
// can't store signatures.
func (d *sifImageDestination) SupportsSignatures(_ context.Context) error {
	return errSignaturesNotSupported
}

// DesiredLayerCompression indicates the kind of compression to apply on layers.
func (d *sifImageDestination) DesiredLayerCompression() types.LayerCompression {
	return types.PreserveOriginal
}

// AcceptsForeignLayerURLs returns false iff foreign layers in manifest should be actually
// uploaded to the image destination, true otherwise.
func (d *sifImageDestination) AcceptsForeignLayerURLs() bool {
	return true
}

// MustMatchRuntimeOS returns true iff the destination can store only images targeted for the
// current runtime architecture and OS.
func (d *sifImageDestination) MustMatchRuntimeOS() bool {
	return false
}

// IgnoresEmbeddedDockerReference() returns true iff the destination does not care about
// Image.EmbeddedDockerReferenceConflicts(), and would prefer to receive an unmodified manifest
// instead of one modified for the destination.
func (d *sifImageDestination) IgnoresEmbeddedDockerReference() bool {
	return false
}

// accumulator is a simple io.Writer implementation that counts the bytes written to it.
type accumulator struct {
	n int64
}

// Write writes len(p) bytes from p to the underlying data stream. It returns the number of bytes
// written from p.
func (w *accumulator) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// PutBlob writes contents of stream and returns data representing the result.
//
// inputInfo.Digest can be optionally provided if known; it is not mandatory for the implementation
// to verify it. inputInfo.Size is the expected length of stream, if known. inputInfo.MediaType
// describes the blob format, if known.
//
// May update cache.
func (d *sifImageDestination) PutBlob(_ context.Context, stream io.Reader, inputInfo types.BlobInfo, _ types.BlobInfoCache, _ bool) (types.BlobInfo, error) { //nolint:lll
	var opts []sif.DescriptorInputOpt

	// If inputInfo.MediaType is known, include it in metadata.
	if mt := inputInfo.MediaType; mt != "" {
		opts = append(opts, sif.OptMetadata(extra{mt}))
	}

	// inputInfo.Digest isn't necessarily known, so calculate from the stream.
	digester := digest.Canonical.Digester()

	// inputInfo.Size isn't necessarily known, so keep track of the size of the stream.
	acc := &accumulator{}

	di, err := sif.NewDescriptorInput(sif.DataGeneric, io.TeeReader(stream, io.MultiWriter(digester.Hash(), acc)), opts...)
	if err != nil {
		return types.BlobInfo{}, err
	}

	if err := d.fi.AddObject(di); err != nil {
		return types.BlobInfo{}, err
	}

	return types.BlobInfo{
		Digest: digester.Digest(),
		Size:   acc.n,
	}, nil
}

// HasThreadSafePutBlob indicates whether PutBlob can be executed concurrently.
func (d *sifImageDestination) HasThreadSafePutBlob() bool {
	return false
}

// TryReusingBlob checks whether the transport already contains, or can efficiently reuse, a blob,
// and if so, applies it to the current destination (e.g. if the blob is a filesystem layer, this
// signifies that the changes it describes need to be applied again when composing a filesystem
// tree).
//
// If canSubstitute, TryReusingBlob can use an equivalent of the desired blob; in that case the
// returned info may not match the input. If the blob has been successfully reused, returns (true,
// info, nil); info must contain at least a digest and size. If the transport can not reuse the
// requested blob, TryReusingBlob returns (false, {}, nil); it returns a non-nil error only on an
// unexpected failure.
//
// May use and/or update cache.
func (d *sifImageDestination) TryReusingBlob(_ context.Context, _ types.BlobInfo, _ types.BlobInfoCache, _ bool) (bool, types.BlobInfo, error) { //nolint:lll
	return false, types.BlobInfo{}, nil
}

// PutManifest writes manifest to the destination.
//
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to write or
// overwrite the signatures for (when the primary manifest is a manifest list); this should always
// be nil if the primary manifest is not a manifest list.
func (d *sifImageDestination) PutManifest(_ context.Context, b []byte, _ *digest.Digest) error {
	var opts []sif.DescriptorInputOpt

	if mt := manifest.GuessMIMEType(b); mt != "" {
		opts = append(opts, sif.OptMetadata(extra{mt}))
	}

	di, err := sif.NewDescriptorInput(sif.DataGeneric, bytes.NewReader(b), opts...)
	if err != nil {
		return err
	}

	return d.fi.AddObject(di)
}

// PutSignatures writes a set of signatures to the destination.
//
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to write or
// overwrite the signatures for (when the primary manifest is a manifest list); this should always
// be nil if the primary manifest is not a manifest list.
func (d *sifImageDestination) PutSignatures(_ context.Context, signatures [][]byte, _ *digest.Digest) error { //nolint:lll
	for range signatures {
		return errSignaturesNotSupported
	}
	return nil
}

// Commit marks the process of storing the image as successful and asks for the image to be
// persisted.
func (d *sifImageDestination) Commit(_ context.Context, _ types.UnparsedImage) error {
	return nil
}
