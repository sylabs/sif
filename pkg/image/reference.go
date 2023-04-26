// Copyright (c) 2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package image

import (
	"context"
	"os"
	"path/filepath"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/types"
	"github.com/sylabs/sif/v2/pkg/sif"
)

// sifReference is an ImageReference for a SIF.
type sifReference struct {
	path string // absolute path of SIF.
}

type NewReferenceOption func(r *sifReference) error

// NewReference returns a SIF reference for a file at the specified path.
func NewReference(path string, opts ...NewReferenceOption) (types.ImageReference, error) {
	// Ensure path is absolute.
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	r := sifReference{path: path}

	// Apply options.
	for _, opt := range opts {
		if err := opt(&r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// image returns a FileImage associated with ref.
func (ref sifReference) image(create bool) (*sif.FileImage, error) {
	if create {
		return sif.CreateContainerAtPath(ref.path, sif.OptCreateDeterministic())
	}
	return sif.LoadContainerFromPath(ref.path)
}

func (ref sifReference) Transport() types.ImageTransport {
	return Transport
}

// StringWithinTransport returns a string representation of the reference, which MUST be such that
// reference.Transport().ParseReference(reference.StringWithinTransport()) returns an equivalent
// reference.
//
// NOTE: The returned string is not promised to be equal to the original input to ParseReference;
// e.g. default attribute values omitted by the user may be included in the return value, or vice
// versa.
//
// WARNING: Do not use the return value in the UI to describe an image, it does not contain the
// Transport().Name() prefix; instead, see transports.ImageName().
func (ref sifReference) StringWithinTransport() string {
	return ref.path
}

// DockerReference returns a Docker reference associated with this reference (fully explicit, i.e.
// !reference.IsNameOnly, but reflecting user intent, not e.g. after redirect or alias processing),
// or nil if unknown/not applicable.
func (ref sifReference) DockerReference() reference.Named {
	return nil
}

// PolicyConfigurationIdentity returns a string representation of the reference, suitable for
// policy lookup. This MUST reflect user intent, not e.g. after processing of third-party redirects
// or aliases; The value SHOULD be fully explicit about its semantics, with no hidden defaults, AND
// canonical (i.e. various references with exactly the same semantics should return the same
// configuration identity). It is fine for the return value to be equal to StringWithinTransport(),
// and it is desirable but not required/guaranteed that it will be a valid input to
// Transport().ParseReference().
//
// Returns "" if configuration identities for these references are not supported.
func (ref sifReference) PolicyConfigurationIdentity() string {
	return ""
}

// PolicyConfigurationNamespaces returns a list of other policy configuration namespaces to search
// for if explicit configuration for PolicyConfigurationIdentity() is not set.  The list will be
// processed in order, terminating on first match, and an implicit "" is always checked at the end.
//
// It is STRONGLY recommended for the first element, if any, to be a prefix of
// PolicyConfigurationIdentity(), and each following element to be a prefix of the element
// preceding it.
func (ref sifReference) PolicyConfigurationNamespaces() []string {
	return nil
}

// NewImage returns a types.ImageCloser for this reference, possibly specialized for this
// ImageTransport.
//
// The caller must call .Close() on the returned ImageCloser.
//
// NOTE: If any kind of signature verification should happen, build an UnparsedImage from the value
// returned by NewImageSource, verify that UnparsedImage, and convert it into a real Image via
// image.FromUnparsedImage.
//
// WARNING: This may not do the right thing for a manifest list, see image.FromSource for details.
func (ref sifReference) NewImage(ctx context.Context, sys *types.SystemContext) (types.ImageCloser, error) {
	src, err := newImageSource(ref)
	if err != nil {
		return nil, err
	}
	return image.FromSource(ctx, sys, src)
}

// NewImageSource returns a types.ImageSource for this reference.
// The caller must call .Close() on the returned ImageSource.
func (ref sifReference) NewImageSource(_ context.Context, _ *types.SystemContext) (types.ImageSource, error) {
	return newImageSource(ref)
}

// NewImageDestination returns a types.ImageDestination for this reference.
// The caller must call .Close() on the returned ImageDestination.
func (ref sifReference) NewImageDestination(_ context.Context, _ *types.SystemContext) (types.ImageDestination, error) { //nolint:lll
	return newImageDestination(ref)
}

// DeleteImage deletes the named image from the registry, if supported.
func (ref sifReference) DeleteImage(_ context.Context, _ *types.SystemContext) error {
	return os.Remove(ref.path)
}
