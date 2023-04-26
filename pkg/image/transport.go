// Copyright (c) 2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package image

import (
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
)

func init() { //nolint:gochecknoinits
	transports.Register(Transport)
}

// Transport is an ImageTransport for SIF images.
var Transport = sifTransport{} //nolint:gochecknoglobals

type sifTransport struct{}

// Name returns the name of the transport, which must be unique among other transports.
func (t sifTransport) Name() string {
	return "oci-sif" // "sif" already registered in containers/image.
}

// ParseReference converts a string, which should not start with the ImageTransport.Name prefix,
// into an ImageReference.
func (t sifTransport) ParseReference(reference string) (types.ImageReference, error) {
	return &sifReference{path: reference}, nil
}

// ValidatePolicyConfigurationScope checks that scope is a valid name for a
// signature.PolicyTransportScopes keys (i.e. a valid PolicyConfigurationIdentity() or
// PolicyConfigurationNamespaces() return value).
//
// It is acceptable to allow an invalid value which will never be matched, it can "only" cause user
// confusion. scope passed to this function will not be "", that value is always allowed.
func (t sifTransport) ValidatePolicyConfigurationScope(_ string) error {
	return nil
}
