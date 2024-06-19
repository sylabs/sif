// Copyright (c) 2018-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"errors"
	"testing"
	"time"

	"github.com/sebdah/goldie/v2"
)

func TestSetPrimPart(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		id         uint32
		opts       []SetOpt
		wantErr    error
	}{
		{
			name: "ErrObjectNotFound",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			id:      1,
			wantErr: ErrObjectNotFound,
		},
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartSystem, "386"),
					),
				),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			id: 1,
			opts: []SetOpt{
				OptSetDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartPrimSys, "386"),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsRaw, PartSystem, "amd64"),
					),
				),
			},
			id: 2,
			opts: []SetOpt{
				OptSetWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "One",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartSystem, "386"),
					),
				),
			},
			id: 1,
		},
		{
			name: "Two",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartPrimSys, "386"),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsRaw, PartSystem, "amd64"),
					),
				),
			},
			id: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.SetPrimPart(tt.id, tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Error(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestSetMetadata(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		id         uint32
		opts       []SetOpt
		wantErr    error
	}{
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			id: 1,
			opts: []SetOpt{
				OptSetDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			opts: []SetOpt{
				OptSetWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "One",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
		},
		{
			name: "Two",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataOCIBlob, []byte{0xfe, 0xed}),
				),
			},
			id: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.SetMetadata(tt.id, newOCIBlobDigest(), tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Error(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}
