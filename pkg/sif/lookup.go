// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrNotFound is the code for when no search key is not found.
var ErrNotFound = errors.New("no match found")

// ErrMultValues is the code for when search key is not unique.
var ErrMultValues = errors.New("lookup would return more than one match")

// GetSIFArch returns the SIF arch code from go runtime arch code.
func GetSIFArch(goarch string) (sifarch string) {
	var ok bool

	archMap := map[string]string{
		"386":      HdrArch386,
		"amd64":    HdrArchAMD64,
		"arm":      HdrArchARM,
		"arm64":    HdrArchARM64,
		"ppc64":    HdrArchPPC64,
		"ppc64le":  HdrArchPPC64le,
		"mips":     HdrArchMIPS,
		"mipsle":   HdrArchMIPSle,
		"mips64":   HdrArchMIPS64,
		"mips64le": HdrArchMIPS64le,
		"s390x":    HdrArchS390x,
	}

	if sifarch, ok = archMap[goarch]; !ok {
		sifarch = HdrArchUnknown
	}
	return sifarch
}

// GetGoArch returns the go runtime arch code from the SIF arch code.
func GetGoArch(sifarch string) (goarch string) {
	var ok bool

	archMap := map[string]string{
		HdrArch386:      "386",
		HdrArchAMD64:    "amd64",
		HdrArchARM:      "arm",
		HdrArchARM64:    "arm64",
		HdrArchPPC64:    "ppc64",
		HdrArchPPC64le:  "ppc64le",
		HdrArchMIPS:     "mips",
		HdrArchMIPSle:   "mipsle",
		HdrArchMIPS64:   "mips64",
		HdrArchMIPS64le: "mips64le",
		HdrArchS390x:    "s390x",
	}

	if goarch, ok = archMap[sifarch]; !ok {
		goarch = "unknown"
	}
	return goarch
}

// GetFromDescrID searches for a descriptor with.
func (fimg *FileImage) GetFromDescrID(id uint32) (*Descriptor, int, error) {
	match := -1

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		}
		if v.ID == id {
			if match != -1 {
				return nil, -1, ErrMultValues
			}
			match = i
		}
	}

	if match == -1 {
		return nil, -1, ErrNotFound
	}

	return &fimg.DescrArr[match], match, nil
}

// GetPartFromGroup searches for partition descriptors inside a specific group.
func (fimg *FileImage) GetPartFromGroup(groupid uint32) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int
	var count int

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		}
		if v.Datatype == DataPartition && v.Groupid == groupid {
			indexes = append(indexes, i)
			descrs = append(descrs, &fimg.DescrArr[i])
			count++
		}
	}

	if count == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetSignFromGroup searches for signature descriptors inside a specific group.
func (fimg *FileImage) GetSignFromGroup(groupid uint32) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int
	var count int

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		}
		if v.Datatype == DataSignature && v.Groupid == groupid {
			indexes = append(indexes, i)
			descrs = append(descrs, &fimg.DescrArr[i])
			count++
		}
	}

	if count == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetLinkedDescrsByType searches for descriptors that point to "id", only returns the specified type.
func (fimg *FileImage) GetLinkedDescrsByType(id uint32, dataType Datatype) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		}
		if v.Datatype == dataType && v.Link == id {
			indexes = append(indexes, i)
			descrs = append(descrs, &fimg.DescrArr[i])
		}
	}

	if len(descrs) == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetFromLinkedDescr searches for descriptors that point to "id".
func (fimg *FileImage) GetFromLinkedDescr(id uint32) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int
	var count int

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		}
		if v.Link == id {
			indexes = append(indexes, i)
			descrs = append(descrs, &fimg.DescrArr[i])
			count++
		}
	}

	if count == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetFromDescr searches for descriptors comparing all non-nil fields of a provided descriptor.
func (fimg *FileImage) GetFromDescr(descr Descriptor) ([]*Descriptor, []int, error) {
	var descrs []*Descriptor
	var indexes []int
	var count int

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		} else {
			if descr.Datatype != 0 && descr.Datatype != v.Datatype {
				continue
			}
			if descr.ID != 0 && descr.ID != v.ID {
				continue
			}
			if descr.Groupid != 0 && descr.Groupid != v.Groupid {
				continue
			}
			if descr.Link != 0 && descr.Link != v.Link {
				continue
			}
			if descr.Fileoff != 0 && descr.Fileoff != v.Fileoff {
				continue
			}
			if descr.Filelen != 0 && descr.Filelen != v.Filelen {
				continue
			}
			if descr.Storelen != 0 && descr.Storelen != v.Storelen {
				continue
			}
			if descr.Ctime != 0 && descr.Ctime != v.Ctime {
				continue
			}
			if descr.Mtime != 0 && descr.Mtime != v.Mtime {
				continue
			}
			if descr.UID != 0 && descr.UID != v.UID {
				continue
			}
			if descr.GID != 0 && descr.GID != v.GID {
				continue
			}
			if descr.Name[0] != 0 && !bytes.Equal(descr.Name[:], v.Name[:]) {
				continue
			}

			indexes = append(indexes, i)
			descrs = append(descrs, &fimg.DescrArr[i])
			count++
		}
	}

	if count == 0 {
		return nil, nil, ErrNotFound
	}

	return descrs, indexes, nil
}

// GetData returns the data object associated with descriptor d from f.
func (d *Descriptor) GetData(f *FileImage) ([]byte, error) {
	b := make([]byte, d.Filelen)
	if _, err := io.ReadFull(d.GetReader(f), b); err != nil {
		return nil, err
	}
	return b, nil
}

// GetReader returns a io.Reader that reads the data object associated with descriptor d from f.
func (d *Descriptor) GetReader(f *FileImage) io.Reader {
	return io.NewSectionReader(f.Fp, d.Fileoff, d.Filelen)
}

// GetName returns the name tag associated with the descriptor. Analogous to file name.
func (d *Descriptor) GetName() string {
	return strings.TrimRight(string(d.Name[:]), "\000")
}

// GetFsType extracts the Fstype field from the Extra field of a Partition Descriptor.
func (d *Descriptor) GetFsType() (Fstype, error) {
	if d.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Fstype, nil
}

// GetPartType extracts the Parttype field from the Extra field of a Partition Descriptor.
func (d *Descriptor) GetPartType() (Parttype, error) {
	if d.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Parttype, nil
}

// GetArch extracts the Arch field from the Extra field of a Partition Descriptor.
func (d *Descriptor) GetArch() ([hdrArchLen]byte, error) {
	if d.Datatype != DataPartition {
		return [hdrArchLen]byte{}, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return [hdrArchLen]byte{}, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Arch, nil
}

// GetHashType extracts the Hashtype field from the Extra field of a Signature Descriptor.
func (d *Descriptor) GetHashType() (Hashtype, error) {
	if d.Datatype != DataSignature {
		return -1, fmt.Errorf("expected DataSignature, got %v", d.Datatype)
	}

	var sinfo Signature
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return -1, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Hashtype, nil
}

// GetEntity extracts the signing entity field from the Extra field of a Signature Descriptor.
func (d *Descriptor) GetEntity() ([]byte, error) {
	if d.Datatype != DataSignature {
		return nil, fmt.Errorf("expected DataSignature, got %v", d.Datatype)
	}

	var sinfo Signature
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return nil, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Entity[:], nil
}

// GetEntityString returns the string version of the stored entity.
func (d *Descriptor) GetEntityString() (string, error) {
	fingerprint, err := d.GetEntity()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0X", fingerprint[:20]), nil
}

// GetFormatType extracts the Formattype field from the Extra field of a Cryptographic Message Descriptor.
func (d *Descriptor) GetFormatType() (Formattype, error) {
	if d.Datatype != DataCryptoMessage {
		return -1, fmt.Errorf("expected DataCryptoMessage, got %v", d.Datatype)
	}

	var cinfo CryptoMessage
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &cinfo); err != nil {
		return -1, fmt.Errorf("while extracting Crypto extra info: %s", err)
	}

	return cinfo.Formattype, nil
}

// GetMessageType extracts the Messagetype field from the Extra field of a Cryptographic Message Descriptor.
func (d *Descriptor) GetMessageType() (Messagetype, error) {
	if d.Datatype != DataCryptoMessage {
		return -1, fmt.Errorf("expected DataCryptoMessage, got %v", d.Datatype)
	}

	var cinfo CryptoMessage
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &cinfo); err != nil {
		return -1, fmt.Errorf("while extracting Crypto extra info: %s", err)
	}

	return cinfo.Messagetype, nil
}

// GetPartPrimSys returns the primary system partition if present. There should
// be only one primary system partition in a SIF file.
func (fimg *FileImage) GetPartPrimSys() (*Descriptor, int, error) {
	var descr *Descriptor
	index := -1

	for i, v := range fimg.DescrArr {
		if !v.Used {
			continue
		}
		if v.Datatype == DataPartition {
			ptype, err := v.GetPartType()
			if err != nil {
				return nil, -1, err
			}
			if ptype == PartPrimSys {
				if index != -1 {
					return nil, -1, ErrMultValues
				}
				index = i
				descr = &fimg.DescrArr[i]
			}
		}
	}

	if index == -1 {
		return nil, -1, ErrNotFound
	}

	return descr, index, nil
}
