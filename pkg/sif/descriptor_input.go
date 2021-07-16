// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type unexpectedDataTypeError struct {
	got  Datatype
	want Datatype
}

func (e *unexpectedDataTypeError) Error() string {
	return fmt.Sprintf("got data type %v (%v), want %v (%v)",
		e.got,
		e.got.String(),
		e.want,
		e.want.String(),
	)
}

// descriptorOpts accumulates data object options.
type descriptorOpts struct {
	groupID   uint32
	linkID    uint32
	alignment int
	name      string
	extra     bytes.Buffer
}

// DescriptorInputOpt are used to specify data object options.
type DescriptorInputOpt func(Datatype, *descriptorOpts) error

// OptDataObjectGroupID specifies id as data object group ID.
func OptDataObjectGroupID(id uint32) DescriptorInputOpt {
	return func(_ Datatype, opts *descriptorOpts) error {
		opts.groupID = id
		return nil
	}
}

// OptDataObjectLinkedID specifies id as data object link ID.
func OptDataObjectLinkedID(id uint32) DescriptorInputOpt {
	return func(_ Datatype, opts *descriptorOpts) error {
		opts.linkID = id
		return nil
	}
}

// OptDataObjectAlignment specifies n as the data object alignment requirement.
func OptDataObjectAlignment(n int) DescriptorInputOpt {
	return func(_ Datatype, opts *descriptorOpts) error {
		opts.alignment = n
		return nil
	}
}

// OptDataObjectName specifies name as the data object name.
func OptDataObjectName(name string) DescriptorInputOpt {
	return func(_ Datatype, opts *descriptorOpts) error {
		opts.name = name
		return nil
	}
}

// OptCryptoMessageMetadata sets metadata for a crypto message data object. The format type is set
// to ft, and the message type is set to mt.
//
// If this option is applied to a data object with an incompatible type, an error is returned.
func OptCryptoMessageMetadata(ft Formattype, mt Messagetype) DescriptorInputOpt {
	return func(t Datatype, opts *descriptorOpts) error {
		if got, want := t, DataCryptoMessage; got != want {
			return &unexpectedDataTypeError{got, want}
		}

		data := CryptoMessage{
			Formattype:  ft,
			Messagetype: mt,
		}
		return binary.Write(&opts.extra, binary.LittleEndian, data)
	}
}

// OptPartitionMetadata sets metadata for a partition data object. The filesystem type is set to
// fs, the partition type is set to pt, and the CPU architecture is set to arch. The value of arch
// should be the architecture as represented by the Go runtime.
//
// If this option is applied to a data object with an incompatible type, an error is returned.
func OptPartitionMetadata(fs Fstype, pt Parttype, arch string) DescriptorInputOpt {
	return func(t Datatype, opts *descriptorOpts) error {
		if got, want := t, DataPartition; got != want {
			return &unexpectedDataTypeError{got, want}
		}

		data := Partition{
			Fstype:   fs,
			Parttype: pt,
		}

		sifarch := GetSIFArch(arch)
		if sifarch == HdrArchUnknown {
			return fmt.Errorf("unknown architecture: %v", arch)
		}
		copy(data.Arch[:], sifarch)

		opts.extra.Reset()
		return binary.Write(&opts.extra, binary.LittleEndian, data)
	}
}

// OptSignatureMetadata sets metadata for a signature data object. The hash type is set to t, and
// the signing entity is set to entity.
//
// If this option is applied to a data object with an incompatible type, an error is returned.
func OptSignatureMetadata(ht Hashtype, entity string) DescriptorInputOpt {
	return func(t Datatype, opts *descriptorOpts) error {
		if got, want := t, DataSignature; got != want {
			return &unexpectedDataTypeError{got, want}
		}

		data := Signature{
			Hashtype: ht,
		}

		b, err := hex.DecodeString(entity)
		if err != nil {
			return err
		}
		copy(data.Entity[:], b)

		return binary.Write(&opts.extra, binary.LittleEndian, data)
	}
}

// NewDescriptorInput returns a DescriptorInput representing a data object of type t, with contents
// read from r, configured according to opts.
//
// It is possible (and often necessary) to store additional metadata related to certain types of
// data objects. Consider supplying options such as OptCryptoMessageMetadata, OptPartitionMetadata,
// and OptSignatureMetadata for this purpose.
//
// By default, the data object will not be part of a data object group. To override this behavior,
// use OptDataObjectGroupID. To link this data object with another data object, use
// OptDataObjectLinkedID.
//
// By default, the data object will be aligned according to the system's memory page size. To
// override this behavior, consider using OptDataObjectAlignment.
//
// By default, no name is set for data object. To set a name, use OptDataObjectName.
func NewDescriptorInput(t Datatype, r io.Reader, opts ...DescriptorInputOpt) (DescriptorInput, error) {
	dopts := descriptorOpts{
		alignment: os.Getpagesize(),
	}

	for _, opt := range opts {
		if err := opt(t, &dopts); err != nil {
			return DescriptorInput{}, err
		}
	}

	di := DescriptorInput{
		Datatype:  t,
		Fp:        r,
		Groupid:   dopts.groupID | DescrGroupMask,
		Link:      dopts.linkID,
		Alignment: dopts.alignment,
		Fname:     dopts.name,
		Extra:     dopts.extra,
	}
	return di, nil
}
