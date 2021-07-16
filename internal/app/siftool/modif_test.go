// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/sylabs/sif/v2/pkg/sif"
)

func TestApp_New(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}
}

func TestApp_Add(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tests := []struct {
		name     string
		data     []byte
		dataType sif.Datatype
		opts     []sif.DescriptorInputOpt
		wantErr  error
	}{
		{
			name:     "DataPartition",
			data:     []byte{0xde, 0xad, 0xbe, 0xef},
			dataType: sif.DataPartition,
			opts: []sif.DescriptorInputOpt{
				sif.OptPartitionMetadata(sif.FsSquash, sif.PartPrimSys, "386"),
			},
		},
		{
			name:     "DataSignature",
			data:     []byte{0xde, 0xad, 0xbe, 0xef},
			dataType: sif.DataSignature,
			opts: []sif.DescriptorInputOpt{
				sif.OptSignatureMetadata(sif.HashSHA256, "12045C8C0B1004D058DE4BEDA20C27EE7FF7BA84"),
			},
		},
		{
			name:     "CryptoMessage",
			data:     []byte{0xde, 0xad, 0xbe, 0xef},
			dataType: sif.DataCryptoMessage,
			opts: []sif.DescriptorInputOpt{
				sif.OptCryptoMessageMetadata(sif.FormatOpenPGP, sif.MessageClearSignature),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf, err := os.CreateTemp("", "sif-test-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tf.Name())
			tf.Close()

			if err := a.New(tf.Name()); err != nil {
				t.Fatal(err)
			}

			data := bytes.NewReader(tt.data)
			if got, want := a.Add(tf.Name(), tt.dataType, data, tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestApp_Del(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}

	err = a.Add(tf.Name(), sif.DataGeneric, bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}))
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Del(tf.Name(), 1); err != nil {
		t.Fatal(err)
	}
}

func TestApp_Setprim(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	tf, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	tf.Close()

	if err := a.New(tf.Name()); err != nil {
		t.Fatal(err)
	}

	err = a.Add(tf.Name(), sif.DataPartition, bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}),
		sif.OptPartitionMetadata(sif.FsSquash, sif.PartSystem, "386"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Setprim(tf.Name(), 1); err != nil {
		t.Fatal(err)
	}
}
