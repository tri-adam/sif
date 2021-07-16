// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"errors"
	"io"
	"testing"
)

func TestNewDataObject(t *testing.T) {
	t.Parallel()

	eofReader := io.MultiReader()

	tests := []struct {
		name    string
		t       Datatype
		r       io.Reader
		opts    []DescriptorInputOpt
		wantErr error
	}{
		{
			name: "Deffile",
			t:    DataDeffile,
			r:    eofReader,
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewDescriptorInput(tt.t, tt.r, tt.opts...)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}
		})
	}
}
