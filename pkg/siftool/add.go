// Copyright (c) 2019-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package siftool

import (
	"errors"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/sylabs/sif/v2/pkg/sif"
)

var (
	dataType   *int
	partType   *int32
	partFS     *int32
	partArch   *int32
	signHash   *int32
	signEntity *string
	groupID    *uint32
	linkID     *uint32
	alignment  *int
	name       *string
)

// getAddExamples returns add command examples based on rootCmd.
func getAddExamples(rootPath string) string {
	examples := []string{
		rootPath +
			" add image.sif recipe.def -datatype 1",
		rootPath +
			" add image.sif rootfs.squashfs --datatype 4 --parttype 1 --partfs 1 ----partarch 2",
		rootPath +
			" add image.sif signature.bin -datatype 5 --signentity 433FE984155206BD962725E20E8713472A879943 --signhash 1",
	}
	return strings.Join(examples, "\n")
}

// addFlags declares the command line flags for the add command.
func addFlags(fs *pflag.FlagSet) {
	dataType = fs.Int("datatype", 0, `the type of data to add
[NEEDED, no default]:
  1-Deffile,   2-EnvVar,    3-Labels,
  4-Partition, 5-Signature, 6-GenericJSON,
  7-Generic,   8-CryptoMessage`)
	partType = fs.Int32("parttype", 0, `the type of partition (with -datatype 4-Partition)
[NEEDED, no default]:
  1-System,    2-PrimSys,   3-Data,
  4-Overlay`)
	partFS = fs.Int32("partfs", 0, `the filesystem used (with -datatype 4-Partition)
[NEEDED, no default]:
  1-Squash,    2-Ext3,      3-ImmuObj,
  4-Raw`)
	partArch = fs.Int32("partarch", 0, `the main architecture used (with -datatype 4-Partition)
[NEEDED, no default]:
  1-386,       2-amd64,     3-arm,
  4-arm64,     5-ppc64,     6-ppc64le,
  7-mips,      8-mipsle,    9-mips64,
  10-mips64le, 11-s390x`)
	signHash = fs.Int32("signhash", 0, `the signature hash used (with -datatype 5-Signature)
[NEEDED, no default]:
  1-SHA256,    2-SHA384,    3-SHA512,
  4-BLAKE2S,   5-BLAKE2B`)
	signEntity = fs.String("signentity", "", `the entity that signs (with -datatype 5-Signature)
[NEEDED, no default]:
  example: 433FE984155206BD962725E20E8713472A879943`)
	groupID = fs.Uint32("groupid", 0, "set groupid [default: 0]")
	linkID = fs.Uint32("link", 0, "set link pointer [default: 0]")
	alignment = fs.Int("alignment", 0, "set alignment constraint [default: aligned on page size]")
	name = fs.String("filename", "", "set logical filename/handle [default: input filename]")
}

// getDataType returns the data type corresponding to input.
func getDataType() (sif.Datatype, error) {
	switch *dataType {
	case 1:
		return sif.DataDeffile, nil
	case 2:
		return sif.DataEnvVar, nil
	case 3:
		return sif.DataLabels, nil
	case 4:
		return sif.DataPartition, nil
	case 5:
		return sif.DataSignature, nil
	case 6:
		return sif.DataGenericJSON, nil
	case 7:
		return sif.DataGeneric, nil
	case 8:
		return sif.DataCryptoMessage, nil
	default:
		return 0, errors.New("-datatype flag is required with a valid range")
	}
}

func getArch() string {
	switch *partArch {
	case 1:
		return "386"
	case 2:
		return "amd64"
	case 3:
		return "arm"
	case 4:
		return "arm64"
	case 5:
		return "ppc64"
	case 6:
		return "ppc64le"
	case 7:
		return "mips"
	case 8:
		return "mipsle"
	case 9:
		return "mips64"
	case 10:
		return "mips64le"
	case 11:
		return "s390x"
	default:
		return "unknown"
	}
}

func getOptions(dt sif.Datatype, fs *pflag.FlagSet) ([]sif.DescriptorInputOpt, error) {
	var opts []sif.DescriptorInputOpt

	if fs.Changed("groupid") {
		opts = append(opts, sif.OptDataObjectGroupID(*groupID))
	}

	if fs.Changed("link") {
		opts = append(opts, sif.OptDataObjectLinkedID(*linkID))
	}

	if fs.Changed("alignment") {
		opts = append(opts, sif.OptDataObjectAlignment(*alignment))
	}

	if fs.Changed("filename") {
		opts = append(opts, sif.OptDataObjectName(*name))
	}

	if dt == sif.DataPartition {
		if *partType == 0 || *partFS == 0 || *partArch == 0 {
			return nil, errors.New("with partition datatype, -partfs, -parttype and -partarch must be passed")
		}

		opts = append(opts,
			sif.OptPartitionMetadata(sif.Fstype(*partFS), sif.Parttype(*partType), getArch()),
		)
	}

	if dt == sif.DataSignature {
		opts = append(opts, sif.OptSignatureMetadata(sif.Hashtype(*signHash), *signEntity))
	}

	return opts, nil
}

// getAdd returns a command that adds a data object to a SIF.
func (c *command) getAdd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add <sif_path> <object_path>",
		Short:   "Add data object",
		Long:    "Add a data object to a SIF image.",
		Example: getAddExamples(c.opts.rootPath),
		Args:    cobra.ExactArgs(2),
	}
	addFlags(cmd.Flags())

	cmd.PreRunE = c.initApp
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		dt, err := getDataType()
		if err != nil {
			return err
		}

		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()

		opts, err := getOptions(dt, cmd.Flags())
		if err != nil {
			return err
		}

		return c.app.Add(args[0], dt, f, opts...)
	}

	return cmd
}
