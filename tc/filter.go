package tc

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

// ReplaceFilter equals to `tc filter replace dev ${dev} ingress pref 10 handle
// 1 bpf da obj ${objPath} sec ${objSec}`.
//
// Load the bpf obj and bpf maps with `cilium/ebpf`. Then, replace the tc filter
// bpf obj with `go-tc`.
func ReplaceFilter(ifindex int, bpfProg *ebpf.Program, annotation string, isIngress bool) (err error) {
	bpfProgFD := uint32(bpfProg.FD())

	var tcBpfFlags uint32
	tcBpfFlags |= tc.BpfActDirect // da, direct-action

	// By default, the protocol is ETH_P_ALL.
	//
	// Ref: `tc/tc_filter.c:tc_filter_modify()` of `iprotue2` source code.
	protocol := htons(unix.ETH_P_ALL)

	// ingress or egress
	//
	// Ref: `tc/tc_filter.c:tc_filter_modify()` of `iproute2` source code.
	var direction uint32
	if isIngress {
		direction = core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress)
	} else {
		direction = core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)
	}

	obj := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  1,
			Parent:  direction,

			// The upper 16 bits hold the priority information while the lower
			// 16 bits hold protocol information.
			//
			// Ref: https://github.com/florianl/go-tc/issues/21
			//
			// Ref: `tc/tc_filter.c:tc_filter_modify()` of `iproute2` source
			// code
			Info: 10<<16 | uint32(protocol), // for `pref 10`
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &bpfProgFD,
				Name:  &annotation,
				Flags: &tcBpfFlags,
			},
		},
	}

	return withTc(func(rtnl *tc.Tc) error {
		if err := rtnl.Filter().Replace(&obj); err != nil {
			return fmt.Errorf("failed to replace tc filter for ifindex(%d): %w", ifindex, err)
		}

		return nil
	})
}
