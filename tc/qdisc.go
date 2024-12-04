package tc

import (
	"fmt"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

// qdisc kinds
const (
	qdiscKindIngress = "ingress"
	qdiscKindClsact  = "clsact"
)

func getQdiscObj(ifindex int, isIngress bool) *tc.Object {
	var (
		parent uint32
		kind   string
	)
	if isIngress {
		parent, kind = tc.HandleIngress, qdiscKindIngress
	} else {
		handleClsact := tc.HandleIngress
		parent, kind = handleClsact, qdiscKindClsact
	}

	return &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  parent,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: kind,
		},
	}
}

// AddQdisc equals to `tc qdisc del dev ${dev} ingress/clsact`.
func AddQdisc(ifindex int, isIngress bool) error {
	return withTc(func(rtnl *tc.Tc) error {
		if err := rtnl.Qdisc().Add(getQdiscObj(ifindex, isIngress)); err != nil {
			return fmt.Errorf("failed to tc qdisc add dev [%d] ingress(%v): %w", ifindex, isIngress, err)
		}

		return nil
	})
}

// DelQdisc equals to `tc qdisc del dev ${dev} ingress/clsact`.
func DelQdisc(ifindex int, isIngress bool) error {
	return withTc(func(rtnl *tc.Tc) error {
		if err := rtnl.Qdisc().Delete(getQdiscObj(ifindex, isIngress)); err != nil {
			return fmt.Errorf("failed to tc qdisc del dev [%d] ingress(%v): %w", ifindex, isIngress, err)
		}

		return nil
	})
}

// ReplaceQdisc equals to `tc qdisc replace dev ${dev} ingress/egress`.
func ReplaceQdisc(ifindex int, isIngress bool) error {
	return withTc(func(rtnl *tc.Tc) error {
		if err := rtnl.Qdisc().Replace(getQdiscObj(ifindex, isIngress)); err != nil {
			return fmt.Errorf("failed to tc qdisc replace dev [%d] ingress(%v): %w", ifindex, isIngress, err)
		}

		return nil
	})
}

func ReplaceQdiscIngress(ifindex int) error {
	return ReplaceQdisc(ifindex, true)
}

func ReplaceQdiscEgress(ifindex int) error {
	return ReplaceQdisc(ifindex, false)
}
