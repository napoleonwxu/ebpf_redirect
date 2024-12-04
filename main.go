// This program demonstrates attaching an eBPF program to a network interface,
// to test redirect packets based on dst mac.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"

	"ebpf_redirect/tc"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ./ebpf_redirect.c -- -I./include

const (
	bpfFSPath = "/sys/fs/bpf"
)

type MACKey struct {
	MAC types.MACAddr
}

func newMACKey(mac net.HardwareAddr) MACKey {
	key := MACKey{}
	copy(key.MAC[:], mac)
	return key
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify <host main link>")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	mainLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to lookup network iface %q: %s", ifaceName, err)
	}

	ifaces, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("failed to list network interfaces: %s", err)
	}

	macs := make([]net.HardwareAddr, 0, len(ifaces))
	ids := make([]int, 0, len(ifaces))
	for _, iface := range ifaces {
		mac := iface.Attrs().HardwareAddr
		if len(mac) == 6 {
			macs = append(macs, mac)
			ids = append(ids, iface.Attrs().Index)
		}
	}
	keys, values := generateMapData(macs, ids)

	objs := initObjects()

	var ebpfMap *ebpf.Map
	var ebpfProg *ebpf.Program
	var annotation string

	ebpfMap = objs.MacMap
	ebpfProg = objs.RedirectBaseDstMac
	annotation = fmt.Sprintf("%s:[%s]", "ebpf_redirect.o", "l2")

	count, err := ebpfMap.BatchUpdate(keys, values, nil)
	if err != nil {
		log.Fatalf("BatchUpdate failed: %v", err)
	}
	if count != len(keys) {
		log.Fatalf("BatchUpdate: expected %d, actually %d", len(keys), count)
	}

	defer objs.Close()

	// Attach the program.
	err = tc.AttachEbpfIngress(mainLink.Attrs().Index, ebpfProg, annotation)
	if err != nil {
		log.Fatalf("could not attach ebpf program: %s", err)
	}

	log.Printf("Successfully attached ebpf to iface %q (index %d), map size: %d", ifaceName, mainLink.Attrs().Index, count)
}

func initObjects() bpfObjects {
	pinPath := path.Join(bpfFSPath, "ebpf_redirect_test")
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs %s: %+v", pinPath, err)
	}

	bpfSpec, err := loadBpf()
	if err != nil {
		log.Fatalf("failed to load bpf spec: %+v", err)
	}

	for _, p := range bpfSpec.Programs {
		// As we know, the elf section of our bpf program is private ones. As a
		// result, `cilium/ebpf` can not recognize the section name, and it will
		// assign the type of bpf program as `UnspecifiedProgram`. Therefore, we
		// have to specify the type of bpf program as `SchedCLS`.
		p.AttachType = ebpf.AttachNone
		if p.Type == ebpf.UnspecifiedProgram {
			p.Type = ebpf.SchedCLS
		}
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	ebpfCollection := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF program,
			// so it can be re-used if it already exists or
			// create it if not.
			PinPath: pinPath,
		},
	}
	err = bpfSpec.LoadAndAssign(&objs, ebpfCollection)
	if err != nil {
		log.Fatalf("loading objects failed: %s", err)
	}

	return objs
}

func generateMapData(macs []net.HardwareAddr, ids []int) ([]MACKey, []uint16) {
	keys := make([]MACKey, 0, len(macs))
	values := make([]uint16, 0, len(ids))
	for i := range macs {
		keys = append(keys, newMACKey(macs[i]))
		values = append(values, uint16(ids[i]))
	}
	return keys, values
}
