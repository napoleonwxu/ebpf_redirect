package tc

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

func AttachEbpfIngress(ifindex int, bpfProg *ebpf.Program, annotation string) error {
	if err := ReplaceQdiscIngress(ifindex); err != nil {
		logrus.WithField("ifindex", ifindex).
			WithField("is ingress", true).
			WithError(err).
			Warn("Failed to tc qdisc replace to the dev")
	}

	return attachEbpf(ifindex, bpfProg, annotation, true)
}

func AttachEbpfEgress(ifindex int, bpfProg *ebpf.Program, annotation string) error {
	if err := ReplaceQdiscEgress(ifindex); err != nil {
		logrus.WithField("ifindex", ifindex).
			WithField("is ingress", false).
			WithError(err).
			Warn("Failed to tc qdisc add to the dev")
	}

	return attachEbpf(ifindex, bpfProg, annotation, false)
}

func attachEbpf(ifindex int, bpfProg *ebpf.Program, annotation string, isIngress bool) error {
	logrus.WithFields(logrus.Fields{
		"ebpf prog": annotation,
		"device":    ifindex,
	}).Debug("Attach the ebpf prog to the device")

	if err := ReplaceFilter(ifindex, bpfProg, annotation, isIngress); err != nil {
		return fmt.Errorf("failed to attach ebpf %s to dev(%d): %w", annotation, ifindex, err)
	}

	return nil
}

func DetachEbpfIngress(ifindex int) error {
	return detachEbpf(ifindex, true)
}

func DetachEbpfEgress(ifindex int) error {
	return detachEbpf(ifindex, false)
}

func detachEbpf(ifindex int, isIngress bool) error {
	// Note: for pod in Kubernetes, the veth device can be destoyed before
	// detaching. As a result, we must check whether the device of `ifindex`
	// exists.

	ifi, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		logrus.WithField("ifindex", ifindex).WithError(err).Debug("device is not found for the ifindex")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"ifindex":    ifindex,
		"name":       ifi.Name,
		"is ingress": isIngress,
	}).Debugf("ebpf prog will be detached from the device")

	if err := DelQdisc(ifindex, isIngress); err != nil {
		return fmt.Errorf("failed to detach ebpf from dev(%d): %w", ifindex, err)
	}

	return nil
}
