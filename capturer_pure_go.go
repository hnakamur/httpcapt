//go:build linux && !cgo

package httpcapt

import "net"

func newEthernetCapturer(device string) (Capturer, error) {
	if device != "any" {
		return newSingleDeviceCapturer(device)
	}

	devices, err := allInterfaceNames()
	if err != nil {
		return nil, err
	}
	return NewMultiEthernetCapturer(devices)
}

func allInterfaceNames() ([]string, error) {
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	names := make([]string, len(intfs))
	for i, intf := range intfs {
		names[i] = intf.Name
	}
	return names, nil
}
