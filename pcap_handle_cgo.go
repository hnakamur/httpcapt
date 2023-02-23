//go:build cgo

package httpcapt

import (
	"time"

	"github.com/google/gopacket/pcap"
)

func openEthernetHandle(device string) (pcapHandle, error) {
	h, err := pcap.OpenLive(device, 1600, false, time.Second)
	if err != nil {
		return nil, err
	}
	return &cgoEthernetHandle{Handle: h}, nil
}

var _ pcapHandle = (*cgoEthernetHandle)(nil)

type cgoEthernetHandle struct {
	*pcap.Handle
}
