//go:build cgo

package httpcapt

import (
	"time"

	"github.com/google/gopacket/pcap"
)

var _ PcapHandle = (*cgoPcapHandle)(nil)

type cgoPcapHandle struct {
	*pcap.Handle
}

func openEthernetHandle(device string) (PcapHandle, error) {
	h, err := pcap.OpenLive(device, 1600, false, time.Second)
	if err != nil {
		return nil, err
	}
	return &cgoPcapHandle{Handle: h}, nil
}
